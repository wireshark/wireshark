/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-f1ap.c                                                              */
/* asn2wrs.py -p f1ap -c ./f1ap.cnf -s ./packet-f1ap-template -D . -O ../.. F1AP-CommonDataTypes.asn F1AP-Constants.asn F1AP-Containers.asn F1AP-IEs.asn F1AP-PDU-Contents.asn F1AP-PDU-Descriptions.asn */

/* Input file: packet-f1ap-template.c */

#line 1 "./asn1/f1ap/packet-f1ap-template.c"
/* packet-f1ap.c
 * Routines for E-UTRAN F1 Application Protocol (F1AP) packet dissection
 * Copyright 2018, Pascal Quantin <pascal.quantin@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 38.473 V15.0.0 (2017-12)
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/asn1.h>
#include <epan/sctpppids.h>
#include <epan/proto_data.h>

#include "packet-per.h"
#include "packet-x2ap.h"
#include "packet-nr-rrc.h"
#include "packet-e212.h"

#define PNAME  "F1 Application Protocol"
#define PSNAME "F1AP"
#define PFNAME "f1ap"

#define SCTP_PORT_F1AP 38472

void proto_register_f1ap(void);
void proto_reg_handoff_f1ap(void);


/*--- Included file: packet-f1ap-val.h ---*/
#line 1 "./asn1/f1ap/packet-f1ap-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxnoofErrors                  256
#define maxnoofIndividualF1ConnectionsToReset 256
#define maxCellingNBDU                 512
#define maxnoofSCells                  64
#define maxnoofSRBs                    8
#define maxnoofDRBs                    64
#define maxnoofULTunnels               2
#define maxnoofDLTunnels               2
#define maxnoofBPLMNs                  6

typedef enum _ProcedureCode_enum {
  id_Reset     =   0,
  id_F1Setup   =   1,
  id_ErrorIndication =   2,
  id_gNBDUConfigurationUpdate =   3,
  id_gNBCUConfigurationUpdate =   4,
  id_UEContextSetup =   5,
  id_UEContextRelease =   6,
  id_UEContextModification =   7,
  id_UEContextModificationRequired =   8,
  id_UEMobilityCommand =   9,
  id_UEContextReleaseRequest =  10,
  id_InitialULRRCMessageTransfer =  11,
  id_DLRRCMessageTransfer =  12,
  id_ULRRCMessageTransfer =  13,
  id_SystemInformationDelivery =  14,
  id_Paging    =  15
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_Cause     =   0,
  id_CriticalityDiagnostics =   1,
  id_gNB_DU_F1AP_ID =   2,
  id_gNB_CU_F1AP_ID =   3,
  id_ResetType =   4,
  id_TimeToWait =   5,
  id_UE_associatedLogicalF1_ConnectionItem =   6,
  id_UE_associatedLogicalF1_ConnectionListResAck =   7,
  id_RRCContainer =   8,
  id_SRBID     =   9,
  id_gNB_DU_ID =  10,
  id_gNB_Name  =  11,
  id_NRCellID  =  12,
  id_PCI       =  13,
  id_gNB_DU_Served_Cells_List =  14,
  id_Cells_to_be_Activated_List =  15,
  id_Served_Cells_To_Add_List =  16,
  id_Served_Cells_To_Modify_List =  17,
  id_Served_Cells_To_Delete_List =  18,
  id_Cells_to_be_Deactivated_List =  19,
  id_Cells_Failed_to_be_Activated_List =  20,
  id_TransactionID =  21,
  id_Served_Cell_Information =  22,
  id_gNB_DU_System_Information =  23,
  id_NCGI      =  24,
  id_gNB_CU_System_Information =  25,
  id_OldNCGI   =  26,
  id_DRBID     =  27,
  id_PSCell_ID =  28,
  id_EUTRANQoS =  29,
  id_SRBs_ToBeSetup_List =  30,
  id_DRBs_ToBeSetup_List =  31,
  id_DLTunnels_ToBeSetup_List =  32,
  id_ULTunnels_ToBeSetup_List =  33,
  id_UL_GTP_Tunnel_EndPoint =  34,
  id_DL_GTP_Tunnel_EndPoint =  35,
  id_CUtoDURRCInformation =  36,
  id_DUtoCURRCInformation =  37,
  id_UERadioCapability =  38,
  id_UEAggregateMaximumBitRate =  39,
  id_SCell_ToBeSetup_List =  40,
  id_ResourceCoordinationTransferContainer =  41,
  id_DRBs_ToBeModified_List =  42,
  id_DRBs_ToBeReleased_List =  43,
  id_DRBs_Modified_List =  44,
  id_DRBs_FailedToSetup_List =  45,
  id_DRBs_FailedToBeModified_List =  46,
  id_SCell_ID  =  47,
  id_DRXCycle  =  48,
  id_DRBs_Setup_List =  49,
  id_SRBs_Setup_List =  50,
  id_DRBs_FailedToBeSetup_List =  51,
  id_SRBs_FailedToBeSetup_List =  52,
  id_DLTunnels_ToBeSetup_list =  53,
  id_ULTunnels_ToBeSetup_list =  54,
  id_TransmissionStopIndicator =  55,
  id_DRBs_Required_ToBeModified_List =  56,
  id_DRBs_Required_ToBeReleased_List =  57,
  id_SRBs_Required_ToBeReleased_List =  58,
  id_oldgNB_DU_F1AP_ID =  59,
  id_SRBs_ToBeReleased_List =  60,
  id_DRBs_ModifiedConf_List =  61,
  id_privateMessage =  62
} ProtocolIE_ID_enum;

/*--- End of included file: packet-f1ap-val.h ---*/
#line 37 "./asn1/f1ap/packet-f1ap-template.c"

/* Initialize the protocol and registered fields */
static int proto_f1ap = -1;

static int hf_f1ap_transportLayerAddressIPv4 = -1;
static int hf_f1ap_transportLayerAddressIPv6 = -1;

/*--- Included file: packet-f1ap-hf.c ---*/
#line 1 "./asn1/f1ap/packet-f1ap-hf.c"
static int hf_f1ap_Cause_PDU = -1;                /* Cause */
static int hf_f1ap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_f1ap_CUtoDURRCInformation_PDU = -1;  /* CUtoDURRCInformation */
static int hf_f1ap_DRBID_PDU = -1;                /* DRBID */
static int hf_f1ap_DRXCycle_PDU = -1;             /* DRXCycle */
static int hf_f1ap_DUtoCURRCInformation_PDU = -1;  /* DUtoCURRCInformation */
static int hf_f1ap_EUTRANQoS_PDU = -1;            /* EUTRANQoS */
static int hf_f1ap_GNB_CU_F1AP_ID_PDU = -1;       /* GNB_CU_F1AP_ID */
static int hf_f1ap_GNB_DU_F1AP_ID_PDU = -1;       /* GNB_DU_F1AP_ID */
static int hf_f1ap_GNB_DU_ID_PDU = -1;            /* GNB_DU_ID */
static int hf_f1ap_GNB_DU_System_Information_PDU = -1;  /* GNB_DU_System_Information */
static int hf_f1ap_GTPTunnelEndpoint_PDU = -1;    /* GTPTunnelEndpoint */
static int hf_f1ap_NCGI_PDU = -1;                 /* NCGI */
static int hf_f1ap_PCI_PDU = -1;                  /* PCI */
static int hf_f1ap_RRCContainer_PDU = -1;         /* RRCContainer */
static int hf_f1ap_Served_Cell_Information_PDU = -1;  /* Served_Cell_Information */
static int hf_f1ap_SRBID_PDU = -1;                /* SRBID */
static int hf_f1ap_TimeToWait_PDU = -1;           /* TimeToWait */
static int hf_f1ap_TransactionID_PDU = -1;        /* TransactionID */
static int hf_f1ap_TransmissionStopIndicator_PDU = -1;  /* TransmissionStopIndicator */
static int hf_f1ap_UE_associatedLogicalF1_ConnectionItem_PDU = -1;  /* UE_associatedLogicalF1_ConnectionItem */
static int hf_f1ap_Reset_PDU = -1;                /* Reset */
static int hf_f1ap_ResetType_PDU = -1;            /* ResetType */
static int hf_f1ap_ResetAcknowledge_PDU = -1;     /* ResetAcknowledge */
static int hf_f1ap_UE_associatedLogicalF1_ConnectionListResAck_PDU = -1;  /* UE_associatedLogicalF1_ConnectionListResAck */
static int hf_f1ap_ErrorIndication_PDU = -1;      /* ErrorIndication */
static int hf_f1ap_F1SetupRequest_PDU = -1;       /* F1SetupRequest */
static int hf_f1ap_GNB_DU_Served_Cells_List_PDU = -1;  /* GNB_DU_Served_Cells_List */
static int hf_f1ap_GNB_Name_PDU = -1;             /* GNB_Name */
static int hf_f1ap_F1SetupResponse_PDU = -1;      /* F1SetupResponse */
static int hf_f1ap_Cells_to_be_Activated_List_PDU = -1;  /* Cells_to_be_Activated_List */
static int hf_f1ap_F1SetupFailure_PDU = -1;       /* F1SetupFailure */
static int hf_f1ap_GNBDUConfigurationUpdate_PDU = -1;  /* GNBDUConfigurationUpdate */
static int hf_f1ap_Served_Cells_To_Add_List_PDU = -1;  /* Served_Cells_To_Add_List */
static int hf_f1ap_Served_Cells_To_Modify_List_PDU = -1;  /* Served_Cells_To_Modify_List */
static int hf_f1ap_Served_Cells_To_Delete_List_PDU = -1;  /* Served_Cells_To_Delete_List */
static int hf_f1ap_GNBDUConfigurationUpdateAcknowledge_PDU = -1;  /* GNBDUConfigurationUpdateAcknowledge */
static int hf_f1ap_GNBDUConfigurationUpdateFailure_PDU = -1;  /* GNBDUConfigurationUpdateFailure */
static int hf_f1ap_GNBCUConfigurationUpdate_PDU = -1;  /* GNBCUConfigurationUpdate */
static int hf_f1ap_Cells_to_be_Deactivated_List_PDU = -1;  /* Cells_to_be_Deactivated_List */
static int hf_f1ap_GNBCUConfigurationUpdateAcknowledge_PDU = -1;  /* GNBCUConfigurationUpdateAcknowledge */
static int hf_f1ap_Cells_Failed_to_be_Activated_List_PDU = -1;  /* Cells_Failed_to_be_Activated_List */
static int hf_f1ap_GNBCUConfigurationUpdateFailure_PDU = -1;  /* GNBCUConfigurationUpdateFailure */
static int hf_f1ap_UEContextSetupRequest_PDU = -1;  /* UEContextSetupRequest */
static int hf_f1ap_SCell_ToBeSetup_List_PDU = -1;  /* SCell_ToBeSetup_List */
static int hf_f1ap_SRBs_ToBeSetup_List_PDU = -1;  /* SRBs_ToBeSetup_List */
static int hf_f1ap_DRBs_ToBeSetup_List_PDU = -1;  /* DRBs_ToBeSetup_List */
static int hf_f1ap_ResourceCoordinationTransferContainer_PDU = -1;  /* ResourceCoordinationTransferContainer */
static int hf_f1ap_ULTunnels_ToBeSetup_list_PDU = -1;  /* ULTunnels_ToBeSetup_list */
static int hf_f1ap_UEContextSetupResponse_PDU = -1;  /* UEContextSetupResponse */
static int hf_f1ap_SRBs_Setup_List_PDU = -1;      /* SRBs_Setup_List */
static int hf_f1ap_DRBs_Setup_List_PDU = -1;      /* DRBs_Setup_List */
static int hf_f1ap_SRBs_FailedToBeSetup_List_PDU = -1;  /* SRBs_FailedToBeSetup_List */
static int hf_f1ap_DRBs_FailedToBeSetup_List_PDU = -1;  /* DRBs_FailedToBeSetup_List */
static int hf_f1ap_DLTunnels_ToBeSetup_list_PDU = -1;  /* DLTunnels_ToBeSetup_list */
static int hf_f1ap_UEContextSetupFailure_PDU = -1;  /* UEContextSetupFailure */
static int hf_f1ap_UEContextReleaseRequest_PDU = -1;  /* UEContextReleaseRequest */
static int hf_f1ap_UEContextReleaseCommand_PDU = -1;  /* UEContextReleaseCommand */
static int hf_f1ap_UEContextReleaseComplete_PDU = -1;  /* UEContextReleaseComplete */
static int hf_f1ap_UEContextModificationRequest_PDU = -1;  /* UEContextModificationRequest */
static int hf_f1ap_DRBs_ToBeModified_List_PDU = -1;  /* DRBs_ToBeModified_List */
static int hf_f1ap_SRBs_ToBeReleased_List_PDU = -1;  /* SRBs_ToBeReleased_List */
static int hf_f1ap_DRBs_ToBeReleased_List_PDU = -1;  /* DRBs_ToBeReleased_List */
static int hf_f1ap_UEContextModificationResponse_PDU = -1;  /* UEContextModificationResponse */
static int hf_f1ap_DRBs_Modified_List_PDU = -1;   /* DRBs_Modified_List */
static int hf_f1ap_DRBs_FailedToBeModified_List_PDU = -1;  /* DRBs_FailedToBeModified_List */
static int hf_f1ap_UEContextModificationFailure_PDU = -1;  /* UEContextModificationFailure */
static int hf_f1ap_UEContextModificationRequired_PDU = -1;  /* UEContextModificationRequired */
static int hf_f1ap_DRBs_Required_ToBeModified_List_PDU = -1;  /* DRBs_Required_ToBeModified_List */
static int hf_f1ap_DRBs_Required_ToBeReleased_List_PDU = -1;  /* DRBs_Required_ToBeReleased_List */
static int hf_f1ap_SRBs_Required_ToBeReleased_List_PDU = -1;  /* SRBs_Required_ToBeReleased_List */
static int hf_f1ap_UEContextModificationConfirm_PDU = -1;  /* UEContextModificationConfirm */
static int hf_f1ap_DRBs_ModifiedConf_List_PDU = -1;  /* DRBs_ModifiedConf_List */
static int hf_f1ap_DLRRCMessageTransfer_PDU = -1;  /* DLRRCMessageTransfer */
static int hf_f1ap_ULRRCMessageTransfer_PDU = -1;  /* ULRRCMessageTransfer */
static int hf_f1ap_PrivateMessage_PDU = -1;       /* PrivateMessage */
static int hf_f1ap_F1AP_PDU_PDU = -1;             /* F1AP_PDU */
static int hf_f1ap_local = -1;                    /* INTEGER_0_65535 */
static int hf_f1ap_global = -1;                   /* T_global */
static int hf_f1ap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_f1ap_id = -1;                       /* ProtocolIE_ID */
static int hf_f1ap_criticality = -1;              /* Criticality */
static int hf_f1ap_ie_field_value = -1;           /* T_ie_field_value */
static int hf_f1ap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_f1ap_ext_id = -1;                   /* ProtocolExtensionID */
static int hf_f1ap_extensionValue = -1;           /* T_extensionValue */
static int hf_f1ap_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_f1ap_private_id = -1;               /* PrivateIE_ID */
static int hf_f1ap_value = -1;                    /* T_value */
static int hf_f1ap_priorityLevel = -1;            /* PriorityLevel */
static int hf_f1ap_pre_emptionCapability = -1;    /* Pre_emptionCapability */
static int hf_f1ap_pre_emptionVulnerability = -1;  /* Pre_emptionVulnerability */
static int hf_f1ap_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_f1ap_BroadcastPLMNs_Item_item = -1;  /* PLMN_Identity */
static int hf_f1ap_radioNetwork = -1;             /* CauseRadioNetwork */
static int hf_f1ap_transport = -1;                /* CauseTransport */
static int hf_f1ap_protocol = -1;                 /* CauseProtocol */
static int hf_f1ap_misc = -1;                     /* CauseMisc */
static int hf_f1ap_procedureCode = -1;            /* ProcedureCode */
static int hf_f1ap_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_f1ap_procedureCriticality = -1;     /* Criticality */
static int hf_f1ap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_f1ap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_Item */
static int hf_f1ap_iECriticality = -1;            /* Criticality */
static int hf_f1ap_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_f1ap_typeOfError = -1;              /* TypeOfError */
static int hf_f1ap_sCG_Config_Info = -1;          /* SCG_Config_Info */
static int hf_f1ap_uERadiocapabilities = -1;      /* UERadiocapabilities */
static int hf_f1ap_longDRXCycleLength = -1;       /* LongDRXCycleLength */
static int hf_f1ap_shortDRXCycleLength = -1;      /* ShortDRXCycleLength */
static int hf_f1ap_shortDRXCycleTimer = -1;       /* ShortDRXCycleTimer */
static int hf_f1ap_cellGroupConfig = -1;          /* CellGroupConfig */
static int hf_f1ap_qCI = -1;                      /* QCI */
static int hf_f1ap_allocationAndRetentionPriority = -1;  /* AllocationAndRetentionPriority */
static int hf_f1ap_gbrQosInformation = -1;        /* GBR_QosInformation */
static int hf_f1ap_uL_NARFCN = -1;                /* NARFCN */
static int hf_f1ap_dL_NARFCN = -1;                /* NARFCN */
static int hf_f1ap_uL_Transmission_Bandwidth = -1;  /* Transmission_Bandwidth */
static int hf_f1ap_dL_Transmission_Bandwidth = -1;  /* Transmission_Bandwidth */
static int hf_f1ap_e_RAB_MaximumBitrateDL = -1;   /* BitRate */
static int hf_f1ap_e_RAB_MaximumBitrateUL = -1;   /* BitRate */
static int hf_f1ap_e_RAB_GuaranteedBitrateDL = -1;  /* BitRate */
static int hf_f1ap_e_RAB_GuaranteedBitrateUL = -1;  /* BitRate */
static int hf_f1ap_mIB_message = -1;              /* MIB_message */
static int hf_f1ap_sIB1_message = -1;             /* SIB1_message */
static int hf_f1ap_transportLayerAddress = -1;    /* TransportLayerAddress */
static int hf_f1ap_gTP_TEID = -1;                 /* GTP_TEID */
static int hf_f1ap_pLMN_Identity = -1;            /* PLMN_Identity */
static int hf_f1ap_nRCellIdentity = -1;           /* NRCellIdentity */
static int hf_f1ap_fDD = -1;                      /* FDD_Info */
static int hf_f1ap_tDD = -1;                      /* TDD_Info */
static int hf_f1ap_nCGI = -1;                     /* NCGI */
static int hf_f1ap_pCI = -1;                      /* PCI */
static int hf_f1ap_broadcastPLMNs = -1;           /* BroadcastPLMNs_Item */
static int hf_f1ap_nR_Mode_Info = -1;             /* NR_Mode_Info */
static int hf_f1ap_nARFCN = -1;                   /* NARFCN */
static int hf_f1ap_transmission_Bandwidth = -1;   /* Transmission_Bandwidth */
static int hf_f1ap_gNB_CU_F1AP_ID = -1;           /* GNB_CU_F1AP_ID */
static int hf_f1ap_gNB_DU_F1AP_ID = -1;           /* GNB_DU_F1AP_ID */
static int hf_f1ap_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_f1ap_f1_Interface = -1;             /* ResetAll */
static int hf_f1ap_partOfF1_Interface = -1;       /* UE_associatedLogicalF1_ConnectionListRes */
static int hf_f1ap_UE_associatedLogicalF1_ConnectionListRes_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_UE_associatedLogicalF1_ConnectionListResAck_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_GNB_DU_Served_Cells_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Cells_to_be_Activated_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Served_Cells_To_Add_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Served_Cells_To_Modify_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Served_Cells_To_Delete_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Cells_to_be_Deactivated_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Cells_Failed_to_be_Activated_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SCell_ToBeSetup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_ToBeSetup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_ToBeSetup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_ULTunnels_ToBeSetup_list_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_Setup_List_item = -1;     /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_Setup_List_item = -1;     /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_FailedToBeSetup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_FailedToBeSetup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DLTunnels_ToBeSetup_list_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_ToBeModified_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_ToBeReleased_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_ToBeReleased_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_Modified_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_FailedToBeModified_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_Required_ToBeModified_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_Required_ToBeReleased_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_Required_ToBeReleased_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_ModifiedConf_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_privateIEs = -1;               /* PrivateIE_Container */
static int hf_f1ap_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_f1ap_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_f1ap_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_f1ap_initiatingMessagevalue = -1;   /* InitiatingMessage_value */
static int hf_f1ap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_f1ap_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-f1ap-hf.c ---*/
#line 44 "./asn1/f1ap/packet-f1ap-template.c"

/* Initialize the subtree pointers */
static gint ett_f1ap = -1;
static gint ett_f1ap_ResourceCoordinationTransferContainer = -1;
static gint ett_f1ap_PLMN_Identity = -1;
static gint ett_f1ap_MIB_message = -1;
static gint ett_f1ap_SCG_Config_Info = -1;
static gint ett_f1ap_CellGroupConfig = -1;
static gint ett_f1ap_TransportLayerAddress = -1;

/*--- Included file: packet-f1ap-ett.c ---*/
#line 1 "./asn1/f1ap/packet-f1ap-ett.c"
static gint ett_f1ap_PrivateIE_ID = -1;
static gint ett_f1ap_ProtocolIE_Container = -1;
static gint ett_f1ap_ProtocolIE_Field = -1;
static gint ett_f1ap_ProtocolExtensionContainer = -1;
static gint ett_f1ap_ProtocolExtensionField = -1;
static gint ett_f1ap_PrivateIE_Container = -1;
static gint ett_f1ap_PrivateIE_Field = -1;
static gint ett_f1ap_AllocationAndRetentionPriority = -1;
static gint ett_f1ap_BroadcastPLMNs_Item = -1;
static gint ett_f1ap_Cause = -1;
static gint ett_f1ap_CriticalityDiagnostics = -1;
static gint ett_f1ap_CriticalityDiagnostics_IE_List = -1;
static gint ett_f1ap_CriticalityDiagnostics_IE_Item = -1;
static gint ett_f1ap_CUtoDURRCInformation = -1;
static gint ett_f1ap_DRXCycle = -1;
static gint ett_f1ap_DUtoCURRCInformation = -1;
static gint ett_f1ap_EUTRANQoS = -1;
static gint ett_f1ap_FDD_Info = -1;
static gint ett_f1ap_GBR_QosInformation = -1;
static gint ett_f1ap_GNB_DU_System_Information = -1;
static gint ett_f1ap_GTPTunnelEndpoint = -1;
static gint ett_f1ap_NCGI = -1;
static gint ett_f1ap_NR_Mode_Info = -1;
static gint ett_f1ap_Served_Cell_Information = -1;
static gint ett_f1ap_TDD_Info = -1;
static gint ett_f1ap_UE_associatedLogicalF1_ConnectionItem = -1;
static gint ett_f1ap_Reset = -1;
static gint ett_f1ap_ResetType = -1;
static gint ett_f1ap_UE_associatedLogicalF1_ConnectionListRes = -1;
static gint ett_f1ap_ResetAcknowledge = -1;
static gint ett_f1ap_UE_associatedLogicalF1_ConnectionListResAck = -1;
static gint ett_f1ap_ErrorIndication = -1;
static gint ett_f1ap_F1SetupRequest = -1;
static gint ett_f1ap_GNB_DU_Served_Cells_List = -1;
static gint ett_f1ap_F1SetupResponse = -1;
static gint ett_f1ap_Cells_to_be_Activated_List = -1;
static gint ett_f1ap_F1SetupFailure = -1;
static gint ett_f1ap_GNBDUConfigurationUpdate = -1;
static gint ett_f1ap_Served_Cells_To_Add_List = -1;
static gint ett_f1ap_Served_Cells_To_Modify_List = -1;
static gint ett_f1ap_Served_Cells_To_Delete_List = -1;
static gint ett_f1ap_GNBDUConfigurationUpdateAcknowledge = -1;
static gint ett_f1ap_GNBDUConfigurationUpdateFailure = -1;
static gint ett_f1ap_GNBCUConfigurationUpdate = -1;
static gint ett_f1ap_Cells_to_be_Deactivated_List = -1;
static gint ett_f1ap_GNBCUConfigurationUpdateAcknowledge = -1;
static gint ett_f1ap_Cells_Failed_to_be_Activated_List = -1;
static gint ett_f1ap_GNBCUConfigurationUpdateFailure = -1;
static gint ett_f1ap_UEContextSetupRequest = -1;
static gint ett_f1ap_SCell_ToBeSetup_List = -1;
static gint ett_f1ap_SRBs_ToBeSetup_List = -1;
static gint ett_f1ap_DRBs_ToBeSetup_List = -1;
static gint ett_f1ap_ULTunnels_ToBeSetup_list = -1;
static gint ett_f1ap_UEContextSetupResponse = -1;
static gint ett_f1ap_SRBs_Setup_List = -1;
static gint ett_f1ap_DRBs_Setup_List = -1;
static gint ett_f1ap_SRBs_FailedToBeSetup_List = -1;
static gint ett_f1ap_DRBs_FailedToBeSetup_List = -1;
static gint ett_f1ap_DLTunnels_ToBeSetup_list = -1;
static gint ett_f1ap_UEContextSetupFailure = -1;
static gint ett_f1ap_UEContextReleaseRequest = -1;
static gint ett_f1ap_UEContextReleaseCommand = -1;
static gint ett_f1ap_UEContextReleaseComplete = -1;
static gint ett_f1ap_UEContextModificationRequest = -1;
static gint ett_f1ap_DRBs_ToBeModified_List = -1;
static gint ett_f1ap_SRBs_ToBeReleased_List = -1;
static gint ett_f1ap_DRBs_ToBeReleased_List = -1;
static gint ett_f1ap_UEContextModificationResponse = -1;
static gint ett_f1ap_DRBs_Modified_List = -1;
static gint ett_f1ap_DRBs_FailedToBeModified_List = -1;
static gint ett_f1ap_UEContextModificationFailure = -1;
static gint ett_f1ap_UEContextModificationRequired = -1;
static gint ett_f1ap_DRBs_Required_ToBeModified_List = -1;
static gint ett_f1ap_DRBs_Required_ToBeReleased_List = -1;
static gint ett_f1ap_SRBs_Required_ToBeReleased_List = -1;
static gint ett_f1ap_UEContextModificationConfirm = -1;
static gint ett_f1ap_DRBs_ModifiedConf_List = -1;
static gint ett_f1ap_DLRRCMessageTransfer = -1;
static gint ett_f1ap_ULRRCMessageTransfer = -1;
static gint ett_f1ap_PrivateMessage = -1;
static gint ett_f1ap_F1AP_PDU = -1;
static gint ett_f1ap_InitiatingMessage = -1;
static gint ett_f1ap_SuccessfulOutcome = -1;
static gint ett_f1ap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-f1ap-ett.c ---*/
#line 54 "./asn1/f1ap/packet-f1ap-template.c"

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

typedef struct {
  guint32 message_type;
  guint32 procedure_code;
  guint32 protocol_ie_id;
  guint32 protocol_extension_id;
  const char *obj_id;
} f1ap_private_data_t;

typedef struct {
  guint32 message_type;
  guint32 ProcedureCode;
  guint32 ProtocolIE_ID;
  guint32 ProtocolExtensionID;
} f1ap_ctx_t;

/* Global variables */
static dissector_handle_t f1ap_handle;

/* Dissector tables */
static dissector_table_t f1ap_ies_dissector_table;
static dissector_table_t f1ap_extension_dissector_table;
static dissector_table_t f1ap_proc_imsg_dissector_table;
static dissector_table_t f1ap_proc_sout_dissector_table;
static dissector_table_t f1ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static f1ap_private_data_t*
f1ap_get_private_data(packet_info *pinfo)
{
  f1ap_private_data_t *f1ap_data = (f1ap_private_data_t*)p_get_proto_data(pinfo->pool, pinfo, proto_f1ap, 0);
  if (!f1ap_data) {
    f1ap_data = wmem_new0(pinfo->pool, f1ap_private_data_t);
    p_add_proto_data(pinfo->pool, pinfo, proto_f1ap, 0, f1ap_data);
  }
  return f1ap_data;
}


/*--- Included file: packet-f1ap-fn.c ---*/
#line 1 "./asn1/f1ap/packet-f1ap-fn.c"

static const value_string f1ap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_f1ap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_T_global(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 132 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  offset = dissect_per_object_identifier_str(tvb, offset, actx, tree, hf_index, &f1ap_data->obj_id);




  return offset;
}


static const value_string f1ap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_f1ap_local          , ASN1_NO_EXTENSIONS     , dissect_f1ap_INTEGER_0_65535 },
  {   1, &hf_f1ap_global         , ASN1_NO_EXTENSIONS     , dissect_f1ap_T_global },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 128 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  f1ap_data->obj_id = NULL;


  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string f1ap_ProcedureCode_vals[] = {
  { id_Reset, "id-Reset" },
  { id_F1Setup, "id-F1Setup" },
  { id_ErrorIndication, "id-ErrorIndication" },
  { id_gNBDUConfigurationUpdate, "id-gNBDUConfigurationUpdate" },
  { id_gNBCUConfigurationUpdate, "id-gNBCUConfigurationUpdate" },
  { id_UEContextSetup, "id-UEContextSetup" },
  { id_UEContextRelease, "id-UEContextRelease" },
  { id_UEContextModification, "id-UEContextModification" },
  { id_UEContextModificationRequired, "id-UEContextModificationRequired" },
  { id_UEMobilityCommand, "id-UEMobilityCommand" },
  { id_UEContextReleaseRequest, "id-UEContextReleaseRequest" },
  { id_InitialULRRCMessageTransfer, "id-InitialULRRCMessageTransfer" },
  { id_DLRRCMessageTransfer, "id-DLRRCMessageTransfer" },
  { id_ULRRCMessageTransfer, "id-ULRRCMessageTransfer" },
  { id_SystemInformationDelivery, "id-SystemInformationDelivery" },
  { id_Paging, "id-Paging" },
  { 0, NULL }
};

static value_string_ext f1ap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(f1ap_ProcedureCode_vals);


static int
dissect_f1ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 74 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &f1ap_data->procedure_code, FALSE);



  return offset;
}



static int
dissect_f1ap_ProtocolExtensionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 68 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &f1ap_data->protocol_extension_id, FALSE);




  return offset;
}


static const value_string f1ap_ProtocolIE_ID_vals[] = {
  { id_Cause, "id-Cause" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_gNB_DU_F1AP_ID, "id-gNB-DU-F1AP-ID" },
  { id_gNB_CU_F1AP_ID, "id-gNB-CU-F1AP-ID" },
  { id_ResetType, "id-ResetType" },
  { id_TimeToWait, "id-TimeToWait" },
  { id_UE_associatedLogicalF1_ConnectionItem, "id-UE-associatedLogicalF1-ConnectionItem" },
  { id_UE_associatedLogicalF1_ConnectionListResAck, "id-UE-associatedLogicalF1-ConnectionListResAck" },
  { id_RRCContainer, "id-RRCContainer" },
  { id_SRBID, "id-SRBID" },
  { id_gNB_DU_ID, "id-gNB-DU-ID" },
  { id_gNB_Name, "id-gNB-Name" },
  { id_NRCellID, "id-NRCellID" },
  { id_PCI, "id-PCI" },
  { id_gNB_DU_Served_Cells_List, "id-gNB-DU-Served-Cells-List" },
  { id_Cells_to_be_Activated_List, "id-Cells-to-be-Activated-List" },
  { id_Served_Cells_To_Add_List, "id-Served-Cells-To-Add-List" },
  { id_Served_Cells_To_Modify_List, "id-Served-Cells-To-Modify-List" },
  { id_Served_Cells_To_Delete_List, "id-Served-Cells-To-Delete-List" },
  { id_Cells_to_be_Deactivated_List, "id-Cells-to-be-Deactivated-List" },
  { id_Cells_Failed_to_be_Activated_List, "id-Cells-Failed-to-be-Activated-List" },
  { id_TransactionID, "id-TransactionID" },
  { id_Served_Cell_Information, "id-Served-Cell-Information" },
  { id_gNB_DU_System_Information, "id-gNB-DU-System-Information" },
  { id_NCGI, "id-NCGI" },
  { id_gNB_CU_System_Information, "id-gNB-CU-System-Information" },
  { id_OldNCGI, "id-OldNCGI" },
  { id_DRBID, "id-DRBID" },
  { id_PSCell_ID, "id-PSCell-ID" },
  { id_EUTRANQoS, "id-EUTRANQoS" },
  { id_SRBs_ToBeSetup_List, "id-SRBs-ToBeSetup-List" },
  { id_DRBs_ToBeSetup_List, "id-DRBs-ToBeSetup-List" },
  { id_DLTunnels_ToBeSetup_List, "id-DLTunnels-ToBeSetup-List" },
  { id_ULTunnels_ToBeSetup_List, "id-ULTunnels-ToBeSetup-List" },
  { id_UL_GTP_Tunnel_EndPoint, "id-UL-GTP-Tunnel-EndPoint" },
  { id_DL_GTP_Tunnel_EndPoint, "id-DL-GTP-Tunnel-EndPoint" },
  { id_CUtoDURRCInformation, "id-CUtoDURRCInformation" },
  { id_DUtoCURRCInformation, "id-DUtoCURRCInformation" },
  { id_UERadioCapability, "id-UERadioCapability" },
  { id_UEAggregateMaximumBitRate, "id-UEAggregateMaximumBitRate" },
  { id_SCell_ToBeSetup_List, "id-SCell-ToBeSetup-List" },
  { id_ResourceCoordinationTransferContainer, "id-ResourceCoordinationTransferContainer" },
  { id_DRBs_ToBeModified_List, "id-DRBs-ToBeModified-List" },
  { id_DRBs_ToBeReleased_List, "id-DRBs-ToBeReleased-List" },
  { id_DRBs_Modified_List, "id-DRBs-Modified-List" },
  { id_DRBs_FailedToSetup_List, "id-DRBs-FailedToSetup-List" },
  { id_DRBs_FailedToBeModified_List, "id-DRBs-FailedToBeModified-List" },
  { id_SCell_ID, "id-SCell-ID" },
  { id_DRXCycle, "id-DRXCycle" },
  { id_DRBs_Setup_List, "id-DRBs-Setup-List" },
  { id_SRBs_Setup_List, "id-SRBs-Setup-List" },
  { id_DRBs_FailedToBeSetup_List, "id-DRBs-FailedToBeSetup-List" },
  { id_SRBs_FailedToBeSetup_List, "id-SRBs-FailedToBeSetup-List" },
  { id_DLTunnels_ToBeSetup_list, "id-DLTunnels-ToBeSetup-list" },
  { id_ULTunnels_ToBeSetup_list, "id-ULTunnels-ToBeSetup-list" },
  { id_TransmissionStopIndicator, "id-TransmissionStopIndicator" },
  { id_DRBs_Required_ToBeModified_List, "id-DRBs-Required-ToBeModified-List" },
  { id_DRBs_Required_ToBeReleased_List, "id-DRBs-Required-ToBeReleased-List" },
  { id_SRBs_Required_ToBeReleased_List, "id-SRBs-Required-ToBeReleased-List" },
  { id_oldgNB_DU_F1AP_ID, "id-oldgNB-DU-F1AP-ID" },
  { id_SRBs_ToBeReleased_List, "id-SRBs-ToBeReleased-List" },
  { id_DRBs_ModifiedConf_List, "id-DRBs-ModifiedConf-List" },
  { id_privateMessage, "id-privateMessage" },
  { 0, NULL }
};

static value_string_ext f1ap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(f1ap_ProtocolIE_ID_vals);


static int
dissect_f1ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 56 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &f1ap_data->protocol_ie_id, FALSE);




#line 60 "./asn1/f1ap/f1ap.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s",
                           val_to_str_ext(f1ap_data->protocol_ie_id, &f1ap_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }


  return offset;
}


static const value_string f1ap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessfull-outcome" },
  { 0, NULL }
};


static int
dissect_f1ap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_f1ap_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_ID },
  { &hf_f1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_ie_field_value , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_T_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_f1ap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Field },
};

static int
dissect_f1ap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}



static int
dissect_f1ap_ProtocolIE_SingleContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_f1ap_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_f1ap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_f1ap_ext_id         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolExtensionID },
  { &hf_f1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_extensionValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_f1ap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolExtensionField },
};

static int
dissect_f1ap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_f1ap_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 136 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  if (f1ap_data->obj_id) {
    offset = call_per_oid_callback(f1ap_data->obj_id, tvb, actx->pinfo, tree, offset, actx, hf_index);
  } else {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  }



  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_f1ap_private_id     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_PrivateIE_ID },
  { &hf_f1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_value          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_f1ap_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_PrivateIE_Field },
};

static int
dissect_f1ap_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, FALSE);

  return offset;
}


static const value_string f1ap_PriorityLevel_vals[] = {
  {   0, "spare" },
  {   1, "highest" },
  {  14, "lowest" },
  {  15, "no-priority" },
  { 0, NULL }
};


static int
dissect_f1ap_PriorityLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const value_string f1ap_Pre_emptionCapability_vals[] = {
  {   0, "shall-not-trigger-pre-emption" },
  {   1, "may-trigger-pre-emption" },
  { 0, NULL }
};


static int
dissect_f1ap_Pre_emptionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string f1ap_Pre_emptionVulnerability_vals[] = {
  {   0, "not-pre-emptable" },
  {   1, "pre-emptable" },
  { 0, NULL }
};


static int
dissect_f1ap_Pre_emptionVulnerability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t AllocationAndRetentionPriority_sequence[] = {
  { &hf_f1ap_priorityLevel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_PriorityLevel },
  { &hf_f1ap_pre_emptionCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Pre_emptionCapability },
  { &hf_f1ap_pre_emptionVulnerability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Pre_emptionVulnerability },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_AllocationAndRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_AllocationAndRetentionPriority, AllocationAndRetentionPriority_sequence);

  return offset;
}



static int
dissect_f1ap_BitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(4000000000000), NULL, TRUE);

  return offset;
}



static int
dissect_f1ap_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 374 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_PLMN_Identity);
    dissect_e212_mcc_mnc(param_tvb, actx->pinfo, subtree, 0, E212_NONE, FALSE);
  }



  return offset;
}


static const per_sequence_t BroadcastPLMNs_Item_sequence_of[1] = {
  { &hf_f1ap_BroadcastPLMNs_Item_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_PLMN_Identity },
};

static int
dissect_f1ap_BroadcastPLMNs_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_BroadcastPLMNs_Item, BroadcastPLMNs_Item_sequence_of,
                                                  1, maxnoofBPLMNs, FALSE);

  return offset;
}


static const value_string f1ap_CauseRadioNetwork_vals[] = {
  {   0, "unspecified" },
  { 0, NULL }
};


static int
dissect_f1ap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_CauseTransport_vals[] = {
  {   0, "unspecified" },
  { 0, NULL }
};


static int
dissect_f1ap_CauseTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_CauseProtocol_vals[] = {
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
dissect_f1ap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_CauseMisc_vals[] = {
  {   0, "control-processing-overload" },
  {   1, "not-enough-user-plane-processing-resources" },
  {   2, "hardware-failure" },
  {   3, "om-intervention" },
  {   4, "unspecified" },
  { 0, NULL }
};


static int
dissect_f1ap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transport" },
  {   2, "protocol" },
  {   3, "misc" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_f1ap_radioNetwork   , ASN1_EXTENSION_ROOT    , dissect_f1ap_CauseRadioNetwork },
  {   1, &hf_f1ap_transport      , ASN1_EXTENSION_ROOT    , dissect_f1ap_CauseTransport },
  {   2, &hf_f1ap_protocol       , ASN1_EXTENSION_ROOT    , dissect_f1ap_CauseProtocol },
  {   3, &hf_f1ap_misc           , ASN1_EXTENSION_ROOT    , dissect_f1ap_CauseMisc },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_Cause, Cause_choice,
                                 NULL);

  return offset;
}



static int
dissect_f1ap_CellGroupConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 401 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_CellGroupConfig);
    dissect_nr_rrc_CellGroupConfig_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const value_string f1ap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_f1ap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_Item_sequence[] = {
  { &hf_f1ap_iECriticality  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_ID },
  { &hf_f1ap_typeOfError    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_TypeOfError },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_CriticalityDiagnostics_IE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_CriticalityDiagnostics_IE_Item, CriticalityDiagnostics_IE_Item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_f1ap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_CriticalityDiagnostics_IE_Item },
};

static int
dissect_f1ap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxnoofErrors, FALSE);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_f1ap_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProcedureCode },
  { &hf_f1ap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_TriggeringMessage },
  { &hf_f1ap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_Criticality },
  { &hf_f1ap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_CriticalityDiagnostics_IE_List },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_f1ap_SCG_Config_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 393 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_SCG_Config_Info);
    dissect_nr_rrc_SCG_ConfigInfo_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_UERadiocapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t CUtoDURRCInformation_sequence[] = {
  { &hf_f1ap_sCG_Config_Info, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_SCG_Config_Info },
  { &hf_f1ap_uERadiocapabilities, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_UERadiocapabilities },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_CUtoDURRCInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_CUtoDURRCInformation, CUtoDURRCInformation_sequence);

  return offset;
}



static int
dissect_f1ap_DRBID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}


static const value_string f1ap_LongDRXCycleLength_vals[] = {
  {   0, "ms10" },
  {   1, "ms20" },
  {   2, "ms32" },
  {   3, "ms40" },
  {   4, "ms60" },
  {   5, "ms64" },
  {   6, "ms70" },
  {   7, "ms80" },
  {   8, "ms128" },
  {   9, "ms160" },
  {  10, "ms256" },
  {  11, "ms320" },
  {  12, "ms512" },
  {  13, "ms640" },
  {  14, "ms1024" },
  {  15, "ms1280" },
  {  16, "ms2048" },
  {  17, "ms2560" },
  {  18, "ms5120" },
  {  19, "ms10240" },
  { 0, NULL }
};

static value_string_ext f1ap_LongDRXCycleLength_vals_ext = VALUE_STRING_EXT_INIT(f1ap_LongDRXCycleLength_vals);


static int
dissect_f1ap_LongDRXCycleLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     20, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_ShortDRXCycleLength_vals[] = {
  {   0, "ms2" },
  {   1, "ms3" },
  {   2, "ms4" },
  {   3, "ms5" },
  {   4, "ms6" },
  {   5, "ms7" },
  {   6, "ms8" },
  {   7, "ms10" },
  {   8, "ms14" },
  {   9, "ms16" },
  {  10, "ms20" },
  {  11, "ms30" },
  {  12, "ms32" },
  {  13, "ms35" },
  {  14, "ms40" },
  {  15, "ms64" },
  {  16, "ms80" },
  {  17, "ms128" },
  {  18, "ms160" },
  {  19, "ms256" },
  {  20, "ms320" },
  {  21, "ms512" },
  {  22, "ms640" },
  { 0, NULL }
};

static value_string_ext f1ap_ShortDRXCycleLength_vals_ext = VALUE_STRING_EXT_INIT(f1ap_ShortDRXCycleLength_vals);


static int
dissect_f1ap_ShortDRXCycleLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     23, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_ShortDRXCycleTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DRXCycle_sequence[] = {
  { &hf_f1ap_longDRXCycleLength, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_LongDRXCycleLength },
  { &hf_f1ap_shortDRXCycleLength, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ShortDRXCycleLength },
  { &hf_f1ap_shortDRXCycleTimer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ShortDRXCycleTimer },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRXCycle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRXCycle, DRXCycle_sequence);

  return offset;
}


static const per_sequence_t DUtoCURRCInformation_sequence[] = {
  { &hf_f1ap_cellGroupConfig, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_CellGroupConfig },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DUtoCURRCInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DUtoCURRCInformation, DUtoCURRCInformation_sequence);

  return offset;
}



static int
dissect_f1ap_QCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GBR_QosInformation_sequence[] = {
  { &hf_f1ap_e_RAB_MaximumBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BitRate },
  { &hf_f1ap_e_RAB_MaximumBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BitRate },
  { &hf_f1ap_e_RAB_GuaranteedBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BitRate },
  { &hf_f1ap_e_RAB_GuaranteedBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BitRate },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GBR_QosInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GBR_QosInformation, GBR_QosInformation_sequence);

  return offset;
}


static const per_sequence_t EUTRANQoS_sequence[] = {
  { &hf_f1ap_qCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_QCI },
  { &hf_f1ap_allocationAndRetentionPriority, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_AllocationAndRetentionPriority },
  { &hf_f1ap_gbrQosInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_GBR_QosInformation },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_EUTRANQoS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_EUTRANQoS, EUTRANQoS_sequence);

  return offset;
}



static int
dissect_f1ap_NARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_Transmission_Bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t FDD_Info_sequence[] = {
  { &hf_f1ap_uL_NARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NARFCN },
  { &hf_f1ap_dL_NARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NARFCN },
  { &hf_f1ap_uL_Transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Transmission_Bandwidth },
  { &hf_f1ap_dL_Transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Transmission_Bandwidth },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_FDD_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_FDD_Info, FDD_Info_sequence);

  return offset;
}



static int
dissect_f1ap_GNB_CU_F1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_GNB_DU_F1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_GNB_DU_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(68719476735), NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_MIB_message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 382 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_MIB_message);
    dissect_nr_rrc_MIB_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_SIB1_message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t GNB_DU_System_Information_sequence[] = {
  { &hf_f1ap_mIB_message    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_MIB_message },
  { &hf_f1ap_sIB1_message   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SIB1_message },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNB_DU_System_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNB_DU_System_Information, GNB_DU_System_Information_sequence);

  return offset;
}



static int
dissect_f1ap_GTP_TEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_f1ap_TransportLayerAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 409 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, &param_tvb, NULL);

  if (param_tvb) {
    proto_tree *subtree;
    gint tvb_len;

    tvb_len = tvb_reported_length(param_tvb);
    subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_TransportLayerAddress);
    if (tvb_len == 4) {
      /* IPv4 */
       proto_tree_add_item(subtree, hf_f1ap_transportLayerAddressIPv4, param_tvb, 0, 4, ENC_BIG_ENDIAN);
    } else if (tvb_len == 16) {
      /* IPv6 */
       proto_tree_add_item(subtree, hf_f1ap_transportLayerAddressIPv6, param_tvb, 0, 16, ENC_NA);
    } else if (tvb_len == 20) {
      /* IPv4 */
       proto_tree_add_item(subtree, hf_f1ap_transportLayerAddressIPv4, param_tvb, 0, 4, ENC_BIG_ENDIAN);
      /* IPv6 */
       proto_tree_add_item(subtree, hf_f1ap_transportLayerAddressIPv6, param_tvb, 4, 16, ENC_NA);
    }
  }




  return offset;
}


static const per_sequence_t GTPTunnelEndpoint_sequence[] = {
  { &hf_f1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_TransportLayerAddress },
  { &hf_f1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_GTP_TEID },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GTPTunnelEndpoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GTPTunnelEndpoint, GTPTunnelEndpoint_sequence);

  return offset;
}



static int
dissect_f1ap_NRCellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t NCGI_sequence[] = {
  { &hf_f1ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_PLMN_Identity },
  { &hf_f1ap_nRCellIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCellIdentity },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_NCGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_NCGI, NCGI_sequence);

  return offset;
}


static const per_sequence_t TDD_Info_sequence[] = {
  { &hf_f1ap_nARFCN         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NARFCN },
  { &hf_f1ap_transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Transmission_Bandwidth },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_TDD_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_TDD_Info, TDD_Info_sequence);

  return offset;
}


static const value_string f1ap_NR_Mode_Info_vals[] = {
  {   0, "fDD" },
  {   1, "tDD" },
  { 0, NULL }
};

static const per_choice_t NR_Mode_Info_choice[] = {
  {   0, &hf_f1ap_fDD            , ASN1_EXTENSION_ROOT    , dissect_f1ap_FDD_Info },
  {   1, &hf_f1ap_tDD            , ASN1_EXTENSION_ROOT    , dissect_f1ap_TDD_Info },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_NR_Mode_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_NR_Mode_Info, NR_Mode_Info_choice,
                                 NULL);

  return offset;
}



static int
dissect_f1ap_PCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1007U, NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_RRCContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t Served_Cell_Information_sequence[] = {
  { &hf_f1ap_nCGI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NCGI },
  { &hf_f1ap_pCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_PCI },
  { &hf_f1ap_broadcastPLMNs , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BroadcastPLMNs_Item },
  { &hf_f1ap_nR_Mode_Info   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NR_Mode_Info },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Served_Cell_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Served_Cell_Information, Served_Cell_Information_sequence);

  return offset;
}



static int
dissect_f1ap_SRBID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, TRUE);

  return offset;
}


static const value_string f1ap_TimeToWait_vals[] = {
  {   0, "v1s" },
  {   1, "v2s" },
  {   2, "v5s" },
  {   3, "v10s" },
  {   4, "v20s" },
  {   5, "v60s" },
  { 0, NULL }
};


static int
dissect_f1ap_TimeToWait(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_TransactionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, TRUE);

  return offset;
}


static const value_string f1ap_TransmissionStopIndicator_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_f1ap_TransmissionStopIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UE_associatedLogicalF1_ConnectionItem_sequence[] = {
  { &hf_f1ap_gNB_CU_F1AP_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_GNB_CU_F1AP_ID },
  { &hf_f1ap_gNB_DU_F1AP_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_GNB_DU_F1AP_ID },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UE_associatedLogicalF1_ConnectionItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UE_associatedLogicalF1_ConnectionItem, UE_associatedLogicalF1_ConnectionItem_sequence);

  return offset;
}


static const per_sequence_t Reset_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Reset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 433 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Reset");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Reset, Reset_sequence);

  return offset;
}


static const value_string f1ap_ResetAll_vals[] = {
  {   0, "reset-all" },
  { 0, NULL }
};


static int
dissect_f1ap_ResetAll(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UE_associatedLogicalF1_ConnectionListRes_sequence_of[1] = {
  { &hf_f1ap_UE_associatedLogicalF1_ConnectionListRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_UE_associatedLogicalF1_ConnectionListRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_UE_associatedLogicalF1_ConnectionListRes, UE_associatedLogicalF1_ConnectionListRes_sequence_of,
                                                  1, maxnoofIndividualF1ConnectionsToReset, FALSE);

  return offset;
}


static const value_string f1ap_ResetType_vals[] = {
  {   0, "f1-Interface" },
  {   1, "partOfF1-Interface" },
  { 0, NULL }
};

static const per_choice_t ResetType_choice[] = {
  {   0, &hf_f1ap_f1_Interface   , ASN1_EXTENSION_ROOT    , dissect_f1ap_ResetAll },
  {   1, &hf_f1ap_partOfF1_Interface, ASN1_EXTENSION_ROOT    , dissect_f1ap_UE_associatedLogicalF1_ConnectionListRes },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_ResetType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_ResetType, ResetType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ResetAcknowledge_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ResetAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 435 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResetAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ResetAcknowledge, ResetAcknowledge_sequence);

  return offset;
}


static const per_sequence_t UE_associatedLogicalF1_ConnectionListResAck_sequence_of[1] = {
  { &hf_f1ap_UE_associatedLogicalF1_ConnectionListResAck_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_UE_associatedLogicalF1_ConnectionListResAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_UE_associatedLogicalF1_ConnectionListResAck, UE_associatedLogicalF1_ConnectionListResAck_sequence_of,
                                                  1, maxnoofIndividualF1ConnectionsToReset, FALSE);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 475 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ErrorIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t F1SetupRequest_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_F1SetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 437 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "F1SetupRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_F1SetupRequest, F1SetupRequest_sequence);

  return offset;
}


static const per_sequence_t GNB_DU_Served_Cells_List_sequence_of[1] = {
  { &hf_f1ap_GNB_DU_Served_Cells_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_GNB_DU_Served_Cells_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_GNB_DU_Served_Cells_List, GNB_DU_Served_Cells_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}



static int
dissect_f1ap_GNB_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}


static const per_sequence_t F1SetupResponse_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_F1SetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 439 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "F1SetupResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_F1SetupResponse, F1SetupResponse_sequence);

  return offset;
}


static const per_sequence_t Cells_to_be_Activated_List_sequence_of[1] = {
  { &hf_f1ap_Cells_to_be_Activated_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Cells_to_be_Activated_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Cells_to_be_Activated_List, Cells_to_be_Activated_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t F1SetupFailure_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_F1SetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 441 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "F1SetupFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_F1SetupFailure, F1SetupFailure_sequence);

  return offset;
}


static const per_sequence_t GNBDUConfigurationUpdate_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBDUConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 443 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBDUConfigurationUpdate");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBDUConfigurationUpdate, GNBDUConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t Served_Cells_To_Add_List_sequence_of[1] = {
  { &hf_f1ap_Served_Cells_To_Add_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Served_Cells_To_Add_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Served_Cells_To_Add_List, Served_Cells_To_Add_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t Served_Cells_To_Modify_List_sequence_of[1] = {
  { &hf_f1ap_Served_Cells_To_Modify_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Served_Cells_To_Modify_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Served_Cells_To_Modify_List, Served_Cells_To_Modify_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t Served_Cells_To_Delete_List_sequence_of[1] = {
  { &hf_f1ap_Served_Cells_To_Delete_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Served_Cells_To_Delete_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Served_Cells_To_Delete_List, Served_Cells_To_Delete_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t GNBDUConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBDUConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 445 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBDUConfigurationUpdateAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBDUConfigurationUpdateAcknowledge, GNBDUConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t GNBDUConfigurationUpdateFailure_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBDUConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 447 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBDUConfigurationUpdateFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBDUConfigurationUpdateFailure, GNBDUConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t GNBCUConfigurationUpdate_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBCUConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 449 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBCUConfigurationUpdate");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBCUConfigurationUpdate, GNBCUConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t Cells_to_be_Deactivated_List_sequence_of[1] = {
  { &hf_f1ap_Cells_to_be_Deactivated_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Cells_to_be_Deactivated_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Cells_to_be_Deactivated_List, Cells_to_be_Deactivated_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t GNBCUConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBCUConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 451 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBCUConfigurationUpdateAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBCUConfigurationUpdateAcknowledge, GNBCUConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t Cells_Failed_to_be_Activated_List_sequence_of[1] = {
  { &hf_f1ap_Cells_Failed_to_be_Activated_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Cells_Failed_to_be_Activated_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Cells_Failed_to_be_Activated_List, Cells_Failed_to_be_Activated_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t GNBCUConfigurationUpdateFailure_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBCUConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 453 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBCUConfigurationUpdateFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBCUConfigurationUpdateFailure, GNBCUConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t UEContextSetupRequest_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 455 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextSetupRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextSetupRequest, UEContextSetupRequest_sequence);

  return offset;
}


static const per_sequence_t SCell_ToBeSetup_List_sequence_of[1] = {
  { &hf_f1ap_SCell_ToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SCell_ToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SCell_ToBeSetup_List, SCell_ToBeSetup_List_sequence_of,
                                                  1, maxnoofSCells, FALSE);

  return offset;
}


static const per_sequence_t SRBs_ToBeSetup_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_ToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_ToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_ToBeSetup_List, SRBs_ToBeSetup_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_ToBeSetup_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_ToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_ToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_ToBeSetup_List, DRBs_ToBeSetup_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}



static int
dissect_f1ap_ResourceCoordinationTransferContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 334 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree;
    f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);

    subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_ResourceCoordinationTransferContainer);
    switch (f1ap_data->message_type) {
    case INITIATING_MESSAGE:
      switch (f1ap_data->procedure_code) {
      case id_UEContextSetup:
      case id_UEContextModification:
        dissect_x2ap_MeNBResourceCoordinationInformation_PDU(param_tvb, actx->pinfo, subtree, NULL);
        break;
      case id_UEContextModificationRequired:
        dissect_x2ap_SgNBResourceCoordinationInformation_PDU(param_tvb, actx->pinfo, subtree, NULL);
        break;
      default:
        break;
      }
      break;
    case SUCCESSFUL_OUTCOME:
      switch (f1ap_data->procedure_code) {
      case id_UEContextSetup:
      case id_UEContextModification:
        dissect_x2ap_SgNBResourceCoordinationInformation_PDU(param_tvb, actx->pinfo, subtree, NULL);
        break;
      case id_UEContextModificationRequired:
        dissect_x2ap_MeNBResourceCoordinationInformation_PDU(param_tvb, actx->pinfo, subtree, NULL);
        break;
      default:
        break;
      }
      break;
    default:
      break;
    }
  }



  return offset;
}


static const per_sequence_t ULTunnels_ToBeSetup_list_sequence_of[1] = {
  { &hf_f1ap_ULTunnels_ToBeSetup_list_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_ULTunnels_ToBeSetup_list(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_ULTunnels_ToBeSetup_list, ULTunnels_ToBeSetup_list_sequence_of,
                                                  1, maxnoofULTunnels, FALSE);

  return offset;
}


static const per_sequence_t UEContextSetupResponse_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 457 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextSetupResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextSetupResponse, UEContextSetupResponse_sequence);

  return offset;
}


static const per_sequence_t SRBs_Setup_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_Setup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_Setup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_Setup_List, SRBs_Setup_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_Setup_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_Setup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_Setup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_Setup_List, DRBs_Setup_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t SRBs_FailedToBeSetup_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_FailedToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_FailedToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_FailedToBeSetup_List, SRBs_FailedToBeSetup_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_FailedToBeSetup_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_FailedToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_FailedToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_FailedToBeSetup_List, DRBs_FailedToBeSetup_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t DLTunnels_ToBeSetup_list_sequence_of[1] = {
  { &hf_f1ap_DLTunnels_ToBeSetup_list_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DLTunnels_ToBeSetup_list(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DLTunnels_ToBeSetup_list, DLTunnels_ToBeSetup_list_sequence_of,
                                                  1, maxnoofDLTunnels, FALSE);

  return offset;
}


static const per_sequence_t UEContextSetupFailure_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextSetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 459 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextSetupFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextSetupFailure, UEContextSetupFailure_sequence);

  return offset;
}


static const per_sequence_t UEContextReleaseRequest_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 477 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextReleaseRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextReleaseRequest, UEContextReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t UEContextReleaseCommand_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextReleaseCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 461 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextReleaseCommand");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextReleaseCommand, UEContextReleaseCommand_sequence);

  return offset;
}


static const per_sequence_t UEContextReleaseComplete_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextReleaseComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 463 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextReleaseComplete");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextReleaseComplete, UEContextReleaseComplete_sequence);

  return offset;
}


static const per_sequence_t UEContextModificationRequest_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextModificationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 465 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextModificationRequest, UEContextModificationRequest_sequence);

  return offset;
}


static const per_sequence_t DRBs_ToBeModified_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_ToBeModified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_ToBeModified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_ToBeModified_List, DRBs_ToBeModified_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t SRBs_ToBeReleased_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_ToBeReleased_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_ToBeReleased_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_ToBeReleased_List, SRBs_ToBeReleased_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_ToBeReleased_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_ToBeReleased_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_ToBeReleased_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_ToBeReleased_List, DRBs_ToBeReleased_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t UEContextModificationResponse_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextModificationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 467 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextModificationResponse, UEContextModificationResponse_sequence);

  return offset;
}


static const per_sequence_t DRBs_Modified_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_Modified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_Modified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_Modified_List, DRBs_Modified_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_FailedToBeModified_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_FailedToBeModified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_FailedToBeModified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_FailedToBeModified_List, DRBs_FailedToBeModified_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t UEContextModificationFailure_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextModificationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 469 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextModificationFailure, UEContextModificationFailure_sequence);

  return offset;
}


static const per_sequence_t UEContextModificationRequired_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextModificationRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 471 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationRequired");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextModificationRequired, UEContextModificationRequired_sequence);

  return offset;
}


static const per_sequence_t DRBs_Required_ToBeModified_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_Required_ToBeModified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_Required_ToBeModified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_Required_ToBeModified_List, DRBs_Required_ToBeModified_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_Required_ToBeReleased_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_Required_ToBeReleased_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_Required_ToBeReleased_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_Required_ToBeReleased_List, DRBs_Required_ToBeReleased_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t SRBs_Required_ToBeReleased_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_Required_ToBeReleased_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_Required_ToBeReleased_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_Required_ToBeReleased_List, SRBs_Required_ToBeReleased_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t UEContextModificationConfirm_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextModificationConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 473 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationConfirm");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextModificationConfirm, UEContextModificationConfirm_sequence);

  return offset;
}


static const per_sequence_t DRBs_ModifiedConf_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_ModifiedConf_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_ModifiedConf_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_ModifiedConf_List, DRBs_ModifiedConf_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t DLRRCMessageTransfer_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DLRRCMessageTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 479 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DLRRCMessageTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DLRRCMessageTransfer, DLRRCMessageTransfer_sequence);

  return offset;
}


static const per_sequence_t ULRRCMessageTransfer_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ULRRCMessageTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 481 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ULRRCMessageTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ULRRCMessageTransfer, ULRRCMessageTransfer_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_f1ap_privateIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 483 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PrivateMessage");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}



static int
dissect_f1ap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 80 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  f1ap_data->message_type = INITIATING_MESSAGE;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_f1ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProcedureCode },
  { &hf_f1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_f1ap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 84 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  f1ap_data->message_type = SUCCESSFUL_OUTCOME;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_f1ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProcedureCode },
  { &hf_f1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_f1ap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 88 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  f1ap_data->message_type = UNSUCCESSFUL_OUTCOME;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_f1ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProcedureCode },
  { &hf_f1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string f1ap_F1AP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t F1AP_PDU_choice[] = {
  {   0, &hf_f1ap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_f1ap_InitiatingMessage },
  {   1, &hf_f1ap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_f1ap_SuccessfulOutcome },
  {   2, &hf_f1ap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_f1ap_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_F1AP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_F1AP_PDU, F1AP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cause(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_f1ap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CUtoDURRCInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_CUtoDURRCInformation(tvb, offset, &asn1_ctx, tree, hf_f1ap_CUtoDURRCInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBID(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRXCycle_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRXCycle(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRXCycle_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DUtoCURRCInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DUtoCURRCInformation(tvb, offset, &asn1_ctx, tree, hf_f1ap_DUtoCURRCInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EUTRANQoS_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_EUTRANQoS(tvb, offset, &asn1_ctx, tree, hf_f1ap_EUTRANQoS_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_F1AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CU_F1AP_ID(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CU_F1AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DU_F1AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_DU_F1AP_ID(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_DU_F1AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DU_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_DU_ID(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_DU_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DU_System_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_DU_System_Information(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_DU_System_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GTPTunnelEndpoint_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GTPTunnelEndpoint(tvb, offset, &asn1_ctx, tree, hf_f1ap_GTPTunnelEndpoint_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NCGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_NCGI(tvb, offset, &asn1_ctx, tree, hf_f1ap_NCGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PCI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PCI(tvb, offset, &asn1_ctx, tree, hf_f1ap_PCI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RRCContainer(tvb, offset, &asn1_ctx, tree, hf_f1ap_RRCContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Served_Cell_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Served_Cell_Information(tvb, offset, &asn1_ctx, tree, hf_f1ap_Served_Cell_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBID(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToWait_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_TimeToWait(tvb, offset, &asn1_ctx, tree, hf_f1ap_TimeToWait_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransactionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_TransactionID(tvb, offset, &asn1_ctx, tree, hf_f1ap_TransactionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransmissionStopIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_TransmissionStopIndicator(tvb, offset, &asn1_ctx, tree, hf_f1ap_TransmissionStopIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_associatedLogicalF1_ConnectionItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UE_associatedLogicalF1_ConnectionItem(tvb, offset, &asn1_ctx, tree, hf_f1ap_UE_associatedLogicalF1_ConnectionItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Reset(tvb, offset, &asn1_ctx, tree, hf_f1ap_Reset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ResetType(tvb, offset, &asn1_ctx, tree, hf_f1ap_ResetType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ResetAcknowledge(tvb, offset, &asn1_ctx, tree, hf_f1ap_ResetAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_associatedLogicalF1_ConnectionListResAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UE_associatedLogicalF1_ConnectionListResAck(tvb, offset, &asn1_ctx, tree, hf_f1ap_UE_associatedLogicalF1_ConnectionListResAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_f1ap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1SetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_F1SetupRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_F1SetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DU_Served_Cells_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_DU_Served_Cells_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_DU_Served_Cells_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_Name_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_Name(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_Name_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1SetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_F1SetupResponse(tvb, offset, &asn1_ctx, tree, hf_f1ap_F1SetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_to_be_Activated_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_to_be_Activated_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_to_be_Activated_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1SetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_F1SetupFailure(tvb, offset, &asn1_ctx, tree, hf_f1ap_F1SetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBDUConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBDUConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBDUConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Served_Cells_To_Add_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Served_Cells_To_Add_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Served_Cells_To_Add_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Served_Cells_To_Modify_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Served_Cells_To_Modify_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Served_Cells_To_Modify_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Served_Cells_To_Delete_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Served_Cells_To_Delete_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Served_Cells_To_Delete_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBDUConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBDUConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBDUConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBDUConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBDUConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBDUConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBCUConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBCUConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBCUConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_to_be_Deactivated_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_to_be_Deactivated_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_to_be_Deactivated_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBCUConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBCUConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBCUConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_Failed_to_be_Activated_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_Failed_to_be_Activated_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_Failed_to_be_Activated_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBCUConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBCUConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBCUConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextSetupRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCell_ToBeSetup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SCell_ToBeSetup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SCell_ToBeSetup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_ToBeSetup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_ToBeSetup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_ToBeSetup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ToBeSetup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ToBeSetup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ToBeSetup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceCoordinationTransferContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ResourceCoordinationTransferContainer(tvb, offset, &asn1_ctx, tree, hf_f1ap_ResourceCoordinationTransferContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ULTunnels_ToBeSetup_list_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ULTunnels_ToBeSetup_list(tvb, offset, &asn1_ctx, tree, hf_f1ap_ULTunnels_ToBeSetup_list_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextSetupResponse(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_Setup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_Setup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_FailedToBeSetup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_FailedToBeSetup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_FailedToBeSetup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_FailedToBeSetup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_FailedToBeSetup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_FailedToBeSetup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DLTunnels_ToBeSetup_list_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DLTunnels_ToBeSetup_list(tvb, offset, &asn1_ctx, tree, hf_f1ap_DLTunnels_ToBeSetup_list_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextSetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextSetupFailure(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextSetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextReleaseComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextReleaseComplete(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextReleaseComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextModificationRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ToBeModified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ToBeModified_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ToBeModified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_ToBeReleased_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_ToBeReleased_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_ToBeReleased_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ToBeReleased_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ToBeReleased_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ToBeReleased_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextModificationResponse(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextModificationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Modified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_Modified_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_Modified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_FailedToBeModified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_FailedToBeModified_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_FailedToBeModified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextModificationFailure(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextModificationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextModificationRequired(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextModificationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Required_ToBeModified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_Required_ToBeModified_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_Required_ToBeModified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Required_ToBeReleased_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_Required_ToBeReleased_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_Required_ToBeReleased_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_Required_ToBeReleased_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_Required_ToBeReleased_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_Required_ToBeReleased_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextModificationConfirm(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextModificationConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ModifiedConf_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ModifiedConf_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ModifiedConf_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DLRRCMessageTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DLRRCMessageTransfer(tvb, offset, &asn1_ctx, tree, hf_f1ap_DLRRCMessageTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ULRRCMessageTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ULRRCMessageTransfer(tvb, offset, &asn1_ctx, tree, hf_f1ap_ULRRCMessageTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_f1ap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_F1AP_PDU(tvb, offset, &asn1_ctx, tree, hf_f1ap_F1AP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-f1ap-fn.c ---*/
#line 104 "./asn1/f1ap/packet-f1ap-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  f1ap_ctx_t f1ap_ctx;
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  f1ap_ctx.message_type        = f1ap_data->message_type;
  f1ap_ctx.ProcedureCode       = f1ap_data->procedure_code;
  f1ap_ctx.ProtocolIE_ID       = f1ap_data->protocol_ie_id;
  f1ap_ctx.ProtocolExtensionID = f1ap_data->protocol_extension_id;

  return (dissector_try_uint_new(f1ap_ies_dissector_table, f1ap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, &f1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  f1ap_ctx_t f1ap_ctx;
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  f1ap_ctx.message_type        = f1ap_data->message_type;
  f1ap_ctx.ProcedureCode       = f1ap_data->procedure_code;
  f1ap_ctx.ProtocolIE_ID       = f1ap_data->protocol_ie_id;
  f1ap_ctx.ProtocolExtensionID = f1ap_data->protocol_extension_id;

  return (dissector_try_uint_new(f1ap_extension_dissector_table, f1ap_data->protocol_extension_id, tvb, pinfo, tree, FALSE, &f1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_imsg_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_sout_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_uout_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_f1ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *f1ap_item = NULL;
  proto_tree *f1ap_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "F1AP");
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the f1ap protocol tree */
  f1ap_item = proto_tree_add_item(tree, proto_f1ap, tvb, 0, -1, ENC_NA);
  f1ap_tree = proto_item_add_subtree(f1ap_item, ett_f1ap);

  dissect_F1AP_PDU_PDU(tvb, pinfo, f1ap_tree, NULL);
  return tvb_captured_length(tvb);
}

void proto_register_f1ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_f1ap_transportLayerAddressIPv4,
      { "IPv4 transportLayerAddress", "f1ap.transportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_transportLayerAddressIPv6,
      { "IPv6 transportLayerAddress", "f1ap.transportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- Included file: packet-f1ap-hfarr.c ---*/
#line 1 "./asn1/f1ap/packet-f1ap-hfarr.c"
    { &hf_f1ap_Cause_PDU,
      { "Cause", "f1ap.Cause",
        FT_UINT32, BASE_DEC, VALS(f1ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "f1ap.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_CUtoDURRCInformation_PDU,
      { "CUtoDURRCInformation", "f1ap.CUtoDURRCInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBID_PDU,
      { "DRBID", "f1ap.DRBID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRXCycle_PDU,
      { "DRXCycle", "f1ap.DRXCycle_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DUtoCURRCInformation_PDU,
      { "DUtoCURRCInformation", "f1ap.DUtoCURRCInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_EUTRANQoS_PDU,
      { "EUTRANQoS", "f1ap.EUTRANQoS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_F1AP_ID_PDU,
      { "GNB-CU-F1AP-ID", "f1ap.GNB_CU_F1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_F1AP_ID_PDU,
      { "GNB-DU-F1AP-ID", "f1ap.GNB_DU_F1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_ID_PDU,
      { "GNB-DU-ID", "f1ap.GNB_DU_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_System_Information_PDU,
      { "GNB-DU-System-Information", "f1ap.GNB_DU_System_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GTPTunnelEndpoint_PDU,
      { "GTPTunnelEndpoint", "f1ap.GTPTunnelEndpoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_NCGI_PDU,
      { "NCGI", "f1ap.NCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PCI_PDU,
      { "PCI", "f1ap.PCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RRCContainer_PDU,
      { "RRCContainer", "f1ap.RRCContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cell_Information_PDU,
      { "Served-Cell-Information", "f1ap.Served_Cell_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBID_PDU,
      { "SRBID", "f1ap.SRBID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_TimeToWait_PDU,
      { "TimeToWait", "f1ap.TimeToWait",
        FT_UINT32, BASE_DEC, VALS(f1ap_TimeToWait_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_TransactionID_PDU,
      { "TransactionID", "f1ap.TransactionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_TransmissionStopIndicator_PDU,
      { "TransmissionStopIndicator", "f1ap.TransmissionStopIndicator",
        FT_UINT32, BASE_DEC, VALS(f1ap_TransmissionStopIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_UE_associatedLogicalF1_ConnectionItem_PDU,
      { "UE-associatedLogicalF1-ConnectionItem", "f1ap.UE_associatedLogicalF1_ConnectionItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Reset_PDU,
      { "Reset", "f1ap.Reset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ResetType_PDU,
      { "ResetType", "f1ap.ResetType",
        FT_UINT32, BASE_DEC, VALS(f1ap_ResetType_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_ResetAcknowledge_PDU,
      { "ResetAcknowledge", "f1ap.ResetAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UE_associatedLogicalF1_ConnectionListResAck_PDU,
      { "UE-associatedLogicalF1-ConnectionListResAck", "f1ap.UE_associatedLogicalF1_ConnectionListResAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ErrorIndication_PDU,
      { "ErrorIndication", "f1ap.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_F1SetupRequest_PDU,
      { "F1SetupRequest", "f1ap.F1SetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_Served_Cells_List_PDU,
      { "GNB-DU-Served-Cells-List", "f1ap.GNB_DU_Served_Cells_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_Name_PDU,
      { "GNB-Name", "f1ap.GNB_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_F1SetupResponse_PDU,
      { "F1SetupResponse", "f1ap.F1SetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_to_be_Activated_List_PDU,
      { "Cells-to-be-Activated-List", "f1ap.Cells_to_be_Activated_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_F1SetupFailure_PDU,
      { "F1SetupFailure", "f1ap.F1SetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBDUConfigurationUpdate_PDU,
      { "GNBDUConfigurationUpdate", "f1ap.GNBDUConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Add_List_PDU,
      { "Served-Cells-To-Add-List", "f1ap.Served_Cells_To_Add_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Modify_List_PDU,
      { "Served-Cells-To-Modify-List", "f1ap.Served_Cells_To_Modify_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Delete_List_PDU,
      { "Served-Cells-To-Delete-List", "f1ap.Served_Cells_To_Delete_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBDUConfigurationUpdateAcknowledge_PDU,
      { "GNBDUConfigurationUpdateAcknowledge", "f1ap.GNBDUConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBDUConfigurationUpdateFailure_PDU,
      { "GNBDUConfigurationUpdateFailure", "f1ap.GNBDUConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBCUConfigurationUpdate_PDU,
      { "GNBCUConfigurationUpdate", "f1ap.GNBCUConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_to_be_Deactivated_List_PDU,
      { "Cells-to-be-Deactivated-List", "f1ap.Cells_to_be_Deactivated_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBCUConfigurationUpdateAcknowledge_PDU,
      { "GNBCUConfigurationUpdateAcknowledge", "f1ap.GNBCUConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Failed_to_be_Activated_List_PDU,
      { "Cells-Failed-to-be-Activated-List", "f1ap.Cells_Failed_to_be_Activated_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBCUConfigurationUpdateFailure_PDU,
      { "GNBCUConfigurationUpdateFailure", "f1ap.GNBCUConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextSetupRequest_PDU,
      { "UEContextSetupRequest", "f1ap.UEContextSetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_ToBeSetup_List_PDU,
      { "SCell-ToBeSetup-List", "f1ap.SCell_ToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_ToBeSetup_List_PDU,
      { "SRBs-ToBeSetup-List", "f1ap.SRBs_ToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeSetup_List_PDU,
      { "DRBs-ToBeSetup-List", "f1ap.DRBs_ToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ResourceCoordinationTransferContainer_PDU,
      { "ResourceCoordinationTransferContainer", "f1ap.ResourceCoordinationTransferContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ULTunnels_ToBeSetup_list_PDU,
      { "ULTunnels-ToBeSetup-list", "f1ap.ULTunnels_ToBeSetup_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextSetupResponse_PDU,
      { "UEContextSetupResponse", "f1ap.UEContextSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_Setup_List_PDU,
      { "SRBs-Setup-List", "f1ap.SRBs_Setup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Setup_List_PDU,
      { "DRBs-Setup-List", "f1ap.DRBs_Setup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_FailedToBeSetup_List_PDU,
      { "SRBs-FailedToBeSetup-List", "f1ap.SRBs_FailedToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_FailedToBeSetup_List_PDU,
      { "DRBs-FailedToBeSetup-List", "f1ap.DRBs_FailedToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DLTunnels_ToBeSetup_list_PDU,
      { "DLTunnels-ToBeSetup-list", "f1ap.DLTunnels_ToBeSetup_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextSetupFailure_PDU,
      { "UEContextSetupFailure", "f1ap.UEContextSetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextReleaseRequest_PDU,
      { "UEContextReleaseRequest", "f1ap.UEContextReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextReleaseCommand_PDU,
      { "UEContextReleaseCommand", "f1ap.UEContextReleaseCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextReleaseComplete_PDU,
      { "UEContextReleaseComplete", "f1ap.UEContextReleaseComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextModificationRequest_PDU,
      { "UEContextModificationRequest", "f1ap.UEContextModificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeModified_List_PDU,
      { "DRBs-ToBeModified-List", "f1ap.DRBs_ToBeModified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_ToBeReleased_List_PDU,
      { "SRBs-ToBeReleased-List", "f1ap.SRBs_ToBeReleased_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeReleased_List_PDU,
      { "DRBs-ToBeReleased-List", "f1ap.DRBs_ToBeReleased_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextModificationResponse_PDU,
      { "UEContextModificationResponse", "f1ap.UEContextModificationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Modified_List_PDU,
      { "DRBs-Modified-List", "f1ap.DRBs_Modified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_FailedToBeModified_List_PDU,
      { "DRBs-FailedToBeModified-List", "f1ap.DRBs_FailedToBeModified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextModificationFailure_PDU,
      { "UEContextModificationFailure", "f1ap.UEContextModificationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextModificationRequired_PDU,
      { "UEContextModificationRequired", "f1ap.UEContextModificationRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Required_ToBeModified_List_PDU,
      { "DRBs-Required-ToBeModified-List", "f1ap.DRBs_Required_ToBeModified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Required_ToBeReleased_List_PDU,
      { "DRBs-Required-ToBeReleased-List", "f1ap.DRBs_Required_ToBeReleased_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_Required_ToBeReleased_List_PDU,
      { "SRBs-Required-ToBeReleased-List", "f1ap.SRBs_Required_ToBeReleased_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextModificationConfirm_PDU,
      { "UEContextModificationConfirm", "f1ap.UEContextModificationConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ModifiedConf_List_PDU,
      { "DRBs-ModifiedConf-List", "f1ap.DRBs_ModifiedConf_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DLRRCMessageTransfer_PDU,
      { "DLRRCMessageTransfer", "f1ap.DLRRCMessageTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ULRRCMessageTransfer_PDU,
      { "ULRRCMessageTransfer", "f1ap.ULRRCMessageTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PrivateMessage_PDU,
      { "PrivateMessage", "f1ap.PrivateMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_F1AP_PDU_PDU,
      { "F1AP-PDU", "f1ap.F1AP_PDU",
        FT_UINT32, BASE_DEC, VALS(f1ap_F1AP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_local,
      { "local", "f1ap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_f1ap_global,
      { "global", "f1ap.global",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "f1ap.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_id,
      { "id", "f1ap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &f1ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_f1ap_criticality,
      { "criticality", "f1ap.criticality",
        FT_UINT32, BASE_DEC, VALS(f1ap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_ie_field_value,
      { "value", "f1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_f1ap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "f1ap.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ext_id,
      { "id", "f1ap.id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionID", HFILL }},
    { &hf_f1ap_extensionValue,
      { "extensionValue", "f1ap.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PrivateIE_Container_item,
      { "PrivateIE-Field", "f1ap.PrivateIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_private_id,
      { "id", "f1ap.id",
        FT_UINT32, BASE_DEC, VALS(f1ap_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_f1ap_value,
      { "value", "f1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_priorityLevel,
      { "priorityLevel", "f1ap.priorityLevel",
        FT_UINT32, BASE_DEC, VALS(f1ap_PriorityLevel_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_pre_emptionCapability,
      { "pre-emptionCapability", "f1ap.pre_emptionCapability",
        FT_UINT32, BASE_DEC, VALS(f1ap_Pre_emptionCapability_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_pre_emptionVulnerability,
      { "pre-emptionVulnerability", "f1ap.pre_emptionVulnerability",
        FT_UINT32, BASE_DEC, VALS(f1ap_Pre_emptionVulnerability_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_iE_Extensions,
      { "iE-Extensions", "f1ap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_f1ap_BroadcastPLMNs_Item_item,
      { "PLMN-Identity", "f1ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_radioNetwork,
      { "radioNetwork", "f1ap.radioNetwork",
        FT_UINT32, BASE_DEC, VALS(f1ap_CauseRadioNetwork_vals), 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_f1ap_transport,
      { "transport", "f1ap.transport",
        FT_UINT32, BASE_DEC, VALS(f1ap_CauseTransport_vals), 0,
        "CauseTransport", HFILL }},
    { &hf_f1ap_protocol,
      { "protocol", "f1ap.protocol",
        FT_UINT32, BASE_DEC, VALS(f1ap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_f1ap_misc,
      { "misc", "f1ap.misc",
        FT_UINT32, BASE_DEC, VALS(f1ap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_f1ap_procedureCode,
      { "procedureCode", "f1ap.procedureCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &f1ap_ProcedureCode_vals_ext, 0,
        NULL, HFILL }},
    { &hf_f1ap_triggeringMessage,
      { "triggeringMessage", "f1ap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(f1ap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_procedureCriticality,
      { "procedureCriticality", "f1ap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(f1ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_f1ap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "f1ap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_f1ap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-Item", "f1ap.CriticalityDiagnostics_IE_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_iECriticality,
      { "iECriticality", "f1ap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(f1ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_f1ap_iE_ID,
      { "iE-ID", "f1ap.iE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &f1ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_f1ap_typeOfError,
      { "typeOfError", "f1ap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(f1ap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_sCG_Config_Info,
      { "sCG-Config-Info", "f1ap.sCG_Config_Info",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_uERadiocapabilities,
      { "uERadiocapabilities", "f1ap.uERadiocapabilities",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_longDRXCycleLength,
      { "longDRXCycleLength", "f1ap.longDRXCycleLength",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &f1ap_LongDRXCycleLength_vals_ext, 0,
        NULL, HFILL }},
    { &hf_f1ap_shortDRXCycleLength,
      { "shortDRXCycleLength", "f1ap.shortDRXCycleLength",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &f1ap_ShortDRXCycleLength_vals_ext, 0,
        NULL, HFILL }},
    { &hf_f1ap_shortDRXCycleTimer,
      { "shortDRXCycleTimer", "f1ap.shortDRXCycleTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_cellGroupConfig,
      { "cellGroupConfig", "f1ap.cellGroupConfig",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_qCI,
      { "qCI", "f1ap.qCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_allocationAndRetentionPriority,
      { "allocationAndRetentionPriority", "f1ap.allocationAndRetentionPriority_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_gbrQosInformation,
      { "gbrQosInformation", "f1ap.gbrQosInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GBR_QosInformation", HFILL }},
    { &hf_f1ap_uL_NARFCN,
      { "uL-NARFCN", "f1ap.uL_NARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NARFCN", HFILL }},
    { &hf_f1ap_dL_NARFCN,
      { "dL-NARFCN", "f1ap.dL_NARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NARFCN", HFILL }},
    { &hf_f1ap_uL_Transmission_Bandwidth,
      { "uL-Transmission-Bandwidth", "f1ap.uL_Transmission_Bandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Transmission_Bandwidth", HFILL }},
    { &hf_f1ap_dL_Transmission_Bandwidth,
      { "dL-Transmission-Bandwidth", "f1ap.dL_Transmission_Bandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Transmission_Bandwidth", HFILL }},
    { &hf_f1ap_e_RAB_MaximumBitrateDL,
      { "e-RAB-MaximumBitrateDL", "f1ap.e_RAB_MaximumBitrateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_f1ap_e_RAB_MaximumBitrateUL,
      { "e-RAB-MaximumBitrateUL", "f1ap.e_RAB_MaximumBitrateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_f1ap_e_RAB_GuaranteedBitrateDL,
      { "e-RAB-GuaranteedBitrateDL", "f1ap.e_RAB_GuaranteedBitrateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_f1ap_e_RAB_GuaranteedBitrateUL,
      { "e-RAB-GuaranteedBitrateUL", "f1ap.e_RAB_GuaranteedBitrateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_f1ap_mIB_message,
      { "mIB-message", "f1ap.mIB_message",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_sIB1_message,
      { "sIB1-message", "f1ap.sIB1_message",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_transportLayerAddress,
      { "transportLayerAddress", "f1ap.transportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_gTP_TEID,
      { "gTP-TEID", "f1ap.gTP_TEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_pLMN_Identity,
      { "pLMN-Identity", "f1ap.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_nRCellIdentity,
      { "nRCellIdentity", "f1ap.nRCellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_fDD,
      { "fDD", "f1ap.fDD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FDD_Info", HFILL }},
    { &hf_f1ap_tDD,
      { "tDD", "f1ap.tDD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TDD_Info", HFILL }},
    { &hf_f1ap_nCGI,
      { "nCGI", "f1ap.nCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_pCI,
      { "pCI", "f1ap.pCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_broadcastPLMNs,
      { "broadcastPLMNs", "f1ap.broadcastPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BroadcastPLMNs_Item", HFILL }},
    { &hf_f1ap_nR_Mode_Info,
      { "nR-Mode-Info", "f1ap.nR_Mode_Info",
        FT_UINT32, BASE_DEC, VALS(f1ap_NR_Mode_Info_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_nARFCN,
      { "nARFCN", "f1ap.nARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_transmission_Bandwidth,
      { "transmission-Bandwidth", "f1ap.transmission_Bandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_gNB_CU_F1AP_ID,
      { "gNB-CU-F1AP-ID", "f1ap.gNB_CU_F1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_gNB_DU_F1AP_ID,
      { "gNB-DU-F1AP-ID", "f1ap.gNB_DU_F1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_protocolIEs,
      { "protocolIEs", "f1ap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_f1ap_f1_Interface,
      { "f1-Interface", "f1ap.f1_Interface",
        FT_UINT32, BASE_DEC, VALS(f1ap_ResetAll_vals), 0,
        "ResetAll", HFILL }},
    { &hf_f1ap_partOfF1_Interface,
      { "partOfF1-Interface", "f1ap.partOfF1_Interface",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UE_associatedLogicalF1_ConnectionListRes", HFILL }},
    { &hf_f1ap_UE_associatedLogicalF1_ConnectionListRes_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UE_associatedLogicalF1_ConnectionListResAck_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_Served_Cells_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_to_be_Activated_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Add_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Modify_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Delete_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_to_be_Deactivated_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Failed_to_be_Activated_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_ToBeSetup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_ToBeSetup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeSetup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ULTunnels_ToBeSetup_list_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_Setup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Setup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_FailedToBeSetup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_FailedToBeSetup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DLTunnels_ToBeSetup_list_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeModified_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_ToBeReleased_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeReleased_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Modified_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_FailedToBeModified_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Required_ToBeModified_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Required_ToBeReleased_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_Required_ToBeReleased_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ModifiedConf_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_privateIEs,
      { "privateIEs", "f1ap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_f1ap_initiatingMessage,
      { "initiatingMessage", "f1ap.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_successfulOutcome,
      { "successfulOutcome", "f1ap.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "f1ap.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_initiatingMessagevalue,
      { "value", "f1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_f1ap_successfulOutcome_value,
      { "value", "f1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_f1ap_unsuccessfulOutcome_value,
      { "value", "f1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},

/*--- End of included file: packet-f1ap-hfarr.c ---*/
#line 185 "./asn1/f1ap/packet-f1ap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_f1ap,
    &ett_f1ap_ResourceCoordinationTransferContainer,
    &ett_f1ap_PLMN_Identity,
    &ett_f1ap_MIB_message,
    &ett_f1ap_SCG_Config_Info,
    &ett_f1ap_CellGroupConfig,
    &ett_f1ap_TransportLayerAddress,

/*--- Included file: packet-f1ap-ettarr.c ---*/
#line 1 "./asn1/f1ap/packet-f1ap-ettarr.c"
    &ett_f1ap_PrivateIE_ID,
    &ett_f1ap_ProtocolIE_Container,
    &ett_f1ap_ProtocolIE_Field,
    &ett_f1ap_ProtocolExtensionContainer,
    &ett_f1ap_ProtocolExtensionField,
    &ett_f1ap_PrivateIE_Container,
    &ett_f1ap_PrivateIE_Field,
    &ett_f1ap_AllocationAndRetentionPriority,
    &ett_f1ap_BroadcastPLMNs_Item,
    &ett_f1ap_Cause,
    &ett_f1ap_CriticalityDiagnostics,
    &ett_f1ap_CriticalityDiagnostics_IE_List,
    &ett_f1ap_CriticalityDiagnostics_IE_Item,
    &ett_f1ap_CUtoDURRCInformation,
    &ett_f1ap_DRXCycle,
    &ett_f1ap_DUtoCURRCInformation,
    &ett_f1ap_EUTRANQoS,
    &ett_f1ap_FDD_Info,
    &ett_f1ap_GBR_QosInformation,
    &ett_f1ap_GNB_DU_System_Information,
    &ett_f1ap_GTPTunnelEndpoint,
    &ett_f1ap_NCGI,
    &ett_f1ap_NR_Mode_Info,
    &ett_f1ap_Served_Cell_Information,
    &ett_f1ap_TDD_Info,
    &ett_f1ap_UE_associatedLogicalF1_ConnectionItem,
    &ett_f1ap_Reset,
    &ett_f1ap_ResetType,
    &ett_f1ap_UE_associatedLogicalF1_ConnectionListRes,
    &ett_f1ap_ResetAcknowledge,
    &ett_f1ap_UE_associatedLogicalF1_ConnectionListResAck,
    &ett_f1ap_ErrorIndication,
    &ett_f1ap_F1SetupRequest,
    &ett_f1ap_GNB_DU_Served_Cells_List,
    &ett_f1ap_F1SetupResponse,
    &ett_f1ap_Cells_to_be_Activated_List,
    &ett_f1ap_F1SetupFailure,
    &ett_f1ap_GNBDUConfigurationUpdate,
    &ett_f1ap_Served_Cells_To_Add_List,
    &ett_f1ap_Served_Cells_To_Modify_List,
    &ett_f1ap_Served_Cells_To_Delete_List,
    &ett_f1ap_GNBDUConfigurationUpdateAcknowledge,
    &ett_f1ap_GNBDUConfigurationUpdateFailure,
    &ett_f1ap_GNBCUConfigurationUpdate,
    &ett_f1ap_Cells_to_be_Deactivated_List,
    &ett_f1ap_GNBCUConfigurationUpdateAcknowledge,
    &ett_f1ap_Cells_Failed_to_be_Activated_List,
    &ett_f1ap_GNBCUConfigurationUpdateFailure,
    &ett_f1ap_UEContextSetupRequest,
    &ett_f1ap_SCell_ToBeSetup_List,
    &ett_f1ap_SRBs_ToBeSetup_List,
    &ett_f1ap_DRBs_ToBeSetup_List,
    &ett_f1ap_ULTunnels_ToBeSetup_list,
    &ett_f1ap_UEContextSetupResponse,
    &ett_f1ap_SRBs_Setup_List,
    &ett_f1ap_DRBs_Setup_List,
    &ett_f1ap_SRBs_FailedToBeSetup_List,
    &ett_f1ap_DRBs_FailedToBeSetup_List,
    &ett_f1ap_DLTunnels_ToBeSetup_list,
    &ett_f1ap_UEContextSetupFailure,
    &ett_f1ap_UEContextReleaseRequest,
    &ett_f1ap_UEContextReleaseCommand,
    &ett_f1ap_UEContextReleaseComplete,
    &ett_f1ap_UEContextModificationRequest,
    &ett_f1ap_DRBs_ToBeModified_List,
    &ett_f1ap_SRBs_ToBeReleased_List,
    &ett_f1ap_DRBs_ToBeReleased_List,
    &ett_f1ap_UEContextModificationResponse,
    &ett_f1ap_DRBs_Modified_List,
    &ett_f1ap_DRBs_FailedToBeModified_List,
    &ett_f1ap_UEContextModificationFailure,
    &ett_f1ap_UEContextModificationRequired,
    &ett_f1ap_DRBs_Required_ToBeModified_List,
    &ett_f1ap_DRBs_Required_ToBeReleased_List,
    &ett_f1ap_SRBs_Required_ToBeReleased_List,
    &ett_f1ap_UEContextModificationConfirm,
    &ett_f1ap_DRBs_ModifiedConf_List,
    &ett_f1ap_DLRRCMessageTransfer,
    &ett_f1ap_ULRRCMessageTransfer,
    &ett_f1ap_PrivateMessage,
    &ett_f1ap_F1AP_PDU,
    &ett_f1ap_InitiatingMessage,
    &ett_f1ap_SuccessfulOutcome,
    &ett_f1ap_UnsuccessfulOutcome,

/*--- End of included file: packet-f1ap-ettarr.c ---*/
#line 197 "./asn1/f1ap/packet-f1ap-template.c"
  };

  /* Register protocol */
  proto_f1ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_f1ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  f1ap_handle = register_dissector("f1ap", dissect_f1ap, proto_f1ap);

  /* Register dissector tables */
  f1ap_ies_dissector_table = register_dissector_table("f1ap.ies", "F1AP-PROTOCOL-IES", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_extension_dissector_table = register_dissector_table("f1ap.extension", "F1AP-PROTOCOL-EXTENSION", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_proc_imsg_dissector_table = register_dissector_table("f1ap.proc.imsg", "F1AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_proc_sout_dissector_table = register_dissector_table("f1ap.proc.sout", "F1AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_proc_uout_dissector_table = register_dissector_table("f1ap.proc.uout", "F1AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_f1ap, FT_UINT32, BASE_DEC);
}

void
proto_reg_handoff_f1ap(void)
{
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_F1AP, f1ap_handle);
  dissector_add_uint("sctp.ppi", F1AP_PROTOCOL_ID, f1ap_handle);

/*--- Included file: packet-f1ap-dis-tab.c ---*/
#line 1 "./asn1/f1ap/packet-f1ap-dis-tab.c"
  dissector_add_uint("f1ap.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_gNB_DU_F1AP_ID, create_dissector_handle(dissect_GNB_DU_F1AP_ID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_gNB_CU_F1AP_ID, create_dissector_handle(dissect_GNB_CU_F1AP_ID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_ResetType, create_dissector_handle(dissect_ResetType_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_TimeToWait, create_dissector_handle(dissect_TimeToWait_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_UE_associatedLogicalF1_ConnectionItem, create_dissector_handle(dissect_UE_associatedLogicalF1_ConnectionItem_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_UE_associatedLogicalF1_ConnectionListResAck, create_dissector_handle(dissect_UE_associatedLogicalF1_ConnectionListResAck_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_RRCContainer, create_dissector_handle(dissect_RRCContainer_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBID, create_dissector_handle(dissect_SRBID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_gNB_DU_ID, create_dissector_handle(dissect_GNB_DU_ID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_gNB_Name, create_dissector_handle(dissect_GNB_Name_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_PCI, create_dissector_handle(dissect_PCI_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_gNB_DU_Served_Cells_List, create_dissector_handle(dissect_GNB_DU_Served_Cells_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_to_be_Activated_List, create_dissector_handle(dissect_Cells_to_be_Activated_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Served_Cells_To_Add_List, create_dissector_handle(dissect_Served_Cells_To_Add_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Served_Cells_To_Modify_List, create_dissector_handle(dissect_Served_Cells_To_Modify_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Served_Cells_To_Delete_List, create_dissector_handle(dissect_Served_Cells_To_Delete_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_to_be_Deactivated_List, create_dissector_handle(dissect_Cells_to_be_Deactivated_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_Failed_to_be_Activated_List, create_dissector_handle(dissect_Cells_Failed_to_be_Activated_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_TransactionID, create_dissector_handle(dissect_TransactionID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Served_Cell_Information, create_dissector_handle(dissect_Served_Cell_Information_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_gNB_DU_System_Information, create_dissector_handle(dissect_GNB_DU_System_Information_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_NCGI, create_dissector_handle(dissect_NCGI_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_OldNCGI, create_dissector_handle(dissect_NCGI_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBID, create_dissector_handle(dissect_DRBID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_PSCell_ID, create_dissector_handle(dissect_NCGI_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_EUTRANQoS, create_dissector_handle(dissect_EUTRANQoS_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_ToBeSetup_List, create_dissector_handle(dissect_SRBs_ToBeSetup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ToBeSetup_List, create_dissector_handle(dissect_DRBs_ToBeSetup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DLTunnels_ToBeSetup_List, create_dissector_handle(dissect_DLTunnels_ToBeSetup_list_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_ULTunnels_ToBeSetup_List, create_dissector_handle(dissect_ULTunnels_ToBeSetup_list_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_UL_GTP_Tunnel_EndPoint, create_dissector_handle(dissect_GTPTunnelEndpoint_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DL_GTP_Tunnel_EndPoint, create_dissector_handle(dissect_GTPTunnelEndpoint_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_CUtoDURRCInformation, create_dissector_handle(dissect_CUtoDURRCInformation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DUtoCURRCInformation, create_dissector_handle(dissect_DUtoCURRCInformation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SCell_ToBeSetup_List, create_dissector_handle(dissect_SCell_ToBeSetup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_ResourceCoordinationTransferContainer, create_dissector_handle(dissect_ResourceCoordinationTransferContainer_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ToBeModified_List, create_dissector_handle(dissect_DRBs_ToBeModified_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ToBeReleased_List, create_dissector_handle(dissect_DRBs_ToBeReleased_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_Modified_List, create_dissector_handle(dissect_DRBs_Modified_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_FailedToBeModified_List, create_dissector_handle(dissect_DRBs_FailedToBeModified_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SCell_ID, create_dissector_handle(dissect_NCGI_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRXCycle, create_dissector_handle(dissect_DRXCycle_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_Setup_List, create_dissector_handle(dissect_DRBs_Setup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_Setup_List, create_dissector_handle(dissect_SRBs_Setup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_FailedToBeSetup_List, create_dissector_handle(dissect_DRBs_FailedToBeSetup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_FailedToBeSetup_List, create_dissector_handle(dissect_SRBs_FailedToBeSetup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DLTunnels_ToBeSetup_list, create_dissector_handle(dissect_DLTunnels_ToBeSetup_list_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_ULTunnels_ToBeSetup_list, create_dissector_handle(dissect_ULTunnels_ToBeSetup_list_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_TransmissionStopIndicator, create_dissector_handle(dissect_TransmissionStopIndicator_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_Required_ToBeModified_List, create_dissector_handle(dissect_DRBs_Required_ToBeModified_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_Required_ToBeReleased_List, create_dissector_handle(dissect_DRBs_Required_ToBeReleased_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_Required_ToBeReleased_List, create_dissector_handle(dissect_SRBs_Required_ToBeReleased_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_oldgNB_DU_F1AP_ID, create_dissector_handle(dissect_GNB_DU_F1AP_ID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_ToBeReleased_List, create_dissector_handle(dissect_SRBs_ToBeReleased_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ModifiedConf_List, create_dissector_handle(dissect_DRBs_ModifiedConf_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_Reset, create_dissector_handle(dissect_Reset_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_Reset, create_dissector_handle(dissect_ResetAcknowledge_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_F1Setup, create_dissector_handle(dissect_F1SetupRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_F1Setup, create_dissector_handle(dissect_F1SetupResponse_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.uout", id_F1Setup, create_dissector_handle(dissect_F1SetupFailure_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_gNBDUConfigurationUpdate, create_dissector_handle(dissect_GNBDUConfigurationUpdate_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_gNBDUConfigurationUpdate, create_dissector_handle(dissect_GNBDUConfigurationUpdateAcknowledge_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.uout", id_gNBDUConfigurationUpdate, create_dissector_handle(dissect_GNBDUConfigurationUpdateFailure_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_gNBCUConfigurationUpdate, create_dissector_handle(dissect_GNBCUConfigurationUpdate_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_gNBCUConfigurationUpdate, create_dissector_handle(dissect_GNBCUConfigurationUpdateAcknowledge_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.uout", id_gNBCUConfigurationUpdate, create_dissector_handle(dissect_GNBCUConfigurationUpdateFailure_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_UEContextSetup, create_dissector_handle(dissect_UEContextSetupRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_UEContextSetup, create_dissector_handle(dissect_UEContextSetupResponse_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.uout", id_UEContextSetup, create_dissector_handle(dissect_UEContextSetupFailure_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_UEContextRelease, create_dissector_handle(dissect_UEContextReleaseCommand_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_UEContextRelease, create_dissector_handle(dissect_UEContextReleaseComplete_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_UEContextModification, create_dissector_handle(dissect_UEContextModificationRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_UEContextModification, create_dissector_handle(dissect_UEContextModificationResponse_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.uout", id_UEContextModification, create_dissector_handle(dissect_UEContextModificationFailure_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_UEContextModificationRequired, create_dissector_handle(dissect_UEContextModificationRequired_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_UEContextModificationRequired, create_dissector_handle(dissect_UEContextModificationConfirm_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_ErrorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_UEContextReleaseRequest, create_dissector_handle(dissect_UEContextReleaseRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_DLRRCMessageTransfer, create_dissector_handle(dissect_DLRRCMessageTransfer_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_ULRRCMessageTransfer, create_dissector_handle(dissect_ULRRCMessageTransfer_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_privateMessage, create_dissector_handle(dissect_PrivateMessage_PDU, proto_f1ap));


/*--- End of included file: packet-f1ap-dis-tab.c ---*/
#line 222 "./asn1/f1ap/packet-f1ap-template.c"
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
