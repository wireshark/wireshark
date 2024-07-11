/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-e1ap.c                                                              */
/* asn2wrs.py -q -L -p e1ap -c ./e1ap.cnf -s ./packet-e1ap-template -D . -O ../.. E1AP-CommonDataTypes.asn E1AP-Constants.asn E1AP-Containers.asn E1AP-IEs.asn E1AP-PDU-Contents.asn E1AP-PDU-Descriptions.asn */

/* packet-e1ap.c
 * Routines for E-UTRAN E1 Application Protocol (E1AP) packet dissection
 * Copyright 2018-2024, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 37.483 V18.2.0 (2024-06)
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/asn1.h>
#include <epan/sctpppids.h>
#include <epan/proto_data.h>

#include "packet-e1ap.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-ntp.h"
#include "packet-nr-rrc.h"
#include "packet-tcp.h"

#define PNAME  "E1 Application Protocol"
#define PSNAME "E1AP"
#define PFNAME "e1ap"

#define SCTP_PORT_E1AP 38462

void proto_register_e1ap(void);
void proto_reg_handoff_e1ap(void);

#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxnoofErrors                  256
#define maxnoofSPLMNs                  12
#define maxnoofSliceItems              1024
#define maxnoofIndividualE1ConnectionsToReset 65536
#define maxnoofEUTRANQOSParameters     256
#define maxnoofNGRANQOSParameters      256
#define maxnoofDRBs                    32
#define maxnoofNRCGI                   512
#define maxnoofPDUSessionResource      256
#define maxnoofQoSFlows                64
#define maxnoofUPParameters            8
#define maxnoofCellGroups              4
#define maxnooftimeperiods             2
#define maxnoofTNLAssociations         32
#define maxnoofTLAs                    16
#define maxnoofGTPTLAs                 16
#define maxnoofTNLAddresses            8
#define maxnoofMDTPLMNs                16
#define maxnoofQoSParaSets             8
#define maxnoofExtSliceItems           65535
#define maxnoofDataForwardingTunneltoE_UTRAN 256
#define maxnoofExtNRCGI                16384
#define maxnoofPSKs                    256
#define maxnoofECGI                    512
#define maxnoofSMBRValues              8
#define maxnoofMBSAreaSessionIDs       256
#define maxnoofSharedNG_UTerminations  8
#define maxnoofMRBs                    32
#define maxnoofMBSSessionIDs           512
#define maxnoofCellsforMBS             512
#define maxnoofTAIforMBS               512
#define maxnoofMBSServiceAreaInformation 256
#define maxnoofDUs                     512

typedef enum _ProcedureCode_enum {
  id_reset     =   0,
  id_errorIndication =   1,
  id_privateMessage =   2,
  id_gNB_CU_UP_E1Setup =   3,
  id_gNB_CU_CP_E1Setup =   4,
  id_gNB_CU_UP_ConfigurationUpdate =   5,
  id_gNB_CU_CP_ConfigurationUpdate =   6,
  id_e1Release =   7,
  id_bearerContextSetup =   8,
  id_bearerContextModification =   9,
  id_bearerContextModificationRequired =  10,
  id_bearerContextRelease =  11,
  id_bearerContextReleaseRequest =  12,
  id_bearerContextInactivityNotification =  13,
  id_dLDataNotification =  14,
  id_dataUsageReport =  15,
  id_gNB_CU_UP_CounterCheck =  16,
  id_gNB_CU_UP_StatusIndication =  17,
  id_uLDataNotification =  18,
  id_mRDC_DataUsageReport =  19,
  id_TraceStart =  20,
  id_DeactivateTrace =  21,
  id_resourceStatusReportingInitiation =  22,
  id_resourceStatusReporting =  23,
  id_iAB_UPTNLAddressUpdate =  24,
  id_CellTrafficTrace =  25,
  id_earlyForwardingSNTransfer =  26,
  id_gNB_CU_CPMeasurementResultsInformation =  27,
  id_iABPSKNotification =  28,
  id_BCBearerContextSetup =  29,
  id_BCBearerContextModification =  30,
  id_BCBearerContextModificationRequired =  31,
  id_BCBearerContextRelease =  32,
  id_BCBearerContextReleaseRequest =  33,
  id_MCBearerContextSetup =  34,
  id_MCBearerContextModification =  35,
  id_MCBearerContextModificationRequired =  36,
  id_MCBearerContextRelease =  37,
  id_MCBearerContextReleaseRequest =  38,
  id_MCBearerNotification =  39
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_Cause     =   0,
  id_CriticalityDiagnostics =   1,
  id_gNB_CU_CP_UE_E1AP_ID =   2,
  id_gNB_CU_UP_UE_E1AP_ID =   3,
  id_ResetType =   4,
  id_UE_associatedLogicalE1_ConnectionItem =   5,
  id_UE_associatedLogicalE1_ConnectionListResAck =   6,
  id_gNB_CU_UP_ID =   7,
  id_gNB_CU_UP_Name =   8,
  id_gNB_CU_CP_Name =   9,
  id_CNSupport =  10,
  id_SupportedPLMNs =  11,
  id_TimeToWait =  12,
  id_SecurityInformation =  13,
  id_UEDLAggregateMaximumBitRate =  14,
  id_System_BearerContextSetupRequest =  15,
  id_System_BearerContextSetupResponse =  16,
  id_BearerContextStatusChange =  17,
  id_System_BearerContextModificationRequest =  18,
  id_System_BearerContextModificationResponse =  19,
  id_System_BearerContextModificationConfirm =  20,
  id_System_BearerContextModificationRequired =  21,
  id_DRB_Status_List =  22,
  id_ActivityNotificationLevel =  23,
  id_ActivityInformation =  24,
  id_Data_Usage_Report_List =  25,
  id_New_UL_TNL_Information_Required =  26,
  id_GNB_CU_CP_TNLA_To_Add_List =  27,
  id_GNB_CU_CP_TNLA_To_Remove_List =  28,
  id_GNB_CU_CP_TNLA_To_Update_List =  29,
  id_GNB_CU_CP_TNLA_Setup_List =  30,
  id_GNB_CU_CP_TNLA_Failed_To_Setup_List =  31,
  id_DRB_To_Setup_List_EUTRAN =  32,
  id_DRB_To_Modify_List_EUTRAN =  33,
  id_DRB_To_Remove_List_EUTRAN =  34,
  id_DRB_Required_To_Modify_List_EUTRAN =  35,
  id_DRB_Required_To_Remove_List_EUTRAN =  36,
  id_DRB_Setup_List_EUTRAN =  37,
  id_DRB_Failed_List_EUTRAN =  38,
  id_DRB_Modified_List_EUTRAN =  39,
  id_DRB_Failed_To_Modify_List_EUTRAN =  40,
  id_DRB_Confirm_Modified_List_EUTRAN =  41,
  id_PDU_Session_Resource_To_Setup_List =  42,
  id_PDU_Session_Resource_To_Modify_List =  43,
  id_PDU_Session_Resource_To_Remove_List =  44,
  id_PDU_Session_Resource_Required_To_Modify_List =  45,
  id_PDU_Session_Resource_Setup_List =  46,
  id_PDU_Session_Resource_Failed_List =  47,
  id_PDU_Session_Resource_Modified_List =  48,
  id_PDU_Session_Resource_Failed_To_Modify_List =  49,
  id_PDU_Session_Resource_Confirm_Modified_List =  50,
  id_DRB_To_Setup_Mod_List_EUTRAN =  51,
  id_DRB_Setup_Mod_List_EUTRAN =  52,
  id_DRB_Failed_Mod_List_EUTRAN =  53,
  id_PDU_Session_Resource_Setup_Mod_List =  54,
  id_PDU_Session_Resource_Failed_Mod_List =  55,
  id_PDU_Session_Resource_To_Setup_Mod_List =  56,
  id_TransactionID =  57,
  id_Serving_PLMN =  58,
  id_UE_Inactivity_Timer =  59,
  id_System_GNB_CU_UP_CounterCheckRequest =  60,
  id_DRBs_Subject_To_Counter_Check_List_EUTRAN =  61,
  id_DRBs_Subject_To_Counter_Check_List_NG_RAN =  62,
  id_PPI       =  63,
  id_gNB_CU_UP_Capacity =  64,
  id_GNB_CU_UP_OverloadInformation =  65,
  id_UEDLMaximumIntegrityProtectedDataRate =  66,
  id_PDU_Session_To_Notify_List =  67,
  id_PDU_Session_Resource_Data_Usage_List =  68,
  id_SNSSAI    =  69,
  id_DataDiscardRequired =  70,
  id_OldQoSFlowMap_ULendmarkerexpected =  71,
  id_DRB_QoS   =  72,
  id_GNB_CU_UP_TNLA_To_Remove_List =  73,
  id_endpoint_IP_Address_and_Port =  74,
  id_TNLAssociationTransportLayerAddressgNBCUUP =  75,
  id_RANUEID   =  76,
  id_GNB_DU_ID =  77,
  id_CommonNetworkInstance =  78,
  id_NetworkInstance =  79,
  id_QoSFlowMappingIndication =  80,
  id_TraceActivation =  81,
  id_TraceID   =  82,
  id_SubscriberProfileIDforRFP =  83,
  id_AdditionalRRMPriorityIndex =  84,
  id_RetainabilityMeasurementsInfo =  85,
  id_Transport_Layer_Address_Info =  86,
  id_QoSMonitoringRequest =  87,
  id_PDCP_StatusReportIndication =  88,
  id_gNB_CU_CP_Measurement_ID =  89,
  id_gNB_CU_UP_Measurement_ID =  90,
  id_RegistrationRequest =  91,
  id_ReportCharacteristics =  92,
  id_ReportingPeriodicity =  93,
  id_TNL_AvailableCapacityIndicator =  94,
  id_HW_CapacityIndicator =  95,
  id_RedundantCommonNetworkInstance =  96,
  id_redundant_nG_UL_UP_TNL_Information =  97,
  id_redundant_nG_DL_UP_TNL_Information =  98,
  id_RedundantQosFlowIndicator =  99,
  id_TSCTrafficCharacteristics = 100,
  id_CNPacketDelayBudgetDownlink = 101,
  id_CNPacketDelayBudgetUplink = 102,
  id_ExtendedPacketDelayBudget = 103,
  id_AdditionalPDCPduplicationInformation = 104,
  id_RedundantPDUSessionInformation = 105,
  id_RedundantPDUSessionInformation_used = 106,
  id_QoS_Mapping_Information = 107,
  id_DLUPTNLAddressToUpdateList = 108,
  id_ULUPTNLAddressToUpdateList = 109,
  id_NPNSupportInfo = 110,
  id_NPNContextInfo = 111,
  id_MDTConfiguration = 112,
  id_ManagementBasedMDTPLMNList = 113,
  id_TraceCollectionEntityIPAddress = 114,
  id_PrivacyIndicator = 115,
  id_TraceCollectionEntityURI = 116,
  id_URIaddress = 117,
  id_EHC_Parameters = 118,
  id_DRBs_Subject_To_Early_Forwarding_List = 119,
  id_DAPSRequestInfo = 120,
  id_CHOInitiation = 121,
  id_EarlyForwardingCOUNTReq = 122,
  id_EarlyForwardingCOUNTInfo = 123,
  id_AlternativeQoSParaSetList = 124,
  id_ExtendedSliceSupportList = 125,
  id_MCG_OfferedGBRQoSFlowInfo = 126,
  id_Number_of_tunnels = 127,
  id_DRB_Measurement_Results_Information_List = 128,
  id_Extended_GNB_CU_CP_Name = 129,
  id_Extended_GNB_CU_UP_Name = 130,
  id_DataForwardingtoE_UTRANInformationList = 131,
  id_QosMonitoringReportingFrequency = 132,
  id_QoSMonitoringDisabled = 133,
  id_AdditionalHandoverInfo = 134,
  id_Extended_NR_CGI_Support_List = 135,
  id_DataForwardingtoNG_RANQoSFlowInformationList = 136,
  id_MaxCIDEHCDL = 137,
  id_ignoreMappingRuleIndication = 138,
  id_DirectForwardingPathAvailability = 139,
  id_EarlyDataForwardingIndicator = 140,
  id_QoSFlowsDRBRemapping = 141,
  id_DataForwardingSourceIPAddress = 142,
  id_SecurityIndicationModify = 143,
  id_IAB_Donor_CU_UPPSKInfo = 144,
  id_ECGI_Support_List = 145,
  id_MDTPollutedMeasurementIndicator = 146,
  id_M4ReportAmount = 147,
  id_M6ReportAmount = 148,
  id_M7ReportAmount = 149,
  id_UESliceMaximumBitRateList = 150,
  id_PDUSession_PairID = 151,
  id_SurvivalTime = 152,
  id_UDC_Parameters = 153,
  id_SCGActivationStatus = 154,
  id_GNB_CU_CP_MBS_E1AP_ID = 155,
  id_GNB_CU_UP_MBS_E1AP_ID = 156,
  id_GlobalMBSSessionID = 157,
  id_BCBearerContextToSetup = 158,
  id_BCBearerContextToSetupResponse = 159,
  id_BCBearerContextToModify = 160,
  id_BCBearerContextToModifyResponse = 161,
  id_BCBearerContextToModifyRequired = 162,
  id_BCBearerContextToModifyConfirm = 163,
  id_MCBearerContextToSetup = 164,
  id_MCBearerContextToSetupResponse = 165,
  id_MCBearerContextToModify = 166,
  id_MCBearerContextToModifyResponse = 167,
  id_MCBearerContextToModifyRequired = 168,
  id_MCBearerContextToModifyConfirm = 169,
  id_MBSMulticastF1UContextDescriptor = 170,
  id_gNB_CU_UP_MBS_Support_Info = 171,
  id_SecurityIndication = 172,
  id_SecurityResult = 173,
  id_SDTContinueROHC = 174,
  id_SDTindicatorSetup = 175,
  id_SDTindicatorMod = 176,
  id_DiscardTimerExtended = 177,
  id_ManagementBasedMDTPLMNModificationList = 178,
  id_MCForwardingResourceRequest = 179,
  id_MCForwardingResourceIndication = 180,
  id_MCForwardingResourceResponse = 181,
  id_MCForwardingResourceRelease = 182,
  id_MCForwardingResourceReleaseIndication = 183,
  id_PDCP_COUNT_Reset = 184,
  id_MBSSessionAssociatedInfoNonSupportToSupport = 185,
  id_VersionID = 186,
  id_InactivityInformationRequest = 187,
  id_UEInactivityInformation = 188,
  id_MBSAreaSessionID = 189,
  id_Secondary_PDU_Session_Data_Forwarding_Information = 190,
  id_MBSSessionResourceNotification = 191,
  id_MCBearerContextInactivityTimer = 192,
  id_MCBearerContextStatusChange = 193,
  id_MT_SDT_Information = 194,
  id_MT_SDT_Information_Request = 195,
  id_SDT_data_size_threshold = 196,
  id_SDT_data_size_threshold_Crossed = 197,
  id_SpecialTriggeringPurpose = 198,
  id_AssociatedSessionID = 199,
  id_MBS_ServiceArea = 200,
  id_PDUSetQoSParameters = 201,
  id_N6JitterInformation = 202,
  id_ECNMarkingorCongestionInformationReportingRequest = 203,
  id_ECNMarkingorCongestionInformationReportingStatus = 204,
  id_PDUSetbasedHandlingIndicator = 205,
  id_IndirectPathIndication = 206,
  id_F1UTunnelNotEstablished = 207,
  id_F1U_TNL_InfoToAdd_List = 208,
  id_F1U_TNL_InfoAdded_List = 209,
  id_F1U_TNL_InfoToAddOrModify_List = 210,
  id_F1U_TNL_InfoAddedOrModified_List = 211,
  id_F1U_TNL_InfoToRelease_List = 212,
  id_BroadcastF1U_ContextReferenceE1 = 213,
  id_PSIbasedDiscardTimer = 214,
  id_UserPlaneErrorIndicator = 215,
  id_MaximumDataBurstVolume = 216,
  id_BCBearerContextNGU_TNLInfoatNGRAN_Request = 217,
  id_PDCPSNGapReport = 218,
  id_UserPlaneFailureIndication = 219
} ProtocolIE_ID_enum;

/* Initialize the protocol and registered fields */
static int proto_e1ap;

static int hf_e1ap_transportLayerAddressIPv4;
static int hf_e1ap_transportLayerAddressIPv6;
static int hf_e1ap_InterfacesToTrace_NG_C;
static int hf_e1ap_InterfacesToTrace_Xn_C;
static int hf_e1ap_InterfacesToTrace_Uu;
static int hf_e1ap_InterfacesToTrace_F1_C;
static int hf_e1ap_InterfacesToTrace_E1;
static int hf_e1ap_InterfacesToTrace_Reserved;
static int hf_e1ap_MeasurementsToActivate_Reserved1;
static int hf_e1ap_MeasurementsToActivate_M4;
static int hf_e1ap_MeasurementsToActivate_Reserved2;
static int hf_e1ap_MeasurementsToActivate_M6;
static int hf_e1ap_MeasurementsToActivate_M7;
static int hf_e1ap_ReportCharacteristics_TNLAvailableCapacityIndPeriodic;
static int hf_e1ap_ReportCharacteristics_HWCapacityIndPeriodic;
static int hf_e1ap_ReportCharacteristics_Reserved;
static int hf_e1ap_tcp_pdu_len;
static int hf_e1ap_ActivityInformation_PDU;       /* ActivityInformation */
static int hf_e1ap_ActivityNotificationLevel_PDU;  /* ActivityNotificationLevel */
static int hf_e1ap_AdditionalHandoverInfo_PDU;    /* AdditionalHandoverInfo */
static int hf_e1ap_AdditionalPDCPduplicationInformation_PDU;  /* AdditionalPDCPduplicationInformation */
static int hf_e1ap_AdditionalRRMPriorityIndex_PDU;  /* AdditionalRRMPriorityIndex */
static int hf_e1ap_AlternativeQoSParaSetList_PDU;  /* AlternativeQoSParaSetList */
static int hf_e1ap_AssociatedSessionID_PDU;       /* AssociatedSessionID */
static int hf_e1ap_BCBearerContextToSetup_PDU;    /* BCBearerContextToSetup */
static int hf_e1ap_BCBearerContextToSetupResponse_PDU;  /* BCBearerContextToSetupResponse */
static int hf_e1ap_BCBearerContextToModify_PDU;   /* BCBearerContextToModify */
static int hf_e1ap_BCBearerContextNGU_TNLInfoatNGRAN_Request_PDU;  /* BCBearerContextNGU_TNLInfoatNGRAN_Request */
static int hf_e1ap_BCBearerContextToModifyResponse_PDU;  /* BCBearerContextToModifyResponse */
static int hf_e1ap_BCBearerContextToModifyRequired_PDU;  /* BCBearerContextToModifyRequired */
static int hf_e1ap_BCBearerContextToModifyConfirm_PDU;  /* BCBearerContextToModifyConfirm */
static int hf_e1ap_BearerContextStatusChange_PDU;  /* BearerContextStatusChange */
static int hf_e1ap_BitRate_PDU;                   /* BitRate */
static int hf_e1ap_Cause_PDU;                     /* Cause */
static int hf_e1ap_CHOInitiation_PDU;             /* CHOInitiation */
static int hf_e1ap_Number_of_tunnels_PDU;         /* Number_of_tunnels */
static int hf_e1ap_CNSupport_PDU;                 /* CNSupport */
static int hf_e1ap_CommonNetworkInstance_PDU;     /* CommonNetworkInstance */
static int hf_e1ap_CP_TNL_Information_PDU;        /* CP_TNL_Information */
static int hf_e1ap_CriticalityDiagnostics_PDU;    /* CriticalityDiagnostics */
static int hf_e1ap_DAPSRequestInfo_PDU;           /* DAPSRequestInfo */
static int hf_e1ap_Data_Forwarding_Information_PDU;  /* Data_Forwarding_Information */
static int hf_e1ap_DataForwardingtoE_UTRANInformationList_PDU;  /* DataForwardingtoE_UTRANInformationList */
static int hf_e1ap_Data_Usage_Report_List_PDU;    /* Data_Usage_Report_List */
static int hf_e1ap_DirectForwardingPathAvailability_PDU;  /* DirectForwardingPathAvailability */
static int hf_e1ap_DiscardTimerExtended_PDU;      /* DiscardTimerExtended */
static int hf_e1ap_PSIbasedDiscardTimer_PDU;      /* PSIbasedDiscardTimer */
static int hf_e1ap_DRB_Confirm_Modified_List_EUTRAN_PDU;  /* DRB_Confirm_Modified_List_EUTRAN */
static int hf_e1ap_DRB_Failed_List_EUTRAN_PDU;    /* DRB_Failed_List_EUTRAN */
static int hf_e1ap_DRB_Failed_Mod_List_EUTRAN_PDU;  /* DRB_Failed_Mod_List_EUTRAN */
static int hf_e1ap_DRB_Failed_To_Modify_List_EUTRAN_PDU;  /* DRB_Failed_To_Modify_List_EUTRAN */
static int hf_e1ap_DRB_Measurement_Results_Information_List_PDU;  /* DRB_Measurement_Results_Information_List */
static int hf_e1ap_DRB_Modified_List_EUTRAN_PDU;  /* DRB_Modified_List_EUTRAN */
static int hf_e1ap_DRB_Required_To_Modify_List_EUTRAN_PDU;  /* DRB_Required_To_Modify_List_EUTRAN */
static int hf_e1ap_DRB_Setup_List_EUTRAN_PDU;     /* DRB_Setup_List_EUTRAN */
static int hf_e1ap_DRB_Setup_Mod_List_EUTRAN_PDU;  /* DRB_Setup_Mod_List_EUTRAN */
static int hf_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN_PDU;  /* DRBs_Subject_To_Counter_Check_List_EUTRAN */
static int hf_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN_PDU;  /* DRBs_Subject_To_Counter_Check_List_NG_RAN */
static int hf_e1ap_DRBs_Subject_To_Early_Forwarding_List_PDU;  /* DRBs_Subject_To_Early_Forwarding_List */
static int hf_e1ap_DRB_To_Modify_List_EUTRAN_PDU;  /* DRB_To_Modify_List_EUTRAN */
static int hf_e1ap_DRB_To_Remove_List_EUTRAN_PDU;  /* DRB_To_Remove_List_EUTRAN */
static int hf_e1ap_DRB_Required_To_Remove_List_EUTRAN_PDU;  /* DRB_Required_To_Remove_List_EUTRAN */
static int hf_e1ap_DRB_To_Setup_List_EUTRAN_PDU;  /* DRB_To_Setup_List_EUTRAN */
static int hf_e1ap_DRB_To_Setup_Mod_List_EUTRAN_PDU;  /* DRB_To_Setup_Mod_List_EUTRAN */
static int hf_e1ap_DataDiscardRequired_PDU;       /* DataDiscardRequired */
static int hf_e1ap_EarlyDataForwardingIndicator_PDU;  /* EarlyDataForwardingIndicator */
static int hf_e1ap_EarlyForwardingCOUNTInfo_PDU;  /* EarlyForwardingCOUNTInfo */
static int hf_e1ap_EarlyForwardingCOUNTReq_PDU;   /* EarlyForwardingCOUNTReq */
static int hf_e1ap_ECNMarkingorCongestionInformationReportingRequest_PDU;  /* ECNMarkingorCongestionInformationReportingRequest */
static int hf_e1ap_ECNMarkingorCongestionInformationReportingStatus_PDU;  /* ECNMarkingorCongestionInformationReportingStatus */
static int hf_e1ap_EHC_Parameters_PDU;            /* EHC_Parameters */
static int hf_e1ap_Endpoint_IP_address_and_port_PDU;  /* Endpoint_IP_address_and_port */
static int hf_e1ap_ExtendedPacketDelayBudget_PDU;  /* ExtendedPacketDelayBudget */
static int hf_e1ap_ECGI_Support_List_PDU;         /* ECGI_Support_List */
static int hf_e1ap_ExtendedSliceSupportList_PDU;  /* ExtendedSliceSupportList */
static int hf_e1ap_F1U_TNL_InfoAdded_List_PDU;    /* F1U_TNL_InfoAdded_List */
static int hf_e1ap_F1U_TNL_InfoToAdd_List_PDU;    /* F1U_TNL_InfoToAdd_List */
static int hf_e1ap_F1U_TNL_InfoAddedOrModified_List_PDU;  /* F1U_TNL_InfoAddedOrModified_List */
static int hf_e1ap_F1U_TNL_InfoToAddOrModify_List_PDU;  /* F1U_TNL_InfoToAddOrModify_List */
static int hf_e1ap_F1U_TNL_InfoToRelease_List_PDU;  /* F1U_TNL_InfoToRelease_List */
static int hf_e1ap_GlobalMBSSessionID_PDU;        /* GlobalMBSSessionID */
static int hf_e1ap_GNB_CU_CP_Name_PDU;            /* GNB_CU_CP_Name */
static int hf_e1ap_Extended_GNB_CU_CP_Name_PDU;   /* Extended_GNB_CU_CP_Name */
static int hf_e1ap_GNB_CU_CP_MBS_E1AP_ID_PDU;     /* GNB_CU_CP_MBS_E1AP_ID */
static int hf_e1ap_GNB_CU_CP_UE_E1AP_ID_PDU;      /* GNB_CU_CP_UE_E1AP_ID */
static int hf_e1ap_GNB_CU_UP_Capacity_PDU;        /* GNB_CU_UP_Capacity */
static int hf_e1ap_GNB_CU_UP_ID_PDU;              /* GNB_CU_UP_ID */
static int hf_e1ap_GNB_CU_UP_MBS_Support_Info_PDU;  /* GNB_CU_UP_MBS_Support_Info */
static int hf_e1ap_GNB_CU_UP_Name_PDU;            /* GNB_CU_UP_Name */
static int hf_e1ap_Extended_GNB_CU_UP_Name_PDU;   /* Extended_GNB_CU_UP_Name */
static int hf_e1ap_GNB_CU_UP_MBS_E1AP_ID_PDU;     /* GNB_CU_UP_MBS_E1AP_ID */
static int hf_e1ap_GNB_CU_UP_UE_E1AP_ID_PDU;      /* GNB_CU_UP_UE_E1AP_ID */
static int hf_e1ap_GBR_QoSFlowInformation_PDU;    /* GBR_QoSFlowInformation */
static int hf_e1ap_GNB_CU_UP_OverloadInformation_PDU;  /* GNB_CU_UP_OverloadInformation */
static int hf_e1ap_GNB_DU_ID_PDU;                 /* GNB_DU_ID */
static int hf_e1ap_HW_CapacityIndicator_PDU;      /* HW_CapacityIndicator */
static int hf_e1ap_IndirectPathIndication_PDU;    /* IndirectPathIndication */
static int hf_e1ap_IgnoreMappingRuleIndication_PDU;  /* IgnoreMappingRuleIndication */
static int hf_e1ap_Inactivity_Timer_PDU;          /* Inactivity_Timer */
static int hf_e1ap_InactivityInformationRequest_PDU;  /* InactivityInformationRequest */
static int hf_e1ap_MaxDataBurstVolume_PDU;        /* MaxDataBurstVolume */
static int hf_e1ap_MaxCIDEHCDL_PDU;               /* MaxCIDEHCDL */
static int hf_e1ap_MBSAreaSessionID_PDU;          /* MBSAreaSessionID */
static int hf_e1ap_MBSSessionAssociatedInfoNonSupportToSupport_PDU;  /* MBSSessionAssociatedInfoNonSupportToSupport */
static int hf_e1ap_MBSSessionResourceNotification_PDU;  /* MBSSessionResourceNotification */
static int hf_e1ap_MCBearerContextToSetup_PDU;    /* MCBearerContextToSetup */
static int hf_e1ap_MCBearerContextStatusChange_PDU;  /* MCBearerContextStatusChange */
static int hf_e1ap_MCBearerContextToSetupResponse_PDU;  /* MCBearerContextToSetupResponse */
static int hf_e1ap_MCBearerContextToModify_PDU;   /* MCBearerContextToModify */
static int hf_e1ap_MBSMulticastF1UContextDescriptor_PDU;  /* MBSMulticastF1UContextDescriptor */
static int hf_e1ap_MCBearerContextToModifyResponse_PDU;  /* MCBearerContextToModifyResponse */
static int hf_e1ap_MCBearerContextToModifyRequired_PDU;  /* MCBearerContextToModifyRequired */
static int hf_e1ap_MCBearerContextToModifyConfirm_PDU;  /* MCBearerContextToModifyConfirm */
static int hf_e1ap_MCForwardingResourceRequest_PDU;  /* MCForwardingResourceRequest */
static int hf_e1ap_MCForwardingResourceIndication_PDU;  /* MCForwardingResourceIndication */
static int hf_e1ap_MCForwardingResourceResponse_PDU;  /* MCForwardingResourceResponse */
static int hf_e1ap_MCForwardingResourceRelease_PDU;  /* MCForwardingResourceRelease */
static int hf_e1ap_MCForwardingResourceReleaseIndication_PDU;  /* MCForwardingResourceReleaseIndication */
static int hf_e1ap_MDTPollutedMeasurementIndicator_PDU;  /* MDTPollutedMeasurementIndicator */
static int hf_e1ap_M4ReportAmount_PDU;            /* M4ReportAmount */
static int hf_e1ap_M6ReportAmount_PDU;            /* M6ReportAmount */
static int hf_e1ap_M7ReportAmount_PDU;            /* M7ReportAmount */
static int hf_e1ap_MDT_Configuration_PDU;         /* MDT_Configuration */
static int hf_e1ap_MDTPLMNList_PDU;               /* MDTPLMNList */
static int hf_e1ap_MDTPLMNModificationList_PDU;   /* MDTPLMNModificationList */
static int hf_e1ap_MT_SDT_Information_PDU;        /* MT_SDT_Information */
static int hf_e1ap_MT_SDT_Information_Request_PDU;  /* MT_SDT_Information_Request */
static int hf_e1ap_MBS_ServiceArea_PDU;           /* MBS_ServiceArea */
static int hf_e1ap_NetworkInstance_PDU;           /* NetworkInstance */
static int hf_e1ap_New_UL_TNL_Information_Required_PDU;  /* New_UL_TNL_Information_Required */
static int hf_e1ap_NPNSupportInfo_PDU;            /* NPNSupportInfo */
static int hf_e1ap_NPNContextInfo_PDU;            /* NPNContextInfo */
static int hf_e1ap_Extended_NR_CGI_Support_List_PDU;  /* Extended_NR_CGI_Support_List */
static int hf_e1ap_N6JitterInformation_PDU;       /* N6JitterInformation */
static int hf_e1ap_PDCPSNGapReport_PDU;           /* PDCPSNGapReport */
static int hf_e1ap_PDCP_COUNT_Reset_PDU;          /* PDCP_COUNT_Reset */
static int hf_e1ap_PDU_Session_Resource_Data_Usage_List_PDU;  /* PDU_Session_Resource_Data_Usage_List */
static int hf_e1ap_PDCP_StatusReportIndication_PDU;  /* PDCP_StatusReportIndication */
static int hf_e1ap_PDUSession_PairID_PDU;         /* PDUSession_PairID */
static int hf_e1ap_PDU_Session_Resource_Confirm_Modified_List_PDU;  /* PDU_Session_Resource_Confirm_Modified_List */
static int hf_e1ap_PDU_Session_Resource_Failed_List_PDU;  /* PDU_Session_Resource_Failed_List */
static int hf_e1ap_PDU_Session_Resource_Failed_Mod_List_PDU;  /* PDU_Session_Resource_Failed_Mod_List */
static int hf_e1ap_PDU_Session_Resource_Failed_To_Modify_List_PDU;  /* PDU_Session_Resource_Failed_To_Modify_List */
static int hf_e1ap_PDU_Session_Resource_Modified_List_PDU;  /* PDU_Session_Resource_Modified_List */
static int hf_e1ap_PDU_Session_Resource_Required_To_Modify_List_PDU;  /* PDU_Session_Resource_Required_To_Modify_List */
static int hf_e1ap_PDU_Session_Resource_Setup_List_PDU;  /* PDU_Session_Resource_Setup_List */
static int hf_e1ap_PDU_Session_Resource_Setup_Mod_List_PDU;  /* PDU_Session_Resource_Setup_Mod_List */
static int hf_e1ap_PDU_Session_Resource_To_Modify_List_PDU;  /* PDU_Session_Resource_To_Modify_List */
static int hf_e1ap_PDU_Session_Resource_To_Remove_List_PDU;  /* PDU_Session_Resource_To_Remove_List */
static int hf_e1ap_PDU_Session_Resource_To_Setup_List_PDU;  /* PDU_Session_Resource_To_Setup_List */
static int hf_e1ap_PDU_Session_Resource_To_Setup_Mod_List_PDU;  /* PDU_Session_Resource_To_Setup_Mod_List */
static int hf_e1ap_PDU_Session_To_Notify_List_PDU;  /* PDU_Session_To_Notify_List */
static int hf_e1ap_PDUSetbasedHandlingIndicator_PDU;  /* PDUSetbasedHandlingIndicator */
static int hf_e1ap_PLMN_Identity_PDU;             /* PLMN_Identity */
static int hf_e1ap_PPI_PDU;                       /* PPI */
static int hf_e1ap_PrivacyIndicator_PDU;          /* PrivacyIndicator */
static int hf_e1ap_PDUSetQoSParameters_PDU;       /* PDUSetQoSParameters */
static int hf_e1ap_QoS_Flow_List_PDU;             /* QoS_Flow_List */
static int hf_e1ap_QoS_Flow_Mapping_Indication_PDU;  /* QoS_Flow_Mapping_Indication */
static int hf_e1ap_QoS_Flows_DRB_Remapping_PDU;   /* QoS_Flows_DRB_Remapping */
static int hf_e1ap_QoSFlowLevelQoSParameters_PDU;  /* QoSFlowLevelQoSParameters */
static int hf_e1ap_QosMonitoringRequest_PDU;      /* QosMonitoringRequest */
static int hf_e1ap_QosMonitoringReportingFrequency_PDU;  /* QosMonitoringReportingFrequency */
static int hf_e1ap_QosMonitoringDisabled_PDU;     /* QosMonitoringDisabled */
static int hf_e1ap_QoS_Mapping_Information_PDU;   /* QoS_Mapping_Information */
static int hf_e1ap_DataForwardingtoNG_RANQoSFlowInformationList_PDU;  /* DataForwardingtoNG_RANQoSFlowInformationList */
static int hf_e1ap_RANUEID_PDU;                   /* RANUEID */
static int hf_e1ap_RedundantQoSFlowIndicator_PDU;  /* RedundantQoSFlowIndicator */
static int hf_e1ap_RedundantPDUSessionInformation_PDU;  /* RedundantPDUSessionInformation */
static int hf_e1ap_RetainabilityMeasurementsInfo_PDU;  /* RetainabilityMeasurementsInfo */
static int hf_e1ap_RegistrationRequest_PDU;       /* RegistrationRequest */
static int hf_e1ap_ReportCharacteristics_PDU;     /* ReportCharacteristics */
static int hf_e1ap_ReportingPeriodicity_PDU;      /* ReportingPeriodicity */
static int hf_e1ap_SDT_data_size_threshold_PDU;   /* SDT_data_size_threshold */
static int hf_e1ap_SDT_data_size_threshold_Crossed_PDU;  /* SDT_data_size_threshold_Crossed */
static int hf_e1ap_SCGActivationStatus_PDU;       /* SCGActivationStatus */
static int hf_e1ap_SecurityIndication_PDU;        /* SecurityIndication */
static int hf_e1ap_SecurityInformation_PDU;       /* SecurityInformation */
static int hf_e1ap_SecurityResult_PDU;            /* SecurityResult */
static int hf_e1ap_SNSSAI_PDU;                    /* SNSSAI */
static int hf_e1ap_SDTContinueROHC_PDU;           /* SDTContinueROHC */
static int hf_e1ap_SDTindicatorSetup_PDU;         /* SDTindicatorSetup */
static int hf_e1ap_SDTindicatorMod_PDU;           /* SDTindicatorMod */
static int hf_e1ap_SubscriberProfileIDforRFP_PDU;  /* SubscriberProfileIDforRFP */
static int hf_e1ap_SurvivalTime_PDU;              /* SurvivalTime */
static int hf_e1ap_SpecialTriggeringPurpose_PDU;  /* SpecialTriggeringPurpose */
static int hf_e1ap_F1UTunnelNotEstablished_PDU;   /* F1UTunnelNotEstablished */
static int hf_e1ap_TimeToWait_PDU;                /* TimeToWait */
static int hf_e1ap_TNL_AvailableCapacityIndicator_PDU;  /* TNL_AvailableCapacityIndicator */
static int hf_e1ap_TSCTrafficCharacteristics_PDU;  /* TSCTrafficCharacteristics */
static int hf_e1ap_TraceActivation_PDU;           /* TraceActivation */
static int hf_e1ap_TraceID_PDU;                   /* TraceID */
static int hf_e1ap_TransportLayerAddress_PDU;     /* TransportLayerAddress */
static int hf_e1ap_TransactionID_PDU;             /* TransactionID */
static int hf_e1ap_Transport_Layer_Address_Info_PDU;  /* Transport_Layer_Address_Info */
static int hf_e1ap_UDC_Parameters_PDU;            /* UDC_Parameters */
static int hf_e1ap_VersionID_PDU;                 /* VersionID */
static int hf_e1ap_UE_associatedLogicalE1_ConnectionItem_PDU;  /* UE_associatedLogicalE1_ConnectionItem */
static int hf_e1ap_UESliceMaximumBitRateList_PDU;  /* UESliceMaximumBitRateList */
static int hf_e1ap_UP_TNL_Information_PDU;        /* UP_TNL_Information */
static int hf_e1ap_URIaddress_PDU;                /* URIaddress */
static int hf_e1ap_UserPlaneErrorIndicator_PDU;   /* UserPlaneErrorIndicator */
static int hf_e1ap_UEInactivityInformation_PDU;   /* UEInactivityInformation */
static int hf_e1ap_UserPlaneFailureIndication_PDU;  /* UserPlaneFailureIndication */
static int hf_e1ap_Reset_PDU;                     /* Reset */
static int hf_e1ap_ResetType_PDU;                 /* ResetType */
static int hf_e1ap_ResetAcknowledge_PDU;          /* ResetAcknowledge */
static int hf_e1ap_UE_associatedLogicalE1_ConnectionListResAck_PDU;  /* UE_associatedLogicalE1_ConnectionListResAck */
static int hf_e1ap_ErrorIndication_PDU;           /* ErrorIndication */
static int hf_e1ap_GNB_CU_UP_E1SetupRequest_PDU;  /* GNB_CU_UP_E1SetupRequest */
static int hf_e1ap_SupportedPLMNs_List_PDU;       /* SupportedPLMNs_List */
static int hf_e1ap_GNB_CU_UP_E1SetupResponse_PDU;  /* GNB_CU_UP_E1SetupResponse */
static int hf_e1ap_GNB_CU_UP_E1SetupFailure_PDU;  /* GNB_CU_UP_E1SetupFailure */
static int hf_e1ap_GNB_CU_CP_E1SetupRequest_PDU;  /* GNB_CU_CP_E1SetupRequest */
static int hf_e1ap_GNB_CU_CP_E1SetupResponse_PDU;  /* GNB_CU_CP_E1SetupResponse */
static int hf_e1ap_GNB_CU_CP_E1SetupFailure_PDU;  /* GNB_CU_CP_E1SetupFailure */
static int hf_e1ap_GNB_CU_UP_ConfigurationUpdate_PDU;  /* GNB_CU_UP_ConfigurationUpdate */
static int hf_e1ap_GNB_CU_UP_TNLA_To_Remove_List_PDU;  /* GNB_CU_UP_TNLA_To_Remove_List */
static int hf_e1ap_GNB_CU_UP_ConfigurationUpdateAcknowledge_PDU;  /* GNB_CU_UP_ConfigurationUpdateAcknowledge */
static int hf_e1ap_GNB_CU_UP_ConfigurationUpdateFailure_PDU;  /* GNB_CU_UP_ConfigurationUpdateFailure */
static int hf_e1ap_GNB_CU_CP_ConfigurationUpdate_PDU;  /* GNB_CU_CP_ConfigurationUpdate */
static int hf_e1ap_GNB_CU_CP_TNLA_To_Add_List_PDU;  /* GNB_CU_CP_TNLA_To_Add_List */
static int hf_e1ap_GNB_CU_CP_TNLA_To_Remove_List_PDU;  /* GNB_CU_CP_TNLA_To_Remove_List */
static int hf_e1ap_GNB_CU_CP_TNLA_To_Update_List_PDU;  /* GNB_CU_CP_TNLA_To_Update_List */
static int hf_e1ap_GNB_CU_CP_ConfigurationUpdateAcknowledge_PDU;  /* GNB_CU_CP_ConfigurationUpdateAcknowledge */
static int hf_e1ap_GNB_CU_CP_TNLA_Setup_List_PDU;  /* GNB_CU_CP_TNLA_Setup_List */
static int hf_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List_PDU;  /* GNB_CU_CP_TNLA_Failed_To_Setup_List */
static int hf_e1ap_GNB_CU_CP_ConfigurationUpdateFailure_PDU;  /* GNB_CU_CP_ConfigurationUpdateFailure */
static int hf_e1ap_E1ReleaseRequest_PDU;          /* E1ReleaseRequest */
static int hf_e1ap_E1ReleaseResponse_PDU;         /* E1ReleaseResponse */
static int hf_e1ap_BearerContextSetupRequest_PDU;  /* BearerContextSetupRequest */
static int hf_e1ap_System_BearerContextSetupRequest_PDU;  /* System_BearerContextSetupRequest */
static int hf_e1ap_BearerContextSetupResponse_PDU;  /* BearerContextSetupResponse */
static int hf_e1ap_System_BearerContextSetupResponse_PDU;  /* System_BearerContextSetupResponse */
static int hf_e1ap_BearerContextSetupFailure_PDU;  /* BearerContextSetupFailure */
static int hf_e1ap_BearerContextModificationRequest_PDU;  /* BearerContextModificationRequest */
static int hf_e1ap_System_BearerContextModificationRequest_PDU;  /* System_BearerContextModificationRequest */
static int hf_e1ap_BearerContextModificationResponse_PDU;  /* BearerContextModificationResponse */
static int hf_e1ap_System_BearerContextModificationResponse_PDU;  /* System_BearerContextModificationResponse */
static int hf_e1ap_BearerContextModificationFailure_PDU;  /* BearerContextModificationFailure */
static int hf_e1ap_BearerContextModificationRequired_PDU;  /* BearerContextModificationRequired */
static int hf_e1ap_System_BearerContextModificationRequired_PDU;  /* System_BearerContextModificationRequired */
static int hf_e1ap_BearerContextModificationConfirm_PDU;  /* BearerContextModificationConfirm */
static int hf_e1ap_System_BearerContextModificationConfirm_PDU;  /* System_BearerContextModificationConfirm */
static int hf_e1ap_BearerContextReleaseCommand_PDU;  /* BearerContextReleaseCommand */
static int hf_e1ap_BearerContextReleaseComplete_PDU;  /* BearerContextReleaseComplete */
static int hf_e1ap_BearerContextReleaseRequest_PDU;  /* BearerContextReleaseRequest */
static int hf_e1ap_DRB_Status_List_PDU;           /* DRB_Status_List */
static int hf_e1ap_BearerContextInactivityNotification_PDU;  /* BearerContextInactivityNotification */
static int hf_e1ap_DLDataNotification_PDU;        /* DLDataNotification */
static int hf_e1ap_ULDataNotification_PDU;        /* ULDataNotification */
static int hf_e1ap_DataUsageReport_PDU;           /* DataUsageReport */
static int hf_e1ap_GNB_CU_UP_CounterCheckRequest_PDU;  /* GNB_CU_UP_CounterCheckRequest */
static int hf_e1ap_System_GNB_CU_UP_CounterCheckRequest_PDU;  /* System_GNB_CU_UP_CounterCheckRequest */
static int hf_e1ap_GNB_CU_UP_StatusIndication_PDU;  /* GNB_CU_UP_StatusIndication */
static int hf_e1ap_GNB_CU_CPMeasurementResultsInformation_PDU;  /* GNB_CU_CPMeasurementResultsInformation */
static int hf_e1ap_MRDC_DataUsageReport_PDU;      /* MRDC_DataUsageReport */
static int hf_e1ap_TraceStart_PDU;                /* TraceStart */
static int hf_e1ap_DeactivateTrace_PDU;           /* DeactivateTrace */
static int hf_e1ap_CellTrafficTrace_PDU;          /* CellTrafficTrace */
static int hf_e1ap_PrivateMessage_PDU;            /* PrivateMessage */
static int hf_e1ap_ResourceStatusRequest_PDU;     /* ResourceStatusRequest */
static int hf_e1ap_Measurement_ID_PDU;            /* Measurement_ID */
static int hf_e1ap_ResourceStatusResponse_PDU;    /* ResourceStatusResponse */
static int hf_e1ap_ResourceStatusFailure_PDU;     /* ResourceStatusFailure */
static int hf_e1ap_ResourceStatusUpdate_PDU;      /* ResourceStatusUpdate */
static int hf_e1ap_IAB_UPTNLAddressUpdate_PDU;    /* IAB_UPTNLAddressUpdate */
static int hf_e1ap_DLUPTNLAddressToUpdateList_PDU;  /* DLUPTNLAddressToUpdateList */
static int hf_e1ap_IAB_UPTNLAddressUpdateAcknowledge_PDU;  /* IAB_UPTNLAddressUpdateAcknowledge */
static int hf_e1ap_ULUPTNLAddressToUpdateList_PDU;  /* ULUPTNLAddressToUpdateList */
static int hf_e1ap_IAB_UPTNLAddressUpdateFailure_PDU;  /* IAB_UPTNLAddressUpdateFailure */
static int hf_e1ap_EarlyForwardingSNTransfer_PDU;  /* EarlyForwardingSNTransfer */
static int hf_e1ap_IABPSKNotification_PDU;        /* IABPSKNotification */
static int hf_e1ap_IAB_Donor_CU_UPPSKInfo_PDU;    /* IAB_Donor_CU_UPPSKInfo */
static int hf_e1ap_BCBearerContextSetupRequest_PDU;  /* BCBearerContextSetupRequest */
static int hf_e1ap_BCBearerContextSetupResponse_PDU;  /* BCBearerContextSetupResponse */
static int hf_e1ap_BCBearerContextSetupFailure_PDU;  /* BCBearerContextSetupFailure */
static int hf_e1ap_BCBearerContextModificationRequest_PDU;  /* BCBearerContextModificationRequest */
static int hf_e1ap_BCBearerContextModificationResponse_PDU;  /* BCBearerContextModificationResponse */
static int hf_e1ap_BCBearerContextModificationFailure_PDU;  /* BCBearerContextModificationFailure */
static int hf_e1ap_BCBearerContextModificationRequired_PDU;  /* BCBearerContextModificationRequired */
static int hf_e1ap_BCBearerContextModificationConfirm_PDU;  /* BCBearerContextModificationConfirm */
static int hf_e1ap_BCBearerContextReleaseCommand_PDU;  /* BCBearerContextReleaseCommand */
static int hf_e1ap_BCBearerContextReleaseComplete_PDU;  /* BCBearerContextReleaseComplete */
static int hf_e1ap_BCBearerContextReleaseRequest_PDU;  /* BCBearerContextReleaseRequest */
static int hf_e1ap_MCBearerContextSetupRequest_PDU;  /* MCBearerContextSetupRequest */
static int hf_e1ap_MCBearerContextSetupResponse_PDU;  /* MCBearerContextSetupResponse */
static int hf_e1ap_MCBearerContextSetupFailure_PDU;  /* MCBearerContextSetupFailure */
static int hf_e1ap_MCBearerContextModificationRequest_PDU;  /* MCBearerContextModificationRequest */
static int hf_e1ap_MCBearerContextModificationResponse_PDU;  /* MCBearerContextModificationResponse */
static int hf_e1ap_MCBearerContextModificationFailure_PDU;  /* MCBearerContextModificationFailure */
static int hf_e1ap_MCBearerContextModificationRequired_PDU;  /* MCBearerContextModificationRequired */
static int hf_e1ap_MCBearerContextModificationConfirm_PDU;  /* MCBearerContextModificationConfirm */
static int hf_e1ap_MCBearerContextReleaseCommand_PDU;  /* MCBearerContextReleaseCommand */
static int hf_e1ap_MCBearerContextReleaseComplete_PDU;  /* MCBearerContextReleaseComplete */
static int hf_e1ap_MCBearerContextReleaseRequest_PDU;  /* MCBearerContextReleaseRequest */
static int hf_e1ap_MCBearerNotification_PDU;      /* MCBearerNotification */
static int hf_e1ap_E1AP_PDU_PDU;                  /* E1AP_PDU */
static int hf_e1ap_local;                         /* INTEGER_0_maxPrivateIEs */
static int hf_e1ap_global;                        /* T_global */
static int hf_e1ap_ProtocolIE_Container_item;     /* ProtocolIE_Field */
static int hf_e1ap_id;                            /* ProtocolIE_ID */
static int hf_e1ap_criticality;                   /* Criticality */
static int hf_e1ap_ie_field_value;                /* T_ie_field_value */
static int hf_e1ap_ProtocolExtensionContainer_item;  /* ProtocolExtensionField */
static int hf_e1ap_ext_id;                        /* ProtocolIE_ID */
static int hf_e1ap_extensionValue;                /* T_extensionValue */
static int hf_e1ap_PrivateIE_Container_item;      /* PrivateIE_Field */
static int hf_e1ap_private_id;                    /* PrivateIE_ID */
static int hf_e1ap_value;                         /* T_value */
static int hf_e1ap_dRB_Activity_List;             /* DRB_Activity_List */
static int hf_e1ap_pDU_Session_Resource_Activity_List;  /* PDU_Session_Resource_Activity_List */
static int hf_e1ap_uE_Activity;                   /* UE_Activity */
static int hf_e1ap_choice_extension;              /* ProtocolIE_SingleContainer */
static int hf_e1ap_AlternativeQoSParaSetList_item;  /* AlternativeQoSParaSetItem */
static int hf_e1ap_alternativeQoSParameterIndex;  /* INTEGER_1_8_ */
static int hf_e1ap_guaranteedFlowBitRateDL;       /* BitRate */
static int hf_e1ap_guaranteedFlowBitRateUL;       /* BitRate */
static int hf_e1ap_packetDelayBudget;             /* PacketDelayBudget */
static int hf_e1ap_packetErrorRate;               /* PacketErrorRate */
static int hf_e1ap_iE_Extensions;                 /* ProtocolExtensionContainer */
static int hf_e1ap_snssai;                        /* SNSSAI */
static int hf_e1ap_bcBearerContextNGU_TNLInfoat5GC;  /* BCBearerContextNGU_TNLInfoat5GC */
static int hf_e1ap_bcMRBToSetupList;              /* BCMRBSetupConfiguration */
static int hf_e1ap_requestedAction;               /* RequestedAction4AvailNGUTermination */
static int hf_e1ap_locationindependent;           /* MBSNGUInformationAt5GC */
static int hf_e1ap_locationdependent;             /* LocationDependentMBSNGUInformationAt5GC */
static int hf_e1ap_BCMRBSetupConfiguration_item;  /* BCMRBSetupConfiguration_Item */
static int hf_e1ap_mrb_ID;                        /* MRB_ID */
static int hf_e1ap_mbs_pdcp_config;               /* PDCP_Configuration */
static int hf_e1ap_qoS_Flow_QoS_Parameter_List;   /* QoS_Flow_QoS_Parameter_List */
static int hf_e1ap_qoSFlowLevelQoSParameters;     /* QoSFlowLevelQoSParameters */
static int hf_e1ap_bcBearerContextNGU_TNLInfoatNGRAN;  /* BCBearerContextNGU_TNLInfoatNGRAN */
static int hf_e1ap_bcMRBSetupResponseList;        /* BCMRBSetupResponseList */
static int hf_e1ap_bcMRBFailedList;               /* BCMRBFailedList */
static int hf_e1ap_availableBCMRBConfig;          /* BCMRBSetupConfiguration */
static int hf_e1ap_locationindependent_01;        /* MBSNGUInformationAtNGRAN */
static int hf_e1ap_locationdependent_01;          /* LocationDependentMBSNGUInformationAtNGRAN */
static int hf_e1ap_BCMRBSetupResponseList_item;   /* BCMRBSetupResponseList_Item */
static int hf_e1ap_qosflow_setup;                 /* QoS_Flow_List */
static int hf_e1ap_qosflow_failed;                /* QoS_Flow_Failed_List */
static int hf_e1ap_bcBearerContextF1U_TNLInfoatCU;  /* BCBearerContextF1U_TNLInfoatCU */
static int hf_e1ap_locationindependent_02;        /* MBSF1UInformationAtCU */
static int hf_e1ap_locationdependent_02;          /* LocationDependentMBSF1UInformationAtCU */
static int hf_e1ap_BCMRBFailedList_item;          /* BCMRBFailedList_Item */
static int hf_e1ap_cause;                         /* Cause */
static int hf_e1ap_bcMRBToModifyList;             /* BCMRBModifyConfiguration */
static int hf_e1ap_bcMRBToRemoveList;             /* BCMRBRemoveConfiguration */
static int hf_e1ap_locationindependent_03;        /* MBSNGUInformationAtNGRAN_Request */
static int hf_e1ap_locationdependent_03;          /* MBSNGUInformationAtNGRAN_Request_List */
static int hf_e1ap_BCMRBModifyConfiguration_item;  /* BCMRBModifyConfiguration_Item */
static int hf_e1ap_bcBearerContextF1U_TNLInfoatDU;  /* BCBearerContextF1U_TNLInfoatDU */
static int hf_e1ap_locationindependent_04;        /* MBSF1UInformationAtDU */
static int hf_e1ap_locationdependent_04;          /* LocationDependentMBSF1UInformationAtDU */
static int hf_e1ap_BCMRBRemoveConfiguration_item;  /* MRB_ID */
static int hf_e1ap_bcMRBSetupModifyResponseList;  /* BCMRBSetupModifyResponseList */
static int hf_e1ap_BCMRBSetupModifyResponseList_item;  /* BCMRBSetupModifyResponseList_Item */
static int hf_e1ap_radioNetwork;                  /* CauseRadioNetwork */
static int hf_e1ap_transport;                     /* CauseTransport */
static int hf_e1ap_protocol;                      /* CauseProtocol */
static int hf_e1ap_misc;                          /* CauseMisc */
static int hf_e1ap_Cell_Group_Information_item;   /* Cell_Group_Information_Item */
static int hf_e1ap_cell_Group_ID;                 /* Cell_Group_ID */
static int hf_e1ap_uL_Configuration;              /* UL_Configuration */
static int hf_e1ap_dL_TX_Stop;                    /* DL_TX_Stop */
static int hf_e1ap_rAT_Type;                      /* RAT_Type */
static int hf_e1ap_endpoint_IP_Address;           /* TransportLayerAddress */
static int hf_e1ap_procedureCode;                 /* ProcedureCode */
static int hf_e1ap_triggeringMessage;             /* TriggeringMessage */
static int hf_e1ap_procedureCriticality;          /* Criticality */
static int hf_e1ap_transactionID;                 /* TransactionID */
static int hf_e1ap_iEsCriticalityDiagnostics;     /* CriticalityDiagnostics_IE_List */
static int hf_e1ap_CriticalityDiagnostics_IE_List_item;  /* CriticalityDiagnostics_IE_List_item */
static int hf_e1ap_iECriticality;                 /* Criticality */
static int hf_e1ap_iE_ID;                         /* ProtocolIE_ID */
static int hf_e1ap_typeOfError;                   /* TypeOfError */
static int hf_e1ap_dapsIndicator;                 /* T_dapsIndicator */
static int hf_e1ap_data_Forwarding_Request;       /* Data_Forwarding_Request */
static int hf_e1ap_qoS_Flows_Forwarded_On_Fwd_Tunnels;  /* QoS_Flow_Mapping_List */
static int hf_e1ap_uL_Data_Forwarding;            /* UP_TNL_Information */
static int hf_e1ap_dL_Data_Forwarding;            /* UP_TNL_Information */
static int hf_e1ap_DataForwardingtoE_UTRANInformationList_item;  /* DataForwardingtoE_UTRANInformationListItem */
static int hf_e1ap_data_forwarding_tunnel_information;  /* UP_TNL_Information */
static int hf_e1ap_qoS_Flows_to_be_forwarded_List;  /* QoS_Flows_to_be_forwarded_List */
static int hf_e1ap_secondaryRATType;              /* T_secondaryRATType */
static int hf_e1ap_pDU_session_Timed_Report_List;  /* SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item */
static int hf_e1ap_pDU_session_Timed_Report_List_item;  /* MRDC_Data_Usage_Report_Item */
static int hf_e1ap_Data_Usage_per_QoS_Flow_List_item;  /* Data_Usage_per_QoS_Flow_Item */
static int hf_e1ap_qoS_Flow_Identifier;           /* QoS_Flow_Identifier */
static int hf_e1ap_secondaryRATType_01;           /* T_secondaryRATType_01 */
static int hf_e1ap_qoS_Flow_Timed_Report_List;    /* SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item */
static int hf_e1ap_qoS_Flow_Timed_Report_List_item;  /* MRDC_Data_Usage_Report_Item */
static int hf_e1ap_Data_Usage_Report_List_item;   /* Data_Usage_Report_Item */
static int hf_e1ap_dRB_ID;                        /* DRB_ID */
static int hf_e1ap_dRB_Usage_Report_List;         /* DRB_Usage_Report_List */
static int hf_e1ap_dLDiscardingCountVal;          /* PDCP_Count */
static int hf_e1ap_oldTNLAdress;                  /* TransportLayerAddress */
static int hf_e1ap_newTNLAdress;                  /* TransportLayerAddress */
static int hf_e1ap_DRB_Activity_List_item;        /* DRB_Activity_Item */
static int hf_e1ap_dRB_Activity;                  /* DRB_Activity */
static int hf_e1ap_DRB_Confirm_Modified_List_EUTRAN_item;  /* DRB_Confirm_Modified_Item_EUTRAN */
static int hf_e1ap_cell_Group_Information;        /* Cell_Group_Information */
static int hf_e1ap_DRB_Confirm_Modified_List_NG_RAN_item;  /* DRB_Confirm_Modified_Item_NG_RAN */
static int hf_e1ap_DRB_Failed_List_EUTRAN_item;   /* DRB_Failed_Item_EUTRAN */
static int hf_e1ap_DRB_Failed_Mod_List_EUTRAN_item;  /* DRB_Failed_Mod_Item_EUTRAN */
static int hf_e1ap_DRB_Failed_List_NG_RAN_item;   /* DRB_Failed_Item_NG_RAN */
static int hf_e1ap_DRB_Failed_Mod_List_NG_RAN_item;  /* DRB_Failed_Mod_Item_NG_RAN */
static int hf_e1ap_DRB_Failed_To_Modify_List_EUTRAN_item;  /* DRB_Failed_To_Modify_Item_EUTRAN */
static int hf_e1ap_DRB_Failed_To_Modify_List_NG_RAN_item;  /* DRB_Failed_To_Modify_Item_NG_RAN */
static int hf_e1ap_DRB_Measurement_Results_Information_List_item;  /* DRB_Measurement_Results_Information_Item */
static int hf_e1ap_uL_D1_Result;                  /* INTEGER_0_10000_ */
static int hf_e1ap_DRB_Modified_List_EUTRAN_item;  /* DRB_Modified_Item_EUTRAN */
static int hf_e1ap_s1_DL_UP_TNL_Information;      /* UP_TNL_Information */
static int hf_e1ap_pDCP_SN_Status_Information;    /* PDCP_SN_Status_Information */
static int hf_e1ap_uL_UP_Transport_Parameters;    /* UP_Parameters */
static int hf_e1ap_DRB_Modified_List_NG_RAN_item;  /* DRB_Modified_Item_NG_RAN */
static int hf_e1ap_flow_Setup_List;               /* QoS_Flow_List */
static int hf_e1ap_flow_Failed_List;              /* QoS_Flow_Failed_List */
static int hf_e1ap_dRB_Released_In_Session;       /* T_dRB_Released_In_Session */
static int hf_e1ap_dRB_Accumulated_Session_Time;  /* OCTET_STRING_SIZE_5 */
static int hf_e1ap_qoS_Flow_Removed_List;         /* SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_QoS_Flow_Removed_Item */
static int hf_e1ap_qoS_Flow_Removed_List_item;    /* QoS_Flow_Removed_Item */
static int hf_e1ap_DRB_Required_To_Modify_List_EUTRAN_item;  /* DRB_Required_To_Modify_Item_EUTRAN */
static int hf_e1ap_gNB_CU_UP_CellGroupRelatedConfiguration;  /* GNB_CU_UP_CellGroupRelatedConfiguration */
static int hf_e1ap_DRB_Required_To_Modify_List_NG_RAN_item;  /* DRB_Required_To_Modify_Item_NG_RAN */
static int hf_e1ap_flow_To_Remove;                /* QoS_Flow_List */
static int hf_e1ap_DRB_Setup_List_EUTRAN_item;    /* DRB_Setup_Item_EUTRAN */
static int hf_e1ap_data_Forwarding_Information_Response;  /* Data_Forwarding_Information */
static int hf_e1ap_s1_DL_UP_Unchanged;            /* T_s1_DL_UP_Unchanged */
static int hf_e1ap_DRB_Setup_Mod_List_EUTRAN_item;  /* DRB_Setup_Mod_Item_EUTRAN */
static int hf_e1ap_DRB_Setup_List_NG_RAN_item;    /* DRB_Setup_Item_NG_RAN */
static int hf_e1ap_dRB_data_Forwarding_Information_Response;  /* Data_Forwarding_Information */
static int hf_e1ap_DRB_Setup_Mod_List_NG_RAN_item;  /* DRB_Setup_Mod_Item_NG_RAN */
static int hf_e1ap_pDCP_DL_Count;                 /* PDCP_Count */
static int hf_e1ap_pDCP_UL_Count;                 /* PDCP_Count */
static int hf_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN_item;  /* DRBs_Subject_To_Counter_Check_Item_EUTRAN */
static int hf_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN_item;  /* DRBs_Subject_To_Counter_Check_Item_NG_RAN */
static int hf_e1ap_pDU_Session_ID;                /* PDU_Session_ID */
static int hf_e1ap_DRBs_Subject_To_Early_Forwarding_List_item;  /* DRBs_Subject_To_Early_Forwarding_Item */
static int hf_e1ap_dLCountValue;                  /* PDCP_Count */
static int hf_e1ap_DRB_To_Modify_List_EUTRAN_item;  /* DRB_To_Modify_Item_EUTRAN */
static int hf_e1ap_pDCP_Configuration;            /* PDCP_Configuration */
static int hf_e1ap_eUTRAN_QoS;                    /* EUTRAN_QoS */
static int hf_e1ap_s1_UL_UP_TNL_Information;      /* UP_TNL_Information */
static int hf_e1ap_data_Forwarding_Information;   /* Data_Forwarding_Information */
static int hf_e1ap_pDCP_SN_Status_Request;        /* PDCP_SN_Status_Request */
static int hf_e1ap_dL_UP_Parameters;              /* UP_Parameters */
static int hf_e1ap_cell_Group_To_Add;             /* Cell_Group_Information */
static int hf_e1ap_cell_Group_To_Modify;          /* Cell_Group_Information */
static int hf_e1ap_cell_Group_To_Remove;          /* Cell_Group_Information */
static int hf_e1ap_dRB_Inactivity_Timer;          /* Inactivity_Timer */
static int hf_e1ap_DRB_To_Modify_List_NG_RAN_item;  /* DRB_To_Modify_Item_NG_RAN */
static int hf_e1ap_sDAP_Configuration;            /* SDAP_Configuration */
static int hf_e1ap_dRB_Data_Forwarding_Information;  /* Data_Forwarding_Information */
static int hf_e1ap_pdcp_SN_Status_Information;    /* PDCP_SN_Status_Information */
static int hf_e1ap_flow_Mapping_Information;      /* QoS_Flow_QoS_Parameter_List */
static int hf_e1ap_DRB_To_Remove_List_EUTRAN_item;  /* DRB_To_Remove_Item_EUTRAN */
static int hf_e1ap_DRB_Required_To_Remove_List_EUTRAN_item;  /* DRB_Required_To_Remove_Item_EUTRAN */
static int hf_e1ap_DRB_To_Remove_List_NG_RAN_item;  /* DRB_To_Remove_Item_NG_RAN */
static int hf_e1ap_DRB_Required_To_Remove_List_NG_RAN_item;  /* DRB_Required_To_Remove_Item_NG_RAN */
static int hf_e1ap_DRB_To_Setup_List_EUTRAN_item;  /* DRB_To_Setup_Item_EUTRAN */
static int hf_e1ap_data_Forwarding_Information_Request;  /* Data_Forwarding_Information_Request */
static int hf_e1ap_existing_Allocated_S1_DL_UP_TNL_Info;  /* UP_TNL_Information */
static int hf_e1ap_DRB_To_Setup_Mod_List_EUTRAN_item;  /* DRB_To_Setup_Mod_Item_EUTRAN */
static int hf_e1ap_DRB_To_Setup_List_NG_RAN_item;  /* DRB_To_Setup_Item_NG_RAN */
static int hf_e1ap_qos_flow_Information_To_Be_Setup;  /* QoS_Flow_QoS_Parameter_List */
static int hf_e1ap_dRB_Data_Forwarding_Information_Request;  /* Data_Forwarding_Information_Request */
static int hf_e1ap_DRB_To_Setup_Mod_List_NG_RAN_item;  /* DRB_To_Setup_Mod_Item_NG_RAN */
static int hf_e1ap_DRB_Usage_Report_List_item;    /* DRB_Usage_Report_Item */
static int hf_e1ap_startTimeStamp;                /* T_startTimeStamp */
static int hf_e1ap_endTimeStamp;                  /* T_endTimeStamp */
static int hf_e1ap_usageCountUL;                  /* INTEGER_0_18446744073709551615 */
static int hf_e1ap_usageCountDL;                  /* INTEGER_0_18446744073709551615 */
static int hf_e1ap_qoSPriorityLevel;              /* QoSPriorityLevel */
static int hf_e1ap_fiveQI;                        /* INTEGER_0_255_ */
static int hf_e1ap_delayCritical;                 /* T_delayCritical */
static int hf_e1ap_averagingWindow;               /* AveragingWindow */
static int hf_e1ap_maxDataBurstVolume;            /* MaxDataBurstVolume */
static int hf_e1ap_firstDLCount;                  /* FirstDLCount */
static int hf_e1ap_dLDiscardingCount;             /* DLDiscarding */
static int hf_e1ap_choice_Extension;              /* ProtocolIE_SingleContainer */
static int hf_e1ap_eCNMarkingatNGRAN;             /* T_eCNMarkingatNGRAN */
static int hf_e1ap_eCNMarkingatUPF;               /* T_eCNMarkingatUPF */
static int hf_e1ap_congestionInformation;         /* T_congestionInformation */
static int hf_e1ap_ehc_CID_Length;                /* T_ehc_CID_Length */
static int hf_e1ap_drb_ContinueEHC_DL;            /* T_drb_ContinueEHC_DL */
static int hf_e1ap_drb_ContinueEHC_UL;            /* T_drb_ContinueEHC_UL */
static int hf_e1ap_ehc_Common;                    /* EHC_Common_Parameters */
static int hf_e1ap_ehc_Downlink;                  /* EHC_Downlink_Parameters */
static int hf_e1ap_ehc_Uplink;                    /* EHC_Uplink_Parameters */
static int hf_e1ap_portNumber;                    /* PortNumber */
static int hf_e1ap_priorityLevel;                 /* PriorityLevel */
static int hf_e1ap_pre_emptionCapability;         /* Pre_emptionCapability */
static int hf_e1ap_pre_emptionVulnerability;      /* Pre_emptionVulnerability */
static int hf_e1ap_pLMN_Identity;                 /* PLMN_Identity */
static int hf_e1ap_eUTRAN_Cell_Identity;          /* E_UTRAN_Cell_Identity */
static int hf_e1ap_ECGI_Support_List_item;        /* ECGI_Support_Item */
static int hf_e1ap_eCGI;                          /* ECGI */
static int hf_e1ap_EUTRAN_QoS_Support_List_item;  /* EUTRAN_QoS_Support_Item */
static int hf_e1ap_qCI;                           /* QCI */
static int hf_e1ap_eUTRANallocationAndRetentionPriority;  /* EUTRANAllocationAndRetentionPriority */
static int hf_e1ap_gbrQosInformation;             /* GBR_QosInformation */
static int hf_e1ap_ExtendedSliceSupportList_item;  /* Slice_Support_Item */
static int hf_e1ap_firstDLCountVal;               /* PDCP_Count */
static int hf_e1ap_F1U_TNL_InfoAdded_List_item;   /* F1U_TNL_InfoAdded_Item */
static int hf_e1ap_broadcastF1U_ContextReferenceE1;  /* BroadcastF1U_ContextReferenceE1 */
static int hf_e1ap_F1U_TNL_InfoToAdd_List_item;   /* F1U_TNL_InfoToAdd_Item */
static int hf_e1ap_F1U_TNL_InfoAddedOrModified_List_item;  /* F1U_TNL_InfoAddedOrModified_Item */
static int hf_e1ap_F1U_TNL_InfoToAddOrModify_List_item;  /* F1U_TNL_InfoToAddOrModify_Item */
static int hf_e1ap_F1U_TNL_InfoToRelease_List_item;  /* F1U_TNL_InfoToRelease_Item */
static int hf_e1ap_tmgi;                          /* OCTET_STRING_SIZE_6 */
static int hf_e1ap_nid;                           /* NID */
static int hf_e1ap_gNB_CU_CP_NameVisibleString;   /* GNB_CU_CP_NameVisibleString */
static int hf_e1ap_gNB_CU_CP_NameUTF8String;      /* GNB_CU_CP_NameUTF8String */
static int hf_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration_item;  /* GNB_CU_UP_CellGroupRelatedConfiguration_Item */
static int hf_e1ap_uP_TNL_Information;            /* UP_TNL_Information */
static int hf_e1ap_mbs_Support_Info_ToAdd_List;   /* MBS_Support_Info_ToAdd_List */
static int hf_e1ap_mbs_Support_Info_ToRemove_List;  /* MBS_Support_Info_ToRemove_List */
static int hf_e1ap_gNB_CU_UP_NameVisibleString;   /* GNB_CU_UP_NameVisibleString */
static int hf_e1ap_gNB_CU_UP_NameUTF8String;      /* GNB_CU_UP_NameUTF8String */
static int hf_e1ap_tNLAssociationTransportLayerAddress;  /* CP_TNL_Information */
static int hf_e1ap_tNLAssociationUsage;           /* TNLAssociationUsage */
static int hf_e1ap_tNLAssociationTransportLayerAddressgNBCUCP;  /* CP_TNL_Information */
static int hf_e1ap_e_RAB_MaximumBitrateDL;        /* BitRate */
static int hf_e1ap_e_RAB_MaximumBitrateUL;        /* BitRate */
static int hf_e1ap_e_RAB_GuaranteedBitrateDL;     /* BitRate */
static int hf_e1ap_e_RAB_GuaranteedBitrateUL;     /* BitRate */
static int hf_e1ap_maxFlowBitRateDownlink;        /* BitRate */
static int hf_e1ap_maxFlowBitRateUplink;          /* BitRate */
static int hf_e1ap_guaranteedFlowBitRateDownlink;  /* BitRate */
static int hf_e1ap_guaranteedFlowBitRateUplink;   /* BitRate */
static int hf_e1ap_maxPacketLossRateDownlink;     /* MaxPacketLossRate */
static int hf_e1ap_maxPacketLossRateUplink;       /* MaxPacketLossRate */
static int hf_e1ap_GTPTLAs_item;                  /* GTPTLA_Item */
static int hf_e1ap_gTPTransportLayerAddresses;    /* TransportLayerAddress */
static int hf_e1ap_transportLayerAddress;         /* TransportLayerAddress */
static int hf_e1ap_gTP_TEID;                      /* GTP_TEID */
static int hf_e1ap_offeredThroughput;             /* INTEGER_1_16777216_ */
static int hf_e1ap_availableThroughput;           /* INTEGER_0_100_ */
static int hf_e1ap_measurementsToActivate;        /* MeasurementsToActivate */
static int hf_e1ap_measurementFour;               /* M4Configuration */
static int hf_e1ap_measurementSix;                /* M6Configuration */
static int hf_e1ap_measurementSeven;              /* M7Configuration */
static int hf_e1ap_iAB_donor_CU_UPPSK;            /* IAB_donor_CU_UPPSK */
static int hf_e1ap_iAB_donor_CU_UPIPAddress;      /* TransportLayerAddress */
static int hf_e1ap_iAB_DUIPAddress;               /* TransportLayerAddress */
static int hf_e1ap_LocationDependentMBSNGUInformationAt5GC_item;  /* LocationDependentMBSNGUInformationAt5GC_Item */
static int hf_e1ap_mbsAreaSession_ID;             /* MBSAreaSessionID */
static int hf_e1ap_mbsNGUInformationAt5GC;        /* MBSNGUInformationAt5GC */
static int hf_e1ap_LocationDependentMBSF1UInformationAtCU_item;  /* LocationDependentMBSF1UInformationAtCU_Item */
static int hf_e1ap_mbs_f1u_info_at_CU;            /* UP_TNL_Information */
static int hf_e1ap_LocationDependentMBSF1UInformationAtDU_item;  /* LocationDependentMBSF1UInformationAtDU_Item */
static int hf_e1ap_mbs_f1u_info_at_DU;            /* UP_TNL_Information */
static int hf_e1ap_LocationDependentMBSNGUInformationAtNGRAN_item;  /* LocationDependentMBSNGUInformationAtNGRAN_Item */
static int hf_e1ap_mbsNGUInformationAtNGRAN;      /* MBSNGUInformationAtNGRAN */
static int hf_e1ap_maxIPrate;                     /* MaxIPrate */
static int hf_e1ap_multicast;                     /* MBSNGUInformationAt5GC_Multicast */
static int hf_e1ap_ipmcAddress;                   /* TransportLayerAddress */
static int hf_e1ap_ipsourceAddress;               /* TransportLayerAddress */
static int hf_e1ap_gtpDLTEID;                     /* GTP_TEID */
static int hf_e1ap_unicast;                       /* UP_TNL_Information */
static int hf_e1ap_MBSNGUInformationAtNGRAN_Request_List_item;  /* MBSNGUInformationAtNGRAN_Request_Item */
static int hf_e1ap_mbsNGUInformationAtNGRAN_Request;  /* MBSNGUInformationAtNGRAN_Request */
static int hf_e1ap_ue_Reference_ID;               /* GNB_CU_CP_UE_E1AP_ID */
static int hf_e1ap_associatedQoSFlowInformationList;  /* MBSSessionAssociatedInformationList */
static int hf_e1ap_mbsSessionAssociatedInformationList;  /* MBSSessionAssociatedInformationList */
static int hf_e1ap_mbsSessionForwardingAddress;   /* UP_TNL_Information */
static int hf_e1ap_MBSSessionAssociatedInformationList_item;  /* MBSSessionAssociatedInformation_Item */
static int hf_e1ap_mbs_QoS_Flow_Identifier;       /* QoS_Flow_Identifier */
static int hf_e1ap_associated_unicast_QoS_Flow_Identifier;  /* QoS_Flow_Identifier */
static int hf_e1ap_MBS_Support_Info_ToAdd_List_item;  /* MBS_Support_Info_ToAdd_Item */
static int hf_e1ap_globalMBSSessionID;            /* GlobalMBSSessionID */
static int hf_e1ap_MBS_Support_Info_ToRemove_List_item;  /* MBS_Support_Info_ToRemove_Item */
static int hf_e1ap_mbs_DL_Data_Arrival;           /* MBS_DL_Data_Arrival */
static int hf_e1ap_inactivity;                    /* MCBearerContext_Inactivity */
static int hf_e1ap_dlDataArrival;                 /* T_dlDataArrival */
static int hf_e1ap_ppi;                           /* PPI */
static int hf_e1ap_mcBearerContext_Inactivity_Indication;  /* T_mcBearerContext_Inactivity_Indication */
static int hf_e1ap_mcMRBToSetupList;              /* MCMRBSetupConfiguration */
static int hf_e1ap_MCMRBSetupConfiguration_item;  /* MCMRBSetupConfiguration_Item */
static int hf_e1ap_mcBearerContextNGU_TNLInfoatNGRAN;  /* MCBearerContextNGU_TNLInfoatNGRAN */
static int hf_e1ap_mcMRBSetupResponseList;        /* MCMRBSetupResponseList */
static int hf_e1ap_mcMRBFailedList;               /* MCMRBFailedList */
static int hf_e1ap_availableMCMRBConfig;          /* MCMRBSetupConfiguration */
static int hf_e1ap_MCMRBSetupResponseList_item;   /* MCMRBSetupResponseList_Item */
static int hf_e1ap_mBS_PDCP_COUNT;                /* MBS_PDCP_COUNT */
static int hf_e1ap_MCMRBFailedList_item;          /* MCMRBFailedList_Item */
static int hf_e1ap_mcBearerContextNGUTNLInfoat5GC;  /* MCBearerContextNGUTNLInfoat5GC */
static int hf_e1ap_mcBearerContextNGUTnlInfoatNGRANRequest;  /* MCBearerContextNGUTnlInfoatNGRANRequest */
static int hf_e1ap_mbsMulticastF1UContextDescriptor;  /* MBSMulticastF1UContextDescriptor */
static int hf_e1ap_mcMRBToSetupModifyList;        /* MCMRBSetupModifyConfiguration */
static int hf_e1ap_mcMRBToRemoveList;             /* MCMRBRemoveConfiguration */
static int hf_e1ap_ngRANNGUTNLRequested;          /* T_ngRANNGUTNLRequested */
static int hf_e1ap_MCMRBSetupModifyConfiguration_item;  /* MCMRBSetupModifyConfiguration_Item */
static int hf_e1ap_f1uTNLatDU;                    /* MCBearerContextF1UTNLInfoatDU */
static int hf_e1ap_mrbQoS;                        /* QoSFlowLevelQoSParameters */
static int hf_e1ap_mbs_PDCP_COUNT_Req;            /* MBS_PDCP_COUNT_Req */
static int hf_e1ap_mbsF1UInfoatDU;                /* UP_TNL_Information */
static int hf_e1ap_multicastF1UContextReferenceE1;  /* MulticastF1UContextReferenceE1 */
static int hf_e1ap_mc_F1UCtxtusage;               /* T_mc_F1UCtxtusage */
static int hf_e1ap_mbsAreaSession;                /* MBSAreaSessionID */
static int hf_e1ap_MCMRBRemoveConfiguration_item;  /* MRB_ID */
static int hf_e1ap_mcBearerContextNGU_TNLInfoatNGRANModifyResponse;  /* MCBearerContextNGU_TNLInfoatNGRANModifyResponse */
static int hf_e1ap_mcMRBModifySetupResponseList;  /* MCMRBSetupModifyResponseList */
static int hf_e1ap_mbs_NGU_InfoatNGRAN;           /* MBSNGUInformationAtNGRAN */
static int hf_e1ap_MCMRBSetupModifyResponseList_item;  /* MCMRBSetupModifyResponseList_Item */
static int hf_e1ap_mcBearerContextF1UTNLInfoatCU;  /* UP_TNL_Information */
static int hf_e1ap_mcMRBToRemoveRequiredList;     /* MCMRBRemoveConfiguration */
static int hf_e1ap_mcMRBToModifyRequiredList;     /* MCMRBModifyRequiredConfiguration */
static int hf_e1ap_MCMRBModifyRequiredConfiguration_item;  /* MCMRBModifyRequiredConfiguration_Item */
static int hf_e1ap_mcMRBModifyConfirmList;        /* MCMRBModifyConfirmList */
static int hf_e1ap_MCMRBModifyConfirmList_item;   /* MCMRBModifyConfirmList_Item */
static int hf_e1ap_mcForwardingResourceID;        /* MCForwardingResourceID */
static int hf_e1ap_mrbForwardingResourceRequestList;  /* MRBForwardingResourceRequestList */
static int hf_e1ap_MRBForwardingResourceRequestList_item;  /* MRBForwardingResourceRequest_Item */
static int hf_e1ap_mrbProgressRequestType;        /* MRB_ProgressInformationType */
static int hf_e1ap_mrbForwardingAddressRequest;   /* T_mrbForwardingAddressRequest */
static int hf_e1ap_mrbForwardingResourceIndicationList;  /* MRBForwardingResourceIndicationList */
static int hf_e1ap_mbsSessionAssociatedInformation;  /* MBSSessionAssociatedInformation */
static int hf_e1ap_MRBForwardingResourceIndicationList_item;  /* MRBForwardingResourceIndication_Item */
static int hf_e1ap_mrb_ProgressInformation;       /* MRB_ProgressInformation */
static int hf_e1ap_mrbForwardingAddress;          /* UP_TNL_Information */
static int hf_e1ap_mrbForwardingResourceResponseList;  /* MRBForwardingResourceResponseList */
static int hf_e1ap_MRBForwardingResourceResponseList_item;  /* MRBForwardingResourceResponse_Item */
static int hf_e1ap_mrb_ProgressInformationSNs;    /* MRB_ProgressInformationSNs */
static int hf_e1ap_mrb_ProgressInformationType;   /* MRB_ProgressInformationType */
static int hf_e1ap_pdcp_SN12;                     /* INTEGER_0_4095 */
static int hf_e1ap_pdcp_SN18;                     /* INTEGER_0_262143 */
static int hf_e1ap_startTimeStamp_01;             /* T_startTimeStamp_01 */
static int hf_e1ap_endTimeStamp_01;               /* T_endTimeStamp_01 */
static int hf_e1ap_data_Usage_per_PDU_Session_Report;  /* Data_Usage_per_PDU_Session_Report */
static int hf_e1ap_data_Usage_per_QoS_Flow_List;  /* Data_Usage_per_QoS_Flow_List */
static int hf_e1ap_m4period;                      /* M4period */
static int hf_e1ap_m4_links_to_log;               /* Links_to_log */
static int hf_e1ap_m6report_Interval;             /* M6report_Interval */
static int hf_e1ap_m6_links_to_log;               /* Links_to_log */
static int hf_e1ap_m7period;                      /* M7period */
static int hf_e1ap_m7_links_to_log;               /* Links_to_log */
static int hf_e1ap_mdt_Activation;                /* MDT_Activation */
static int hf_e1ap_mDTMode;                       /* MDTMode */
static int hf_e1ap_immediateMDT;                  /* ImmediateMDT */
static int hf_e1ap_MDTPLMNList_item;              /* PLMN_Identity */
static int hf_e1ap_MDTPLMNModificationList_item;  /* PLMN_Identity */
static int hf_e1ap_mT_SDT_Data_Size;              /* MT_SDT_Data_Size */
static int hf_e1ap_mBS_ServiceAreaInformationList;  /* MBS_ServiceAreaInformationList */
static int hf_e1ap_mBS_ServiceAreaCellList;       /* MBS_ServiceAreaCellList */
static int hf_e1ap_mBS_ServiceAreaTAIList;        /* MBS_ServiceAreaTAIList */
static int hf_e1ap_MBS_ServiceAreaCellList_item;  /* NR_CGI */
static int hf_e1ap_MBS_ServiceAreaTAIList_item;   /* MBS_ServiceAreaTAIList_Item */
static int hf_e1ap_plmn_ID;                       /* PLMN_Identity */
static int hf_e1ap_fiveGS_TAC;                    /* FiveGS_TAC */
static int hf_e1ap_MBS_ServiceAreaInformationList_item;  /* MBS_ServiceAreaInformationItem */
static int hf_e1ap_mBS_AreaSessionID;             /* MBSAreaSessionID */
static int hf_e1ap_mBS_ServiceAreaInformation;    /* MBS_ServiceAreaInformation */
static int hf_e1ap_NG_RAN_QoS_Support_List_item;  /* NG_RAN_QoS_Support_Item */
static int hf_e1ap_non_Dynamic5QIDescriptor;      /* Non_Dynamic5QIDescriptor */
static int hf_e1ap_sNPN;                          /* NPNSupportInfo_SNPN */
static int hf_e1ap_nID;                           /* NID */
static int hf_e1ap_sNPN_01;                       /* NPNContextInfo_SNPN */
static int hf_e1ap_nR_Cell_Identity;              /* NR_Cell_Identity */
static int hf_e1ap_NR_CGI_Support_List_item;      /* NR_CGI_Support_Item */
static int hf_e1ap_nR_CGI;                        /* NR_CGI */
static int hf_e1ap_Extended_NR_CGI_Support_List_item;  /* Extended_NR_CGI_Support_Item */
static int hf_e1ap_n6JitterLowerBound;            /* INTEGER_M127_127 */
static int hf_e1ap_n6JitterUpperBound;            /* INTEGER_M127_127 */
static int hf_e1ap_pER_Scalar;                    /* PER_Scalar */
static int hf_e1ap_pER_Exponent;                  /* PER_Exponent */
static int hf_e1ap_pDCP_SN_Size_UL;               /* PDCP_SN_Size */
static int hf_e1ap_pDCP_SN_Size_DL;               /* PDCP_SN_Size */
static int hf_e1ap_rLC_Mode;                      /* RLC_Mode */
static int hf_e1ap_rOHC_Parameters;               /* ROHC_Parameters */
static int hf_e1ap_t_ReorderingTimer;             /* T_ReorderingTimer */
static int hf_e1ap_discardTimer;                  /* DiscardTimer */
static int hf_e1ap_uLDataSplitThreshold;          /* ULDataSplitThreshold */
static int hf_e1ap_pDCP_Duplication;              /* PDCP_Duplication */
static int hf_e1ap_pDCP_Reestablishment;          /* PDCP_Reestablishment */
static int hf_e1ap_pDCP_DataRecovery;             /* PDCP_DataRecovery */
static int hf_e1ap_duplication_Activation;        /* Duplication_Activation */
static int hf_e1ap_outOfOrderDelivery;            /* OutOfOrderDelivery */
static int hf_e1ap_pDCP_SN;                       /* PDCP_SN */
static int hf_e1ap_hFN;                           /* HFN */
static int hf_e1ap_PDU_Session_Resource_Data_Usage_List_item;  /* PDU_Session_Resource_Data_Usage_Item */
static int hf_e1ap_mRDC_Usage_Information;        /* MRDC_Usage_Information */
static int hf_e1ap_pdcpStatusTransfer_UL;         /* DRBBStatusTransfer */
static int hf_e1ap_pdcpStatusTransfer_DL;         /* PDCP_Count */
static int hf_e1ap_iE_Extension;                  /* ProtocolExtensionContainer */
static int hf_e1ap_receiveStatusofPDCPSDU;        /* BIT_STRING_SIZE_1_131072 */
static int hf_e1ap_countValue;                    /* PDCP_Count */
static int hf_e1ap_PDU_Session_Resource_Activity_List_item;  /* PDU_Session_Resource_Activity_Item */
static int hf_e1ap_pDU_Session_Resource_Activity;  /* PDU_Session_Resource_Activity */
static int hf_e1ap_PDU_Session_Resource_Confirm_Modified_List_item;  /* PDU_Session_Resource_Confirm_Modified_Item */
static int hf_e1ap_dRB_Confirm_Modified_List_NG_RAN;  /* DRB_Confirm_Modified_List_NG_RAN */
static int hf_e1ap_PDU_Session_Resource_Failed_List_item;  /* PDU_Session_Resource_Failed_Item */
static int hf_e1ap_PDU_Session_Resource_Failed_Mod_List_item;  /* PDU_Session_Resource_Failed_Mod_Item */
static int hf_e1ap_PDU_Session_Resource_Failed_To_Modify_List_item;  /* PDU_Session_Resource_Failed_To_Modify_Item */
static int hf_e1ap_PDU_Session_Resource_Modified_List_item;  /* PDU_Session_Resource_Modified_Item */
static int hf_e1ap_nG_DL_UP_TNL_Information;      /* UP_TNL_Information */
static int hf_e1ap_securityResult;                /* SecurityResult */
static int hf_e1ap_pDU_Session_Data_Forwarding_Information_Response;  /* Data_Forwarding_Information */
static int hf_e1ap_dRB_Setup_List_NG_RAN;         /* DRB_Setup_List_NG_RAN */
static int hf_e1ap_dRB_Failed_List_NG_RAN;        /* DRB_Failed_List_NG_RAN */
static int hf_e1ap_dRB_Modified_List_NG_RAN;      /* DRB_Modified_List_NG_RAN */
static int hf_e1ap_dRB_Failed_To_Modify_List_NG_RAN;  /* DRB_Failed_To_Modify_List_NG_RAN */
static int hf_e1ap_PDU_Session_Resource_Required_To_Modify_List_item;  /* PDU_Session_Resource_Required_To_Modify_Item */
static int hf_e1ap_dRB_Required_To_Modify_List_NG_RAN;  /* DRB_Required_To_Modify_List_NG_RAN */
static int hf_e1ap_dRB_Required_To_Remove_List_NG_RAN;  /* DRB_Required_To_Remove_List_NG_RAN */
static int hf_e1ap_PDU_Session_Resource_Setup_List_item;  /* PDU_Session_Resource_Setup_Item */
static int hf_e1ap_nG_DL_UP_Unchanged;            /* T_nG_DL_UP_Unchanged */
static int hf_e1ap_PDU_Session_Resource_Setup_Mod_List_item;  /* PDU_Session_Resource_Setup_Mod_Item */
static int hf_e1ap_dRB_Setup_Mod_List_NG_RAN;     /* DRB_Setup_Mod_List_NG_RAN */
static int hf_e1ap_dRB_Failed_Mod_List_NG_RAN;    /* DRB_Failed_Mod_List_NG_RAN */
static int hf_e1ap_PDU_Session_Resource_To_Modify_List_item;  /* PDU_Session_Resource_To_Modify_Item */
static int hf_e1ap_securityIndication;            /* SecurityIndication */
static int hf_e1ap_pDU_Session_Resource_DL_AMBR;  /* BitRate */
static int hf_e1ap_nG_UL_UP_TNL_Information;      /* UP_TNL_Information */
static int hf_e1ap_pDU_Session_Data_Forwarding_Information_Request;  /* Data_Forwarding_Information_Request */
static int hf_e1ap_pDU_Session_Data_Forwarding_Information;  /* Data_Forwarding_Information */
static int hf_e1ap_pDU_Session_Inactivity_Timer;  /* Inactivity_Timer */
static int hf_e1ap_networkInstance;               /* NetworkInstance */
static int hf_e1ap_dRB_To_Setup_List_NG_RAN;      /* DRB_To_Setup_List_NG_RAN */
static int hf_e1ap_dRB_To_Modify_List_NG_RAN;     /* DRB_To_Modify_List_NG_RAN */
static int hf_e1ap_dRB_To_Remove_List_NG_RAN;     /* DRB_To_Remove_List_NG_RAN */
static int hf_e1ap_PDU_Session_Resource_To_Remove_List_item;  /* PDU_Session_Resource_To_Remove_Item */
static int hf_e1ap_PDU_Session_Resource_To_Setup_List_item;  /* PDU_Session_Resource_To_Setup_Item */
static int hf_e1ap_pDU_Session_Type;              /* PDU_Session_Type */
static int hf_e1ap_sNSSAI;                        /* SNSSAI */
static int hf_e1ap_existing_Allocated_NG_DL_UP_TNL_Info;  /* UP_TNL_Information */
static int hf_e1ap_PDU_Session_Resource_To_Setup_Mod_List_item;  /* PDU_Session_Resource_To_Setup_Mod_Item */
static int hf_e1ap_pDU_Session_Resource_AMBR;     /* BitRate */
static int hf_e1ap_dRB_To_Setup_Mod_List_NG_RAN;  /* DRB_To_Setup_Mod_List_NG_RAN */
static int hf_e1ap_PDU_Session_To_Notify_List_item;  /* PDU_Session_To_Notify_Item */
static int hf_e1ap_qoS_Flow_List;                 /* QoS_Flow_List */
static int hf_e1ap_ulPDUSetQoSInformation;        /* PDUSetQoSInformation */
static int hf_e1ap_dlPDUSetQoSInformation;        /* PDUSetQoSInformation */
static int hf_e1ap_pduSetDelayBudget;             /* ExtendedPacketDelayBudget */
static int hf_e1ap_pduSetErrorRate;               /* PacketErrorRate */
static int hf_e1ap_pduSetIntegratedHandlingInformation;  /* T_pduSetIntegratedHandlingInformation */
static int hf_e1ap_non_Dynamic_5QI;               /* Non_Dynamic5QIDescriptor */
static int hf_e1ap_dynamic_5QI;                   /* Dynamic5QIDescriptor */
static int hf_e1ap_QoS_Flow_List_item;            /* QoS_Flow_Item */
static int hf_e1ap_QoS_Flow_Failed_List_item;     /* QoS_Flow_Failed_Item */
static int hf_e1ap_QoS_Flow_Mapping_List_item;    /* QoS_Flow_Mapping_Item */
static int hf_e1ap_qoSFlowMappingIndication;      /* QoS_Flow_Mapping_Indication */
static int hf_e1ap_eUTRAN_QoS_Support_List;       /* EUTRAN_QoS_Support_List */
static int hf_e1ap_nG_RAN_QoS_Support_List;       /* NG_RAN_QoS_Support_List */
static int hf_e1ap_QoS_Flow_QoS_Parameter_List_item;  /* QoS_Flow_QoS_Parameter_Item */
static int hf_e1ap_qoS_Characteristics;           /* QoS_Characteristics */
static int hf_e1ap_nGRANallocationRetentionPriority;  /* NGRANAllocationAndRetentionPriority */
static int hf_e1ap_gBR_QoS_Flow_Information;      /* GBR_QoSFlowInformation */
static int hf_e1ap_reflective_QoS_Attribute;      /* T_reflective_QoS_Attribute */
static int hf_e1ap_additional_QoS_Information;    /* T_additional_QoS_Information */
static int hf_e1ap_paging_Policy_Index;           /* INTEGER_1_8_ */
static int hf_e1ap_reflective_QoS_Indicator;      /* T_reflective_QoS_Indicator */
static int hf_e1ap_qoS_Flow_Released_In_Session;  /* T_qoS_Flow_Released_In_Session */
static int hf_e1ap_qoS_Flow_Accumulated_Session_Time;  /* OCTET_STRING_SIZE_5 */
static int hf_e1ap_QoS_Flows_to_be_forwarded_List_item;  /* QoS_Flows_to_be_forwarded_Item */
static int hf_e1ap_dscp;                          /* BIT_STRING_SIZE_6 */
static int hf_e1ap_flow_label;                    /* BIT_STRING_SIZE_20 */
static int hf_e1ap_DataForwardingtoNG_RANQoSFlowInformationList_item;  /* DataForwardingtoNG_RANQoSFlowInformationList_Item */
static int hf_e1ap_rSN;                           /* RSN */
static int hf_e1ap_RetainabilityMeasurementsInfo_item;  /* DRB_Removed_Item */
static int hf_e1ap_rOHC;                          /* ROHC */
static int hf_e1ap_uPlinkOnlyROHC;                /* UplinkOnlyROHC */
static int hf_e1ap_maxCID;                        /* INTEGER_0_16383_ */
static int hf_e1ap_rOHC_Profiles;                 /* INTEGER_0_511_ */
static int hf_e1ap_continueROHC;                  /* T_continueROHC */
static int hf_e1ap_cipheringAlgorithm;            /* CipheringAlgorithm */
static int hf_e1ap_integrityProtectionAlgorithm;  /* IntegrityProtectionAlgorithm */
static int hf_e1ap_integrityProtectionIndication;  /* IntegrityProtectionIndication */
static int hf_e1ap_confidentialityProtectionIndication;  /* ConfidentialityProtectionIndication */
static int hf_e1ap_maximumIPdatarate;             /* MaximumIPdatarate */
static int hf_e1ap_securityAlgorithm;             /* SecurityAlgorithm */
static int hf_e1ap_uPSecuritykey;                 /* UPSecuritykey */
static int hf_e1ap_integrityProtectionResult;     /* IntegrityProtectionResult */
static int hf_e1ap_confidentialityProtectionResult;  /* ConfidentialityProtectionResult */
static int hf_e1ap_Slice_Support_List_item;       /* Slice_Support_Item */
static int hf_e1ap_sST;                           /* OCTET_STRING_SIZE_1 */
static int hf_e1ap_sD;                            /* OCTET_STRING_SIZE_3 */
static int hf_e1ap_defaultDRB;                    /* DefaultDRB */
static int hf_e1ap_sDAP_Header_UL;                /* SDAP_Header_UL */
static int hf_e1ap_sDAP_Header_DL;                /* SDAP_Header_DL */
static int hf_e1ap_dL_TNL_OfferedCapacity;        /* INTEGER_0_16777216_ */
static int hf_e1ap_dL_TNL_AvailableCapacity;      /* INTEGER_0_100_ */
static int hf_e1ap_uL_TNL_OfferedCapacity;        /* INTEGER_0_16777216_ */
static int hf_e1ap_uL_TNL_AvailableCapacity;      /* INTEGER_0_100_ */
static int hf_e1ap_tSCTrafficCharacteristicsUL;   /* TSCAssistanceInformation */
static int hf_e1ap_tSCTrafficCharacteristicsDL;   /* TSCAssistanceInformation */
static int hf_e1ap_periodicity;                   /* Periodicity */
static int hf_e1ap_burstArrivalTime;              /* BurstArrivalTime */
static int hf_e1ap_traceID;                       /* TraceID */
static int hf_e1ap_interfacesToTrace;             /* InterfacesToTrace */
static int hf_e1ap_traceDepth;                    /* TraceDepth */
static int hf_e1ap_traceCollectionEntityIPAddress;  /* TransportLayerAddress */
static int hf_e1ap_t_Reordering;                  /* T_Reordering */
static int hf_e1ap_transport_UP_Layer_Addresses_Info_To_Add_List;  /* Transport_UP_Layer_Addresses_Info_To_Add_List */
static int hf_e1ap_transport_UP_Layer_Addresses_Info_To_Remove_List;  /* Transport_UP_Layer_Addresses_Info_To_Remove_List */
static int hf_e1ap_Transport_UP_Layer_Addresses_Info_To_Add_List_item;  /* Transport_UP_Layer_Addresses_Info_To_Add_Item */
static int hf_e1ap_iP_SecTransportLayerAddress;   /* TransportLayerAddress */
static int hf_e1ap_gTPTransportLayerAddressesToAdd;  /* GTPTLAs */
static int hf_e1ap_Transport_UP_Layer_Addresses_Info_To_Remove_List_item;  /* Transport_UP_Layer_Addresses_Info_To_Remove_Item */
static int hf_e1ap_gTPTransportLayerAddressesToRemove;  /* GTPTLAs */
static int hf_e1ap_bufferSize;                    /* BufferSize */
static int hf_e1ap_dictionary;                    /* Dictionary */
static int hf_e1ap_continueUDC;                   /* T_continueUDC */
static int hf_e1ap_gNB_CU_CP_UE_E1AP_ID;          /* GNB_CU_CP_UE_E1AP_ID */
static int hf_e1ap_gNB_CU_UP_UE_E1AP_ID;          /* GNB_CU_UP_UE_E1AP_ID */
static int hf_e1ap_UESliceMaximumBitRateList_item;  /* UESliceMaximumBitRateItem */
static int hf_e1ap_uESliceMaximumBitRateDL;       /* BitRate */
static int hf_e1ap_UP_Parameters_item;            /* UP_Parameters_Item */
static int hf_e1ap_encryptionKey;                 /* EncryptionKey */
static int hf_e1ap_integrityProtectionKey;        /* IntegrityProtectionKey */
static int hf_e1ap_gTPTunnel;                     /* GTPTunnel */
static int hf_e1ap_continueROHC_01;               /* T_continueROHC_01 */
static int hf_e1ap_userPlaneFailureType;          /* UserPlaneFailureType */
static int hf_e1ap_protocolIEs;                   /* ProtocolIE_Container */
static int hf_e1ap_e1_Interface;                  /* ResetAll */
static int hf_e1ap_partOfE1_Interface;            /* UE_associatedLogicalE1_ConnectionListRes */
static int hf_e1ap_UE_associatedLogicalE1_ConnectionListRes_item;  /* ProtocolIE_SingleContainer */
static int hf_e1ap_UE_associatedLogicalE1_ConnectionListResAck_item;  /* ProtocolIE_SingleContainer */
static int hf_e1ap_SupportedPLMNs_List_item;      /* SupportedPLMNs_Item */
static int hf_e1ap_slice_Support_List;            /* Slice_Support_List */
static int hf_e1ap_nR_CGI_Support_List;           /* NR_CGI_Support_List */
static int hf_e1ap_qoS_Parameters_Support_List;   /* QoS_Parameters_Support_List */
static int hf_e1ap_GNB_CU_UP_TNLA_To_Remove_List_item;  /* GNB_CU_UP_TNLA_To_Remove_Item */
static int hf_e1ap_GNB_CU_CP_TNLA_To_Add_List_item;  /* GNB_CU_CP_TNLA_To_Add_Item */
static int hf_e1ap_GNB_CU_CP_TNLA_To_Remove_List_item;  /* GNB_CU_CP_TNLA_To_Remove_Item */
static int hf_e1ap_GNB_CU_CP_TNLA_To_Update_List_item;  /* GNB_CU_CP_TNLA_To_Update_Item */
static int hf_e1ap_GNB_CU_CP_TNLA_Setup_List_item;  /* GNB_CU_CP_TNLA_Setup_Item */
static int hf_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List_item;  /* GNB_CU_CP_TNLA_Failed_To_Setup_Item */
static int hf_e1ap_e_UTRAN_BearerContextSetupRequest;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_BearerContextSetupRequest;  /* ProtocolIE_Container */
static int hf_e1ap_e_UTRAN_BearerContextSetupResponse;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_BearerContextSetupResponse;  /* ProtocolIE_Container */
static int hf_e1ap_e_UTRAN_BearerContextModificationRequest;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_BearerContextModificationRequest;  /* ProtocolIE_Container */
static int hf_e1ap_e_UTRAN_BearerContextModificationResponse;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_BearerContextModificationResponse;  /* ProtocolIE_Container */
static int hf_e1ap_e_UTRAN_BearerContextModificationRequired;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_BearerContextModificationRequired;  /* ProtocolIE_Container */
static int hf_e1ap_e_UTRAN_BearerContextModificationConfirm;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_BearerContextModificationConfirm;  /* ProtocolIE_Container */
static int hf_e1ap_DRB_Status_List_item;          /* DRB_Status_Item */
static int hf_e1ap_e_UTRAN_GNB_CU_UP_CounterCheckRequest;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_GNB_CU_UP_CounterCheckRequest;  /* ProtocolIE_Container */
static int hf_e1ap_privateIEs;                    /* PrivateIE_Container */
static int hf_e1ap_DLUPTNLAddressToUpdateList_item;  /* DLUPTNLAddressToUpdateItem */
static int hf_e1ap_ULUPTNLAddressToUpdateList_item;  /* ULUPTNLAddressToUpdateItem */
static int hf_e1ap_IAB_Donor_CU_UPPSKInfo_item;   /* IAB_Donor_CU_UPPSKInfo_Item */
static int hf_e1ap_initiatingMessage;             /* InitiatingMessage */
static int hf_e1ap_successfulOutcome;             /* SuccessfulOutcome */
static int hf_e1ap_unsuccessfulOutcome;           /* UnsuccessfulOutcome */
static int hf_e1ap_initiatingMessagevalue;        /* InitiatingMessage_value */
static int hf_e1ap_successfulOutcome_value;       /* SuccessfulOutcome_value */
static int hf_e1ap_unsuccessfulOutcome_value;     /* UnsuccessfulOutcome_value */

/* Initialize the subtree pointers */
static int ett_e1ap;
static int ett_e1ap_PLMN_Identity;
static int ett_e1ap_TransportLayerAddress;
static int ett_e1ap_InterfacesToTrace;
static int ett_e1ap_MeasurementsToActivate;
static int ett_e1ap_ReportCharacteristics;
static int ett_e1ap_BurstArrivalTime;
static int ett_e1ap_PrivateIE_ID;
static int ett_e1ap_ProtocolIE_Container;
static int ett_e1ap_ProtocolIE_Field;
static int ett_e1ap_ProtocolExtensionContainer;
static int ett_e1ap_ProtocolExtensionField;
static int ett_e1ap_PrivateIE_Container;
static int ett_e1ap_PrivateIE_Field;
static int ett_e1ap_ActivityInformation;
static int ett_e1ap_AlternativeQoSParaSetList;
static int ett_e1ap_AlternativeQoSParaSetItem;
static int ett_e1ap_BCBearerContextToSetup;
static int ett_e1ap_BCBearerContextNGU_TNLInfoat5GC;
static int ett_e1ap_BCMRBSetupConfiguration;
static int ett_e1ap_BCMRBSetupConfiguration_Item;
static int ett_e1ap_BCBearerContextToSetupResponse;
static int ett_e1ap_BCBearerContextNGU_TNLInfoatNGRAN;
static int ett_e1ap_BCMRBSetupResponseList;
static int ett_e1ap_BCMRBSetupResponseList_Item;
static int ett_e1ap_BCBearerContextF1U_TNLInfoatCU;
static int ett_e1ap_BCMRBFailedList;
static int ett_e1ap_BCMRBFailedList_Item;
static int ett_e1ap_BCBearerContextToModify;
static int ett_e1ap_BCBearerContextNGU_TNLInfoatNGRAN_Request;
static int ett_e1ap_BCMRBModifyConfiguration;
static int ett_e1ap_BCMRBModifyConfiguration_Item;
static int ett_e1ap_BCBearerContextF1U_TNLInfoatDU;
static int ett_e1ap_BCMRBRemoveConfiguration;
static int ett_e1ap_BCBearerContextToModifyResponse;
static int ett_e1ap_BCMRBSetupModifyResponseList;
static int ett_e1ap_BCMRBSetupModifyResponseList_Item;
static int ett_e1ap_BCBearerContextToModifyRequired;
static int ett_e1ap_BCBearerContextToModifyConfirm;
static int ett_e1ap_Cause;
static int ett_e1ap_Cell_Group_Information;
static int ett_e1ap_Cell_Group_Information_Item;
static int ett_e1ap_CP_TNL_Information;
static int ett_e1ap_CriticalityDiagnostics;
static int ett_e1ap_CriticalityDiagnostics_IE_List;
static int ett_e1ap_CriticalityDiagnostics_IE_List_item;
static int ett_e1ap_DAPSRequestInfo;
static int ett_e1ap_Data_Forwarding_Information_Request;
static int ett_e1ap_Data_Forwarding_Information;
static int ett_e1ap_DataForwardingtoE_UTRANInformationList;
static int ett_e1ap_DataForwardingtoE_UTRANInformationListItem;
static int ett_e1ap_Data_Usage_per_PDU_Session_Report;
static int ett_e1ap_SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item;
static int ett_e1ap_Data_Usage_per_QoS_Flow_List;
static int ett_e1ap_Data_Usage_per_QoS_Flow_Item;
static int ett_e1ap_Data_Usage_Report_List;
static int ett_e1ap_Data_Usage_Report_Item;
static int ett_e1ap_DLDiscarding;
static int ett_e1ap_DLUPTNLAddressToUpdateItem;
static int ett_e1ap_DRB_Activity_List;
static int ett_e1ap_DRB_Activity_Item;
static int ett_e1ap_DRB_Confirm_Modified_List_EUTRAN;
static int ett_e1ap_DRB_Confirm_Modified_Item_EUTRAN;
static int ett_e1ap_DRB_Confirm_Modified_List_NG_RAN;
static int ett_e1ap_DRB_Confirm_Modified_Item_NG_RAN;
static int ett_e1ap_DRB_Failed_List_EUTRAN;
static int ett_e1ap_DRB_Failed_Item_EUTRAN;
static int ett_e1ap_DRB_Failed_Mod_List_EUTRAN;
static int ett_e1ap_DRB_Failed_Mod_Item_EUTRAN;
static int ett_e1ap_DRB_Failed_List_NG_RAN;
static int ett_e1ap_DRB_Failed_Item_NG_RAN;
static int ett_e1ap_DRB_Failed_Mod_List_NG_RAN;
static int ett_e1ap_DRB_Failed_Mod_Item_NG_RAN;
static int ett_e1ap_DRB_Failed_To_Modify_List_EUTRAN;
static int ett_e1ap_DRB_Failed_To_Modify_Item_EUTRAN;
static int ett_e1ap_DRB_Failed_To_Modify_List_NG_RAN;
static int ett_e1ap_DRB_Failed_To_Modify_Item_NG_RAN;
static int ett_e1ap_DRB_Measurement_Results_Information_List;
static int ett_e1ap_DRB_Measurement_Results_Information_Item;
static int ett_e1ap_DRB_Modified_List_EUTRAN;
static int ett_e1ap_DRB_Modified_Item_EUTRAN;
static int ett_e1ap_DRB_Modified_List_NG_RAN;
static int ett_e1ap_DRB_Modified_Item_NG_RAN;
static int ett_e1ap_DRB_Removed_Item;
static int ett_e1ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_QoS_Flow_Removed_Item;
static int ett_e1ap_DRB_Required_To_Modify_List_EUTRAN;
static int ett_e1ap_DRB_Required_To_Modify_Item_EUTRAN;
static int ett_e1ap_DRB_Required_To_Modify_List_NG_RAN;
static int ett_e1ap_DRB_Required_To_Modify_Item_NG_RAN;
static int ett_e1ap_DRB_Setup_List_EUTRAN;
static int ett_e1ap_DRB_Setup_Item_EUTRAN;
static int ett_e1ap_DRB_Setup_Mod_List_EUTRAN;
static int ett_e1ap_DRB_Setup_Mod_Item_EUTRAN;
static int ett_e1ap_DRB_Setup_List_NG_RAN;
static int ett_e1ap_DRB_Setup_Item_NG_RAN;
static int ett_e1ap_DRB_Setup_Mod_List_NG_RAN;
static int ett_e1ap_DRB_Setup_Mod_Item_NG_RAN;
static int ett_e1ap_DRB_Status_Item;
static int ett_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN;
static int ett_e1ap_DRBs_Subject_To_Counter_Check_Item_EUTRAN;
static int ett_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN;
static int ett_e1ap_DRBs_Subject_To_Counter_Check_Item_NG_RAN;
static int ett_e1ap_DRBs_Subject_To_Early_Forwarding_List;
static int ett_e1ap_DRBs_Subject_To_Early_Forwarding_Item;
static int ett_e1ap_DRB_To_Modify_List_EUTRAN;
static int ett_e1ap_DRB_To_Modify_Item_EUTRAN;
static int ett_e1ap_DRB_To_Modify_List_NG_RAN;
static int ett_e1ap_DRB_To_Modify_Item_NG_RAN;
static int ett_e1ap_DRB_To_Remove_List_EUTRAN;
static int ett_e1ap_DRB_To_Remove_Item_EUTRAN;
static int ett_e1ap_DRB_Required_To_Remove_List_EUTRAN;
static int ett_e1ap_DRB_Required_To_Remove_Item_EUTRAN;
static int ett_e1ap_DRB_To_Remove_List_NG_RAN;
static int ett_e1ap_DRB_To_Remove_Item_NG_RAN;
static int ett_e1ap_DRB_Required_To_Remove_List_NG_RAN;
static int ett_e1ap_DRB_Required_To_Remove_Item_NG_RAN;
static int ett_e1ap_DRB_To_Setup_List_EUTRAN;
static int ett_e1ap_DRB_To_Setup_Item_EUTRAN;
static int ett_e1ap_DRB_To_Setup_Mod_List_EUTRAN;
static int ett_e1ap_DRB_To_Setup_Mod_Item_EUTRAN;
static int ett_e1ap_DRB_To_Setup_List_NG_RAN;
static int ett_e1ap_DRB_To_Setup_Item_NG_RAN;
static int ett_e1ap_DRB_To_Setup_Mod_List_NG_RAN;
static int ett_e1ap_DRB_To_Setup_Mod_Item_NG_RAN;
static int ett_e1ap_DRB_Usage_Report_List;
static int ett_e1ap_DRB_Usage_Report_Item;
static int ett_e1ap_Dynamic5QIDescriptor;
static int ett_e1ap_EarlyForwardingCOUNTInfo;
static int ett_e1ap_ECNMarkingorCongestionInformationReportingRequest;
static int ett_e1ap_EHC_Common_Parameters;
static int ett_e1ap_EHC_Downlink_Parameters;
static int ett_e1ap_EHC_Uplink_Parameters;
static int ett_e1ap_EHC_Parameters;
static int ett_e1ap_Endpoint_IP_address_and_port;
static int ett_e1ap_EUTRANAllocationAndRetentionPriority;
static int ett_e1ap_ECGI;
static int ett_e1ap_ECGI_Support_List;
static int ett_e1ap_ECGI_Support_Item;
static int ett_e1ap_EUTRAN_QoS_Support_List;
static int ett_e1ap_EUTRAN_QoS_Support_Item;
static int ett_e1ap_EUTRAN_QoS;
static int ett_e1ap_ExtendedSliceSupportList;
static int ett_e1ap_FirstDLCount;
static int ett_e1ap_F1U_TNL_InfoAdded_List;
static int ett_e1ap_F1U_TNL_InfoAdded_Item;
static int ett_e1ap_F1U_TNL_InfoToAdd_List;
static int ett_e1ap_F1U_TNL_InfoToAdd_Item;
static int ett_e1ap_F1U_TNL_InfoAddedOrModified_List;
static int ett_e1ap_F1U_TNL_InfoAddedOrModified_Item;
static int ett_e1ap_F1U_TNL_InfoToAddOrModify_List;
static int ett_e1ap_F1U_TNL_InfoToAddOrModify_Item;
static int ett_e1ap_F1U_TNL_InfoToRelease_List;
static int ett_e1ap_F1U_TNL_InfoToRelease_Item;
static int ett_e1ap_GlobalMBSSessionID;
static int ett_e1ap_Extended_GNB_CU_CP_Name;
static int ett_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration;
static int ett_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration_Item;
static int ett_e1ap_GNB_CU_UP_MBS_Support_Info;
static int ett_e1ap_Extended_GNB_CU_UP_Name;
static int ett_e1ap_GNB_CU_CP_TNLA_Setup_Item;
static int ett_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_Item;
static int ett_e1ap_GNB_CU_CP_TNLA_To_Add_Item;
static int ett_e1ap_GNB_CU_CP_TNLA_To_Remove_Item;
static int ett_e1ap_GNB_CU_CP_TNLA_To_Update_Item;
static int ett_e1ap_GNB_CU_UP_TNLA_To_Remove_Item;
static int ett_e1ap_GBR_QosInformation;
static int ett_e1ap_GBR_QoSFlowInformation;
static int ett_e1ap_GTPTLAs;
static int ett_e1ap_GTPTLA_Item;
static int ett_e1ap_GTPTunnel;
static int ett_e1ap_HW_CapacityIndicator;
static int ett_e1ap_ImmediateMDT;
static int ett_e1ap_IAB_Donor_CU_UPPSKInfo_Item;
static int ett_e1ap_LocationDependentMBSNGUInformationAt5GC;
static int ett_e1ap_LocationDependentMBSNGUInformationAt5GC_Item;
static int ett_e1ap_LocationDependentMBSF1UInformationAtCU;
static int ett_e1ap_LocationDependentMBSF1UInformationAtCU_Item;
static int ett_e1ap_LocationDependentMBSF1UInformationAtDU;
static int ett_e1ap_LocationDependentMBSF1UInformationAtDU_Item;
static int ett_e1ap_LocationDependentMBSNGUInformationAtNGRAN;
static int ett_e1ap_LocationDependentMBSNGUInformationAtNGRAN_Item;
static int ett_e1ap_MaximumIPdatarate;
static int ett_e1ap_MBSF1UInformationAtCU;
static int ett_e1ap_MBSF1UInformationAtDU;
static int ett_e1ap_MBSNGUInformationAt5GC;
static int ett_e1ap_MBSNGUInformationAt5GC_Multicast;
static int ett_e1ap_MBSNGUInformationAtNGRAN;
static int ett_e1ap_MBSNGUInformationAtNGRAN_Request_List;
static int ett_e1ap_MBSNGUInformationAtNGRAN_Request_Item;
static int ett_e1ap_MBSSessionAssociatedInfoNonSupportToSupport;
static int ett_e1ap_MBSSessionAssociatedInformation;
static int ett_e1ap_MBSSessionAssociatedInformationList;
static int ett_e1ap_MBSSessionAssociatedInformation_Item;
static int ett_e1ap_MBS_Support_Info_ToAdd_List;
static int ett_e1ap_MBS_Support_Info_ToAdd_Item;
static int ett_e1ap_MBS_Support_Info_ToRemove_List;
static int ett_e1ap_MBSSessionResourceNotification;
static int ett_e1ap_MBS_DL_Data_Arrival;
static int ett_e1ap_MCBearerContext_Inactivity;
static int ett_e1ap_MBS_Support_Info_ToRemove_Item;
static int ett_e1ap_MCBearerContextToSetup;
static int ett_e1ap_MCMRBSetupConfiguration;
static int ett_e1ap_MCMRBSetupConfiguration_Item;
static int ett_e1ap_MCBearerContextToSetupResponse;
static int ett_e1ap_MCBearerContextNGU_TNLInfoatNGRAN;
static int ett_e1ap_MCMRBSetupResponseList;
static int ett_e1ap_MCMRBSetupResponseList_Item;
static int ett_e1ap_MCMRBFailedList;
static int ett_e1ap_MCMRBFailedList_Item;
static int ett_e1ap_MCBearerContextToModify;
static int ett_e1ap_MCBearerContextNGUTNLInfoat5GC;
static int ett_e1ap_MCBearerContextNGUTnlInfoatNGRANRequest;
static int ett_e1ap_MCMRBSetupModifyConfiguration;
static int ett_e1ap_MCMRBSetupModifyConfiguration_Item;
static int ett_e1ap_MCBearerContextF1UTNLInfoatDU;
static int ett_e1ap_MBSMulticastF1UContextDescriptor;
static int ett_e1ap_MCMRBRemoveConfiguration;
static int ett_e1ap_MCBearerContextToModifyResponse;
static int ett_e1ap_MCBearerContextNGU_TNLInfoatNGRANModifyResponse;
static int ett_e1ap_MCMRBSetupModifyResponseList;
static int ett_e1ap_MCMRBSetupModifyResponseList_Item;
static int ett_e1ap_MCBearerContextToModifyRequired;
static int ett_e1ap_MCMRBModifyRequiredConfiguration;
static int ett_e1ap_MCMRBModifyRequiredConfiguration_Item;
static int ett_e1ap_MCBearerContextToModifyConfirm;
static int ett_e1ap_MCMRBModifyConfirmList;
static int ett_e1ap_MCMRBModifyConfirmList_Item;
static int ett_e1ap_MCForwardingResourceRequest;
static int ett_e1ap_MRBForwardingResourceRequestList;
static int ett_e1ap_MRBForwardingResourceRequest_Item;
static int ett_e1ap_MCForwardingResourceIndication;
static int ett_e1ap_MRBForwardingResourceIndicationList;
static int ett_e1ap_MRBForwardingResourceIndication_Item;
static int ett_e1ap_MCForwardingResourceResponse;
static int ett_e1ap_MRBForwardingResourceResponseList;
static int ett_e1ap_MRBForwardingResourceResponse_Item;
static int ett_e1ap_MCForwardingResourceRelease;
static int ett_e1ap_MCForwardingResourceReleaseIndication;
static int ett_e1ap_MRB_ProgressInformation;
static int ett_e1ap_MRB_ProgressInformationSNs;
static int ett_e1ap_MRDC_Data_Usage_Report_Item;
static int ett_e1ap_MRDC_Usage_Information;
static int ett_e1ap_M4Configuration;
static int ett_e1ap_M6Configuration;
static int ett_e1ap_M7Configuration;
static int ett_e1ap_MDT_Configuration;
static int ett_e1ap_MDTMode;
static int ett_e1ap_MDTPLMNList;
static int ett_e1ap_MDTPLMNModificationList;
static int ett_e1ap_MT_SDT_Information;
static int ett_e1ap_MBS_ServiceArea;
static int ett_e1ap_MBS_ServiceAreaInformation;
static int ett_e1ap_MBS_ServiceAreaCellList;
static int ett_e1ap_MBS_ServiceAreaTAIList;
static int ett_e1ap_MBS_ServiceAreaTAIList_Item;
static int ett_e1ap_MBS_ServiceAreaInformationList;
static int ett_e1ap_MBS_ServiceAreaInformationItem;
static int ett_e1ap_NGRANAllocationAndRetentionPriority;
static int ett_e1ap_NG_RAN_QoS_Support_List;
static int ett_e1ap_NG_RAN_QoS_Support_Item;
static int ett_e1ap_Non_Dynamic5QIDescriptor;
static int ett_e1ap_NPNSupportInfo;
static int ett_e1ap_NPNSupportInfo_SNPN;
static int ett_e1ap_NPNContextInfo;
static int ett_e1ap_NPNContextInfo_SNPN;
static int ett_e1ap_NR_CGI;
static int ett_e1ap_NR_CGI_Support_List;
static int ett_e1ap_NR_CGI_Support_Item;
static int ett_e1ap_Extended_NR_CGI_Support_List;
static int ett_e1ap_Extended_NR_CGI_Support_Item;
static int ett_e1ap_N6JitterInformation;
static int ett_e1ap_PacketErrorRate;
static int ett_e1ap_PDCP_Configuration;
static int ett_e1ap_PDCP_Count;
static int ett_e1ap_PDU_Session_Resource_Data_Usage_List;
static int ett_e1ap_PDU_Session_Resource_Data_Usage_Item;
static int ett_e1ap_PDCP_SN_Status_Information;
static int ett_e1ap_DRBBStatusTransfer;
static int ett_e1ap_PDU_Session_Resource_Activity_List;
static int ett_e1ap_PDU_Session_Resource_Activity_Item;
static int ett_e1ap_PDU_Session_Resource_Confirm_Modified_List;
static int ett_e1ap_PDU_Session_Resource_Confirm_Modified_Item;
static int ett_e1ap_PDU_Session_Resource_Failed_List;
static int ett_e1ap_PDU_Session_Resource_Failed_Item;
static int ett_e1ap_PDU_Session_Resource_Failed_Mod_List;
static int ett_e1ap_PDU_Session_Resource_Failed_Mod_Item;
static int ett_e1ap_PDU_Session_Resource_Failed_To_Modify_List;
static int ett_e1ap_PDU_Session_Resource_Failed_To_Modify_Item;
static int ett_e1ap_PDU_Session_Resource_Modified_List;
static int ett_e1ap_PDU_Session_Resource_Modified_Item;
static int ett_e1ap_PDU_Session_Resource_Required_To_Modify_List;
static int ett_e1ap_PDU_Session_Resource_Required_To_Modify_Item;
static int ett_e1ap_PDU_Session_Resource_Setup_List;
static int ett_e1ap_PDU_Session_Resource_Setup_Item;
static int ett_e1ap_PDU_Session_Resource_Setup_Mod_List;
static int ett_e1ap_PDU_Session_Resource_Setup_Mod_Item;
static int ett_e1ap_PDU_Session_Resource_To_Modify_List;
static int ett_e1ap_PDU_Session_Resource_To_Modify_Item;
static int ett_e1ap_PDU_Session_Resource_To_Remove_List;
static int ett_e1ap_PDU_Session_Resource_To_Remove_Item;
static int ett_e1ap_PDU_Session_Resource_To_Setup_List;
static int ett_e1ap_PDU_Session_Resource_To_Setup_Item;
static int ett_e1ap_PDU_Session_Resource_To_Setup_Mod_List;
static int ett_e1ap_PDU_Session_Resource_To_Setup_Mod_Item;
static int ett_e1ap_PDU_Session_To_Notify_List;
static int ett_e1ap_PDU_Session_To_Notify_Item;
static int ett_e1ap_PDUSetQoSParameters;
static int ett_e1ap_PDUSetQoSInformation;
static int ett_e1ap_QoS_Characteristics;
static int ett_e1ap_QoS_Flow_List;
static int ett_e1ap_QoS_Flow_Item;
static int ett_e1ap_QoS_Flow_Failed_List;
static int ett_e1ap_QoS_Flow_Failed_Item;
static int ett_e1ap_QoS_Flow_Mapping_List;
static int ett_e1ap_QoS_Flow_Mapping_Item;
static int ett_e1ap_QoS_Parameters_Support_List;
static int ett_e1ap_QoS_Flow_QoS_Parameter_List;
static int ett_e1ap_QoS_Flow_QoS_Parameter_Item;
static int ett_e1ap_QoSFlowLevelQoSParameters;
static int ett_e1ap_QoS_Flow_Removed_Item;
static int ett_e1ap_QoS_Flows_to_be_forwarded_List;
static int ett_e1ap_QoS_Flows_to_be_forwarded_Item;
static int ett_e1ap_QoS_Mapping_Information;
static int ett_e1ap_DataForwardingtoNG_RANQoSFlowInformationList;
static int ett_e1ap_DataForwardingtoNG_RANQoSFlowInformationList_Item;
static int ett_e1ap_RedundantPDUSessionInformation;
static int ett_e1ap_RetainabilityMeasurementsInfo;
static int ett_e1ap_ROHC_Parameters;
static int ett_e1ap_ROHC;
static int ett_e1ap_SecurityAlgorithm;
static int ett_e1ap_SecurityIndication;
static int ett_e1ap_SecurityInformation;
static int ett_e1ap_SecurityResult;
static int ett_e1ap_Slice_Support_List;
static int ett_e1ap_Slice_Support_Item;
static int ett_e1ap_SNSSAI;
static int ett_e1ap_SDAP_Configuration;
static int ett_e1ap_TNL_AvailableCapacityIndicator;
static int ett_e1ap_TSCTrafficCharacteristics;
static int ett_e1ap_TSCAssistanceInformation;
static int ett_e1ap_TraceActivation;
static int ett_e1ap_T_ReorderingTimer;
static int ett_e1ap_Transport_Layer_Address_Info;
static int ett_e1ap_Transport_UP_Layer_Addresses_Info_To_Add_List;
static int ett_e1ap_Transport_UP_Layer_Addresses_Info_To_Add_Item;
static int ett_e1ap_Transport_UP_Layer_Addresses_Info_To_Remove_List;
static int ett_e1ap_Transport_UP_Layer_Addresses_Info_To_Remove_Item;
static int ett_e1ap_UDC_Parameters;
static int ett_e1ap_UE_associatedLogicalE1_ConnectionItem;
static int ett_e1ap_UESliceMaximumBitRateList;
static int ett_e1ap_UESliceMaximumBitRateItem;
static int ett_e1ap_ULUPTNLAddressToUpdateItem;
static int ett_e1ap_UP_Parameters;
static int ett_e1ap_UP_Parameters_Item;
static int ett_e1ap_UPSecuritykey;
static int ett_e1ap_UP_TNL_Information;
static int ett_e1ap_UplinkOnlyROHC;
static int ett_e1ap_UserPlaneFailureIndication;
static int ett_e1ap_Reset;
static int ett_e1ap_ResetType;
static int ett_e1ap_UE_associatedLogicalE1_ConnectionListRes;
static int ett_e1ap_ResetAcknowledge;
static int ett_e1ap_UE_associatedLogicalE1_ConnectionListResAck;
static int ett_e1ap_ErrorIndication;
static int ett_e1ap_GNB_CU_UP_E1SetupRequest;
static int ett_e1ap_SupportedPLMNs_List;
static int ett_e1ap_SupportedPLMNs_Item;
static int ett_e1ap_GNB_CU_UP_E1SetupResponse;
static int ett_e1ap_GNB_CU_UP_E1SetupFailure;
static int ett_e1ap_GNB_CU_CP_E1SetupRequest;
static int ett_e1ap_GNB_CU_CP_E1SetupResponse;
static int ett_e1ap_GNB_CU_CP_E1SetupFailure;
static int ett_e1ap_GNB_CU_UP_ConfigurationUpdate;
static int ett_e1ap_GNB_CU_UP_TNLA_To_Remove_List;
static int ett_e1ap_GNB_CU_UP_ConfigurationUpdateAcknowledge;
static int ett_e1ap_GNB_CU_UP_ConfigurationUpdateFailure;
static int ett_e1ap_GNB_CU_CP_ConfigurationUpdate;
static int ett_e1ap_GNB_CU_CP_TNLA_To_Add_List;
static int ett_e1ap_GNB_CU_CP_TNLA_To_Remove_List;
static int ett_e1ap_GNB_CU_CP_TNLA_To_Update_List;
static int ett_e1ap_GNB_CU_CP_ConfigurationUpdateAcknowledge;
static int ett_e1ap_GNB_CU_CP_TNLA_Setup_List;
static int ett_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List;
static int ett_e1ap_GNB_CU_CP_ConfigurationUpdateFailure;
static int ett_e1ap_E1ReleaseRequest;
static int ett_e1ap_E1ReleaseResponse;
static int ett_e1ap_BearerContextSetupRequest;
static int ett_e1ap_System_BearerContextSetupRequest;
static int ett_e1ap_BearerContextSetupResponse;
static int ett_e1ap_System_BearerContextSetupResponse;
static int ett_e1ap_BearerContextSetupFailure;
static int ett_e1ap_BearerContextModificationRequest;
static int ett_e1ap_System_BearerContextModificationRequest;
static int ett_e1ap_BearerContextModificationResponse;
static int ett_e1ap_System_BearerContextModificationResponse;
static int ett_e1ap_BearerContextModificationFailure;
static int ett_e1ap_BearerContextModificationRequired;
static int ett_e1ap_System_BearerContextModificationRequired;
static int ett_e1ap_BearerContextModificationConfirm;
static int ett_e1ap_System_BearerContextModificationConfirm;
static int ett_e1ap_BearerContextReleaseCommand;
static int ett_e1ap_BearerContextReleaseComplete;
static int ett_e1ap_BearerContextReleaseRequest;
static int ett_e1ap_DRB_Status_List;
static int ett_e1ap_BearerContextInactivityNotification;
static int ett_e1ap_DLDataNotification;
static int ett_e1ap_ULDataNotification;
static int ett_e1ap_DataUsageReport;
static int ett_e1ap_GNB_CU_UP_CounterCheckRequest;
static int ett_e1ap_System_GNB_CU_UP_CounterCheckRequest;
static int ett_e1ap_GNB_CU_UP_StatusIndication;
static int ett_e1ap_GNB_CU_CPMeasurementResultsInformation;
static int ett_e1ap_MRDC_DataUsageReport;
static int ett_e1ap_TraceStart;
static int ett_e1ap_DeactivateTrace;
static int ett_e1ap_CellTrafficTrace;
static int ett_e1ap_PrivateMessage;
static int ett_e1ap_ResourceStatusRequest;
static int ett_e1ap_ResourceStatusResponse;
static int ett_e1ap_ResourceStatusFailure;
static int ett_e1ap_ResourceStatusUpdate;
static int ett_e1ap_IAB_UPTNLAddressUpdate;
static int ett_e1ap_DLUPTNLAddressToUpdateList;
static int ett_e1ap_IAB_UPTNLAddressUpdateAcknowledge;
static int ett_e1ap_ULUPTNLAddressToUpdateList;
static int ett_e1ap_IAB_UPTNLAddressUpdateFailure;
static int ett_e1ap_EarlyForwardingSNTransfer;
static int ett_e1ap_IABPSKNotification;
static int ett_e1ap_IAB_Donor_CU_UPPSKInfo;
static int ett_e1ap_BCBearerContextSetupRequest;
static int ett_e1ap_BCBearerContextSetupResponse;
static int ett_e1ap_BCBearerContextSetupFailure;
static int ett_e1ap_BCBearerContextModificationRequest;
static int ett_e1ap_BCBearerContextModificationResponse;
static int ett_e1ap_BCBearerContextModificationFailure;
static int ett_e1ap_BCBearerContextModificationRequired;
static int ett_e1ap_BCBearerContextModificationConfirm;
static int ett_e1ap_BCBearerContextReleaseCommand;
static int ett_e1ap_BCBearerContextReleaseComplete;
static int ett_e1ap_BCBearerContextReleaseRequest;
static int ett_e1ap_MCBearerContextSetupRequest;
static int ett_e1ap_MCBearerContextSetupResponse;
static int ett_e1ap_MCBearerContextSetupFailure;
static int ett_e1ap_MCBearerContextModificationRequest;
static int ett_e1ap_MCBearerContextModificationResponse;
static int ett_e1ap_MCBearerContextModificationFailure;
static int ett_e1ap_MCBearerContextModificationRequired;
static int ett_e1ap_MCBearerContextModificationConfirm;
static int ett_e1ap_MCBearerContextReleaseCommand;
static int ett_e1ap_MCBearerContextReleaseComplete;
static int ett_e1ap_MCBearerContextReleaseRequest;
static int ett_e1ap_MCBearerNotification;
static int ett_e1ap_E1AP_PDU;
static int ett_e1ap_InitiatingMessage;
static int ett_e1ap_SuccessfulOutcome;
static int ett_e1ap_UnsuccessfulOutcome;

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

typedef struct {
  uint32_t message_type;
  uint32_t procedure_code;
  uint32_t protocol_ie_id;
  const char *obj_id;
  e212_number_type_t number_type;
} e1ap_private_data_t;

/* Global variables */
static dissector_handle_t e1ap_handle;
static dissector_handle_t e1ap_tcp_handle;

/* Dissector tables */
static dissector_table_t e1ap_ies_dissector_table;
static dissector_table_t e1ap_extension_dissector_table;
static dissector_table_t e1ap_proc_imsg_dissector_table;
static dissector_table_t e1ap_proc_sout_dissector_table;
static dissector_table_t e1ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static void
e1ap_MaxPacketLossRate_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1f%% (%u)", (float)v/10, v);
}

static void
e1ap_PacketDelayBudget_uL_D1_Result_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/2, v);
}

static void
e1ap_ExtendedPacketDelayBudget_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fms (%u)", (float)v/100, v);
}

static void
e1ap_N6Jitter_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%d)", (float)v/2, (int32_t)v);
}

static e1ap_private_data_t*
e1ap_get_private_data(packet_info *pinfo)
{
  e1ap_private_data_t *e1ap_data = (e1ap_private_data_t*)p_get_proto_data(pinfo->pool, pinfo, proto_e1ap, 0);
  if (!e1ap_data) {
    e1ap_data = wmem_new0(pinfo->pool, e1ap_private_data_t);
    p_add_proto_data(pinfo->pool, pinfo, proto_e1ap, 0, e1ap_data);
  }
  return e1ap_data;
}


static const value_string e1ap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_e1ap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_e1ap_INTEGER_0_maxPrivateIEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxPrivateIEs, NULL, false);

  return offset;
}



static int
dissect_e1ap_T_global(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(actx->pinfo);
  offset = dissect_per_object_identifier_str(tvb, offset, actx, tree, hf_index, &e1ap_data->obj_id);



  return offset;
}


static const value_string e1ap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_e1ap_local          , ASN1_NO_EXTENSIONS     , dissect_e1ap_INTEGER_0_maxPrivateIEs },
  {   1, &hf_e1ap_global         , ASN1_NO_EXTENSIONS     , dissect_e1ap_T_global },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(actx->pinfo);
  e1ap_data->obj_id = NULL;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string e1ap_ProcedureCode_vals[] = {
  { id_reset, "id-reset" },
  { id_errorIndication, "id-errorIndication" },
  { id_privateMessage, "id-privateMessage" },
  { id_gNB_CU_UP_E1Setup, "id-gNB-CU-UP-E1Setup" },
  { id_gNB_CU_CP_E1Setup, "id-gNB-CU-CP-E1Setup" },
  { id_gNB_CU_UP_ConfigurationUpdate, "id-gNB-CU-UP-ConfigurationUpdate" },
  { id_gNB_CU_CP_ConfigurationUpdate, "id-gNB-CU-CP-ConfigurationUpdate" },
  { id_e1Release, "id-e1Release" },
  { id_bearerContextSetup, "id-bearerContextSetup" },
  { id_bearerContextModification, "id-bearerContextModification" },
  { id_bearerContextModificationRequired, "id-bearerContextModificationRequired" },
  { id_bearerContextRelease, "id-bearerContextRelease" },
  { id_bearerContextReleaseRequest, "id-bearerContextReleaseRequest" },
  { id_bearerContextInactivityNotification, "id-bearerContextInactivityNotification" },
  { id_dLDataNotification, "id-dLDataNotification" },
  { id_dataUsageReport, "id-dataUsageReport" },
  { id_gNB_CU_UP_CounterCheck, "id-gNB-CU-UP-CounterCheck" },
  { id_gNB_CU_UP_StatusIndication, "id-gNB-CU-UP-StatusIndication" },
  { id_uLDataNotification, "id-uLDataNotification" },
  { id_mRDC_DataUsageReport, "id-mRDC-DataUsageReport" },
  { id_TraceStart, "id-TraceStart" },
  { id_DeactivateTrace, "id-DeactivateTrace" },
  { id_resourceStatusReportingInitiation, "id-resourceStatusReportingInitiation" },
  { id_resourceStatusReporting, "id-resourceStatusReporting" },
  { id_iAB_UPTNLAddressUpdate, "id-iAB-UPTNLAddressUpdate" },
  { id_CellTrafficTrace, "id-CellTrafficTrace" },
  { id_earlyForwardingSNTransfer, "id-earlyForwardingSNTransfer" },
  { id_gNB_CU_CPMeasurementResultsInformation, "id-gNB-CU-CPMeasurementResultsInformation" },
  { id_iABPSKNotification, "id-iABPSKNotification" },
  { id_BCBearerContextSetup, "id-BCBearerContextSetup" },
  { id_BCBearerContextModification, "id-BCBearerContextModification" },
  { id_BCBearerContextModificationRequired, "id-BCBearerContextModificationRequired" },
  { id_BCBearerContextRelease, "id-BCBearerContextRelease" },
  { id_BCBearerContextReleaseRequest, "id-BCBearerContextReleaseRequest" },
  { id_MCBearerContextSetup, "id-MCBearerContextSetup" },
  { id_MCBearerContextModification, "id-MCBearerContextModification" },
  { id_MCBearerContextModificationRequired, "id-MCBearerContextModificationRequired" },
  { id_MCBearerContextRelease, "id-MCBearerContextRelease" },
  { id_MCBearerContextReleaseRequest, "id-MCBearerContextReleaseRequest" },
  { id_MCBearerNotification, "id-MCBearerNotification" },
  { 0, NULL }
};

static value_string_ext e1ap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(e1ap_ProcedureCode_vals);


static int
dissect_e1ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &e1ap_data->procedure_code, false);


  return offset;
}


static const value_string e1ap_ProtocolIE_ID_vals[] = {
  { id_Cause, "id-Cause" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_gNB_CU_CP_UE_E1AP_ID, "id-gNB-CU-CP-UE-E1AP-ID" },
  { id_gNB_CU_UP_UE_E1AP_ID, "id-gNB-CU-UP-UE-E1AP-ID" },
  { id_ResetType, "id-ResetType" },
  { id_UE_associatedLogicalE1_ConnectionItem, "id-UE-associatedLogicalE1-ConnectionItem" },
  { id_UE_associatedLogicalE1_ConnectionListResAck, "id-UE-associatedLogicalE1-ConnectionListResAck" },
  { id_gNB_CU_UP_ID, "id-gNB-CU-UP-ID" },
  { id_gNB_CU_UP_Name, "id-gNB-CU-UP-Name" },
  { id_gNB_CU_CP_Name, "id-gNB-CU-CP-Name" },
  { id_CNSupport, "id-CNSupport" },
  { id_SupportedPLMNs, "id-SupportedPLMNs" },
  { id_TimeToWait, "id-TimeToWait" },
  { id_SecurityInformation, "id-SecurityInformation" },
  { id_UEDLAggregateMaximumBitRate, "id-UEDLAggregateMaximumBitRate" },
  { id_System_BearerContextSetupRequest, "id-System-BearerContextSetupRequest" },
  { id_System_BearerContextSetupResponse, "id-System-BearerContextSetupResponse" },
  { id_BearerContextStatusChange, "id-BearerContextStatusChange" },
  { id_System_BearerContextModificationRequest, "id-System-BearerContextModificationRequest" },
  { id_System_BearerContextModificationResponse, "id-System-BearerContextModificationResponse" },
  { id_System_BearerContextModificationConfirm, "id-System-BearerContextModificationConfirm" },
  { id_System_BearerContextModificationRequired, "id-System-BearerContextModificationRequired" },
  { id_DRB_Status_List, "id-DRB-Status-List" },
  { id_ActivityNotificationLevel, "id-ActivityNotificationLevel" },
  { id_ActivityInformation, "id-ActivityInformation" },
  { id_Data_Usage_Report_List, "id-Data-Usage-Report-List" },
  { id_New_UL_TNL_Information_Required, "id-New-UL-TNL-Information-Required" },
  { id_GNB_CU_CP_TNLA_To_Add_List, "id-GNB-CU-CP-TNLA-To-Add-List" },
  { id_GNB_CU_CP_TNLA_To_Remove_List, "id-GNB-CU-CP-TNLA-To-Remove-List" },
  { id_GNB_CU_CP_TNLA_To_Update_List, "id-GNB-CU-CP-TNLA-To-Update-List" },
  { id_GNB_CU_CP_TNLA_Setup_List, "id-GNB-CU-CP-TNLA-Setup-List" },
  { id_GNB_CU_CP_TNLA_Failed_To_Setup_List, "id-GNB-CU-CP-TNLA-Failed-To-Setup-List" },
  { id_DRB_To_Setup_List_EUTRAN, "id-DRB-To-Setup-List-EUTRAN" },
  { id_DRB_To_Modify_List_EUTRAN, "id-DRB-To-Modify-List-EUTRAN" },
  { id_DRB_To_Remove_List_EUTRAN, "id-DRB-To-Remove-List-EUTRAN" },
  { id_DRB_Required_To_Modify_List_EUTRAN, "id-DRB-Required-To-Modify-List-EUTRAN" },
  { id_DRB_Required_To_Remove_List_EUTRAN, "id-DRB-Required-To-Remove-List-EUTRAN" },
  { id_DRB_Setup_List_EUTRAN, "id-DRB-Setup-List-EUTRAN" },
  { id_DRB_Failed_List_EUTRAN, "id-DRB-Failed-List-EUTRAN" },
  { id_DRB_Modified_List_EUTRAN, "id-DRB-Modified-List-EUTRAN" },
  { id_DRB_Failed_To_Modify_List_EUTRAN, "id-DRB-Failed-To-Modify-List-EUTRAN" },
  { id_DRB_Confirm_Modified_List_EUTRAN, "id-DRB-Confirm-Modified-List-EUTRAN" },
  { id_PDU_Session_Resource_To_Setup_List, "id-PDU-Session-Resource-To-Setup-List" },
  { id_PDU_Session_Resource_To_Modify_List, "id-PDU-Session-Resource-To-Modify-List" },
  { id_PDU_Session_Resource_To_Remove_List, "id-PDU-Session-Resource-To-Remove-List" },
  { id_PDU_Session_Resource_Required_To_Modify_List, "id-PDU-Session-Resource-Required-To-Modify-List" },
  { id_PDU_Session_Resource_Setup_List, "id-PDU-Session-Resource-Setup-List" },
  { id_PDU_Session_Resource_Failed_List, "id-PDU-Session-Resource-Failed-List" },
  { id_PDU_Session_Resource_Modified_List, "id-PDU-Session-Resource-Modified-List" },
  { id_PDU_Session_Resource_Failed_To_Modify_List, "id-PDU-Session-Resource-Failed-To-Modify-List" },
  { id_PDU_Session_Resource_Confirm_Modified_List, "id-PDU-Session-Resource-Confirm-Modified-List" },
  { id_DRB_To_Setup_Mod_List_EUTRAN, "id-DRB-To-Setup-Mod-List-EUTRAN" },
  { id_DRB_Setup_Mod_List_EUTRAN, "id-DRB-Setup-Mod-List-EUTRAN" },
  { id_DRB_Failed_Mod_List_EUTRAN, "id-DRB-Failed-Mod-List-EUTRAN" },
  { id_PDU_Session_Resource_Setup_Mod_List, "id-PDU-Session-Resource-Setup-Mod-List" },
  { id_PDU_Session_Resource_Failed_Mod_List, "id-PDU-Session-Resource-Failed-Mod-List" },
  { id_PDU_Session_Resource_To_Setup_Mod_List, "id-PDU-Session-Resource-To-Setup-Mod-List" },
  { id_TransactionID, "id-TransactionID" },
  { id_Serving_PLMN, "id-Serving-PLMN" },
  { id_UE_Inactivity_Timer, "id-UE-Inactivity-Timer" },
  { id_System_GNB_CU_UP_CounterCheckRequest, "id-System-GNB-CU-UP-CounterCheckRequest" },
  { id_DRBs_Subject_To_Counter_Check_List_EUTRAN, "id-DRBs-Subject-To-Counter-Check-List-EUTRAN" },
  { id_DRBs_Subject_To_Counter_Check_List_NG_RAN, "id-DRBs-Subject-To-Counter-Check-List-NG-RAN" },
  { id_PPI, "id-PPI" },
  { id_gNB_CU_UP_Capacity, "id-gNB-CU-UP-Capacity" },
  { id_GNB_CU_UP_OverloadInformation, "id-GNB-CU-UP-OverloadInformation" },
  { id_UEDLMaximumIntegrityProtectedDataRate, "id-UEDLMaximumIntegrityProtectedDataRate" },
  { id_PDU_Session_To_Notify_List, "id-PDU-Session-To-Notify-List" },
  { id_PDU_Session_Resource_Data_Usage_List, "id-PDU-Session-Resource-Data-Usage-List" },
  { id_SNSSAI, "id-SNSSAI" },
  { id_DataDiscardRequired, "id-DataDiscardRequired" },
  { id_OldQoSFlowMap_ULendmarkerexpected, "id-OldQoSFlowMap-ULendmarkerexpected" },
  { id_DRB_QoS, "id-DRB-QoS" },
  { id_GNB_CU_UP_TNLA_To_Remove_List, "id-GNB-CU-UP-TNLA-To-Remove-List" },
  { id_endpoint_IP_Address_and_Port, "id-endpoint-IP-Address-and-Port" },
  { id_TNLAssociationTransportLayerAddressgNBCUUP, "id-TNLAssociationTransportLayerAddressgNBCUUP" },
  { id_RANUEID, "id-RANUEID" },
  { id_GNB_DU_ID, "id-GNB-DU-ID" },
  { id_CommonNetworkInstance, "id-CommonNetworkInstance" },
  { id_NetworkInstance, "id-NetworkInstance" },
  { id_QoSFlowMappingIndication, "id-QoSFlowMappingIndication" },
  { id_TraceActivation, "id-TraceActivation" },
  { id_TraceID, "id-TraceID" },
  { id_SubscriberProfileIDforRFP, "id-SubscriberProfileIDforRFP" },
  { id_AdditionalRRMPriorityIndex, "id-AdditionalRRMPriorityIndex" },
  { id_RetainabilityMeasurementsInfo, "id-RetainabilityMeasurementsInfo" },
  { id_Transport_Layer_Address_Info, "id-Transport-Layer-Address-Info" },
  { id_QoSMonitoringRequest, "id-QoSMonitoringRequest" },
  { id_PDCP_StatusReportIndication, "id-PDCP-StatusReportIndication" },
  { id_gNB_CU_CP_Measurement_ID, "id-gNB-CU-CP-Measurement-ID" },
  { id_gNB_CU_UP_Measurement_ID, "id-gNB-CU-UP-Measurement-ID" },
  { id_RegistrationRequest, "id-RegistrationRequest" },
  { id_ReportCharacteristics, "id-ReportCharacteristics" },
  { id_ReportingPeriodicity, "id-ReportingPeriodicity" },
  { id_TNL_AvailableCapacityIndicator, "id-TNL-AvailableCapacityIndicator" },
  { id_HW_CapacityIndicator, "id-HW-CapacityIndicator" },
  { id_RedundantCommonNetworkInstance, "id-RedundantCommonNetworkInstance" },
  { id_redundant_nG_UL_UP_TNL_Information, "id-redundant-nG-UL-UP-TNL-Information" },
  { id_redundant_nG_DL_UP_TNL_Information, "id-redundant-nG-DL-UP-TNL-Information" },
  { id_RedundantQosFlowIndicator, "id-RedundantQosFlowIndicator" },
  { id_TSCTrafficCharacteristics, "id-TSCTrafficCharacteristics" },
  { id_CNPacketDelayBudgetDownlink, "id-CNPacketDelayBudgetDownlink" },
  { id_CNPacketDelayBudgetUplink, "id-CNPacketDelayBudgetUplink" },
  { id_ExtendedPacketDelayBudget, "id-ExtendedPacketDelayBudget" },
  { id_AdditionalPDCPduplicationInformation, "id-AdditionalPDCPduplicationInformation" },
  { id_RedundantPDUSessionInformation, "id-RedundantPDUSessionInformation" },
  { id_RedundantPDUSessionInformation_used, "id-RedundantPDUSessionInformation-used" },
  { id_QoS_Mapping_Information, "id-QoS-Mapping-Information" },
  { id_DLUPTNLAddressToUpdateList, "id-DLUPTNLAddressToUpdateList" },
  { id_ULUPTNLAddressToUpdateList, "id-ULUPTNLAddressToUpdateList" },
  { id_NPNSupportInfo, "id-NPNSupportInfo" },
  { id_NPNContextInfo, "id-NPNContextInfo" },
  { id_MDTConfiguration, "id-MDTConfiguration" },
  { id_ManagementBasedMDTPLMNList, "id-ManagementBasedMDTPLMNList" },
  { id_TraceCollectionEntityIPAddress, "id-TraceCollectionEntityIPAddress" },
  { id_PrivacyIndicator, "id-PrivacyIndicator" },
  { id_TraceCollectionEntityURI, "id-TraceCollectionEntityURI" },
  { id_URIaddress, "id-URIaddress" },
  { id_EHC_Parameters, "id-EHC-Parameters" },
  { id_DRBs_Subject_To_Early_Forwarding_List, "id-DRBs-Subject-To-Early-Forwarding-List" },
  { id_DAPSRequestInfo, "id-DAPSRequestInfo" },
  { id_CHOInitiation, "id-CHOInitiation" },
  { id_EarlyForwardingCOUNTReq, "id-EarlyForwardingCOUNTReq" },
  { id_EarlyForwardingCOUNTInfo, "id-EarlyForwardingCOUNTInfo" },
  { id_AlternativeQoSParaSetList, "id-AlternativeQoSParaSetList" },
  { id_ExtendedSliceSupportList, "id-ExtendedSliceSupportList" },
  { id_MCG_OfferedGBRQoSFlowInfo, "id-MCG-OfferedGBRQoSFlowInfo" },
  { id_Number_of_tunnels, "id-Number-of-tunnels" },
  { id_DRB_Measurement_Results_Information_List, "id-DRB-Measurement-Results-Information-List" },
  { id_Extended_GNB_CU_CP_Name, "id-Extended-GNB-CU-CP-Name" },
  { id_Extended_GNB_CU_UP_Name, "id-Extended-GNB-CU-UP-Name" },
  { id_DataForwardingtoE_UTRANInformationList, "id-DataForwardingtoE-UTRANInformationList" },
  { id_QosMonitoringReportingFrequency, "id-QosMonitoringReportingFrequency" },
  { id_QoSMonitoringDisabled, "id-QoSMonitoringDisabled" },
  { id_AdditionalHandoverInfo, "id-AdditionalHandoverInfo" },
  { id_Extended_NR_CGI_Support_List, "id-Extended-NR-CGI-Support-List" },
  { id_DataForwardingtoNG_RANQoSFlowInformationList, "id-DataForwardingtoNG-RANQoSFlowInformationList" },
  { id_MaxCIDEHCDL, "id-MaxCIDEHCDL" },
  { id_ignoreMappingRuleIndication, "id-ignoreMappingRuleIndication" },
  { id_DirectForwardingPathAvailability, "id-DirectForwardingPathAvailability" },
  { id_EarlyDataForwardingIndicator, "id-EarlyDataForwardingIndicator" },
  { id_QoSFlowsDRBRemapping, "id-QoSFlowsDRBRemapping" },
  { id_DataForwardingSourceIPAddress, "id-DataForwardingSourceIPAddress" },
  { id_SecurityIndicationModify, "id-SecurityIndicationModify" },
  { id_IAB_Donor_CU_UPPSKInfo, "id-IAB-Donor-CU-UPPSKInfo" },
  { id_ECGI_Support_List, "id-ECGI-Support-List" },
  { id_MDTPollutedMeasurementIndicator, "id-MDTPollutedMeasurementIndicator" },
  { id_M4ReportAmount, "id-M4ReportAmount" },
  { id_M6ReportAmount, "id-M6ReportAmount" },
  { id_M7ReportAmount, "id-M7ReportAmount" },
  { id_UESliceMaximumBitRateList, "id-UESliceMaximumBitRateList" },
  { id_PDUSession_PairID, "id-PDUSession-PairID" },
  { id_SurvivalTime, "id-SurvivalTime" },
  { id_UDC_Parameters, "id-UDC-Parameters" },
  { id_SCGActivationStatus, "id-SCGActivationStatus" },
  { id_GNB_CU_CP_MBS_E1AP_ID, "id-GNB-CU-CP-MBS-E1AP-ID" },
  { id_GNB_CU_UP_MBS_E1AP_ID, "id-GNB-CU-UP-MBS-E1AP-ID" },
  { id_GlobalMBSSessionID, "id-GlobalMBSSessionID" },
  { id_BCBearerContextToSetup, "id-BCBearerContextToSetup" },
  { id_BCBearerContextToSetupResponse, "id-BCBearerContextToSetupResponse" },
  { id_BCBearerContextToModify, "id-BCBearerContextToModify" },
  { id_BCBearerContextToModifyResponse, "id-BCBearerContextToModifyResponse" },
  { id_BCBearerContextToModifyRequired, "id-BCBearerContextToModifyRequired" },
  { id_BCBearerContextToModifyConfirm, "id-BCBearerContextToModifyConfirm" },
  { id_MCBearerContextToSetup, "id-MCBearerContextToSetup" },
  { id_MCBearerContextToSetupResponse, "id-MCBearerContextToSetupResponse" },
  { id_MCBearerContextToModify, "id-MCBearerContextToModify" },
  { id_MCBearerContextToModifyResponse, "id-MCBearerContextToModifyResponse" },
  { id_MCBearerContextToModifyRequired, "id-MCBearerContextToModifyRequired" },
  { id_MCBearerContextToModifyConfirm, "id-MCBearerContextToModifyConfirm" },
  { id_MBSMulticastF1UContextDescriptor, "id-MBSMulticastF1UContextDescriptor" },
  { id_gNB_CU_UP_MBS_Support_Info, "id-gNB-CU-UP-MBS-Support-Info" },
  { id_SecurityIndication, "id-SecurityIndication" },
  { id_SecurityResult, "id-SecurityResult" },
  { id_SDTContinueROHC, "id-SDTContinueROHC" },
  { id_SDTindicatorSetup, "id-SDTindicatorSetup" },
  { id_SDTindicatorMod, "id-SDTindicatorMod" },
  { id_DiscardTimerExtended, "id-DiscardTimerExtended" },
  { id_ManagementBasedMDTPLMNModificationList, "id-ManagementBasedMDTPLMNModificationList" },
  { id_MCForwardingResourceRequest, "id-MCForwardingResourceRequest" },
  { id_MCForwardingResourceIndication, "id-MCForwardingResourceIndication" },
  { id_MCForwardingResourceResponse, "id-MCForwardingResourceResponse" },
  { id_MCForwardingResourceRelease, "id-MCForwardingResourceRelease" },
  { id_MCForwardingResourceReleaseIndication, "id-MCForwardingResourceReleaseIndication" },
  { id_PDCP_COUNT_Reset, "id-PDCP-COUNT-Reset" },
  { id_MBSSessionAssociatedInfoNonSupportToSupport, "id-MBSSessionAssociatedInfoNonSupportToSupport" },
  { id_VersionID, "id-VersionID" },
  { id_InactivityInformationRequest, "id-InactivityInformationRequest" },
  { id_UEInactivityInformation, "id-UEInactivityInformation" },
  { id_MBSAreaSessionID, "id-MBSAreaSessionID" },
  { id_Secondary_PDU_Session_Data_Forwarding_Information, "id-Secondary-PDU-Session-Data-Forwarding-Information" },
  { id_MBSSessionResourceNotification, "id-MBSSessionResourceNotification" },
  { id_MCBearerContextInactivityTimer, "id-MCBearerContextInactivityTimer" },
  { id_MCBearerContextStatusChange, "id-MCBearerContextStatusChange" },
  { id_MT_SDT_Information, "id-MT-SDT-Information" },
  { id_MT_SDT_Information_Request, "id-MT-SDT-Information-Request" },
  { id_SDT_data_size_threshold, "id-SDT-data-size-threshold" },
  { id_SDT_data_size_threshold_Crossed, "id-SDT-data-size-threshold-Crossed" },
  { id_SpecialTriggeringPurpose, "id-SpecialTriggeringPurpose" },
  { id_AssociatedSessionID, "id-AssociatedSessionID" },
  { id_MBS_ServiceArea, "id-MBS-ServiceArea" },
  { id_PDUSetQoSParameters, "id-PDUSetQoSParameters" },
  { id_N6JitterInformation, "id-N6JitterInformation" },
  { id_ECNMarkingorCongestionInformationReportingRequest, "id-ECNMarkingorCongestionInformationReportingRequest" },
  { id_ECNMarkingorCongestionInformationReportingStatus, "id-ECNMarkingorCongestionInformationReportingStatus" },
  { id_PDUSetbasedHandlingIndicator, "id-PDUSetbasedHandlingIndicator" },
  { id_IndirectPathIndication, "id-IndirectPathIndication" },
  { id_F1UTunnelNotEstablished, "id-F1UTunnelNotEstablished" },
  { id_F1U_TNL_InfoToAdd_List, "id-F1U-TNL-InfoToAdd-List" },
  { id_F1U_TNL_InfoAdded_List, "id-F1U-TNL-InfoAdded-List" },
  { id_F1U_TNL_InfoToAddOrModify_List, "id-F1U-TNL-InfoToAddOrModify-List" },
  { id_F1U_TNL_InfoAddedOrModified_List, "id-F1U-TNL-InfoAddedOrModified-List" },
  { id_F1U_TNL_InfoToRelease_List, "id-F1U-TNL-InfoToRelease-List" },
  { id_BroadcastF1U_ContextReferenceE1, "id-BroadcastF1U-ContextReferenceE1" },
  { id_PSIbasedDiscardTimer, "id-PSIbasedDiscardTimer" },
  { id_UserPlaneErrorIndicator, "id-UserPlaneErrorIndicator" },
  { id_MaximumDataBurstVolume, "id-MaximumDataBurstVolume" },
  { id_BCBearerContextNGU_TNLInfoatNGRAN_Request, "id-BCBearerContextNGU-TNLInfoatNGRAN-Request" },
  { id_PDCPSNGapReport, "id-PDCPSNGapReport" },
  { id_UserPlaneFailureIndication, "id-UserPlaneFailureIndication" },
  { 0, NULL }
};

static value_string_ext e1ap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(e1ap_ProtocolIE_ID_vals);


static int
dissect_e1ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &e1ap_data->protocol_ie_id, false);



  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s",
                           val_to_str_ext(e1ap_data->protocol_ie_id, &e1ap_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }

  return offset;
}


static const value_string e1ap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessful-outcome" },
  { 0, NULL }
};


static int
dissect_e1ap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_e1ap_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_e1ap_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_ID },
  { &hf_e1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Criticality },
  { &hf_e1ap_ie_field_value , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_T_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_e1ap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Field },
};

static int
dissect_e1ap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, false);

  return offset;
}



static int
dissect_e1ap_ProtocolIE_SingleContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e1ap_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_e1ap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_e1ap_ext_id         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_ID },
  { &hf_e1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Criticality },
  { &hf_e1ap_extensionValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_e1ap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolExtensionField },
};

static int
dissect_e1ap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, false);

  return offset;
}



static int
dissect_e1ap_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(actx->pinfo);
  if (e1ap_data->obj_id) {
    offset = call_per_oid_callback(e1ap_data->obj_id, tvb, actx->pinfo, tree, offset, actx, hf_index);
  } else {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  }


  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_e1ap_private_id     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PrivateIE_ID },
  { &hf_e1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Criticality },
  { &hf_e1ap_value          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_e1ap_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PrivateIE_Field },
};

static int
dissect_e1ap_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, false);

  return offset;
}



static int
dissect_e1ap_DRB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, true);

  return offset;
}


static const value_string e1ap_DRB_Activity_vals[] = {
  {   0, "active" },
  {   1, "not-active" },
  { 0, NULL }
};


static int
dissect_e1ap_DRB_Activity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t DRB_Activity_Item_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_dRB_Activity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Activity },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Activity_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Activity_Item, DRB_Activity_Item_sequence);

  return offset;
}


static const per_sequence_t DRB_Activity_List_sequence_of[1] = {
  { &hf_e1ap_DRB_Activity_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Activity_Item },
};

static int
dissect_e1ap_DRB_Activity_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Activity_List, DRB_Activity_List_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}



static int
dissect_e1ap_PDU_Session_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const value_string e1ap_PDU_Session_Resource_Activity_vals[] = {
  {   0, "active" },
  {   1, "not-active" },
  { 0, NULL }
};


static int
dissect_e1ap_PDU_Session_Resource_Activity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Activity_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_pDU_Session_Resource_Activity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_Activity },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_Activity_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_Activity_Item, PDU_Session_Resource_Activity_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Activity_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_Activity_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_Activity_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_Activity_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_Activity_List, PDU_Session_Resource_Activity_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const value_string e1ap_UE_Activity_vals[] = {
  {   0, "active" },
  {   1, "not-active" },
  { 0, NULL }
};


static int
dissect_e1ap_UE_Activity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_ActivityInformation_vals[] = {
  {   0, "dRB-Activity-List" },
  {   1, "pDU-Session-Resource-Activity-List" },
  {   2, "uE-Activity" },
  {   3, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ActivityInformation_choice[] = {
  {   0, &hf_e1ap_dRB_Activity_List, ASN1_NO_EXTENSIONS     , dissect_e1ap_DRB_Activity_List },
  {   1, &hf_e1ap_pDU_Session_Resource_Activity_List, ASN1_NO_EXTENSIONS     , dissect_e1ap_PDU_Session_Resource_Activity_List },
  {   2, &hf_e1ap_uE_Activity    , ASN1_NO_EXTENSIONS     , dissect_e1ap_UE_Activity },
  {   3, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_ActivityInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_ActivityInformation, ActivityInformation_choice,
                                 NULL);

  return offset;
}


static const value_string e1ap_ActivityNotificationLevel_vals[] = {
  {   0, "drb" },
  {   1, "pdu-session" },
  {   2, "ue" },
  { 0, NULL }
};


static int
dissect_e1ap_ActivityNotificationLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_AdditionalHandoverInfo_vals[] = {
  {   0, "discard-pdpc-SN" },
  { 0, NULL }
};


static int
dissect_e1ap_AdditionalHandoverInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_AdditionalPDCPduplicationInformation_vals[] = {
  {   0, "three" },
  {   1, "four" },
  { 0, NULL }
};


static int
dissect_e1ap_AdditionalPDCPduplicationInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_AdditionalRRMPriorityIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e1ap_AveragingWindow(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, true);

  return offset;
}



static int
dissect_e1ap_INTEGER_1_8_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8U, NULL, true);

  return offset;
}



static int
dissect_e1ap_BitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(4000000000000), NULL, true);

  return offset;
}



static int
dissect_e1ap_PacketDelayBudget(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, true);

  return offset;
}



static int
dissect_e1ap_PER_Scalar(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, true);

  return offset;
}



static int
dissect_e1ap_PER_Exponent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, true);

  return offset;
}


static const per_sequence_t PacketErrorRate_sequence[] = {
  { &hf_e1ap_pER_Scalar     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PER_Scalar },
  { &hf_e1ap_pER_Exponent   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PER_Exponent },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PacketErrorRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PacketErrorRate, PacketErrorRate_sequence);

  return offset;
}


static const per_sequence_t AlternativeQoSParaSetItem_sequence[] = {
  { &hf_e1ap_alternativeQoSParameterIndex, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_1_8_ },
  { &hf_e1ap_guaranteedFlowBitRateDL, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BitRate },
  { &hf_e1ap_guaranteedFlowBitRateUL, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BitRate },
  { &hf_e1ap_packetDelayBudget, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PacketDelayBudget },
  { &hf_e1ap_packetErrorRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PacketErrorRate },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_AlternativeQoSParaSetItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_AlternativeQoSParaSetItem, AlternativeQoSParaSetItem_sequence);

  return offset;
}


static const per_sequence_t AlternativeQoSParaSetList_sequence_of[1] = {
  { &hf_e1ap_AlternativeQoSParaSetList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_AlternativeQoSParaSetItem },
};

static int
dissect_e1ap_AlternativeQoSParaSetList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_AlternativeQoSParaSetList, AlternativeQoSParaSetList_sequence_of,
                                                  1, maxnoofQoSParaSets, false);

  return offset;
}



static int
dissect_e1ap_AssociatedSessionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}



static int
dissect_e1ap_OCTET_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}



static int
dissect_e1ap_OCTET_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}


static const per_sequence_t SNSSAI_sequence[] = {
  { &hf_e1ap_sST            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_OCTET_STRING_SIZE_1 },
  { &hf_e1ap_sD             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_OCTET_STRING_SIZE_3 },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_SNSSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_SNSSAI, SNSSAI_sequence);

  return offset;
}



static int
dissect_e1ap_TransportLayerAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, true, NULL, 0, &param_tvb, NULL);

  if (param_tvb) {
    proto_tree *subtree;
    int tvb_len;

    tvb_len = tvb_reported_length(param_tvb);
    subtree = proto_item_add_subtree(actx->created_item, ett_e1ap_TransportLayerAddress);
    if (tvb_len == 4) {
      /* IPv4 */
       proto_tree_add_item(subtree, hf_e1ap_transportLayerAddressIPv4, param_tvb, 0, 4, ENC_BIG_ENDIAN);
    } else if (tvb_len == 16) {
      /* IPv6 */
       proto_tree_add_item(subtree, hf_e1ap_transportLayerAddressIPv6, param_tvb, 0, 16, ENC_NA);
    } else if (tvb_len == 20) {
      /* IPv4 */
       proto_tree_add_item(subtree, hf_e1ap_transportLayerAddressIPv4, param_tvb, 0, 4, ENC_BIG_ENDIAN);
      /* IPv6 */
       proto_tree_add_item(subtree, hf_e1ap_transportLayerAddressIPv6, param_tvb, 4, 16, ENC_NA);
    }
  }


  return offset;
}



static int
dissect_e1ap_GTP_TEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}


static const per_sequence_t MBSNGUInformationAt5GC_Multicast_sequence[] = {
  { &hf_e1ap_ipmcAddress    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_ipsourceAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_gtpDLTEID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_GTP_TEID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBSNGUInformationAt5GC_Multicast(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBSNGUInformationAt5GC_Multicast, MBSNGUInformationAt5GC_Multicast_sequence);

  return offset;
}


static const value_string e1ap_MBSNGUInformationAt5GC_vals[] = {
  {   0, "multicast" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t MBSNGUInformationAt5GC_choice[] = {
  {   0, &hf_e1ap_multicast      , ASN1_NO_EXTENSIONS     , dissect_e1ap_MBSNGUInformationAt5GC_Multicast },
  {   1, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_MBSNGUInformationAt5GC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_MBSNGUInformationAt5GC, MBSNGUInformationAt5GC_choice,
                                 NULL);

  return offset;
}



static int
dissect_e1ap_MBSAreaSessionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, true);

  return offset;
}


static const per_sequence_t LocationDependentMBSNGUInformationAt5GC_Item_sequence[] = {
  { &hf_e1ap_mbsAreaSession_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSAreaSessionID },
  { &hf_e1ap_mbsNGUInformationAt5GC, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSNGUInformationAt5GC },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_LocationDependentMBSNGUInformationAt5GC_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_LocationDependentMBSNGUInformationAt5GC_Item, LocationDependentMBSNGUInformationAt5GC_Item_sequence);

  return offset;
}


static const per_sequence_t LocationDependentMBSNGUInformationAt5GC_sequence_of[1] = {
  { &hf_e1ap_LocationDependentMBSNGUInformationAt5GC_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_LocationDependentMBSNGUInformationAt5GC_Item },
};

static int
dissect_e1ap_LocationDependentMBSNGUInformationAt5GC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_LocationDependentMBSNGUInformationAt5GC, LocationDependentMBSNGUInformationAt5GC_sequence_of,
                                                  1, maxnoofMBSAreaSessionIDs, false);

  return offset;
}


static const value_string e1ap_BCBearerContextNGU_TNLInfoat5GC_vals[] = {
  {   0, "locationindependent" },
  {   1, "locationdependent" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t BCBearerContextNGU_TNLInfoat5GC_choice[] = {
  {   0, &hf_e1ap_locationindependent, ASN1_NO_EXTENSIONS     , dissect_e1ap_MBSNGUInformationAt5GC },
  {   1, &hf_e1ap_locationdependent, ASN1_NO_EXTENSIONS     , dissect_e1ap_LocationDependentMBSNGUInformationAt5GC },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextNGU_TNLInfoat5GC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_BCBearerContextNGU_TNLInfoat5GC, BCBearerContextNGU_TNLInfoat5GC_choice,
                                 NULL);

  return offset;
}



static int
dissect_e1ap_MRB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 512U, NULL, true);

  return offset;
}


static const value_string e1ap_PDCP_SN_Size_vals[] = {
  {   0, "s-12" },
  {   1, "s-18" },
  {   2, "s-7" },
  {   3, "s-15" },
  {   4, "s-16" },
  { 0, NULL }
};


static int
dissect_e1ap_PDCP_SN_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 3, NULL);

  return offset;
}


static const value_string e1ap_RLC_Mode_vals[] = {
  {   0, "rlc-tm" },
  {   1, "rlc-am" },
  {   2, "rlc-um-bidirectional" },
  {   3, "rlc-um-unidirectional-ul" },
  {   4, "rlc-um-unidirectional-dl" },
  { 0, NULL }
};


static int
dissect_e1ap_RLC_Mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_INTEGER_0_16383_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, true);

  return offset;
}



static int
dissect_e1ap_INTEGER_0_511_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, true);

  return offset;
}


static const value_string e1ap_T_continueROHC_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_T_continueROHC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t ROHC_sequence[] = {
  { &hf_e1ap_maxCID         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_16383_ },
  { &hf_e1ap_rOHC_Profiles  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_511_ },
  { &hf_e1ap_continueROHC   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_T_continueROHC },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ROHC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ROHC, ROHC_sequence);

  return offset;
}


static const value_string e1ap_T_continueROHC_01_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_T_continueROHC_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t UplinkOnlyROHC_sequence[] = {
  { &hf_e1ap_maxCID         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_16383_ },
  { &hf_e1ap_rOHC_Profiles  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_511_ },
  { &hf_e1ap_continueROHC_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_T_continueROHC_01 },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_UplinkOnlyROHC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_UplinkOnlyROHC, UplinkOnlyROHC_sequence);

  return offset;
}


static const value_string e1ap_ROHC_Parameters_vals[] = {
  {   0, "rOHC" },
  {   1, "uPlinkOnlyROHC" },
  {   2, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t ROHC_Parameters_choice[] = {
  {   0, &hf_e1ap_rOHC           , ASN1_NO_EXTENSIONS     , dissect_e1ap_ROHC },
  {   1, &hf_e1ap_uPlinkOnlyROHC , ASN1_NO_EXTENSIONS     , dissect_e1ap_UplinkOnlyROHC },
  {   2, &hf_e1ap_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_ROHC_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_ROHC_Parameters, ROHC_Parameters_choice,
                                 NULL);

  return offset;
}


static const value_string e1ap_T_Reordering_vals[] = {
  {   0, "ms0" },
  {   1, "ms1" },
  {   2, "ms2" },
  {   3, "ms4" },
  {   4, "ms5" },
  {   5, "ms8" },
  {   6, "ms10" },
  {   7, "ms15" },
  {   8, "ms20" },
  {   9, "ms30" },
  {  10, "ms40" },
  {  11, "ms50" },
  {  12, "ms60" },
  {  13, "ms80" },
  {  14, "ms100" },
  {  15, "ms120" },
  {  16, "ms140" },
  {  17, "ms160" },
  {  18, "ms180" },
  {  19, "ms200" },
  {  20, "ms220" },
  {  21, "ms240" },
  {  22, "ms260" },
  {  23, "ms280" },
  {  24, "ms300" },
  {  25, "ms500" },
  {  26, "ms750" },
  {  27, "ms1000" },
  {  28, "ms1250" },
  {  29, "ms1500" },
  {  30, "ms1750" },
  {  31, "ms2000" },
  {  32, "ms2250" },
  {  33, "ms2500" },
  {  34, "ms2750" },
  {  35, "ms3000" },
  { 0, NULL }
};

static value_string_ext e1ap_T_Reordering_vals_ext = VALUE_STRING_EXT_INIT(e1ap_T_Reordering_vals);


static int
dissect_e1ap_T_Reordering(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     36, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t T_ReorderingTimer_sequence[] = {
  { &hf_e1ap_t_Reordering   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_T_Reordering },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_T_ReorderingTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_T_ReorderingTimer, T_ReorderingTimer_sequence);

  return offset;
}


static const value_string e1ap_DiscardTimer_vals[] = {
  {   0, "ms10" },
  {   1, "ms20" },
  {   2, "ms30" },
  {   3, "ms40" },
  {   4, "ms50" },
  {   5, "ms60" },
  {   6, "ms75" },
  {   7, "ms100" },
  {   8, "ms150" },
  {   9, "ms200" },
  {  10, "ms250" },
  {  11, "ms300" },
  {  12, "ms500" },
  {  13, "ms750" },
  {  14, "ms1500" },
  {  15, "infinity" },
  { 0, NULL }
};


static int
dissect_e1ap_DiscardTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, false, 0, NULL);

  return offset;
}


static const value_string e1ap_ULDataSplitThreshold_vals[] = {
  {   0, "b0" },
  {   1, "b100" },
  {   2, "b200" },
  {   3, "b400" },
  {   4, "b800" },
  {   5, "b1600" },
  {   6, "b3200" },
  {   7, "b6400" },
  {   8, "b12800" },
  {   9, "b25600" },
  {  10, "b51200" },
  {  11, "b102400" },
  {  12, "b204800" },
  {  13, "b409600" },
  {  14, "b819200" },
  {  15, "b1228800" },
  {  16, "b1638400" },
  {  17, "b2457600" },
  {  18, "b3276800" },
  {  19, "b4096000" },
  {  20, "b4915200" },
  {  21, "b5734400" },
  {  22, "b6553600" },
  {  23, "infinity" },
  { 0, NULL }
};

static value_string_ext e1ap_ULDataSplitThreshold_vals_ext = VALUE_STRING_EXT_INIT(e1ap_ULDataSplitThreshold_vals);


static int
dissect_e1ap_ULDataSplitThreshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     24, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_PDCP_Duplication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_PDCP_Duplication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_PDCP_Reestablishment_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_PDCP_Reestablishment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_PDCP_DataRecovery_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_PDCP_DataRecovery(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_Duplication_Activation_vals[] = {
  {   0, "active" },
  {   1, "inactive" },
  { 0, NULL }
};


static int
dissect_e1ap_Duplication_Activation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_OutOfOrderDelivery_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_OutOfOrderDelivery(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PDCP_Configuration_sequence[] = {
  { &hf_e1ap_pDCP_SN_Size_UL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_SN_Size },
  { &hf_e1ap_pDCP_SN_Size_DL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_SN_Size },
  { &hf_e1ap_rLC_Mode       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_RLC_Mode },
  { &hf_e1ap_rOHC_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ROHC_Parameters },
  { &hf_e1ap_t_ReorderingTimer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_T_ReorderingTimer },
  { &hf_e1ap_discardTimer   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DiscardTimer },
  { &hf_e1ap_uLDataSplitThreshold, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ULDataSplitThreshold },
  { &hf_e1ap_pDCP_Duplication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_Duplication },
  { &hf_e1ap_pDCP_Reestablishment, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_Reestablishment },
  { &hf_e1ap_pDCP_DataRecovery, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_DataRecovery },
  { &hf_e1ap_duplication_Activation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Duplication_Activation },
  { &hf_e1ap_outOfOrderDelivery, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_OutOfOrderDelivery },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDCP_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDCP_Configuration, PDCP_Configuration_sequence);

  return offset;
}



static int
dissect_e1ap_QoS_Flow_Identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}



static int
dissect_e1ap_INTEGER_0_255_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, true);

  return offset;
}



static int
dissect_e1ap_QoSPriorityLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, true);

  return offset;
}



static int
dissect_e1ap_MaxDataBurstVolume(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, true);

  return offset;
}


static const per_sequence_t Non_Dynamic5QIDescriptor_sequence[] = {
  { &hf_e1ap_fiveQI         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_255_ },
  { &hf_e1ap_qoSPriorityLevel, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_QoSPriorityLevel },
  { &hf_e1ap_averagingWindow, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_AveragingWindow },
  { &hf_e1ap_maxDataBurstVolume, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_MaxDataBurstVolume },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Non_Dynamic5QIDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Non_Dynamic5QIDescriptor, Non_Dynamic5QIDescriptor_sequence);

  return offset;
}


static const value_string e1ap_T_delayCritical_vals[] = {
  {   0, "delay-critical" },
  {   1, "non-delay-critical" },
  { 0, NULL }
};


static int
dissect_e1ap_T_delayCritical(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t Dynamic5QIDescriptor_sequence[] = {
  { &hf_e1ap_qoSPriorityLevel, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_QoSPriorityLevel },
  { &hf_e1ap_packetDelayBudget, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PacketDelayBudget },
  { &hf_e1ap_packetErrorRate, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PacketErrorRate },
  { &hf_e1ap_fiveQI         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_INTEGER_0_255_ },
  { &hf_e1ap_delayCritical  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_T_delayCritical },
  { &hf_e1ap_averagingWindow, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_AveragingWindow },
  { &hf_e1ap_maxDataBurstVolume, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_MaxDataBurstVolume },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Dynamic5QIDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Dynamic5QIDescriptor, Dynamic5QIDescriptor_sequence);

  return offset;
}


static const value_string e1ap_QoS_Characteristics_vals[] = {
  {   0, "non-Dynamic-5QI" },
  {   1, "dynamic-5QI" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t QoS_Characteristics_choice[] = {
  {   0, &hf_e1ap_non_Dynamic_5QI, ASN1_NO_EXTENSIONS     , dissect_e1ap_Non_Dynamic5QIDescriptor },
  {   1, &hf_e1ap_dynamic_5QI    , ASN1_NO_EXTENSIONS     , dissect_e1ap_Dynamic5QIDescriptor },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_QoS_Characteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_QoS_Characteristics, QoS_Characteristics_choice,
                                 NULL);

  return offset;
}


static const value_string e1ap_PriorityLevel_vals[] = {
  {   0, "spare" },
  {   1, "highest" },
  {  14, "lowest" },
  {  15, "no-priority" },
  { 0, NULL }
};


static int
dissect_e1ap_PriorityLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}


static const value_string e1ap_Pre_emptionCapability_vals[] = {
  {   0, "shall-not-trigger-pre-emption" },
  {   1, "may-trigger-pre-emption" },
  { 0, NULL }
};


static int
dissect_e1ap_Pre_emptionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const value_string e1ap_Pre_emptionVulnerability_vals[] = {
  {   0, "not-pre-emptable" },
  {   1, "pre-emptable" },
  { 0, NULL }
};


static int
dissect_e1ap_Pre_emptionVulnerability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t NGRANAllocationAndRetentionPriority_sequence[] = {
  { &hf_e1ap_priorityLevel  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PriorityLevel },
  { &hf_e1ap_pre_emptionCapability, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Pre_emptionCapability },
  { &hf_e1ap_pre_emptionVulnerability, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Pre_emptionVulnerability },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_NGRANAllocationAndRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_NGRANAllocationAndRetentionPriority, NGRANAllocationAndRetentionPriority_sequence);

  return offset;
}



static int
dissect_e1ap_MaxPacketLossRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1000U, NULL, true);

  return offset;
}


static const per_sequence_t GBR_QoSFlowInformation_sequence[] = {
  { &hf_e1ap_maxFlowBitRateDownlink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BitRate },
  { &hf_e1ap_maxFlowBitRateUplink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BitRate },
  { &hf_e1ap_guaranteedFlowBitRateDownlink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BitRate },
  { &hf_e1ap_guaranteedFlowBitRateUplink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BitRate },
  { &hf_e1ap_maxPacketLossRateDownlink, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MaxPacketLossRate },
  { &hf_e1ap_maxPacketLossRateUplink, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MaxPacketLossRate },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GBR_QoSFlowInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GBR_QoSFlowInformation, GBR_QoSFlowInformation_sequence);

  return offset;
}


static const value_string e1ap_T_reflective_QoS_Attribute_vals[] = {
  {   0, "subject-to" },
  { 0, NULL }
};


static int
dissect_e1ap_T_reflective_QoS_Attribute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_T_additional_QoS_Information_vals[] = {
  {   0, "more-likely" },
  { 0, NULL }
};


static int
dissect_e1ap_T_additional_QoS_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_T_reflective_QoS_Indicator_vals[] = {
  {   0, "enabled" },
  { 0, NULL }
};


static int
dissect_e1ap_T_reflective_QoS_Indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t QoSFlowLevelQoSParameters_sequence[] = {
  { &hf_e1ap_qoS_Characteristics, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Characteristics },
  { &hf_e1ap_nGRANallocationRetentionPriority, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_NGRANAllocationAndRetentionPriority },
  { &hf_e1ap_gBR_QoS_Flow_Information, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_GBR_QoSFlowInformation },
  { &hf_e1ap_reflective_QoS_Attribute, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_T_reflective_QoS_Attribute },
  { &hf_e1ap_additional_QoS_Information, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_T_additional_QoS_Information },
  { &hf_e1ap_paging_Policy_Index, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_INTEGER_1_8_ },
  { &hf_e1ap_reflective_QoS_Indicator, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_T_reflective_QoS_Indicator },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_QoSFlowLevelQoSParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_QoSFlowLevelQoSParameters, QoSFlowLevelQoSParameters_sequence);

  return offset;
}


static const value_string e1ap_QoS_Flow_Mapping_Indication_vals[] = {
  {   0, "ul" },
  {   1, "dl" },
  { 0, NULL }
};


static int
dissect_e1ap_QoS_Flow_Mapping_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t QoS_Flow_QoS_Parameter_Item_sequence[] = {
  { &hf_e1ap_qoS_Flow_Identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Identifier },
  { &hf_e1ap_qoSFlowLevelQoSParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoSFlowLevelQoSParameters },
  { &hf_e1ap_qoSFlowMappingIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_Mapping_Indication },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_QoS_Flow_QoS_Parameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_QoS_Flow_QoS_Parameter_Item, QoS_Flow_QoS_Parameter_Item_sequence);

  return offset;
}


static const per_sequence_t QoS_Flow_QoS_Parameter_List_sequence_of[1] = {
  { &hf_e1ap_QoS_Flow_QoS_Parameter_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_QoS_Parameter_Item },
};

static int
dissect_e1ap_QoS_Flow_QoS_Parameter_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_QoS_Flow_QoS_Parameter_List, QoS_Flow_QoS_Parameter_List_sequence_of,
                                                  1, maxnoofQoSFlows, false);

  return offset;
}


static const per_sequence_t BCMRBSetupConfiguration_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_mbs_pdcp_config, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Configuration },
  { &hf_e1ap_qoS_Flow_QoS_Parameter_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_QoS_Parameter_List },
  { &hf_e1ap_qoSFlowLevelQoSParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoSFlowLevelQoSParameters },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCMRBSetupConfiguration_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCMRBSetupConfiguration_Item, BCMRBSetupConfiguration_Item_sequence);

  return offset;
}


static const per_sequence_t BCMRBSetupConfiguration_sequence_of[1] = {
  { &hf_e1ap_BCMRBSetupConfiguration_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_BCMRBSetupConfiguration_Item },
};

static int
dissect_e1ap_BCMRBSetupConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_BCMRBSetupConfiguration, BCMRBSetupConfiguration_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const value_string e1ap_RequestedAction4AvailNGUTermination_vals[] = {
  {   0, "apply-available-configuration" },
  {   1, "apply-requested-configuration" },
  {   2, "apply-available-configuration-if-same-as-requested" },
  { 0, NULL }
};


static int
dissect_e1ap_RequestedAction4AvailNGUTermination(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 1, NULL);

  return offset;
}


static const per_sequence_t BCBearerContextToSetup_sequence[] = {
  { &hf_e1ap_snssai         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SNSSAI },
  { &hf_e1ap_bcBearerContextNGU_TNLInfoat5GC, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCBearerContextNGU_TNLInfoat5GC },
  { &hf_e1ap_bcMRBToSetupList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BCMRBSetupConfiguration },
  { &hf_e1ap_requestedAction, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_RequestedAction4AvailNGUTermination },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextToSetup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextToSetup, BCBearerContextToSetup_sequence);

  return offset;
}


static const per_sequence_t GTPTunnel_sequence[] = {
  { &hf_e1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_GTP_TEID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GTPTunnel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GTPTunnel, GTPTunnel_sequence);

  return offset;
}


static const value_string e1ap_UP_TNL_Information_vals[] = {
  {   0, "gTPTunnel" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t UP_TNL_Information_choice[] = {
  {   0, &hf_e1ap_gTPTunnel      , ASN1_NO_EXTENSIONS     , dissect_e1ap_GTPTunnel },
  {   1, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_UP_TNL_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_UP_TNL_Information, UP_TNL_Information_choice,
                                 NULL);

  return offset;
}


static const value_string e1ap_MBSNGUInformationAtNGRAN_vals[] = {
  {   0, "unicast" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t MBSNGUInformationAtNGRAN_choice[] = {
  {   0, &hf_e1ap_unicast        , ASN1_NO_EXTENSIONS     , dissect_e1ap_UP_TNL_Information },
  {   1, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_MBSNGUInformationAtNGRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_MBSNGUInformationAtNGRAN, MBSNGUInformationAtNGRAN_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t LocationDependentMBSNGUInformationAtNGRAN_Item_sequence[] = {
  { &hf_e1ap_mbsAreaSession_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSAreaSessionID },
  { &hf_e1ap_mbsNGUInformationAtNGRAN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSNGUInformationAtNGRAN },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_LocationDependentMBSNGUInformationAtNGRAN_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_LocationDependentMBSNGUInformationAtNGRAN_Item, LocationDependentMBSNGUInformationAtNGRAN_Item_sequence);

  return offset;
}


static const per_sequence_t LocationDependentMBSNGUInformationAtNGRAN_sequence_of[1] = {
  { &hf_e1ap_LocationDependentMBSNGUInformationAtNGRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_LocationDependentMBSNGUInformationAtNGRAN_Item },
};

static int
dissect_e1ap_LocationDependentMBSNGUInformationAtNGRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_LocationDependentMBSNGUInformationAtNGRAN, LocationDependentMBSNGUInformationAtNGRAN_sequence_of,
                                                  1, maxnoofMBSAreaSessionIDs, false);

  return offset;
}


static const value_string e1ap_BCBearerContextNGU_TNLInfoatNGRAN_vals[] = {
  {   0, "locationindependent" },
  {   1, "locationdependent" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t BCBearerContextNGU_TNLInfoatNGRAN_choice[] = {
  {   0, &hf_e1ap_locationindependent_01, ASN1_NO_EXTENSIONS     , dissect_e1ap_MBSNGUInformationAtNGRAN },
  {   1, &hf_e1ap_locationdependent_01, ASN1_NO_EXTENSIONS     , dissect_e1ap_LocationDependentMBSNGUInformationAtNGRAN },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextNGU_TNLInfoatNGRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_BCBearerContextNGU_TNLInfoatNGRAN, BCBearerContextNGU_TNLInfoatNGRAN_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t QoS_Flow_Item_sequence[] = {
  { &hf_e1ap_qoS_Flow_Identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Identifier },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_QoS_Flow_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_QoS_Flow_Item, QoS_Flow_Item_sequence);

  return offset;
}


static const per_sequence_t QoS_Flow_List_sequence_of[1] = {
  { &hf_e1ap_QoS_Flow_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Item },
};

static int
dissect_e1ap_QoS_Flow_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_QoS_Flow_List, QoS_Flow_List_sequence_of,
                                                  1, maxnoofQoSFlows, false);

  return offset;
}


static const value_string e1ap_CauseRadioNetwork_vals[] = {
  {   0, "unspecified" },
  {   1, "unknown-or-already-allocated-gnb-cu-cp-ue-e1ap-id" },
  {   2, "unknown-or-already-allocated-gnb-cu-up-ue-e1ap-id" },
  {   3, "unknown-or-inconsistent-pair-of-ue-e1ap-id" },
  {   4, "interaction-with-other-procedure" },
  {   5, "pPDCP-Count-wrap-around" },
  {   6, "not-supported-QCI-value" },
  {   7, "not-supported-5QI-value" },
  {   8, "encryption-algorithms-not-supported" },
  {   9, "integrity-protection-algorithms-not-supported" },
  {  10, "uP-integrity-protection-not-possible" },
  {  11, "uP-confidentiality-protection-not-possible" },
  {  12, "multiple-PDU-Session-ID-Instances" },
  {  13, "unknown-PDU-Session-ID" },
  {  14, "multiple-QoS-Flow-ID-Instances" },
  {  15, "unknown-QoS-Flow-ID" },
  {  16, "multiple-DRB-ID-Instances" },
  {  17, "unknown-DRB-ID" },
  {  18, "invalid-QoS-combination" },
  {  19, "procedure-cancelled" },
  {  20, "normal-release" },
  {  21, "no-radio-resources-available" },
  {  22, "action-desirable-for-radio-reasons" },
  {  23, "resources-not-available-for-the-slice" },
  {  24, "pDCP-configuration-not-supported" },
  {  25, "ue-dl-max-IP-data-rate-reason" },
  {  26, "uP-integrity-protection-failure" },
  {  27, "release-due-to-pre-emption" },
  {  28, "rsn-not-available-for-the-up" },
  {  29, "nPN-not-supported" },
  {  30, "report-characteristic-empty" },
  {  31, "existing-measurement-ID" },
  {  32, "measurement-temporarily-not-available" },
  {  33, "measurement-not-supported-for-the-object" },
  {  34, "scg-activation-deactivation-failure" },
  {  35, "scg-deactivation-failure-due-to-data-transmission" },
  {  36, "unknown-or-already-allocated-gNB-CU-CP-MBS-E1AP-ID" },
  {  37, "unknown-or-already-allocated-gNB-CU-UP-MBS-E1AP-ID" },
  {  38, "unknown-or-inconsistent-pair-of-MBS-E1AP-ID" },
  {  39, "unknown-or-inconsistent-MRB-ID" },
  { 0, NULL }
};

static value_string_ext e1ap_CauseRadioNetwork_vals_ext = VALUE_STRING_EXT_INIT(e1ap_CauseRadioNetwork_vals);


static int
dissect_e1ap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     25, NULL, true, 15, NULL);

  return offset;
}


static const value_string e1ap_CauseTransport_vals[] = {
  {   0, "unspecified" },
  {   1, "transport-resource-unavailable" },
  {   2, "unknown-TNL-address-for-IAB" },
  { 0, NULL }
};


static int
dissect_e1ap_CauseTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 1, NULL);

  return offset;
}


static const value_string e1ap_CauseProtocol_vals[] = {
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
dissect_e1ap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_CauseMisc_vals[] = {
  {   0, "control-processing-overload" },
  {   1, "not-enough-user-plane-processing-resources" },
  {   2, "hardware-failure" },
  {   3, "om-intervention" },
  {   4, "unspecified" },
  { 0, NULL }
};


static int
dissect_e1ap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transport" },
  {   2, "protocol" },
  {   3, "misc" },
  {   4, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_e1ap_radioNetwork   , ASN1_NO_EXTENSIONS     , dissect_e1ap_CauseRadioNetwork },
  {   1, &hf_e1ap_transport      , ASN1_NO_EXTENSIONS     , dissect_e1ap_CauseTransport },
  {   2, &hf_e1ap_protocol       , ASN1_NO_EXTENSIONS     , dissect_e1ap_CauseProtocol },
  {   3, &hf_e1ap_misc           , ASN1_NO_EXTENSIONS     , dissect_e1ap_CauseMisc },
  {   4, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_Cause, Cause_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t QoS_Flow_Failed_Item_sequence[] = {
  { &hf_e1ap_qoS_Flow_Identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Identifier },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_QoS_Flow_Failed_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_QoS_Flow_Failed_Item, QoS_Flow_Failed_Item_sequence);

  return offset;
}


static const per_sequence_t QoS_Flow_Failed_List_sequence_of[1] = {
  { &hf_e1ap_QoS_Flow_Failed_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Failed_Item },
};

static int
dissect_e1ap_QoS_Flow_Failed_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_QoS_Flow_Failed_List, QoS_Flow_Failed_List_sequence_of,
                                                  1, maxnoofQoSFlows, false);

  return offset;
}


static const per_sequence_t MBSF1UInformationAtCU_sequence[] = {
  { &hf_e1ap_mbs_f1u_info_at_CU, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBSF1UInformationAtCU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBSF1UInformationAtCU, MBSF1UInformationAtCU_sequence);

  return offset;
}


static const per_sequence_t LocationDependentMBSF1UInformationAtCU_Item_sequence[] = {
  { &hf_e1ap_mbsAreaSession_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSAreaSessionID },
  { &hf_e1ap_mbs_f1u_info_at_CU, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_LocationDependentMBSF1UInformationAtCU_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_LocationDependentMBSF1UInformationAtCU_Item, LocationDependentMBSF1UInformationAtCU_Item_sequence);

  return offset;
}


static const per_sequence_t LocationDependentMBSF1UInformationAtCU_sequence_of[1] = {
  { &hf_e1ap_LocationDependentMBSF1UInformationAtCU_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_LocationDependentMBSF1UInformationAtCU_Item },
};

static int
dissect_e1ap_LocationDependentMBSF1UInformationAtCU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_LocationDependentMBSF1UInformationAtCU, LocationDependentMBSF1UInformationAtCU_sequence_of,
                                                  1, maxnoofMBSAreaSessionIDs, false);

  return offset;
}


static const value_string e1ap_BCBearerContextF1U_TNLInfoatCU_vals[] = {
  {   0, "locationindependent" },
  {   1, "locationdependent" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t BCBearerContextF1U_TNLInfoatCU_choice[] = {
  {   0, &hf_e1ap_locationindependent_02, ASN1_NO_EXTENSIONS     , dissect_e1ap_MBSF1UInformationAtCU },
  {   1, &hf_e1ap_locationdependent_02, ASN1_NO_EXTENSIONS     , dissect_e1ap_LocationDependentMBSF1UInformationAtCU },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextF1U_TNLInfoatCU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_BCBearerContextF1U_TNLInfoatCU, BCBearerContextF1U_TNLInfoatCU_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BCMRBSetupResponseList_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_qosflow_setup  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_List },
  { &hf_e1ap_qosflow_failed , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_Failed_List },
  { &hf_e1ap_bcBearerContextF1U_TNLInfoatCU, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BCBearerContextF1U_TNLInfoatCU },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCMRBSetupResponseList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCMRBSetupResponseList_Item, BCMRBSetupResponseList_Item_sequence);

  return offset;
}


static const per_sequence_t BCMRBSetupResponseList_sequence_of[1] = {
  { &hf_e1ap_BCMRBSetupResponseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_BCMRBSetupResponseList_Item },
};

static int
dissect_e1ap_BCMRBSetupResponseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_BCMRBSetupResponseList, BCMRBSetupResponseList_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const per_sequence_t BCMRBFailedList_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCMRBFailedList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCMRBFailedList_Item, BCMRBFailedList_Item_sequence);

  return offset;
}


static const per_sequence_t BCMRBFailedList_sequence_of[1] = {
  { &hf_e1ap_BCMRBFailedList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_BCMRBFailedList_Item },
};

static int
dissect_e1ap_BCMRBFailedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_BCMRBFailedList, BCMRBFailedList_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const per_sequence_t BCBearerContextToSetupResponse_sequence[] = {
  { &hf_e1ap_bcBearerContextNGU_TNLInfoatNGRAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCBearerContextNGU_TNLInfoatNGRAN },
  { &hf_e1ap_bcMRBSetupResponseList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BCMRBSetupResponseList },
  { &hf_e1ap_bcMRBFailedList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCMRBFailedList },
  { &hf_e1ap_availableBCMRBConfig, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCMRBSetupConfiguration },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextToSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextToSetupResponse, BCBearerContextToSetupResponse_sequence);

  return offset;
}


static const per_sequence_t MBSF1UInformationAtDU_sequence[] = {
  { &hf_e1ap_mbs_f1u_info_at_DU, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBSF1UInformationAtDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBSF1UInformationAtDU, MBSF1UInformationAtDU_sequence);

  return offset;
}


static const per_sequence_t LocationDependentMBSF1UInformationAtDU_Item_sequence[] = {
  { &hf_e1ap_mbsAreaSession_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSAreaSessionID },
  { &hf_e1ap_mbs_f1u_info_at_DU, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_LocationDependentMBSF1UInformationAtDU_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_LocationDependentMBSF1UInformationAtDU_Item, LocationDependentMBSF1UInformationAtDU_Item_sequence);

  return offset;
}


static const per_sequence_t LocationDependentMBSF1UInformationAtDU_sequence_of[1] = {
  { &hf_e1ap_LocationDependentMBSF1UInformationAtDU_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_LocationDependentMBSF1UInformationAtDU_Item },
};

static int
dissect_e1ap_LocationDependentMBSF1UInformationAtDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_LocationDependentMBSF1UInformationAtDU, LocationDependentMBSF1UInformationAtDU_sequence_of,
                                                  1, maxnoofMBSAreaSessionIDs, false);

  return offset;
}


static const value_string e1ap_BCBearerContextF1U_TNLInfoatDU_vals[] = {
  {   0, "locationindependent" },
  {   1, "locationdependent" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t BCBearerContextF1U_TNLInfoatDU_choice[] = {
  {   0, &hf_e1ap_locationindependent_04, ASN1_NO_EXTENSIONS     , dissect_e1ap_MBSF1UInformationAtDU },
  {   1, &hf_e1ap_locationdependent_04, ASN1_NO_EXTENSIONS     , dissect_e1ap_LocationDependentMBSF1UInformationAtDU },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextF1U_TNLInfoatDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_BCBearerContextF1U_TNLInfoatDU, BCBearerContextF1U_TNLInfoatDU_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BCMRBModifyConfiguration_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_bcBearerContextF1U_TNLInfoatDU, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCBearerContextF1U_TNLInfoatDU },
  { &hf_e1ap_mbs_pdcp_config, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_Configuration },
  { &hf_e1ap_qoS_Flow_QoS_Parameter_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_QoS_Parameter_List },
  { &hf_e1ap_qoSFlowLevelQoSParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoSFlowLevelQoSParameters },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCMRBModifyConfiguration_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCMRBModifyConfiguration_Item, BCMRBModifyConfiguration_Item_sequence);

  return offset;
}


static const per_sequence_t BCMRBModifyConfiguration_sequence_of[1] = {
  { &hf_e1ap_BCMRBModifyConfiguration_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_BCMRBModifyConfiguration_Item },
};

static int
dissect_e1ap_BCMRBModifyConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_BCMRBModifyConfiguration, BCMRBModifyConfiguration_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const per_sequence_t BCMRBRemoveConfiguration_sequence_of[1] = {
  { &hf_e1ap_BCMRBRemoveConfiguration_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
};

static int
dissect_e1ap_BCMRBRemoveConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_BCMRBRemoveConfiguration, BCMRBRemoveConfiguration_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const per_sequence_t BCBearerContextToModify_sequence[] = {
  { &hf_e1ap_bcBearerContextNGU_TNLInfoat5GC, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCBearerContextNGU_TNLInfoat5GC },
  { &hf_e1ap_bcMRBToSetupList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCMRBSetupConfiguration },
  { &hf_e1ap_bcMRBToModifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCMRBModifyConfiguration },
  { &hf_e1ap_bcMRBToRemoveList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCMRBRemoveConfiguration },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextToModify(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextToModify, BCBearerContextToModify_sequence);

  return offset;
}


static const value_string e1ap_MBSNGUInformationAtNGRAN_Request_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_MBSNGUInformationAtNGRAN_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MBSNGUInformationAtNGRAN_Request_Item_sequence[] = {
  { &hf_e1ap_mbsAreaSession_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSAreaSessionID },
  { &hf_e1ap_mbsNGUInformationAtNGRAN_Request, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSNGUInformationAtNGRAN_Request },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBSNGUInformationAtNGRAN_Request_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBSNGUInformationAtNGRAN_Request_Item, MBSNGUInformationAtNGRAN_Request_Item_sequence);

  return offset;
}


static const per_sequence_t MBSNGUInformationAtNGRAN_Request_List_sequence_of[1] = {
  { &hf_e1ap_MBSNGUInformationAtNGRAN_Request_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSNGUInformationAtNGRAN_Request_Item },
};

static int
dissect_e1ap_MBSNGUInformationAtNGRAN_Request_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MBSNGUInformationAtNGRAN_Request_List, MBSNGUInformationAtNGRAN_Request_List_sequence_of,
                                                  1, maxnoofMBSAreaSessionIDs, false);

  return offset;
}


static const value_string e1ap_BCBearerContextNGU_TNLInfoatNGRAN_Request_vals[] = {
  {   0, "locationindependent" },
  {   1, "locationdependent" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t BCBearerContextNGU_TNLInfoatNGRAN_Request_choice[] = {
  {   0, &hf_e1ap_locationindependent_03, ASN1_NO_EXTENSIONS     , dissect_e1ap_MBSNGUInformationAtNGRAN_Request },
  {   1, &hf_e1ap_locationdependent_03, ASN1_NO_EXTENSIONS     , dissect_e1ap_MBSNGUInformationAtNGRAN_Request_List },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextNGU_TNLInfoatNGRAN_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_BCBearerContextNGU_TNLInfoatNGRAN_Request, BCBearerContextNGU_TNLInfoatNGRAN_Request_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BCMRBSetupModifyResponseList_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_qosflow_setup  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_List },
  { &hf_e1ap_qosflow_failed , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_Failed_List },
  { &hf_e1ap_bcBearerContextF1U_TNLInfoatCU, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCBearerContextF1U_TNLInfoatCU },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCMRBSetupModifyResponseList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCMRBSetupModifyResponseList_Item, BCMRBSetupModifyResponseList_Item_sequence);

  return offset;
}


static const per_sequence_t BCMRBSetupModifyResponseList_sequence_of[1] = {
  { &hf_e1ap_BCMRBSetupModifyResponseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_BCMRBSetupModifyResponseList_Item },
};

static int
dissect_e1ap_BCMRBSetupModifyResponseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_BCMRBSetupModifyResponseList, BCMRBSetupModifyResponseList_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const per_sequence_t BCBearerContextToModifyResponse_sequence[] = {
  { &hf_e1ap_bcBearerContextNGU_TNLInfoatNGRAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCBearerContextNGU_TNLInfoatNGRAN },
  { &hf_e1ap_bcMRBSetupModifyResponseList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BCMRBSetupModifyResponseList },
  { &hf_e1ap_bcMRBFailedList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCMRBFailedList },
  { &hf_e1ap_availableBCMRBConfig, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCMRBSetupConfiguration },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextToModifyResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextToModifyResponse, BCBearerContextToModifyResponse_sequence);

  return offset;
}



static int
dissect_e1ap_BroadcastF1U_ContextReferenceE1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}


static const per_sequence_t BCBearerContextToModifyRequired_sequence[] = {
  { &hf_e1ap_bcMRBToRemoveList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCMRBRemoveConfiguration },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextToModifyRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextToModifyRequired, BCBearerContextToModifyRequired_sequence);

  return offset;
}


static const per_sequence_t BCBearerContextToModifyConfirm_sequence[] = {
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextToModifyConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextToModifyConfirm, BCBearerContextToModifyConfirm_sequence);

  return offset;
}


static const value_string e1ap_BearerContextStatusChange_vals[] = {
  {   0, "suspend" },
  {   1, "resume" },
  {   2, "resumeforSDT" },
  { 0, NULL }
};


static int
dissect_e1ap_BearerContextStatusChange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 1, NULL);

  return offset;
}


static const value_string e1ap_BufferSize_vals[] = {
  {   0, "kbyte2" },
  {   1, "kbyte4" },
  {   2, "kbyte8" },
  { 0, NULL }
};


static int
dissect_e1ap_BufferSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_Cell_Group_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, true);

  return offset;
}


static const value_string e1ap_UL_Configuration_vals[] = {
  {   0, "no-data" },
  {   1, "shared" },
  {   2, "only" },
  { 0, NULL }
};


static int
dissect_e1ap_UL_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_DL_TX_Stop_vals[] = {
  {   0, "stop" },
  {   1, "resume" },
  { 0, NULL }
};


static int
dissect_e1ap_DL_TX_Stop(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_RAT_Type_vals[] = {
  {   0, "e-UTRA" },
  {   1, "nR" },
  { 0, NULL }
};


static int
dissect_e1ap_RAT_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t Cell_Group_Information_Item_sequence[] = {
  { &hf_e1ap_cell_Group_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cell_Group_ID },
  { &hf_e1ap_uL_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UL_Configuration },
  { &hf_e1ap_dL_TX_Stop     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DL_TX_Stop },
  { &hf_e1ap_rAT_Type       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_RAT_Type },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Cell_Group_Information_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Cell_Group_Information_Item, Cell_Group_Information_Item_sequence);

  return offset;
}


static const per_sequence_t Cell_Group_Information_sequence_of[1] = {
  { &hf_e1ap_Cell_Group_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Cell_Group_Information_Item },
};

static int
dissect_e1ap_Cell_Group_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_Cell_Group_Information, Cell_Group_Information_sequence_of,
                                                  1, maxnoofCellGroups, false);

  return offset;
}


static const value_string e1ap_CHOInitiation_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_CHOInitiation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_Number_of_tunnels(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4U, NULL, true);

  return offset;
}


static const value_string e1ap_CipheringAlgorithm_vals[] = {
  {   0, "nEA0" },
  {   1, "c-128-NEA1" },
  {   2, "c-128-NEA2" },
  {   3, "c-128-NEA3" },
  { 0, NULL }
};


static int
dissect_e1ap_CipheringAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_CNSupport_vals[] = {
  {   0, "c-epc" },
  {   1, "c-5gc" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_e1ap_CNSupport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_CommonNetworkInstance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const value_string e1ap_ConfidentialityProtectionIndication_vals[] = {
  {   0, "required" },
  {   1, "preferred" },
  {   2, "not-needed" },
  { 0, NULL }
};


static int
dissect_e1ap_ConfidentialityProtectionIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_ConfidentialityProtectionResult_vals[] = {
  {   0, "performed" },
  {   1, "not-performed" },
  { 0, NULL }
};


static int
dissect_e1ap_ConfidentialityProtectionResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_CP_TNL_Information_vals[] = {
  {   0, "endpoint-IP-Address" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t CP_TNL_Information_choice[] = {
  {   0, &hf_e1ap_endpoint_IP_Address, ASN1_NO_EXTENSIONS     , dissect_e1ap_TransportLayerAddress },
  {   1, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_CP_TNL_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_CP_TNL_Information, CP_TNL_Information_choice,
                                 NULL);

  return offset;
}



static int
dissect_e1ap_TransactionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, true);

  return offset;
}


static const value_string e1ap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_e1ap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_e1ap_iECriticality  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Criticality },
  { &hf_e1ap_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_ID },
  { &hf_e1ap_typeOfError    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TypeOfError },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_e1ap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_e1ap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxnoofErrors, false);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_e1ap_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProcedureCode },
  { &hf_e1ap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_TriggeringMessage },
  { &hf_e1ap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Criticality },
  { &hf_e1ap_transactionID  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_TransactionID },
  { &hf_e1ap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_CriticalityDiagnostics_IE_List },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}


static const value_string e1ap_T_dapsIndicator_vals[] = {
  {   0, "daps-HO-required" },
  { 0, NULL }
};


static int
dissect_e1ap_T_dapsIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t DAPSRequestInfo_sequence[] = {
  { &hf_e1ap_dapsIndicator  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_T_dapsIndicator },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DAPSRequestInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DAPSRequestInfo, DAPSRequestInfo_sequence);

  return offset;
}


static const value_string e1ap_Data_Forwarding_Request_vals[] = {
  {   0, "uL" },
  {   1, "dL" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_e1ap_Data_Forwarding_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t QoS_Flow_Mapping_Item_sequence[] = {
  { &hf_e1ap_qoS_Flow_Identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Identifier },
  { &hf_e1ap_qoSFlowMappingIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_Mapping_Indication },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_QoS_Flow_Mapping_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_QoS_Flow_Mapping_Item, QoS_Flow_Mapping_Item_sequence);

  return offset;
}


static const per_sequence_t QoS_Flow_Mapping_List_sequence_of[1] = {
  { &hf_e1ap_QoS_Flow_Mapping_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Mapping_Item },
};

static int
dissect_e1ap_QoS_Flow_Mapping_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_QoS_Flow_Mapping_List, QoS_Flow_Mapping_List_sequence_of,
                                                  1, maxnoofQoSFlows, false);

  return offset;
}


static const per_sequence_t Data_Forwarding_Information_Request_sequence[] = {
  { &hf_e1ap_data_Forwarding_Request, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Data_Forwarding_Request },
  { &hf_e1ap_qoS_Flows_Forwarded_On_Fwd_Tunnels, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_Mapping_List },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Data_Forwarding_Information_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Data_Forwarding_Information_Request, Data_Forwarding_Information_Request_sequence);

  return offset;
}


static const per_sequence_t Data_Forwarding_Information_sequence[] = {
  { &hf_e1ap_uL_Data_Forwarding, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_dL_Data_Forwarding, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Data_Forwarding_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Data_Forwarding_Information, Data_Forwarding_Information_sequence);

  return offset;
}


static const per_sequence_t QoS_Flows_to_be_forwarded_Item_sequence[] = {
  { &hf_e1ap_qoS_Flow_Identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Identifier },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_QoS_Flows_to_be_forwarded_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_QoS_Flows_to_be_forwarded_Item, QoS_Flows_to_be_forwarded_Item_sequence);

  return offset;
}


static const per_sequence_t QoS_Flows_to_be_forwarded_List_sequence_of[1] = {
  { &hf_e1ap_QoS_Flows_to_be_forwarded_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flows_to_be_forwarded_Item },
};

static int
dissect_e1ap_QoS_Flows_to_be_forwarded_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_QoS_Flows_to_be_forwarded_List, QoS_Flows_to_be_forwarded_List_sequence_of,
                                                  1, maxnoofQoSFlows, false);

  return offset;
}


static const per_sequence_t DataForwardingtoE_UTRANInformationListItem_sequence[] = {
  { &hf_e1ap_data_forwarding_tunnel_information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_qoS_Flows_to_be_forwarded_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flows_to_be_forwarded_List },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DataForwardingtoE_UTRANInformationListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DataForwardingtoE_UTRANInformationListItem, DataForwardingtoE_UTRANInformationListItem_sequence);

  return offset;
}


static const per_sequence_t DataForwardingtoE_UTRANInformationList_sequence_of[1] = {
  { &hf_e1ap_DataForwardingtoE_UTRANInformationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DataForwardingtoE_UTRANInformationListItem },
};

static int
dissect_e1ap_DataForwardingtoE_UTRANInformationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DataForwardingtoE_UTRANInformationList, DataForwardingtoE_UTRANInformationList_sequence_of,
                                                  1, maxnoofDataForwardingTunneltoE_UTRAN, false);

  return offset;
}


static const value_string e1ap_T_secondaryRATType_vals[] = {
  {   0, "nR" },
  {   1, "e-UTRA" },
  { 0, NULL }
};


static int
dissect_e1ap_T_secondaryRATType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_T_startTimeStamp_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *timestamp_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, &timestamp_tvb);



  if (timestamp_tvb) {
    proto_item_append_text(actx->created_item, " (%s)", tvb_ntp_fmt_ts_sec(timestamp_tvb, 0));
  }

  return offset;
}



static int
dissect_e1ap_T_endTimeStamp_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *timestamp_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, &timestamp_tvb);



  if (timestamp_tvb) {
    proto_item_append_text(actx->created_item, " (%s)", tvb_ntp_fmt_ts_sec(timestamp_tvb, 0));
  }

  return offset;
}



static int
dissect_e1ap_INTEGER_0_18446744073709551615(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(18446744073709551615), NULL, false);

  return offset;
}


static const per_sequence_t MRDC_Data_Usage_Report_Item_sequence[] = {
  { &hf_e1ap_startTimeStamp_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_T_startTimeStamp_01 },
  { &hf_e1ap_endTimeStamp_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_T_endTimeStamp_01 },
  { &hf_e1ap_usageCountUL   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_18446744073709551615 },
  { &hf_e1ap_usageCountDL   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_18446744073709551615 },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MRDC_Data_Usage_Report_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MRDC_Data_Usage_Report_Item, MRDC_Data_Usage_Report_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item_sequence_of[1] = {
  { &hf_e1ap_pDU_session_Timed_Report_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MRDC_Data_Usage_Report_Item },
};

static int
dissect_e1ap_SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item, SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item_sequence_of,
                                                  1, maxnooftimeperiods, false);

  return offset;
}


static const per_sequence_t Data_Usage_per_PDU_Session_Report_sequence[] = {
  { &hf_e1ap_secondaryRATType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_T_secondaryRATType },
  { &hf_e1ap_pDU_session_Timed_Report_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Data_Usage_per_PDU_Session_Report(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Data_Usage_per_PDU_Session_Report, Data_Usage_per_PDU_Session_Report_sequence);

  return offset;
}


static const value_string e1ap_T_secondaryRATType_01_vals[] = {
  {   0, "nR" },
  {   1, "e-UTRA" },
  { 0, NULL }
};


static int
dissect_e1ap_T_secondaryRATType_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t Data_Usage_per_QoS_Flow_Item_sequence[] = {
  { &hf_e1ap_qoS_Flow_Identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Identifier },
  { &hf_e1ap_secondaryRATType_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_T_secondaryRATType_01 },
  { &hf_e1ap_qoS_Flow_Timed_Report_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Data_Usage_per_QoS_Flow_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Data_Usage_per_QoS_Flow_Item, Data_Usage_per_QoS_Flow_Item_sequence);

  return offset;
}


static const per_sequence_t Data_Usage_per_QoS_Flow_List_sequence_of[1] = {
  { &hf_e1ap_Data_Usage_per_QoS_Flow_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Data_Usage_per_QoS_Flow_Item },
};

static int
dissect_e1ap_Data_Usage_per_QoS_Flow_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_Data_Usage_per_QoS_Flow_List, Data_Usage_per_QoS_Flow_List_sequence_of,
                                                  1, maxnoofQoSFlows, false);

  return offset;
}



static int
dissect_e1ap_T_startTimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *timestamp_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, &timestamp_tvb);



  if (timestamp_tvb) {
    proto_item_append_text(actx->created_item, " (%s)", tvb_ntp_fmt_ts_sec(timestamp_tvb, 0));
  }

  return offset;
}



static int
dissect_e1ap_T_endTimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *timestamp_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, &timestamp_tvb);



  if (timestamp_tvb) {
    proto_item_append_text(actx->created_item, " (%s)", tvb_ntp_fmt_ts_sec(timestamp_tvb, 0));
  }

  return offset;
}


static const per_sequence_t DRB_Usage_Report_Item_sequence[] = {
  { &hf_e1ap_startTimeStamp , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_T_startTimeStamp },
  { &hf_e1ap_endTimeStamp   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_T_endTimeStamp },
  { &hf_e1ap_usageCountUL   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_18446744073709551615 },
  { &hf_e1ap_usageCountDL   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_18446744073709551615 },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Usage_Report_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Usage_Report_Item, DRB_Usage_Report_Item_sequence);

  return offset;
}


static const per_sequence_t DRB_Usage_Report_List_sequence_of[1] = {
  { &hf_e1ap_DRB_Usage_Report_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Usage_Report_Item },
};

static int
dissect_e1ap_DRB_Usage_Report_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Usage_Report_List, DRB_Usage_Report_List_sequence_of,
                                                  1, maxnooftimeperiods, false);

  return offset;
}


static const per_sequence_t Data_Usage_Report_Item_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_rAT_Type       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_RAT_Type },
  { &hf_e1ap_dRB_Usage_Report_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Usage_Report_List },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Data_Usage_Report_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Data_Usage_Report_Item, Data_Usage_Report_Item_sequence);

  return offset;
}


static const per_sequence_t Data_Usage_Report_List_sequence_of[1] = {
  { &hf_e1ap_Data_Usage_Report_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Data_Usage_Report_Item },
};

static int
dissect_e1ap_Data_Usage_Report_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_Data_Usage_Report_List, Data_Usage_Report_List_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const value_string e1ap_DefaultDRB_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_e1ap_DefaultDRB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_Dictionary_vals[] = {
  {   0, "sip-SDP" },
  {   1, "operator" },
  { 0, NULL }
};


static int
dissect_e1ap_Dictionary(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_DirectForwardingPathAvailability_vals[] = {
  {   0, "inter-system-direct-path-available" },
  {   1, "intra-system-direct-path-available" },
  { 0, NULL }
};


static int
dissect_e1ap_DirectForwardingPathAvailability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 1, NULL);

  return offset;
}


static const value_string e1ap_DiscardTimerExtended_vals[] = {
  {   0, "ms0dot5" },
  {   1, "ms1" },
  {   2, "ms2" },
  {   3, "ms4" },
  {   4, "ms6" },
  {   5, "ms8" },
  {   6, "ms2000" },
  { 0, NULL }
};


static int
dissect_e1ap_DiscardTimerExtended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 1, NULL);

  return offset;
}


static const value_string e1ap_PSIbasedDiscardTimer_vals[] = {
  {   0, "ms0" },
  {   1, "ms2" },
  {   2, "ms4" },
  {   3, "ms6" },
  {   4, "ms8" },
  {   5, "ms10" },
  {   6, "ms12" },
  {   7, "ms14" },
  {   8, "ms18" },
  {   9, "ms22" },
  {  10, "ms26" },
  {  11, "ms30" },
  {  12, "ms40" },
  {  13, "ms50" },
  {  14, "ms75" },
  {  15, "ms100" },
  { 0, NULL }
};


static int
dissect_e1ap_PSIbasedDiscardTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_PDCP_SN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 262143U, NULL, false);

  return offset;
}



static int
dissect_e1ap_HFN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t PDCP_Count_sequence[] = {
  { &hf_e1ap_pDCP_SN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_SN },
  { &hf_e1ap_hFN            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_HFN },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDCP_Count(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDCP_Count, PDCP_Count_sequence);

  return offset;
}


static const per_sequence_t DLDiscarding_sequence[] = {
  { &hf_e1ap_dLDiscardingCountVal, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Count },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DLDiscarding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DLDiscarding, DLDiscarding_sequence);

  return offset;
}


static const per_sequence_t DLUPTNLAddressToUpdateItem_sequence[] = {
  { &hf_e1ap_oldTNLAdress   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_newTNLAdress   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DLUPTNLAddressToUpdateItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DLUPTNLAddressToUpdateItem, DLUPTNLAddressToUpdateItem_sequence);

  return offset;
}


static const per_sequence_t DRB_Confirm_Modified_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_cell_Group_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Cell_Group_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Confirm_Modified_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Confirm_Modified_Item_EUTRAN, DRB_Confirm_Modified_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Confirm_Modified_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Confirm_Modified_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Confirm_Modified_Item_EUTRAN },
};

static int
dissect_e1ap_DRB_Confirm_Modified_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Confirm_Modified_List_EUTRAN, DRB_Confirm_Modified_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Confirm_Modified_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_cell_Group_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Cell_Group_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Confirm_Modified_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Confirm_Modified_Item_NG_RAN, DRB_Confirm_Modified_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Confirm_Modified_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Confirm_Modified_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Confirm_Modified_Item_NG_RAN },
};

static int
dissect_e1ap_DRB_Confirm_Modified_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Confirm_Modified_List_NG_RAN, DRB_Confirm_Modified_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Failed_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Failed_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Failed_Item_EUTRAN, DRB_Failed_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Failed_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Failed_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Failed_Item_EUTRAN },
};

static int
dissect_e1ap_DRB_Failed_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Failed_List_EUTRAN, DRB_Failed_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Failed_Mod_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Failed_Mod_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Failed_Mod_Item_EUTRAN, DRB_Failed_Mod_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Failed_Mod_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Failed_Mod_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Failed_Mod_Item_EUTRAN },
};

static int
dissect_e1ap_DRB_Failed_Mod_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Failed_Mod_List_EUTRAN, DRB_Failed_Mod_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Failed_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Failed_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Failed_Item_NG_RAN, DRB_Failed_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Failed_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Failed_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Failed_Item_NG_RAN },
};

static int
dissect_e1ap_DRB_Failed_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Failed_List_NG_RAN, DRB_Failed_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Failed_Mod_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Failed_Mod_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Failed_Mod_Item_NG_RAN, DRB_Failed_Mod_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Failed_Mod_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Failed_Mod_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Failed_Mod_Item_NG_RAN },
};

static int
dissect_e1ap_DRB_Failed_Mod_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Failed_Mod_List_NG_RAN, DRB_Failed_Mod_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Failed_To_Modify_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Failed_To_Modify_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Failed_To_Modify_Item_EUTRAN, DRB_Failed_To_Modify_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Failed_To_Modify_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Failed_To_Modify_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Failed_To_Modify_Item_EUTRAN },
};

static int
dissect_e1ap_DRB_Failed_To_Modify_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Failed_To_Modify_List_EUTRAN, DRB_Failed_To_Modify_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Failed_To_Modify_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Failed_To_Modify_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Failed_To_Modify_Item_NG_RAN, DRB_Failed_To_Modify_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Failed_To_Modify_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Failed_To_Modify_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Failed_To_Modify_Item_NG_RAN },
};

static int
dissect_e1ap_DRB_Failed_To_Modify_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Failed_To_Modify_List_NG_RAN, DRB_Failed_To_Modify_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}



static int
dissect_e1ap_INTEGER_0_10000_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 10000U, NULL, true);

  return offset;
}


static const per_sequence_t DRB_Measurement_Results_Information_Item_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_uL_D1_Result   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_INTEGER_0_10000_ },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Measurement_Results_Information_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Measurement_Results_Information_Item, DRB_Measurement_Results_Information_Item_sequence);

  return offset;
}


static const per_sequence_t DRB_Measurement_Results_Information_List_sequence_of[1] = {
  { &hf_e1ap_DRB_Measurement_Results_Information_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Measurement_Results_Information_Item },
};

static int
dissect_e1ap_DRB_Measurement_Results_Information_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Measurement_Results_Information_List, DRB_Measurement_Results_Information_List_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}



static int
dissect_e1ap_BIT_STRING_SIZE_1_131072(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 131072, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t DRBBStatusTransfer_sequence[] = {
  { &hf_e1ap_receiveStatusofPDCPSDU, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BIT_STRING_SIZE_1_131072 },
  { &hf_e1ap_countValue     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Count },
  { &hf_e1ap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRBBStatusTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRBBStatusTransfer, DRBBStatusTransfer_sequence);

  return offset;
}


static const per_sequence_t PDCP_SN_Status_Information_sequence[] = {
  { &hf_e1ap_pdcpStatusTransfer_UL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRBBStatusTransfer },
  { &hf_e1ap_pdcpStatusTransfer_DL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Count },
  { &hf_e1ap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDCP_SN_Status_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDCP_SN_Status_Information, PDCP_SN_Status_Information_sequence);

  return offset;
}


static const per_sequence_t UP_Parameters_Item_sequence[] = {
  { &hf_e1ap_uP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_cell_Group_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cell_Group_ID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_UP_Parameters_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_UP_Parameters_Item, UP_Parameters_Item_sequence);

  return offset;
}


static const per_sequence_t UP_Parameters_sequence_of[1] = {
  { &hf_e1ap_UP_Parameters_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_Parameters_Item },
};

static int
dissect_e1ap_UP_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_UP_Parameters, UP_Parameters_sequence_of,
                                                  1, maxnoofUPParameters, false);

  return offset;
}


static const per_sequence_t DRB_Modified_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_s1_DL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_pDCP_SN_Status_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_SN_Status_Information },
  { &hf_e1ap_uL_UP_Transport_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_Parameters },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Modified_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Modified_Item_EUTRAN, DRB_Modified_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Modified_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Modified_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Modified_Item_EUTRAN },
};

static int
dissect_e1ap_DRB_Modified_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Modified_List_EUTRAN, DRB_Modified_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Modified_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_uL_UP_Transport_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_Parameters },
  { &hf_e1ap_pDCP_SN_Status_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_SN_Status_Information },
  { &hf_e1ap_flow_Setup_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_List },
  { &hf_e1ap_flow_Failed_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_Failed_List },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Modified_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Modified_Item_NG_RAN, DRB_Modified_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Modified_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Modified_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Modified_Item_NG_RAN },
};

static int
dissect_e1ap_DRB_Modified_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Modified_List_NG_RAN, DRB_Modified_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const value_string e1ap_T_dRB_Released_In_Session_vals[] = {
  {   0, "released-in-session" },
  {   1, "not-released-in-session" },
  { 0, NULL }
};


static int
dissect_e1ap_T_dRB_Released_In_Session(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_OCTET_STRING_SIZE_5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       5, 5, false, NULL);

  return offset;
}


static const value_string e1ap_T_qoS_Flow_Released_In_Session_vals[] = {
  {   0, "released-in-session" },
  {   1, "not-released-in-session" },
  { 0, NULL }
};


static int
dissect_e1ap_T_qoS_Flow_Released_In_Session(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t QoS_Flow_Removed_Item_sequence[] = {
  { &hf_e1ap_qoS_Flow_Identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Identifier },
  { &hf_e1ap_qoS_Flow_Released_In_Session, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_T_qoS_Flow_Released_In_Session },
  { &hf_e1ap_qoS_Flow_Accumulated_Session_Time, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_OCTET_STRING_SIZE_5 },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_QoS_Flow_Removed_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_QoS_Flow_Removed_Item, QoS_Flow_Removed_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_QoS_Flow_Removed_Item_sequence_of[1] = {
  { &hf_e1ap_qoS_Flow_Removed_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Removed_Item },
};

static int
dissect_e1ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_QoS_Flow_Removed_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_QoS_Flow_Removed_Item, SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_QoS_Flow_Removed_Item_sequence_of,
                                                  1, maxnoofQoSFlows, false);

  return offset;
}


static const per_sequence_t DRB_Removed_Item_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_dRB_Released_In_Session, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_T_dRB_Released_In_Session },
  { &hf_e1ap_dRB_Accumulated_Session_Time, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_OCTET_STRING_SIZE_5 },
  { &hf_e1ap_qoS_Flow_Removed_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_QoS_Flow_Removed_Item },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Removed_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Removed_Item, DRB_Removed_Item_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_UP_CellGroupRelatedConfiguration_Item_sequence[] = {
  { &hf_e1ap_cell_Group_ID  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Cell_Group_ID },
  { &hf_e1ap_uP_TNL_Information, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_uL_Configuration, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_UL_Configuration },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration_Item, GNB_CU_UP_CellGroupRelatedConfiguration_Item_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_UP_CellGroupRelatedConfiguration_sequence_of[1] = {
  { &hf_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration_Item },
};

static int
dissect_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration, GNB_CU_UP_CellGroupRelatedConfiguration_sequence_of,
                                                  1, maxnoofUPParameters, false);

  return offset;
}


static const per_sequence_t DRB_Required_To_Modify_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_s1_DL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_gNB_CU_UP_CellGroupRelatedConfiguration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Required_To_Modify_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Required_To_Modify_Item_EUTRAN, DRB_Required_To_Modify_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Required_To_Modify_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Required_To_Modify_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Required_To_Modify_Item_EUTRAN },
};

static int
dissect_e1ap_DRB_Required_To_Modify_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Required_To_Modify_List_EUTRAN, DRB_Required_To_Modify_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Required_To_Modify_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_gNB_CU_UP_CellGroupRelatedConfiguration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration },
  { &hf_e1ap_flow_To_Remove , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_List },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Required_To_Modify_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Required_To_Modify_Item_NG_RAN, DRB_Required_To_Modify_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Required_To_Modify_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Required_To_Modify_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Required_To_Modify_Item_NG_RAN },
};

static int
dissect_e1ap_DRB_Required_To_Modify_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Required_To_Modify_List_NG_RAN, DRB_Required_To_Modify_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const value_string e1ap_T_s1_DL_UP_Unchanged_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_T_s1_DL_UP_Unchanged(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t DRB_Setup_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_s1_DL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_data_Forwarding_Information_Response, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information },
  { &hf_e1ap_uL_UP_Transport_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_Parameters },
  { &hf_e1ap_s1_DL_UP_Unchanged, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_T_s1_DL_UP_Unchanged },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Setup_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Setup_Item_EUTRAN, DRB_Setup_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Setup_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Setup_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Setup_Item_EUTRAN },
};

static int
dissect_e1ap_DRB_Setup_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Setup_List_EUTRAN, DRB_Setup_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Setup_Mod_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_s1_DL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_data_Forwarding_Information_Response, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information },
  { &hf_e1ap_uL_UP_Transport_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_Parameters },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Setup_Mod_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Setup_Mod_Item_EUTRAN, DRB_Setup_Mod_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Setup_Mod_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Setup_Mod_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Setup_Mod_Item_EUTRAN },
};

static int
dissect_e1ap_DRB_Setup_Mod_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Setup_Mod_List_EUTRAN, DRB_Setup_Mod_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Setup_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_dRB_data_Forwarding_Information_Response, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information },
  { &hf_e1ap_uL_UP_Transport_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_Parameters },
  { &hf_e1ap_flow_Setup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_List },
  { &hf_e1ap_flow_Failed_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_Failed_List },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Setup_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Setup_Item_NG_RAN, DRB_Setup_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Setup_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Setup_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Setup_Item_NG_RAN },
};

static int
dissect_e1ap_DRB_Setup_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Setup_List_NG_RAN, DRB_Setup_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Setup_Mod_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_dRB_data_Forwarding_Information_Response, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information },
  { &hf_e1ap_uL_UP_Transport_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_Parameters },
  { &hf_e1ap_flow_Setup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_List },
  { &hf_e1ap_flow_Failed_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_Failed_List },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Setup_Mod_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Setup_Mod_Item_NG_RAN, DRB_Setup_Mod_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Setup_Mod_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Setup_Mod_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Setup_Mod_Item_NG_RAN },
};

static int
dissect_e1ap_DRB_Setup_Mod_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Setup_Mod_List_NG_RAN, DRB_Setup_Mod_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Status_Item_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_pDCP_DL_Count  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_Count },
  { &hf_e1ap_pDCP_UL_Count  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_Count },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Status_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Status_Item, DRB_Status_Item_sequence);

  return offset;
}


static const per_sequence_t DRBs_Subject_To_Counter_Check_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_pDCP_UL_Count  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Count },
  { &hf_e1ap_pDCP_DL_Count  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Count },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRBs_Subject_To_Counter_Check_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRBs_Subject_To_Counter_Check_Item_EUTRAN, DRBs_Subject_To_Counter_Check_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRBs_Subject_To_Counter_Check_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRBs_Subject_To_Counter_Check_Item_EUTRAN },
};

static int
dissect_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN, DRBs_Subject_To_Counter_Check_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRBs_Subject_To_Counter_Check_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_pDCP_UL_Count  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Count },
  { &hf_e1ap_pDCP_DL_Count  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Count },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRBs_Subject_To_Counter_Check_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRBs_Subject_To_Counter_Check_Item_NG_RAN, DRBs_Subject_To_Counter_Check_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRBs_Subject_To_Counter_Check_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRBs_Subject_To_Counter_Check_Item_NG_RAN },
};

static int
dissect_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN, DRBs_Subject_To_Counter_Check_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRBs_Subject_To_Early_Forwarding_Item_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_dLCountValue   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Count },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRBs_Subject_To_Early_Forwarding_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRBs_Subject_To_Early_Forwarding_Item, DRBs_Subject_To_Early_Forwarding_Item_sequence);

  return offset;
}


static const per_sequence_t DRBs_Subject_To_Early_Forwarding_List_sequence_of[1] = {
  { &hf_e1ap_DRBs_Subject_To_Early_Forwarding_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRBs_Subject_To_Early_Forwarding_Item },
};

static int
dissect_e1ap_DRBs_Subject_To_Early_Forwarding_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRBs_Subject_To_Early_Forwarding_List, DRBs_Subject_To_Early_Forwarding_List_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}



static int
dissect_e1ap_QCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t EUTRANAllocationAndRetentionPriority_sequence[] = {
  { &hf_e1ap_priorityLevel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PriorityLevel },
  { &hf_e1ap_pre_emptionCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Pre_emptionCapability },
  { &hf_e1ap_pre_emptionVulnerability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Pre_emptionVulnerability },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_EUTRANAllocationAndRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_EUTRANAllocationAndRetentionPriority, EUTRANAllocationAndRetentionPriority_sequence);

  return offset;
}


static const per_sequence_t GBR_QosInformation_sequence[] = {
  { &hf_e1ap_e_RAB_MaximumBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BitRate },
  { &hf_e1ap_e_RAB_MaximumBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BitRate },
  { &hf_e1ap_e_RAB_GuaranteedBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BitRate },
  { &hf_e1ap_e_RAB_GuaranteedBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BitRate },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GBR_QosInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GBR_QosInformation, GBR_QosInformation_sequence);

  return offset;
}


static const per_sequence_t EUTRAN_QoS_sequence[] = {
  { &hf_e1ap_qCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QCI },
  { &hf_e1ap_eUTRANallocationAndRetentionPriority, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_EUTRANAllocationAndRetentionPriority },
  { &hf_e1ap_gbrQosInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_GBR_QosInformation },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_EUTRAN_QoS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_EUTRAN_QoS, EUTRAN_QoS_sequence);

  return offset;
}


static const value_string e1ap_PDCP_SN_Status_Request_vals[] = {
  {   0, "requested" },
  { 0, NULL }
};


static int
dissect_e1ap_PDCP_SN_Status_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_Inactivity_Timer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 7200U, NULL, true);

  return offset;
}


static const per_sequence_t DRB_To_Modify_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_pDCP_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_Configuration },
  { &hf_e1ap_eUTRAN_QoS     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_EUTRAN_QoS },
  { &hf_e1ap_s1_UL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_data_Forwarding_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information },
  { &hf_e1ap_pDCP_SN_Status_Request, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_SN_Status_Request },
  { &hf_e1ap_pDCP_SN_Status_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_SN_Status_Information },
  { &hf_e1ap_dL_UP_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_Parameters },
  { &hf_e1ap_cell_Group_To_Add, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Cell_Group_Information },
  { &hf_e1ap_cell_Group_To_Modify, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Cell_Group_Information },
  { &hf_e1ap_cell_Group_To_Remove, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Cell_Group_Information },
  { &hf_e1ap_dRB_Inactivity_Timer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Inactivity_Timer },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_To_Modify_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_To_Modify_Item_EUTRAN, DRB_To_Modify_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRB_To_Modify_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRB_To_Modify_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_To_Modify_Item_EUTRAN },
};

static int
dissect_e1ap_DRB_To_Modify_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_To_Modify_List_EUTRAN, DRB_To_Modify_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const value_string e1ap_SDAP_Header_UL_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};


static int
dissect_e1ap_SDAP_Header_UL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_SDAP_Header_DL_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};


static int
dissect_e1ap_SDAP_Header_DL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t SDAP_Configuration_sequence[] = {
  { &hf_e1ap_defaultDRB     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DefaultDRB },
  { &hf_e1ap_sDAP_Header_UL , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SDAP_Header_UL },
  { &hf_e1ap_sDAP_Header_DL , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SDAP_Header_DL },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_SDAP_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_SDAP_Configuration, SDAP_Configuration_sequence);

  return offset;
}


static const per_sequence_t DRB_To_Modify_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_sDAP_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_SDAP_Configuration },
  { &hf_e1ap_pDCP_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_Configuration },
  { &hf_e1ap_dRB_Data_Forwarding_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information },
  { &hf_e1ap_pDCP_SN_Status_Request, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_SN_Status_Request },
  { &hf_e1ap_pdcp_SN_Status_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_SN_Status_Information },
  { &hf_e1ap_dL_UP_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_Parameters },
  { &hf_e1ap_cell_Group_To_Add, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Cell_Group_Information },
  { &hf_e1ap_cell_Group_To_Modify, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Cell_Group_Information },
  { &hf_e1ap_cell_Group_To_Remove, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Cell_Group_Information },
  { &hf_e1ap_flow_Mapping_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_QoS_Parameter_List },
  { &hf_e1ap_dRB_Inactivity_Timer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Inactivity_Timer },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_To_Modify_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_To_Modify_Item_NG_RAN, DRB_To_Modify_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRB_To_Modify_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRB_To_Modify_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_To_Modify_Item_NG_RAN },
};

static int
dissect_e1ap_DRB_To_Modify_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_To_Modify_List_NG_RAN, DRB_To_Modify_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_To_Remove_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_To_Remove_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_To_Remove_Item_EUTRAN, DRB_To_Remove_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRB_To_Remove_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRB_To_Remove_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_To_Remove_Item_EUTRAN },
};

static int
dissect_e1ap_DRB_To_Remove_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_To_Remove_List_EUTRAN, DRB_To_Remove_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Required_To_Remove_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Required_To_Remove_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Required_To_Remove_Item_EUTRAN, DRB_Required_To_Remove_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Required_To_Remove_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Required_To_Remove_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Required_To_Remove_Item_EUTRAN },
};

static int
dissect_e1ap_DRB_Required_To_Remove_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Required_To_Remove_List_EUTRAN, DRB_Required_To_Remove_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_To_Remove_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_To_Remove_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_To_Remove_Item_NG_RAN, DRB_To_Remove_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRB_To_Remove_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRB_To_Remove_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_To_Remove_Item_NG_RAN },
};

static int
dissect_e1ap_DRB_To_Remove_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_To_Remove_List_NG_RAN, DRB_To_Remove_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_Required_To_Remove_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_Required_To_Remove_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_Required_To_Remove_Item_NG_RAN, DRB_Required_To_Remove_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRB_Required_To_Remove_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRB_Required_To_Remove_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Required_To_Remove_Item_NG_RAN },
};

static int
dissect_e1ap_DRB_Required_To_Remove_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Required_To_Remove_List_NG_RAN, DRB_Required_To_Remove_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_To_Setup_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_pDCP_Configuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Configuration },
  { &hf_e1ap_eUTRAN_QoS     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_EUTRAN_QoS },
  { &hf_e1ap_s1_UL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_data_Forwarding_Information_Request, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information_Request },
  { &hf_e1ap_cell_Group_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cell_Group_Information },
  { &hf_e1ap_dL_UP_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_Parameters },
  { &hf_e1ap_dRB_Inactivity_Timer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Inactivity_Timer },
  { &hf_e1ap_existing_Allocated_S1_DL_UP_TNL_Info, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_To_Setup_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_To_Setup_Item_EUTRAN, DRB_To_Setup_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRB_To_Setup_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRB_To_Setup_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_To_Setup_Item_EUTRAN },
};

static int
dissect_e1ap_DRB_To_Setup_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_To_Setup_List_EUTRAN, DRB_To_Setup_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_To_Setup_Mod_Item_EUTRAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_pDCP_Configuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Configuration },
  { &hf_e1ap_eUTRAN_QoS     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_EUTRAN_QoS },
  { &hf_e1ap_s1_UL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_data_Forwarding_Information_Request, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information_Request },
  { &hf_e1ap_cell_Group_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cell_Group_Information },
  { &hf_e1ap_dL_UP_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_Parameters },
  { &hf_e1ap_dRB_Inactivity_Timer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Inactivity_Timer },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_To_Setup_Mod_Item_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_To_Setup_Mod_Item_EUTRAN, DRB_To_Setup_Mod_Item_EUTRAN_sequence);

  return offset;
}


static const per_sequence_t DRB_To_Setup_Mod_List_EUTRAN_sequence_of[1] = {
  { &hf_e1ap_DRB_To_Setup_Mod_List_EUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_To_Setup_Mod_Item_EUTRAN },
};

static int
dissect_e1ap_DRB_To_Setup_Mod_List_EUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_To_Setup_Mod_List_EUTRAN, DRB_To_Setup_Mod_List_EUTRAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_To_Setup_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_sDAP_Configuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SDAP_Configuration },
  { &hf_e1ap_pDCP_Configuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Configuration },
  { &hf_e1ap_cell_Group_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cell_Group_Information },
  { &hf_e1ap_qos_flow_Information_To_Be_Setup, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_QoS_Parameter_List },
  { &hf_e1ap_dRB_Data_Forwarding_Information_Request, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information_Request },
  { &hf_e1ap_dRB_Inactivity_Timer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Inactivity_Timer },
  { &hf_e1ap_pDCP_SN_Status_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_SN_Status_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_To_Setup_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_To_Setup_Item_NG_RAN, DRB_To_Setup_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRB_To_Setup_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRB_To_Setup_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_To_Setup_Item_NG_RAN },
};

static int
dissect_e1ap_DRB_To_Setup_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_To_Setup_List_NG_RAN, DRB_To_Setup_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t DRB_To_Setup_Mod_Item_NG_RAN_sequence[] = {
  { &hf_e1ap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_ID },
  { &hf_e1ap_sDAP_Configuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SDAP_Configuration },
  { &hf_e1ap_pDCP_Configuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Configuration },
  { &hf_e1ap_cell_Group_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cell_Group_Information },
  { &hf_e1ap_flow_Mapping_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_QoS_Parameter_List },
  { &hf_e1ap_dRB_Data_Forwarding_Information_Request, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information_Request },
  { &hf_e1ap_dRB_Inactivity_Timer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Inactivity_Timer },
  { &hf_e1ap_pDCP_SN_Status_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_SN_Status_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DRB_To_Setup_Mod_Item_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DRB_To_Setup_Mod_Item_NG_RAN, DRB_To_Setup_Mod_Item_NG_RAN_sequence);

  return offset;
}


static const per_sequence_t DRB_To_Setup_Mod_List_NG_RAN_sequence_of[1] = {
  { &hf_e1ap_DRB_To_Setup_Mod_List_NG_RAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_To_Setup_Mod_Item_NG_RAN },
};

static int
dissect_e1ap_DRB_To_Setup_Mod_List_NG_RAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_To_Setup_Mod_List_NG_RAN, DRB_To_Setup_Mod_List_NG_RAN_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const value_string e1ap_DataDiscardRequired_vals[] = {
  {   0, "required" },
  { 0, NULL }
};


static int
dissect_e1ap_DataDiscardRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_EarlyDataForwardingIndicator_vals[] = {
  {   0, "stop" },
  { 0, NULL }
};


static int
dissect_e1ap_EarlyDataForwardingIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t FirstDLCount_sequence[] = {
  { &hf_e1ap_firstDLCountVal, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Count },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_FirstDLCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_FirstDLCount, FirstDLCount_sequence);

  return offset;
}


static const value_string e1ap_EarlyForwardingCOUNTInfo_vals[] = {
  {   0, "firstDLCount" },
  {   1, "dLDiscardingCount" },
  {   2, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t EarlyForwardingCOUNTInfo_choice[] = {
  {   0, &hf_e1ap_firstDLCount   , ASN1_NO_EXTENSIONS     , dissect_e1ap_FirstDLCount },
  {   1, &hf_e1ap_dLDiscardingCount, ASN1_NO_EXTENSIONS     , dissect_e1ap_DLDiscarding },
  {   2, &hf_e1ap_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_EarlyForwardingCOUNTInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_EarlyForwardingCOUNTInfo, EarlyForwardingCOUNTInfo_choice,
                                 NULL);

  return offset;
}


static const value_string e1ap_EarlyForwardingCOUNTReq_vals[] = {
  {   0, "first-dl-count" },
  {   1, "dl-discarding" },
  { 0, NULL }
};


static int
dissect_e1ap_EarlyForwardingCOUNTReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_T_eCNMarkingatNGRAN_vals[] = {
  {   0, "ul" },
  {   1, "dl" },
  {   2, "both" },
  {   3, "stop" },
  { 0, NULL }
};


static int
dissect_e1ap_T_eCNMarkingatNGRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_T_eCNMarkingatUPF_vals[] = {
  {   0, "ul" },
  {   1, "dl" },
  {   2, "both" },
  {   3, "stop" },
  { 0, NULL }
};


static int
dissect_e1ap_T_eCNMarkingatUPF(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_T_congestionInformation_vals[] = {
  {   0, "ul" },
  {   1, "dl" },
  {   2, "both" },
  {   3, "stop" },
  { 0, NULL }
};


static int
dissect_e1ap_T_congestionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_ECNMarkingorCongestionInformationReportingRequest_vals[] = {
  {   0, "eCNMarkingatNGRAN" },
  {   1, "eCNMarkingatUPF" },
  {   2, "congestionInformation" },
  {   3, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ECNMarkingorCongestionInformationReportingRequest_choice[] = {
  {   0, &hf_e1ap_eCNMarkingatNGRAN, ASN1_NO_EXTENSIONS     , dissect_e1ap_T_eCNMarkingatNGRAN },
  {   1, &hf_e1ap_eCNMarkingatUPF, ASN1_NO_EXTENSIONS     , dissect_e1ap_T_eCNMarkingatUPF },
  {   2, &hf_e1ap_congestionInformation, ASN1_NO_EXTENSIONS     , dissect_e1ap_T_congestionInformation },
  {   3, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_ECNMarkingorCongestionInformationReportingRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_ECNMarkingorCongestionInformationReportingRequest, ECNMarkingorCongestionInformationReportingRequest_choice,
                                 NULL);

  return offset;
}


static const value_string e1ap_ECNMarkingorCongestionInformationReportingStatus_vals[] = {
  {   0, "active" },
  {   1, "not-active" },
  { 0, NULL }
};


static int
dissect_e1ap_ECNMarkingorCongestionInformationReportingStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_T_ehc_CID_Length_vals[] = {
  {   0, "bits7" },
  {   1, "bits15" },
  { 0, NULL }
};


static int
dissect_e1ap_T_ehc_CID_Length(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t EHC_Common_Parameters_sequence[] = {
  { &hf_e1ap_ehc_CID_Length , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_T_ehc_CID_Length },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_EHC_Common_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_EHC_Common_Parameters, EHC_Common_Parameters_sequence);

  return offset;
}


static const value_string e1ap_T_drb_ContinueEHC_DL_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_e1ap_T_drb_ContinueEHC_DL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 1, NULL);

  return offset;
}


static const per_sequence_t EHC_Downlink_Parameters_sequence[] = {
  { &hf_e1ap_drb_ContinueEHC_DL, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_T_drb_ContinueEHC_DL },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_EHC_Downlink_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_EHC_Downlink_Parameters, EHC_Downlink_Parameters_sequence);

  return offset;
}


static const value_string e1ap_T_drb_ContinueEHC_UL_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_e1ap_T_drb_ContinueEHC_UL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 1, NULL);

  return offset;
}


static const per_sequence_t EHC_Uplink_Parameters_sequence[] = {
  { &hf_e1ap_drb_ContinueEHC_UL, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_T_drb_ContinueEHC_UL },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_EHC_Uplink_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_EHC_Uplink_Parameters, EHC_Uplink_Parameters_sequence);

  return offset;
}


static const per_sequence_t EHC_Parameters_sequence[] = {
  { &hf_e1ap_ehc_Common     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_EHC_Common_Parameters },
  { &hf_e1ap_ehc_Downlink   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_EHC_Downlink_Parameters },
  { &hf_e1ap_ehc_Uplink     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_EHC_Uplink_Parameters },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_EHC_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_EHC_Parameters, EHC_Parameters_sequence);

  return offset;
}



static int
dissect_e1ap_EncryptionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}



static int
dissect_e1ap_PortNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     16, 16, false, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const per_sequence_t Endpoint_IP_address_and_port_sequence[] = {
  { &hf_e1ap_endpoint_IP_Address, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_portNumber     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PortNumber },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Endpoint_IP_address_and_port(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Endpoint_IP_address_and_port, Endpoint_IP_address_and_port_sequence);

  return offset;
}



static int
dissect_e1ap_ExtendedPacketDelayBudget(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_e1ap_E_UTRAN_Cell_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e1ap_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *param_tvb = NULL;
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(actx->pinfo);
  e212_number_type_t number_type = e1ap_data->number_type;
  e1ap_data->number_type = E212_NONE;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_e1ap_PLMN_Identity);
    dissect_e212_mcc_mnc(param_tvb, actx->pinfo, subtree, 0, number_type, false);
  }


  return offset;
}


static const per_sequence_t ECGI_sequence[] = {
  { &hf_e1ap_pLMN_Identity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PLMN_Identity },
  { &hf_e1ap_eUTRAN_Cell_Identity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_E_UTRAN_Cell_Identity },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ECGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ECGI, ECGI_sequence);

  return offset;
}


static const per_sequence_t ECGI_Support_Item_sequence[] = {
  { &hf_e1ap_eCGI           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_ECGI },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ECGI_Support_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ECGI_Support_Item, ECGI_Support_Item_sequence);

  return offset;
}


static const per_sequence_t ECGI_Support_List_sequence_of[1] = {
  { &hf_e1ap_ECGI_Support_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_ECGI_Support_Item },
};

static int
dissect_e1ap_ECGI_Support_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_ECGI_Support_List, ECGI_Support_List_sequence_of,
                                                  1, maxnoofECGI, false);

  return offset;
}


static const per_sequence_t EUTRAN_QoS_Support_Item_sequence[] = {
  { &hf_e1ap_eUTRAN_QoS     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_EUTRAN_QoS },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_EUTRAN_QoS_Support_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_EUTRAN_QoS_Support_Item, EUTRAN_QoS_Support_Item_sequence);

  return offset;
}


static const per_sequence_t EUTRAN_QoS_Support_List_sequence_of[1] = {
  { &hf_e1ap_EUTRAN_QoS_Support_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_EUTRAN_QoS_Support_Item },
};

static int
dissect_e1ap_EUTRAN_QoS_Support_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_EUTRAN_QoS_Support_List, EUTRAN_QoS_Support_List_sequence_of,
                                                  1, maxnoofEUTRANQOSParameters, false);

  return offset;
}


static const per_sequence_t Slice_Support_Item_sequence[] = {
  { &hf_e1ap_sNSSAI         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_SNSSAI },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Slice_Support_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Slice_Support_Item, Slice_Support_Item_sequence);

  return offset;
}


static const per_sequence_t ExtendedSliceSupportList_sequence_of[1] = {
  { &hf_e1ap_ExtendedSliceSupportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Slice_Support_Item },
};

static int
dissect_e1ap_ExtendedSliceSupportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_ExtendedSliceSupportList, ExtendedSliceSupportList_sequence_of,
                                                  1, maxnoofExtSliceItems, false);

  return offset;
}



static int
dissect_e1ap_FiveGS_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}


static const per_sequence_t F1U_TNL_InfoAdded_Item_sequence[] = {
  { &hf_e1ap_broadcastF1U_ContextReferenceE1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BroadcastF1U_ContextReferenceE1 },
  { &hf_e1ap_bcBearerContextF1U_TNLInfoatCU, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BCBearerContextF1U_TNLInfoatCU },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_F1U_TNL_InfoAdded_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_F1U_TNL_InfoAdded_Item, F1U_TNL_InfoAdded_Item_sequence);

  return offset;
}


static const per_sequence_t F1U_TNL_InfoAdded_List_sequence_of[1] = {
  { &hf_e1ap_F1U_TNL_InfoAdded_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_F1U_TNL_InfoAdded_Item },
};

static int
dissect_e1ap_F1U_TNL_InfoAdded_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_F1U_TNL_InfoAdded_List, F1U_TNL_InfoAdded_List_sequence_of,
                                                  1, maxnoofDUs, false);

  return offset;
}


static const per_sequence_t F1U_TNL_InfoToAdd_Item_sequence[] = {
  { &hf_e1ap_broadcastF1U_ContextReferenceE1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BroadcastF1U_ContextReferenceE1 },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_F1U_TNL_InfoToAdd_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_F1U_TNL_InfoToAdd_Item, F1U_TNL_InfoToAdd_Item_sequence);

  return offset;
}


static const per_sequence_t F1U_TNL_InfoToAdd_List_sequence_of[1] = {
  { &hf_e1ap_F1U_TNL_InfoToAdd_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_F1U_TNL_InfoToAdd_Item },
};

static int
dissect_e1ap_F1U_TNL_InfoToAdd_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_F1U_TNL_InfoToAdd_List, F1U_TNL_InfoToAdd_List_sequence_of,
                                                  1, maxnoofDUs, false);

  return offset;
}


static const per_sequence_t F1U_TNL_InfoAddedOrModified_Item_sequence[] = {
  { &hf_e1ap_broadcastF1U_ContextReferenceE1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BroadcastF1U_ContextReferenceE1 },
  { &hf_e1ap_bcBearerContextF1U_TNLInfoatCU, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCBearerContextF1U_TNLInfoatCU },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_F1U_TNL_InfoAddedOrModified_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_F1U_TNL_InfoAddedOrModified_Item, F1U_TNL_InfoAddedOrModified_Item_sequence);

  return offset;
}


static const per_sequence_t F1U_TNL_InfoAddedOrModified_List_sequence_of[1] = {
  { &hf_e1ap_F1U_TNL_InfoAddedOrModified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_F1U_TNL_InfoAddedOrModified_Item },
};

static int
dissect_e1ap_F1U_TNL_InfoAddedOrModified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_F1U_TNL_InfoAddedOrModified_List, F1U_TNL_InfoAddedOrModified_List_sequence_of,
                                                  1, maxnoofDUs, false);

  return offset;
}


static const per_sequence_t F1U_TNL_InfoToAddOrModify_Item_sequence[] = {
  { &hf_e1ap_broadcastF1U_ContextReferenceE1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BroadcastF1U_ContextReferenceE1 },
  { &hf_e1ap_bcBearerContextF1U_TNLInfoatDU, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BCBearerContextF1U_TNLInfoatDU },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_F1U_TNL_InfoToAddOrModify_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_F1U_TNL_InfoToAddOrModify_Item, F1U_TNL_InfoToAddOrModify_Item_sequence);

  return offset;
}


static const per_sequence_t F1U_TNL_InfoToAddOrModify_List_sequence_of[1] = {
  { &hf_e1ap_F1U_TNL_InfoToAddOrModify_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_F1U_TNL_InfoToAddOrModify_Item },
};

static int
dissect_e1ap_F1U_TNL_InfoToAddOrModify_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_F1U_TNL_InfoToAddOrModify_List, F1U_TNL_InfoToAddOrModify_List_sequence_of,
                                                  1, maxnoofDUs, false);

  return offset;
}


static const per_sequence_t F1U_TNL_InfoToRelease_Item_sequence[] = {
  { &hf_e1ap_broadcastF1U_ContextReferenceE1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BroadcastF1U_ContextReferenceE1 },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_F1U_TNL_InfoToRelease_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_F1U_TNL_InfoToRelease_Item, F1U_TNL_InfoToRelease_Item_sequence);

  return offset;
}


static const per_sequence_t F1U_TNL_InfoToRelease_List_sequence_of[1] = {
  { &hf_e1ap_F1U_TNL_InfoToRelease_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_F1U_TNL_InfoToRelease_Item },
};

static int
dissect_e1ap_F1U_TNL_InfoToRelease_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_F1U_TNL_InfoToRelease_List, F1U_TNL_InfoToRelease_List_sequence_of,
                                                  1, maxnoofDUs, false);

  return offset;
}



static int
dissect_e1ap_OCTET_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       6, 6, false, NULL);

  return offset;
}



static int
dissect_e1ap_NID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     44, 44, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GlobalMBSSessionID_sequence[] = {
  { &hf_e1ap_tmgi           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_OCTET_STRING_SIZE_6 },
  { &hf_e1ap_nid            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_NID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GlobalMBSSessionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GlobalMBSSessionID, GlobalMBSSessionID_sequence);

  return offset;
}



static int
dissect_e1ap_GNB_CU_CP_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_e1ap_GNB_CU_CP_NameVisibleString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_VisibleString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_e1ap_GNB_CU_CP_NameUTF8String(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_UTF8String(tvb, offset, actx, tree, hf_index,
                                          1, 150, true);

  return offset;
}


static const per_sequence_t Extended_GNB_CU_CP_Name_sequence[] = {
  { &hf_e1ap_gNB_CU_CP_NameVisibleString, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_GNB_CU_CP_NameVisibleString },
  { &hf_e1ap_gNB_CU_CP_NameUTF8String, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_GNB_CU_CP_NameUTF8String },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Extended_GNB_CU_CP_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Extended_GNB_CU_CP_Name, Extended_GNB_CU_CP_Name_sequence);

  return offset;
}



static int
dissect_e1ap_GNB_CU_CP_MBS_E1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777215U, NULL, false);

  return offset;
}



static int
dissect_e1ap_GNB_CU_CP_UE_E1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_e1ap_GNB_CU_UP_Capacity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_e1ap_GNB_CU_UP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(68719476735), NULL, false);

  return offset;
}


static const per_sequence_t MBS_Support_Info_ToAdd_Item_sequence[] = {
  { &hf_e1ap_globalMBSSessionID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_GlobalMBSSessionID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBS_Support_Info_ToAdd_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBS_Support_Info_ToAdd_Item, MBS_Support_Info_ToAdd_Item_sequence);

  return offset;
}


static const per_sequence_t MBS_Support_Info_ToAdd_List_sequence_of[1] = {
  { &hf_e1ap_MBS_Support_Info_ToAdd_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MBS_Support_Info_ToAdd_Item },
};

static int
dissect_e1ap_MBS_Support_Info_ToAdd_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MBS_Support_Info_ToAdd_List, MBS_Support_Info_ToAdd_List_sequence_of,
                                                  1, maxnoofMBSSessionIDs, false);

  return offset;
}


static const per_sequence_t MBS_Support_Info_ToRemove_Item_sequence[] = {
  { &hf_e1ap_globalMBSSessionID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_GlobalMBSSessionID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBS_Support_Info_ToRemove_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBS_Support_Info_ToRemove_Item, MBS_Support_Info_ToRemove_Item_sequence);

  return offset;
}


static const per_sequence_t MBS_Support_Info_ToRemove_List_sequence_of[1] = {
  { &hf_e1ap_MBS_Support_Info_ToRemove_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MBS_Support_Info_ToRemove_Item },
};

static int
dissect_e1ap_MBS_Support_Info_ToRemove_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MBS_Support_Info_ToRemove_List, MBS_Support_Info_ToRemove_List_sequence_of,
                                                  1, maxnoofMBSSessionIDs, false);

  return offset;
}


static const per_sequence_t GNB_CU_UP_MBS_Support_Info_sequence[] = {
  { &hf_e1ap_mbs_Support_Info_ToAdd_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBS_Support_Info_ToAdd_List },
  { &hf_e1ap_mbs_Support_Info_ToRemove_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBS_Support_Info_ToRemove_List },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_UP_MBS_Support_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_UP_MBS_Support_Info, GNB_CU_UP_MBS_Support_Info_sequence);

  return offset;
}



static int
dissect_e1ap_GNB_CU_UP_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_e1ap_GNB_CU_UP_NameVisibleString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_VisibleString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_e1ap_GNB_CU_UP_NameUTF8String(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_UTF8String(tvb, offset, actx, tree, hf_index,
                                          1, 150, true);

  return offset;
}


static const per_sequence_t Extended_GNB_CU_UP_Name_sequence[] = {
  { &hf_e1ap_gNB_CU_UP_NameVisibleString, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_GNB_CU_UP_NameVisibleString },
  { &hf_e1ap_gNB_CU_UP_NameUTF8String, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_GNB_CU_UP_NameUTF8String },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Extended_GNB_CU_UP_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Extended_GNB_CU_UP_Name, Extended_GNB_CU_UP_Name_sequence);

  return offset;
}



static int
dissect_e1ap_GNB_CU_UP_MBS_E1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_e1ap_GNB_CU_UP_UE_E1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t GNB_CU_CP_TNLA_Setup_Item_sequence[] = {
  { &hf_e1ap_tNLAssociationTransportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_CP_TNL_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CP_TNLA_Setup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_CP_TNLA_Setup_Item, GNB_CU_CP_TNLA_Setup_Item_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_CP_TNLA_Failed_To_Setup_Item_sequence[] = {
  { &hf_e1ap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_CP_TNL_Information },
  { &hf_e1ap_cause          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_Item, GNB_CU_CP_TNLA_Failed_To_Setup_Item_sequence);

  return offset;
}


static const value_string e1ap_TNLAssociationUsage_vals[] = {
  {   0, "ue" },
  {   1, "non-ue" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_e1ap_TNLAssociationUsage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t GNB_CU_CP_TNLA_To_Add_Item_sequence[] = {
  { &hf_e1ap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_CP_TNL_Information },
  { &hf_e1ap_tNLAssociationUsage, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_TNLAssociationUsage },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CP_TNLA_To_Add_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_CP_TNLA_To_Add_Item, GNB_CU_CP_TNLA_To_Add_Item_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_CP_TNLA_To_Remove_Item_sequence[] = {
  { &hf_e1ap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_CP_TNL_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CP_TNLA_To_Remove_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_CP_TNLA_To_Remove_Item, GNB_CU_CP_TNLA_To_Remove_Item_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_CP_TNLA_To_Update_Item_sequence[] = {
  { &hf_e1ap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_CP_TNL_Information },
  { &hf_e1ap_tNLAssociationUsage, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_TNLAssociationUsage },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CP_TNLA_To_Update_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_CP_TNLA_To_Update_Item, GNB_CU_CP_TNLA_To_Update_Item_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_UP_TNLA_To_Remove_Item_sequence[] = {
  { &hf_e1ap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_CP_TNL_Information },
  { &hf_e1ap_tNLAssociationTransportLayerAddressgNBCUCP, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_CP_TNL_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_UP_TNLA_To_Remove_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_UP_TNLA_To_Remove_Item, GNB_CU_UP_TNLA_To_Remove_Item_sequence);

  return offset;
}


static const per_sequence_t GTPTLA_Item_sequence[] = {
  { &hf_e1ap_gTPTransportLayerAddresses, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GTPTLA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GTPTLA_Item, GTPTLA_Item_sequence);

  return offset;
}


static const per_sequence_t GTPTLAs_sequence_of[1] = {
  { &hf_e1ap_GTPTLAs_item   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_GTPTLA_Item },
};

static int
dissect_e1ap_GTPTLAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_GTPTLAs, GTPTLAs_sequence_of,
                                                  1, maxnoofGTPTLAs, false);

  return offset;
}


static const value_string e1ap_GNB_CU_UP_OverloadInformation_vals[] = {
  {   0, "overloaded" },
  {   1, "not-overloaded" },
  { 0, NULL }
};


static int
dissect_e1ap_GNB_CU_UP_OverloadInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_e1ap_GNB_DU_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(68719476735), NULL, false);

  return offset;
}



static int
dissect_e1ap_INTEGER_1_16777216_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16777216U, NULL, true);

  return offset;
}



static int
dissect_e1ap_INTEGER_0_100_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, true);

  return offset;
}


static const per_sequence_t HW_CapacityIndicator_sequence[] = {
  { &hf_e1ap_offeredThroughput, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_1_16777216_ },
  { &hf_e1ap_availableThroughput, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_100_ },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_HW_CapacityIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_HW_CapacityIndicator, HW_CapacityIndicator_sequence);

  return offset;
}


static const value_string e1ap_IndirectPathIndication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_IndirectPathIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_IgnoreMappingRuleIndication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_IgnoreMappingRuleIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_IntegrityProtectionIndication_vals[] = {
  {   0, "required" },
  {   1, "preferred" },
  {   2, "not-needed" },
  { 0, NULL }
};


static int
dissect_e1ap_IntegrityProtectionIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_IntegrityProtectionAlgorithm_vals[] = {
  {   0, "nIA0" },
  {   1, "i-128-NIA1" },
  {   2, "i-128-NIA2" },
  {   3, "i-128-NIA3" },
  { 0, NULL }
};


static int
dissect_e1ap_IntegrityProtectionAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_IntegrityProtectionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const value_string e1ap_IntegrityProtectionResult_vals[] = {
  {   0, "performed" },
  {   1, "not-performed" },
  { 0, NULL }
};


static int
dissect_e1ap_IntegrityProtectionResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_InterfacesToTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, &param_tvb, NULL);

  if(param_tvb){
    static int * const fields[] = {
      &hf_e1ap_InterfacesToTrace_NG_C,
      &hf_e1ap_InterfacesToTrace_Xn_C,
      &hf_e1ap_InterfacesToTrace_Uu,
      &hf_e1ap_InterfacesToTrace_F1_C,
      &hf_e1ap_InterfacesToTrace_E1,
      &hf_e1ap_InterfacesToTrace_Reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_e1ap_InterfacesToTrace);
    proto_tree_add_bitmask_list(subtree, param_tvb, 0, 1, fields, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_e1ap_MeasurementsToActivate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, &param_tvb, NULL);

  if (param_tvb) {
    static int * const fields[] = {
      &hf_e1ap_MeasurementsToActivate_Reserved1,
      &hf_e1ap_MeasurementsToActivate_M4,
      &hf_e1ap_MeasurementsToActivate_Reserved2,
      &hf_e1ap_MeasurementsToActivate_M6,
      &hf_e1ap_MeasurementsToActivate_M7,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_e1ap_MeasurementsToActivate);
    proto_tree_add_bitmask_list(subtree, param_tvb, 0, 1, fields, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const value_string e1ap_M4period_vals[] = {
  {   0, "ms1024" },
  {   1, "ms2048" },
  {   2, "ms5120" },
  {   3, "ms10240" },
  {   4, "min1" },
  { 0, NULL }
};


static int
dissect_e1ap_M4period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_Links_to_log_vals[] = {
  {   0, "uplink" },
  {   1, "downlink" },
  {   2, "both-uplink-and-downlink" },
  { 0, NULL }
};


static int
dissect_e1ap_Links_to_log(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t M4Configuration_sequence[] = {
  { &hf_e1ap_m4period       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_M4period },
  { &hf_e1ap_m4_links_to_log, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Links_to_log },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_M4Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_M4Configuration, M4Configuration_sequence);

  return offset;
}


static const value_string e1ap_M6report_Interval_vals[] = {
  {   0, "ms120" },
  {   1, "ms240" },
  {   2, "ms480" },
  {   3, "ms640" },
  {   4, "ms1024" },
  {   5, "ms2048" },
  {   6, "ms5120" },
  {   7, "ms10240" },
  {   8, "ms20480" },
  {   9, "ms40960" },
  {  10, "min1" },
  {  11, "min6" },
  {  12, "min12" },
  {  13, "min30" },
  { 0, NULL }
};


static int
dissect_e1ap_M6report_Interval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t M6Configuration_sequence[] = {
  { &hf_e1ap_m6report_Interval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_M6report_Interval },
  { &hf_e1ap_m6_links_to_log, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Links_to_log },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_M6Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_M6Configuration, M6Configuration_sequence);

  return offset;
}



static int
dissect_e1ap_M7period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 60U, NULL, true);

  return offset;
}


static const per_sequence_t M7Configuration_sequence[] = {
  { &hf_e1ap_m7period       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_M7period },
  { &hf_e1ap_m7_links_to_log, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Links_to_log },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_M7Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_M7Configuration, M7Configuration_sequence);

  return offset;
}


static const per_sequence_t ImmediateMDT_sequence[] = {
  { &hf_e1ap_measurementsToActivate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MeasurementsToActivate },
  { &hf_e1ap_measurementFour, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_M4Configuration },
  { &hf_e1ap_measurementSix , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_M6Configuration },
  { &hf_e1ap_measurementSeven, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_M7Configuration },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ImmediateMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ImmediateMDT, ImmediateMDT_sequence);

  return offset;
}



static int
dissect_e1ap_IAB_donor_CU_UPPSK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const per_sequence_t IAB_Donor_CU_UPPSKInfo_Item_sequence[] = {
  { &hf_e1ap_iAB_donor_CU_UPPSK, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_IAB_donor_CU_UPPSK },
  { &hf_e1ap_iAB_donor_CU_UPIPAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_iAB_DUIPAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_IAB_Donor_CU_UPPSKInfo_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_IAB_Donor_CU_UPPSKInfo_Item, IAB_Donor_CU_UPPSKInfo_Item_sequence);

  return offset;
}


static const value_string e1ap_InactivityInformationRequest_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_InactivityInformationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_MaxIPrate_vals[] = {
  {   0, "bitrate64kbs" },
  {   1, "max-UErate" },
  { 0, NULL }
};


static int
dissect_e1ap_MaxIPrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MaximumIPdatarate_sequence[] = {
  { &hf_e1ap_maxIPrate      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MaxIPrate },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MaximumIPdatarate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MaximumIPdatarate, MaximumIPdatarate_sequence);

  return offset;
}



static int
dissect_e1ap_MaxCIDEHCDL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32767U, NULL, true);

  return offset;
}


static const per_sequence_t MBSSessionAssociatedInformation_Item_sequence[] = {
  { &hf_e1ap_mbs_QoS_Flow_Identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Identifier },
  { &hf_e1ap_associated_unicast_QoS_Flow_Identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Identifier },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBSSessionAssociatedInformation_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBSSessionAssociatedInformation_Item, MBSSessionAssociatedInformation_Item_sequence);

  return offset;
}


static const per_sequence_t MBSSessionAssociatedInformationList_sequence_of[1] = {
  { &hf_e1ap_MBSSessionAssociatedInformationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSSessionAssociatedInformation_Item },
};

static int
dissect_e1ap_MBSSessionAssociatedInformationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MBSSessionAssociatedInformationList, MBSSessionAssociatedInformationList_sequence_of,
                                                  1, maxnoofQoSFlows, false);

  return offset;
}


static const per_sequence_t MBSSessionAssociatedInfoNonSupportToSupport_sequence[] = {
  { &hf_e1ap_ue_Reference_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_GNB_CU_CP_UE_E1AP_ID },
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_associatedQoSFlowInformationList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSSessionAssociatedInformationList },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBSSessionAssociatedInfoNonSupportToSupport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBSSessionAssociatedInfoNonSupportToSupport, MBSSessionAssociatedInfoNonSupportToSupport_sequence);

  return offset;
}


static const per_sequence_t MBSSessionAssociatedInformation_sequence[] = {
  { &hf_e1ap_mbsSessionAssociatedInformationList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSSessionAssociatedInformationList },
  { &hf_e1ap_mbsSessionForwardingAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBSSessionAssociatedInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBSSessionAssociatedInformation, MBSSessionAssociatedInformation_sequence);

  return offset;
}


static const value_string e1ap_T_dlDataArrival_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_T_dlDataArrival(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_PPI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, true);

  return offset;
}


static const per_sequence_t MBS_DL_Data_Arrival_sequence[] = {
  { &hf_e1ap_dlDataArrival  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_T_dlDataArrival },
  { &hf_e1ap_ppi            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PPI },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBS_DL_Data_Arrival(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBS_DL_Data_Arrival, MBS_DL_Data_Arrival_sequence);

  return offset;
}


static const value_string e1ap_T_mcBearerContext_Inactivity_Indication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_T_mcBearerContext_Inactivity_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MCBearerContext_Inactivity_sequence[] = {
  { &hf_e1ap_mcBearerContext_Inactivity_Indication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_T_mcBearerContext_Inactivity_Indication },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContext_Inactivity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContext_Inactivity, MCBearerContext_Inactivity_sequence);

  return offset;
}


static const value_string e1ap_MBSSessionResourceNotification_vals[] = {
  {   0, "mbs-DL-Data-Arrival" },
  {   1, "inactivity" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t MBSSessionResourceNotification_choice[] = {
  {   0, &hf_e1ap_mbs_DL_Data_Arrival, ASN1_NO_EXTENSIONS     , dissect_e1ap_MBS_DL_Data_Arrival },
  {   1, &hf_e1ap_inactivity     , ASN1_NO_EXTENSIONS     , dissect_e1ap_MCBearerContext_Inactivity },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_MBSSessionResourceNotification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_MBSSessionResourceNotification, MBSSessionResourceNotification_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MCMRBSetupConfiguration_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_mbs_pdcp_config, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDCP_Configuration },
  { &hf_e1ap_qoS_Flow_QoS_Parameter_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_QoS_Parameter_List },
  { &hf_e1ap_qoSFlowLevelQoSParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoSFlowLevelQoSParameters },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCMRBSetupConfiguration_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCMRBSetupConfiguration_Item, MCMRBSetupConfiguration_Item_sequence);

  return offset;
}


static const per_sequence_t MCMRBSetupConfiguration_sequence_of[1] = {
  { &hf_e1ap_MCMRBSetupConfiguration_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MCMRBSetupConfiguration_Item },
};

static int
dissect_e1ap_MCMRBSetupConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MCMRBSetupConfiguration, MCMRBSetupConfiguration_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const per_sequence_t MCBearerContextToSetup_sequence[] = {
  { &hf_e1ap_snssai         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SNSSAI },
  { &hf_e1ap_mcMRBToSetupList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCMRBSetupConfiguration },
  { &hf_e1ap_requestedAction, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_RequestedAction4AvailNGUTermination },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextToSetup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextToSetup, MCBearerContextToSetup_sequence);

  return offset;
}


static const value_string e1ap_MCBearerContextStatusChange_vals[] = {
  {   0, "suspend" },
  {   1, "resume" },
  { 0, NULL }
};


static int
dissect_e1ap_MCBearerContextStatusChange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_MCBearerContextNGU_TNLInfoatNGRAN_vals[] = {
  {   0, "locationindependent" },
  {   1, "locationdependent" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t MCBearerContextNGU_TNLInfoatNGRAN_choice[] = {
  {   0, &hf_e1ap_locationindependent_01, ASN1_NO_EXTENSIONS     , dissect_e1ap_MBSNGUInformationAtNGRAN },
  {   1, &hf_e1ap_locationdependent_01, ASN1_NO_EXTENSIONS     , dissect_e1ap_LocationDependentMBSNGUInformationAtNGRAN },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextNGU_TNLInfoatNGRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_MCBearerContextNGU_TNLInfoatNGRAN, MCBearerContextNGU_TNLInfoatNGRAN_choice,
                                 NULL);

  return offset;
}



static int
dissect_e1ap_MBS_PDCP_COUNT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t MCMRBSetupResponseList_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_qosflow_setup  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_List },
  { &hf_e1ap_qosflow_failed , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_Failed_List },
  { &hf_e1ap_mBS_PDCP_COUNT , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBS_PDCP_COUNT },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCMRBSetupResponseList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCMRBSetupResponseList_Item, MCMRBSetupResponseList_Item_sequence);

  return offset;
}


static const per_sequence_t MCMRBSetupResponseList_sequence_of[1] = {
  { &hf_e1ap_MCMRBSetupResponseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MCMRBSetupResponseList_Item },
};

static int
dissect_e1ap_MCMRBSetupResponseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MCMRBSetupResponseList, MCMRBSetupResponseList_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const per_sequence_t MCMRBFailedList_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCMRBFailedList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCMRBFailedList_Item, MCMRBFailedList_Item_sequence);

  return offset;
}


static const per_sequence_t MCMRBFailedList_sequence_of[1] = {
  { &hf_e1ap_MCMRBFailedList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MCMRBFailedList_Item },
};

static int
dissect_e1ap_MCMRBFailedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MCMRBFailedList, MCMRBFailedList_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const per_sequence_t MCBearerContextToSetupResponse_sequence[] = {
  { &hf_e1ap_mcBearerContextNGU_TNLInfoatNGRAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCBearerContextNGU_TNLInfoatNGRAN },
  { &hf_e1ap_mcMRBSetupResponseList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCMRBSetupResponseList },
  { &hf_e1ap_mcMRBFailedList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCMRBFailedList },
  { &hf_e1ap_availableMCMRBConfig, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCMRBSetupConfiguration },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextToSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextToSetupResponse, MCBearerContextToSetupResponse_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextNGUTNLInfoat5GC_sequence[] = {
  { &hf_e1ap_mbsNGUInformationAt5GC, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSNGUInformationAt5GC },
  { &hf_e1ap_mbsAreaSession_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBSAreaSessionID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextNGUTNLInfoat5GC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextNGUTNLInfoat5GC, MCBearerContextNGUTNLInfoat5GC_sequence);

  return offset;
}


static const value_string e1ap_T_ngRANNGUTNLRequested_vals[] = {
  {   0, "requested" },
  { 0, NULL }
};


static int
dissect_e1ap_T_ngRANNGUTNLRequested(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MCBearerContextNGUTnlInfoatNGRANRequest_sequence[] = {
  { &hf_e1ap_ngRANNGUTNLRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_T_ngRANNGUTNLRequested },
  { &hf_e1ap_mbsAreaSession_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBSAreaSessionID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextNGUTnlInfoatNGRANRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextNGUTnlInfoatNGRANRequest, MCBearerContextNGUTnlInfoatNGRANRequest_sequence);

  return offset;
}



static int
dissect_e1ap_MulticastF1UContextReferenceE1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}


static const value_string e1ap_T_mc_F1UCtxtusage_vals[] = {
  {   0, "ptm" },
  {   1, "ptp" },
  {   2, "ptp-retransmission" },
  {   3, "ptp-forwarding" },
  { 0, NULL }
};


static int
dissect_e1ap_T_mc_F1UCtxtusage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MBSMulticastF1UContextDescriptor_sequence[] = {
  { &hf_e1ap_multicastF1UContextReferenceE1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MulticastF1UContextReferenceE1 },
  { &hf_e1ap_mc_F1UCtxtusage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_T_mc_F1UCtxtusage },
  { &hf_e1ap_mbsAreaSession , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBSAreaSessionID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBSMulticastF1UContextDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBSMulticastF1UContextDescriptor, MBSMulticastF1UContextDescriptor_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextF1UTNLInfoatDU_sequence[] = {
  { &hf_e1ap_mbsF1UInfoatDU , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_mbsMulticastF1UContextDescriptor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSMulticastF1UContextDescriptor },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextF1UTNLInfoatDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextF1UTNLInfoatDU, MCBearerContextF1UTNLInfoatDU_sequence);

  return offset;
}


static const value_string e1ap_MBS_PDCP_COUNT_Req_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_MBS_PDCP_COUNT_Req(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MCMRBSetupModifyConfiguration_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_f1uTNLatDU     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCBearerContextF1UTNLInfoatDU },
  { &hf_e1ap_mbs_pdcp_config, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_PDCP_Configuration },
  { &hf_e1ap_qoS_Flow_QoS_Parameter_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_QoS_Parameter_List },
  { &hf_e1ap_mrbQoS         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoSFlowLevelQoSParameters },
  { &hf_e1ap_mbs_PDCP_COUNT_Req, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBS_PDCP_COUNT_Req },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCMRBSetupModifyConfiguration_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCMRBSetupModifyConfiguration_Item, MCMRBSetupModifyConfiguration_Item_sequence);

  return offset;
}


static const per_sequence_t MCMRBSetupModifyConfiguration_sequence_of[1] = {
  { &hf_e1ap_MCMRBSetupModifyConfiguration_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MCMRBSetupModifyConfiguration_Item },
};

static int
dissect_e1ap_MCMRBSetupModifyConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MCMRBSetupModifyConfiguration, MCMRBSetupModifyConfiguration_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const per_sequence_t MCMRBRemoveConfiguration_sequence_of[1] = {
  { &hf_e1ap_MCMRBRemoveConfiguration_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
};

static int
dissect_e1ap_MCMRBRemoveConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MCMRBRemoveConfiguration, MCMRBRemoveConfiguration_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const per_sequence_t MCBearerContextToModify_sequence[] = {
  { &hf_e1ap_mcBearerContextNGUTNLInfoat5GC, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCBearerContextNGUTNLInfoat5GC },
  { &hf_e1ap_mcBearerContextNGUTnlInfoatNGRANRequest, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCBearerContextNGUTnlInfoatNGRANRequest },
  { &hf_e1ap_mbsMulticastF1UContextDescriptor, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBSMulticastF1UContextDescriptor },
  { &hf_e1ap_requestedAction, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_RequestedAction4AvailNGUTermination },
  { &hf_e1ap_mcMRBToSetupModifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCMRBSetupModifyConfiguration },
  { &hf_e1ap_mcMRBToRemoveList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCMRBRemoveConfiguration },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextToModify(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextToModify, MCBearerContextToModify_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextNGU_TNLInfoatNGRANModifyResponse_sequence[] = {
  { &hf_e1ap_mbs_NGU_InfoatNGRAN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSNGUInformationAtNGRAN },
  { &hf_e1ap_mbsAreaSession , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBSAreaSessionID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextNGU_TNLInfoatNGRANModifyResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextNGU_TNLInfoatNGRANModifyResponse, MCBearerContextNGU_TNLInfoatNGRANModifyResponse_sequence);

  return offset;
}


static const per_sequence_t MCMRBSetupModifyResponseList_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_qosflow_setup  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_List },
  { &hf_e1ap_qosflow_failed , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Flow_Failed_List },
  { &hf_e1ap_mcBearerContextF1UTNLInfoatCU, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_mBS_PDCP_COUNT , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBS_PDCP_COUNT },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCMRBSetupModifyResponseList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCMRBSetupModifyResponseList_Item, MCMRBSetupModifyResponseList_Item_sequence);

  return offset;
}


static const per_sequence_t MCMRBSetupModifyResponseList_sequence_of[1] = {
  { &hf_e1ap_MCMRBSetupModifyResponseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MCMRBSetupModifyResponseList_Item },
};

static int
dissect_e1ap_MCMRBSetupModifyResponseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MCMRBSetupModifyResponseList, MCMRBSetupModifyResponseList_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const per_sequence_t MCBearerContextToModifyResponse_sequence[] = {
  { &hf_e1ap_mcBearerContextNGU_TNLInfoatNGRANModifyResponse, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCBearerContextNGU_TNLInfoatNGRANModifyResponse },
  { &hf_e1ap_mbsMulticastF1UContextDescriptor, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBSMulticastF1UContextDescriptor },
  { &hf_e1ap_mcMRBModifySetupResponseList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCMRBSetupModifyResponseList },
  { &hf_e1ap_mcMRBFailedList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCMRBFailedList },
  { &hf_e1ap_availableMCMRBConfig, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCMRBSetupConfiguration },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextToModifyResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextToModifyResponse, MCBearerContextToModifyResponse_sequence);

  return offset;
}


static const per_sequence_t MCMRBModifyRequiredConfiguration_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_mBS_PDCP_COUNT , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBS_PDCP_COUNT },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCMRBModifyRequiredConfiguration_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCMRBModifyRequiredConfiguration_Item, MCMRBModifyRequiredConfiguration_Item_sequence);

  return offset;
}


static const per_sequence_t MCMRBModifyRequiredConfiguration_sequence_of[1] = {
  { &hf_e1ap_MCMRBModifyRequiredConfiguration_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MCMRBModifyRequiredConfiguration_Item },
};

static int
dissect_e1ap_MCMRBModifyRequiredConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MCMRBModifyRequiredConfiguration, MCMRBModifyRequiredConfiguration_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const per_sequence_t MCBearerContextToModifyRequired_sequence[] = {
  { &hf_e1ap_mbsMulticastF1UContextDescriptor, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBSMulticastF1UContextDescriptor },
  { &hf_e1ap_mcMRBToRemoveRequiredList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCMRBRemoveConfiguration },
  { &hf_e1ap_mcMRBToModifyRequiredList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCMRBModifyRequiredConfiguration },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextToModifyRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextToModifyRequired, MCBearerContextToModifyRequired_sequence);

  return offset;
}


static const per_sequence_t MCMRBModifyConfirmList_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCMRBModifyConfirmList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCMRBModifyConfirmList_Item, MCMRBModifyConfirmList_Item_sequence);

  return offset;
}


static const per_sequence_t MCMRBModifyConfirmList_sequence_of[1] = {
  { &hf_e1ap_MCMRBModifyConfirmList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MCMRBModifyConfirmList_Item },
};

static int
dissect_e1ap_MCMRBModifyConfirmList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MCMRBModifyConfirmList, MCMRBModifyConfirmList_sequence_of,
                                                  1, maxnoofMRBs, false);

  return offset;
}


static const per_sequence_t MCBearerContextToModifyConfirm_sequence[] = {
  { &hf_e1ap_mbsMulticastF1UContextDescriptor, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBSMulticastF1UContextDescriptor },
  { &hf_e1ap_mcMRBModifyConfirmList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MCMRBModifyConfirmList },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextToModifyConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextToModifyConfirm, MCBearerContextToModifyConfirm_sequence);

  return offset;
}



static int
dissect_e1ap_MCForwardingResourceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, NULL);

  return offset;
}


static const value_string e1ap_MRB_ProgressInformationType_vals[] = {
  {   0, "oldest-available" },
  {   1, "last-delivered" },
  { 0, NULL }
};


static int
dissect_e1ap_MRB_ProgressInformationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_T_mrbForwardingAddressRequest_vals[] = {
  {   0, "request" },
  { 0, NULL }
};


static int
dissect_e1ap_T_mrbForwardingAddressRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MRBForwardingResourceRequest_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_mrbProgressRequestType, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MRB_ProgressInformationType },
  { &hf_e1ap_mrbForwardingAddressRequest, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_T_mrbForwardingAddressRequest },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MRBForwardingResourceRequest_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MRBForwardingResourceRequest_Item, MRBForwardingResourceRequest_Item_sequence);

  return offset;
}


static const per_sequence_t MRBForwardingResourceRequestList_sequence_of[1] = {
  { &hf_e1ap_MRBForwardingResourceRequestList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MRBForwardingResourceRequest_Item },
};

static int
dissect_e1ap_MRBForwardingResourceRequestList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MRBForwardingResourceRequestList, MRBForwardingResourceRequestList_sequence_of,
                                                  1, maxnoofQoSFlows, false);

  return offset;
}


static const per_sequence_t MCForwardingResourceRequest_sequence[] = {
  { &hf_e1ap_mcForwardingResourceID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MCForwardingResourceID },
  { &hf_e1ap_mbsAreaSession_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBSAreaSessionID },
  { &hf_e1ap_mrbForwardingResourceRequestList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MRBForwardingResourceRequestList },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCForwardingResourceRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCForwardingResourceRequest, MCForwardingResourceRequest_sequence);

  return offset;
}



static int
dissect_e1ap_INTEGER_0_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}



static int
dissect_e1ap_INTEGER_0_262143(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 262143U, NULL, false);

  return offset;
}


static const value_string e1ap_MRB_ProgressInformationSNs_vals[] = {
  {   0, "pdcp-SN12" },
  {   1, "pdcp-SN18" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t MRB_ProgressInformationSNs_choice[] = {
  {   0, &hf_e1ap_pdcp_SN12      , ASN1_NO_EXTENSIONS     , dissect_e1ap_INTEGER_0_4095 },
  {   1, &hf_e1ap_pdcp_SN18      , ASN1_NO_EXTENSIONS     , dissect_e1ap_INTEGER_0_262143 },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_MRB_ProgressInformationSNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_MRB_ProgressInformationSNs, MRB_ProgressInformationSNs_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MRB_ProgressInformation_sequence[] = {
  { &hf_e1ap_mrb_ProgressInformationSNs, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ProgressInformationSNs },
  { &hf_e1ap_mrb_ProgressInformationType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ProgressInformationType },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MRB_ProgressInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MRB_ProgressInformation, MRB_ProgressInformation_sequence);

  return offset;
}


static const per_sequence_t MRBForwardingResourceIndication_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_mrb_ProgressInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MRB_ProgressInformation },
  { &hf_e1ap_mrbForwardingAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MRBForwardingResourceIndication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MRBForwardingResourceIndication_Item, MRBForwardingResourceIndication_Item_sequence);

  return offset;
}


static const per_sequence_t MRBForwardingResourceIndicationList_sequence_of[1] = {
  { &hf_e1ap_MRBForwardingResourceIndicationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MRBForwardingResourceIndication_Item },
};

static int
dissect_e1ap_MRBForwardingResourceIndicationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MRBForwardingResourceIndicationList, MRBForwardingResourceIndicationList_sequence_of,
                                                  1, maxnoofQoSFlows, false);

  return offset;
}


static const per_sequence_t MCForwardingResourceIndication_sequence[] = {
  { &hf_e1ap_mcForwardingResourceID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MCForwardingResourceID },
  { &hf_e1ap_mrbForwardingResourceIndicationList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MRBForwardingResourceIndicationList },
  { &hf_e1ap_mbsSessionAssociatedInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBSSessionAssociatedInformation },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCForwardingResourceIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCForwardingResourceIndication, MCForwardingResourceIndication_sequence);

  return offset;
}


static const per_sequence_t MRBForwardingResourceResponse_Item_sequence[] = {
  { &hf_e1ap_mrb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRB_ID },
  { &hf_e1ap_mrb_ProgressInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MRB_ProgressInformation },
  { &hf_e1ap_mrbForwardingAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MRBForwardingResourceResponse_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MRBForwardingResourceResponse_Item, MRBForwardingResourceResponse_Item_sequence);

  return offset;
}


static const per_sequence_t MRBForwardingResourceResponseList_sequence_of[1] = {
  { &hf_e1ap_MRBForwardingResourceResponseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MRBForwardingResourceResponse_Item },
};

static int
dissect_e1ap_MRBForwardingResourceResponseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MRBForwardingResourceResponseList, MRBForwardingResourceResponseList_sequence_of,
                                                  1, maxnoofQoSFlows, false);

  return offset;
}


static const per_sequence_t MCForwardingResourceResponse_sequence[] = {
  { &hf_e1ap_mcForwardingResourceID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MCForwardingResourceID },
  { &hf_e1ap_mrbForwardingResourceResponseList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MRBForwardingResourceResponseList },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCForwardingResourceResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCForwardingResourceResponse, MCForwardingResourceResponse_sequence);

  return offset;
}


static const per_sequence_t MCForwardingResourceRelease_sequence[] = {
  { &hf_e1ap_mcForwardingResourceID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MCForwardingResourceID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCForwardingResourceRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCForwardingResourceRelease, MCForwardingResourceRelease_sequence);

  return offset;
}


static const per_sequence_t MCForwardingResourceReleaseIndication_sequence[] = {
  { &hf_e1ap_mcForwardingResourceID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MCForwardingResourceID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCForwardingResourceReleaseIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCForwardingResourceReleaseIndication, MCForwardingResourceReleaseIndication_sequence);

  return offset;
}


static const value_string e1ap_MDTPollutedMeasurementIndicator_vals[] = {
  {   0, "iDC" },
  {   1, "no-IDC" },
  { 0, NULL }
};


static int
dissect_e1ap_MDTPollutedMeasurementIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MRDC_Usage_Information_sequence[] = {
  { &hf_e1ap_data_Usage_per_PDU_Session_Report, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Usage_per_PDU_Session_Report },
  { &hf_e1ap_data_Usage_per_QoS_Flow_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Usage_per_QoS_Flow_List },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MRDC_Usage_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MRDC_Usage_Information, MRDC_Usage_Information_sequence);

  return offset;
}


static const value_string e1ap_M4ReportAmount_vals[] = {
  {   0, "r1" },
  {   1, "r2" },
  {   2, "r4" },
  {   3, "r8" },
  {   4, "r16" },
  {   5, "r32" },
  {   6, "r64" },
  {   7, "infinity" },
  { 0, NULL }
};


static int
dissect_e1ap_M4ReportAmount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_M6ReportAmount_vals[] = {
  {   0, "r1" },
  {   1, "r2" },
  {   2, "r4" },
  {   3, "r8" },
  {   4, "r16" },
  {   5, "r32" },
  {   6, "r64" },
  {   7, "infinity" },
  { 0, NULL }
};


static int
dissect_e1ap_M6ReportAmount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_M7ReportAmount_vals[] = {
  {   0, "r1" },
  {   1, "r2" },
  {   2, "r4" },
  {   3, "r8" },
  {   4, "r16" },
  {   5, "r32" },
  {   6, "r64" },
  {   7, "infinity" },
  { 0, NULL }
};


static int
dissect_e1ap_M7ReportAmount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_MDT_Activation_vals[] = {
  {   0, "immediate-MDT-only" },
  {   1, "immediate-MDT-and-Trace" },
  { 0, NULL }
};


static int
dissect_e1ap_MDT_Activation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_MDTMode_vals[] = {
  {   0, "immediateMDT" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t MDTMode_choice[] = {
  {   0, &hf_e1ap_immediateMDT   , ASN1_NO_EXTENSIONS     , dissect_e1ap_ImmediateMDT },
  {   1, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_MDTMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_MDTMode, MDTMode_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MDT_Configuration_sequence[] = {
  { &hf_e1ap_mdt_Activation , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MDT_Activation },
  { &hf_e1ap_mDTMode        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MDTMode },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MDT_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MDT_Configuration, MDT_Configuration_sequence);

  return offset;
}


static const per_sequence_t MDTPLMNList_sequence_of[1] = {
  { &hf_e1ap_MDTPLMNList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PLMN_Identity },
};

static int
dissect_e1ap_MDTPLMNList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MDTPLMNList, MDTPLMNList_sequence_of,
                                                  1, maxnoofMDTPLMNs, false);

  return offset;
}


static const per_sequence_t MDTPLMNModificationList_sequence_of[1] = {
  { &hf_e1ap_MDTPLMNModificationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PLMN_Identity },
};

static int
dissect_e1ap_MDTPLMNModificationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MDTPLMNModificationList, MDTPLMNModificationList_sequence_of,
                                                  0, maxnoofMDTPLMNs, false);

  return offset;
}



static int
dissect_e1ap_MT_SDT_Data_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 96000U, NULL, true);

  return offset;
}


static const per_sequence_t MT_SDT_Information_sequence[] = {
  { &hf_e1ap_mT_SDT_Data_Size, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MT_SDT_Data_Size },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MT_SDT_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MT_SDT_Information, MT_SDT_Information_sequence);

  return offset;
}


static const value_string e1ap_MT_SDT_Information_Request_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_MT_SDT_Information_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_NR_Cell_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NR_CGI_sequence[] = {
  { &hf_e1ap_pLMN_Identity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PLMN_Identity },
  { &hf_e1ap_nR_Cell_Identity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_NR_Cell_Identity },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_NR_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(actx->pinfo);
  e1ap_data->number_type = E212_NRCGI;
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_NR_CGI, NR_CGI_sequence);



  return offset;
}


static const per_sequence_t MBS_ServiceAreaCellList_sequence_of[1] = {
  { &hf_e1ap_MBS_ServiceAreaCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_NR_CGI },
};

static int
dissect_e1ap_MBS_ServiceAreaCellList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MBS_ServiceAreaCellList, MBS_ServiceAreaCellList_sequence_of,
                                                  1, maxnoofCellsforMBS, false);

  return offset;
}


static const per_sequence_t MBS_ServiceAreaTAIList_Item_sequence[] = {
  { &hf_e1ap_plmn_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PLMN_Identity },
  { &hf_e1ap_fiveGS_TAC     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_FiveGS_TAC },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBS_ServiceAreaTAIList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBS_ServiceAreaTAIList_Item, MBS_ServiceAreaTAIList_Item_sequence);

  return offset;
}


static const per_sequence_t MBS_ServiceAreaTAIList_sequence_of[1] = {
  { &hf_e1ap_MBS_ServiceAreaTAIList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MBS_ServiceAreaTAIList_Item },
};

static int
dissect_e1ap_MBS_ServiceAreaTAIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MBS_ServiceAreaTAIList, MBS_ServiceAreaTAIList_sequence_of,
                                                  1, maxnoofTAIforMBS, false);

  return offset;
}


static const per_sequence_t MBS_ServiceAreaInformation_sequence[] = {
  { &hf_e1ap_mBS_ServiceAreaCellList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBS_ServiceAreaCellList },
  { &hf_e1ap_mBS_ServiceAreaTAIList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBS_ServiceAreaTAIList },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBS_ServiceAreaInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBS_ServiceAreaInformation, MBS_ServiceAreaInformation_sequence);

  return offset;
}


static const per_sequence_t MBS_ServiceAreaInformationItem_sequence[] = {
  { &hf_e1ap_mBS_AreaSessionID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBSAreaSessionID },
  { &hf_e1ap_mBS_ServiceAreaInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MBS_ServiceAreaInformation },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBS_ServiceAreaInformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBS_ServiceAreaInformationItem, MBS_ServiceAreaInformationItem_sequence);

  return offset;
}


static const per_sequence_t MBS_ServiceAreaInformationList_sequence_of[1] = {
  { &hf_e1ap_MBS_ServiceAreaInformationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_MBS_ServiceAreaInformationItem },
};

static int
dissect_e1ap_MBS_ServiceAreaInformationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_MBS_ServiceAreaInformationList, MBS_ServiceAreaInformationList_sequence_of,
                                                  1, maxnoofMBSServiceAreaInformation, false);

  return offset;
}


static const per_sequence_t MBS_ServiceArea_sequence[] = {
  { &hf_e1ap_mBS_ServiceAreaInformationList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MBS_ServiceAreaInformationList },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MBS_ServiceArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MBS_ServiceArea, MBS_ServiceArea_sequence);

  return offset;
}



static int
dissect_e1ap_NetworkInstance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, true);

  return offset;
}


static const value_string e1ap_New_UL_TNL_Information_Required_vals[] = {
  {   0, "required" },
  { 0, NULL }
};


static int
dissect_e1ap_New_UL_TNL_Information_Required(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t NG_RAN_QoS_Support_Item_sequence[] = {
  { &hf_e1ap_non_Dynamic5QIDescriptor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Non_Dynamic5QIDescriptor },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_NG_RAN_QoS_Support_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_NG_RAN_QoS_Support_Item, NG_RAN_QoS_Support_Item_sequence);

  return offset;
}


static const per_sequence_t NG_RAN_QoS_Support_List_sequence_of[1] = {
  { &hf_e1ap_NG_RAN_QoS_Support_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_NG_RAN_QoS_Support_Item },
};

static int
dissect_e1ap_NG_RAN_QoS_Support_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_NG_RAN_QoS_Support_List, NG_RAN_QoS_Support_List_sequence_of,
                                                  1, maxnoofNGRANQOSParameters, false);

  return offset;
}


static const per_sequence_t NPNSupportInfo_SNPN_sequence[] = {
  { &hf_e1ap_nID            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_NID },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_NPNSupportInfo_SNPN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_NPNSupportInfo_SNPN, NPNSupportInfo_SNPN_sequence);

  return offset;
}


static const value_string e1ap_NPNSupportInfo_vals[] = {
  {   0, "sNPN" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t NPNSupportInfo_choice[] = {
  {   0, &hf_e1ap_sNPN           , ASN1_NO_EXTENSIONS     , dissect_e1ap_NPNSupportInfo_SNPN },
  {   1, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_NPNSupportInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_NPNSupportInfo, NPNSupportInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NPNContextInfo_SNPN_sequence[] = {
  { &hf_e1ap_nID            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_NID },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_NPNContextInfo_SNPN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_NPNContextInfo_SNPN, NPNContextInfo_SNPN_sequence);

  return offset;
}


static const value_string e1ap_NPNContextInfo_vals[] = {
  {   0, "sNPN" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t NPNContextInfo_choice[] = {
  {   0, &hf_e1ap_sNPN_01        , ASN1_NO_EXTENSIONS     , dissect_e1ap_NPNContextInfo_SNPN },
  {   1, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_NPNContextInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_NPNContextInfo, NPNContextInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NR_CGI_Support_Item_sequence[] = {
  { &hf_e1ap_nR_CGI         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_NR_CGI },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_NR_CGI_Support_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_NR_CGI_Support_Item, NR_CGI_Support_Item_sequence);

  return offset;
}


static const per_sequence_t NR_CGI_Support_List_sequence_of[1] = {
  { &hf_e1ap_NR_CGI_Support_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_NR_CGI_Support_Item },
};

static int
dissect_e1ap_NR_CGI_Support_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_NR_CGI_Support_List, NR_CGI_Support_List_sequence_of,
                                                  1, maxnoofNRCGI, false);

  return offset;
}


static const per_sequence_t Extended_NR_CGI_Support_Item_sequence[] = {
  { &hf_e1ap_nR_CGI         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_NR_CGI },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Extended_NR_CGI_Support_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Extended_NR_CGI_Support_Item, Extended_NR_CGI_Support_Item_sequence);

  return offset;
}


static const per_sequence_t Extended_NR_CGI_Support_List_sequence_of[1] = {
  { &hf_e1ap_Extended_NR_CGI_Support_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Extended_NR_CGI_Support_Item },
};

static int
dissect_e1ap_Extended_NR_CGI_Support_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_Extended_NR_CGI_Support_List, Extended_NR_CGI_Support_List_sequence_of,
                                                  1, maxnoofExtNRCGI, false);

  return offset;
}



static int
dissect_e1ap_INTEGER_M127_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 127U, NULL, false);

  return offset;
}


static const per_sequence_t N6JitterInformation_sequence[] = {
  { &hf_e1ap_n6JitterLowerBound, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_M127_127 },
  { &hf_e1ap_n6JitterUpperBound, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_M127_127 },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_N6JitterInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_N6JitterInformation, N6JitterInformation_sequence);

  return offset;
}


static const value_string e1ap_PDCPSNGapReport_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_PDCPSNGapReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_PDCP_COUNT_Reset_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_PDCP_COUNT_Reset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Data_Usage_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_mRDC_Usage_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_MRDC_Usage_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_Data_Usage_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_Data_Usage_Item, PDU_Session_Resource_Data_Usage_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Data_Usage_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_Data_Usage_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_Data_Usage_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_Data_Usage_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_Data_Usage_List, PDU_Session_Resource_Data_Usage_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const value_string e1ap_PDCP_StatusReportIndication_vals[] = {
  {   0, "downlink" },
  {   1, "uplink" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_e1ap_PDCP_StatusReportIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_PDUSession_PairID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, true);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Confirm_Modified_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_dRB_Confirm_Modified_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DRB_Confirm_Modified_List_NG_RAN },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_Confirm_Modified_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_Confirm_Modified_Item, PDU_Session_Resource_Confirm_Modified_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Confirm_Modified_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_Confirm_Modified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_Confirm_Modified_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_Confirm_Modified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_Confirm_Modified_List, PDU_Session_Resource_Confirm_Modified_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Failed_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_Failed_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_Failed_Item, PDU_Session_Resource_Failed_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Failed_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_Failed_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_Failed_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_Failed_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_Failed_List, PDU_Session_Resource_Failed_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Failed_Mod_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_Failed_Mod_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_Failed_Mod_Item, PDU_Session_Resource_Failed_Mod_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Failed_Mod_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_Failed_Mod_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_Failed_Mod_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_Failed_Mod_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_Failed_Mod_List, PDU_Session_Resource_Failed_Mod_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Failed_To_Modify_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_Cause },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_Failed_To_Modify_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_Failed_To_Modify_Item, PDU_Session_Resource_Failed_To_Modify_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Failed_To_Modify_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_Failed_To_Modify_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_Failed_To_Modify_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_Failed_To_Modify_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_Failed_To_Modify_List, PDU_Session_Resource_Failed_To_Modify_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const per_sequence_t SecurityResult_sequence[] = {
  { &hf_e1ap_integrityProtectionResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_IntegrityProtectionResult },
  { &hf_e1ap_confidentialityProtectionResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ConfidentialityProtectionResult },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_SecurityResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_SecurityResult, SecurityResult_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Modified_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_nG_DL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_securityResult , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_SecurityResult },
  { &hf_e1ap_pDU_Session_Data_Forwarding_Information_Response, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information },
  { &hf_e1ap_dRB_Setup_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DRB_Setup_List_NG_RAN },
  { &hf_e1ap_dRB_Failed_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DRB_Failed_List_NG_RAN },
  { &hf_e1ap_dRB_Modified_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DRB_Modified_List_NG_RAN },
  { &hf_e1ap_dRB_Failed_To_Modify_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DRB_Failed_To_Modify_List_NG_RAN },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_Modified_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_Modified_Item, PDU_Session_Resource_Modified_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Modified_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_Modified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_Modified_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_Modified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_Modified_List, PDU_Session_Resource_Modified_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Required_To_Modify_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_nG_DL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_dRB_Required_To_Modify_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DRB_Required_To_Modify_List_NG_RAN },
  { &hf_e1ap_dRB_Required_To_Remove_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DRB_Required_To_Remove_List_NG_RAN },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_Required_To_Modify_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_Required_To_Modify_Item, PDU_Session_Resource_Required_To_Modify_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Required_To_Modify_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_Required_To_Modify_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_Required_To_Modify_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_Required_To_Modify_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_Required_To_Modify_List, PDU_Session_Resource_Required_To_Modify_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const value_string e1ap_T_nG_DL_UP_Unchanged_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_T_nG_DL_UP_Unchanged(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Setup_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_securityResult , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_SecurityResult },
  { &hf_e1ap_nG_DL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_pDU_Session_Data_Forwarding_Information_Response, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information },
  { &hf_e1ap_nG_DL_UP_Unchanged, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_T_nG_DL_UP_Unchanged },
  { &hf_e1ap_dRB_Setup_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Setup_List_NG_RAN },
  { &hf_e1ap_dRB_Failed_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DRB_Failed_List_NG_RAN },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_Setup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_Setup_Item, PDU_Session_Resource_Setup_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Setup_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_Setup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_Setup_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_Setup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_Setup_List, PDU_Session_Resource_Setup_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Setup_Mod_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_securityResult , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_SecurityResult },
  { &hf_e1ap_nG_DL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_pDU_Session_Data_Forwarding_Information_Response, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information },
  { &hf_e1ap_dRB_Setup_Mod_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Setup_Mod_List_NG_RAN },
  { &hf_e1ap_dRB_Failed_Mod_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DRB_Failed_Mod_List_NG_RAN },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_Setup_Mod_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_Setup_Mod_Item, PDU_Session_Resource_Setup_Mod_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_Setup_Mod_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_Setup_Mod_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_Setup_Mod_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_Setup_Mod_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_Setup_Mod_List, PDU_Session_Resource_Setup_Mod_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const per_sequence_t SecurityIndication_sequence[] = {
  { &hf_e1ap_integrityProtectionIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_IntegrityProtectionIndication },
  { &hf_e1ap_confidentialityProtectionIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ConfidentialityProtectionIndication },
  { &hf_e1ap_maximumIPdatarate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_MaximumIPdatarate },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_SecurityIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_SecurityIndication, SecurityIndication_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_To_Modify_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_securityIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_SecurityIndication },
  { &hf_e1ap_pDU_Session_Resource_DL_AMBR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BitRate },
  { &hf_e1ap_nG_UL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_pDU_Session_Data_Forwarding_Information_Request, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information_Request },
  { &hf_e1ap_pDU_Session_Data_Forwarding_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information },
  { &hf_e1ap_pDU_Session_Inactivity_Timer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Inactivity_Timer },
  { &hf_e1ap_networkInstance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_NetworkInstance },
  { &hf_e1ap_dRB_To_Setup_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DRB_To_Setup_List_NG_RAN },
  { &hf_e1ap_dRB_To_Modify_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DRB_To_Modify_List_NG_RAN },
  { &hf_e1ap_dRB_To_Remove_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_DRB_To_Remove_List_NG_RAN },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_To_Modify_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_To_Modify_Item, PDU_Session_Resource_To_Modify_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_To_Modify_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_To_Modify_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_To_Modify_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_To_Modify_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_To_Modify_List, PDU_Session_Resource_To_Modify_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_To_Remove_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_To_Remove_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_To_Remove_Item, PDU_Session_Resource_To_Remove_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_To_Remove_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_To_Remove_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_To_Remove_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_To_Remove_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_To_Remove_List, PDU_Session_Resource_To_Remove_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const value_string e1ap_PDU_Session_Type_vals[] = {
  {   0, "ipv4" },
  {   1, "ipv6" },
  {   2, "ipv4v6" },
  {   3, "ethernet" },
  {   4, "unstructured" },
  { 0, NULL }
};


static int
dissect_e1ap_PDU_Session_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_To_Setup_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_pDU_Session_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Type },
  { &hf_e1ap_sNSSAI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SNSSAI },
  { &hf_e1ap_securityIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SecurityIndication },
  { &hf_e1ap_pDU_Session_Resource_DL_AMBR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BitRate },
  { &hf_e1ap_nG_UL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_pDU_Session_Data_Forwarding_Information_Request, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information_Request },
  { &hf_e1ap_pDU_Session_Inactivity_Timer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Inactivity_Timer },
  { &hf_e1ap_existing_Allocated_NG_DL_UP_TNL_Info, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_networkInstance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_NetworkInstance },
  { &hf_e1ap_dRB_To_Setup_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_To_Setup_List_NG_RAN },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_To_Setup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_To_Setup_Item, PDU_Session_Resource_To_Setup_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_To_Setup_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_To_Setup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_To_Setup_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_To_Setup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_To_Setup_List, PDU_Session_Resource_To_Setup_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_To_Setup_Mod_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_pDU_Session_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Type },
  { &hf_e1ap_sNSSAI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SNSSAI },
  { &hf_e1ap_securityIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SecurityIndication },
  { &hf_e1ap_pDU_Session_Resource_AMBR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BitRate },
  { &hf_e1ap_nG_UL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_pDU_Session_Data_Forwarding_Information_Request, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Data_Forwarding_Information_Request },
  { &hf_e1ap_pDU_Session_Inactivity_Timer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Inactivity_Timer },
  { &hf_e1ap_dRB_To_Setup_Mod_List_NG_RAN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_To_Setup_Mod_List_NG_RAN },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_Resource_To_Setup_Mod_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_Resource_To_Setup_Mod_Item, PDU_Session_Resource_To_Setup_Mod_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_Resource_To_Setup_Mod_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_Resource_To_Setup_Mod_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_Resource_To_Setup_Mod_Item },
};

static int
dissect_e1ap_PDU_Session_Resource_To_Setup_Mod_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_Resource_To_Setup_Mod_List, PDU_Session_Resource_To_Setup_Mod_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const per_sequence_t PDU_Session_To_Notify_Item_sequence[] = {
  { &hf_e1ap_pDU_Session_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_ID },
  { &hf_e1ap_qoS_Flow_List  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_List },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDU_Session_To_Notify_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDU_Session_To_Notify_Item, PDU_Session_To_Notify_Item_sequence);

  return offset;
}


static const per_sequence_t PDU_Session_To_Notify_List_sequence_of[1] = {
  { &hf_e1ap_PDU_Session_To_Notify_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_PDU_Session_To_Notify_Item },
};

static int
dissect_e1ap_PDU_Session_To_Notify_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_PDU_Session_To_Notify_List, PDU_Session_To_Notify_List_sequence_of,
                                                  1, maxnoofPDUSessionResource, false);

  return offset;
}


static const value_string e1ap_PDUSetbasedHandlingIndicator_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_e1ap_PDUSetbasedHandlingIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_PrivacyIndicator_vals[] = {
  {   0, "immediate-MDT" },
  {   1, "logged-MDT" },
  { 0, NULL }
};


static int
dissect_e1ap_PrivacyIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_T_pduSetIntegratedHandlingInformation_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_e1ap_T_pduSetIntegratedHandlingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PDUSetQoSInformation_sequence[] = {
  { &hf_e1ap_pduSetDelayBudget, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ExtendedPacketDelayBudget },
  { &hf_e1ap_pduSetErrorRate, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_PacketErrorRate },
  { &hf_e1ap_pduSetIntegratedHandlingInformation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_T_pduSetIntegratedHandlingInformation },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDUSetQoSInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDUSetQoSInformation, PDUSetQoSInformation_sequence);

  return offset;
}


static const per_sequence_t PDUSetQoSParameters_sequence[] = {
  { &hf_e1ap_ulPDUSetQoSInformation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_PDUSetQoSInformation },
  { &hf_e1ap_dlPDUSetQoSInformation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_PDUSetQoSInformation },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PDUSetQoSParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PDUSetQoSParameters, PDUSetQoSParameters_sequence);

  return offset;
}


static const value_string e1ap_QoS_Flows_DRB_Remapping_vals[] = {
  {   0, "update" },
  {   1, "source-configuration" },
  { 0, NULL }
};


static int
dissect_e1ap_QoS_Flows_DRB_Remapping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t QoS_Parameters_Support_List_sequence[] = {
  { &hf_e1ap_eUTRAN_QoS_Support_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_EUTRAN_QoS_Support_List },
  { &hf_e1ap_nG_RAN_QoS_Support_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_NG_RAN_QoS_Support_List },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_QoS_Parameters_Support_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_QoS_Parameters_Support_List, QoS_Parameters_Support_List_sequence);

  return offset;
}


static const value_string e1ap_QosMonitoringRequest_vals[] = {
  {   0, "ul" },
  {   1, "dl" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_e1ap_QosMonitoringRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_e1ap_QosMonitoringReportingFrequency(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1800U, NULL, true);

  return offset;
}


static const value_string e1ap_QosMonitoringDisabled_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_QosMonitoringDisabled(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_BIT_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e1ap_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t QoS_Mapping_Information_sequence[] = {
  { &hf_e1ap_dscp           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BIT_STRING_SIZE_6 },
  { &hf_e1ap_flow_label     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_BIT_STRING_SIZE_20 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_QoS_Mapping_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_QoS_Mapping_Information, QoS_Mapping_Information_sequence);

  return offset;
}


static const per_sequence_t DataForwardingtoNG_RANQoSFlowInformationList_Item_sequence[] = {
  { &hf_e1ap_qoS_Flow_Identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Flow_Identifier },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DataForwardingtoNG_RANQoSFlowInformationList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DataForwardingtoNG_RANQoSFlowInformationList_Item, DataForwardingtoNG_RANQoSFlowInformationList_Item_sequence);

  return offset;
}


static const per_sequence_t DataForwardingtoNG_RANQoSFlowInformationList_sequence_of[1] = {
  { &hf_e1ap_DataForwardingtoNG_RANQoSFlowInformationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DataForwardingtoNG_RANQoSFlowInformationList_Item },
};

static int
dissect_e1ap_DataForwardingtoNG_RANQoSFlowInformationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DataForwardingtoNG_RANQoSFlowInformationList, DataForwardingtoNG_RANQoSFlowInformationList_sequence_of,
                                                  1, maxnoofQoSFlows, false);

  return offset;
}



static int
dissect_e1ap_RANUEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}


static const value_string e1ap_RedundantQoSFlowIndicator_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_e1ap_RedundantQoSFlowIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const value_string e1ap_RSN_vals[] = {
  {   0, "v1" },
  {   1, "v2" },
  { 0, NULL }
};


static int
dissect_e1ap_RSN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t RedundantPDUSessionInformation_sequence[] = {
  { &hf_e1ap_rSN            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_RSN },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_RedundantPDUSessionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_RedundantPDUSessionInformation, RedundantPDUSessionInformation_sequence);

  return offset;
}


static const per_sequence_t RetainabilityMeasurementsInfo_sequence_of[1] = {
  { &hf_e1ap_RetainabilityMeasurementsInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Removed_Item },
};

static int
dissect_e1ap_RetainabilityMeasurementsInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_RetainabilityMeasurementsInfo, RetainabilityMeasurementsInfo_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const value_string e1ap_RegistrationRequest_vals[] = {
  {   0, "start" },
  {   1, "stop" },
  { 0, NULL }
};


static int
dissect_e1ap_RegistrationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_ReportCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, false, NULL, 0, &parameter_tvb, NULL);

  if(parameter_tvb){
    static int * const fields[] = {
      &hf_e1ap_ReportCharacteristics_TNLAvailableCapacityIndPeriodic,
      &hf_e1ap_ReportCharacteristics_HWCapacityIndPeriodic,
      &hf_e1ap_ReportCharacteristics_Reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_e1ap_ReportCharacteristics);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 5, fields, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const value_string e1ap_ReportingPeriodicity_vals[] = {
  {   0, "ms500" },
  {   1, "ms1000" },
  {   2, "ms2000" },
  {   3, "ms5000" },
  {   4, "ms10000" },
  {   5, "ms20000" },
  {   6, "ms30000" },
  {   7, "ms40000" },
  {   8, "ms50000" },
  {   9, "ms60000" },
  {  10, "ms70000" },
  {  11, "ms80000" },
  {  12, "ms90000" },
  {  13, "ms100000" },
  {  14, "ms110000" },
  {  15, "ms120000" },
  { 0, NULL }
};


static int
dissect_e1ap_ReportingPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_SDT_data_size_threshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 192000U, NULL, true);

  return offset;
}


static const value_string e1ap_SDT_data_size_threshold_Crossed_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_SDT_data_size_threshold_Crossed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_SCGActivationStatus_vals[] = {
  {   0, "scg-activated" },
  {   1, "scg-deactivated" },
  { 0, NULL }
};


static int
dissect_e1ap_SCGActivationStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t SecurityAlgorithm_sequence[] = {
  { &hf_e1ap_cipheringAlgorithm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_CipheringAlgorithm },
  { &hf_e1ap_integrityProtectionAlgorithm, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_IntegrityProtectionAlgorithm },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_SecurityAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_SecurityAlgorithm, SecurityAlgorithm_sequence);

  return offset;
}


static const per_sequence_t UPSecuritykey_sequence[] = {
  { &hf_e1ap_encryptionKey  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_EncryptionKey },
  { &hf_e1ap_integrityProtectionKey, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_IntegrityProtectionKey },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_UPSecuritykey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_UPSecuritykey, UPSecuritykey_sequence);

  return offset;
}


static const per_sequence_t SecurityInformation_sequence[] = {
  { &hf_e1ap_securityAlgorithm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SecurityAlgorithm },
  { &hf_e1ap_uPSecuritykey  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UPSecuritykey },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_SecurityInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_SecurityInformation, SecurityInformation_sequence);

  return offset;
}


static const per_sequence_t Slice_Support_List_sequence_of[1] = {
  { &hf_e1ap_Slice_Support_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Slice_Support_Item },
};

static int
dissect_e1ap_Slice_Support_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_Slice_Support_List, Slice_Support_List_sequence_of,
                                                  1, maxnoofSliceItems, false);

  return offset;
}


static const value_string e1ap_SDTContinueROHC_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_SDTContinueROHC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_SDTindicatorSetup_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_SDTindicatorSetup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_SDTindicatorMod_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_e1ap_SDTindicatorMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_SubscriberProfileIDforRFP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, true);

  return offset;
}



static int
dissect_e1ap_SurvivalTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1920000U, NULL, true);

  return offset;
}


static const value_string e1ap_SpecialTriggeringPurpose_vals[] = {
  {   0, "indirect-data-forwarding" },
  { 0, NULL }
};


static int
dissect_e1ap_SpecialTriggeringPurpose(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_F1UTunnelNotEstablished_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_F1UTunnelNotEstablished(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e1ap_TimeToWait_vals[] = {
  {   0, "v1s" },
  {   1, "v2s" },
  {   2, "v5s" },
  {   3, "v10s" },
  {   4, "v20s" },
  {   5, "v60s" },
  { 0, NULL }
};


static int
dissect_e1ap_TimeToWait(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_INTEGER_0_16777216_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777216U, NULL, true);

  return offset;
}


static const per_sequence_t TNL_AvailableCapacityIndicator_sequence[] = {
  { &hf_e1ap_dL_TNL_OfferedCapacity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_16777216_ },
  { &hf_e1ap_dL_TNL_AvailableCapacity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_100_ },
  { &hf_e1ap_uL_TNL_OfferedCapacity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_16777216_ },
  { &hf_e1ap_uL_TNL_AvailableCapacity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_INTEGER_0_100_ },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_TNL_AvailableCapacityIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_TNL_AvailableCapacityIndicator, TNL_AvailableCapacityIndicator_sequence);

  return offset;
}



static int
dissect_e1ap_Periodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 640000U, NULL, true);

  return offset;
}



static int
dissect_e1ap_BurstArrivalTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_e1ap_BurstArrivalTime);
    dissect_nr_rrc_ReferenceTime_r16_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }


  return offset;
}


static const per_sequence_t TSCAssistanceInformation_sequence[] = {
  { &hf_e1ap_periodicity    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Periodicity },
  { &hf_e1ap_burstArrivalTime, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_BurstArrivalTime },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_TSCAssistanceInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_TSCAssistanceInformation, TSCAssistanceInformation_sequence);

  return offset;
}


static const per_sequence_t TSCTrafficCharacteristics_sequence[] = {
  { &hf_e1ap_tSCTrafficCharacteristicsUL, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_TSCAssistanceInformation },
  { &hf_e1ap_tSCTrafficCharacteristicsDL, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_TSCAssistanceInformation },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_TSCTrafficCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_TSCTrafficCharacteristics, TSCTrafficCharacteristics_sequence);

  return offset;
}



static int
dissect_e1ap_TraceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}


static const value_string e1ap_TraceDepth_vals[] = {
  {   0, "minimum" },
  {   1, "medium" },
  {   2, "maximum" },
  {   3, "minimumWithoutVendorSpecificExtension" },
  {   4, "mediumWithoutVendorSpecificExtension" },
  {   5, "maximumWithoutVendorSpecificExtension" },
  { 0, NULL }
};


static int
dissect_e1ap_TraceDepth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TraceActivation_sequence[] = {
  { &hf_e1ap_traceID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TraceID },
  { &hf_e1ap_interfacesToTrace, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_InterfacesToTrace },
  { &hf_e1ap_traceDepth     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TraceDepth },
  { &hf_e1ap_traceCollectionEntityIPAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_TraceActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_TraceActivation, TraceActivation_sequence);

  return offset;
}


static const per_sequence_t Transport_UP_Layer_Addresses_Info_To_Add_Item_sequence[] = {
  { &hf_e1ap_iP_SecTransportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_gTPTransportLayerAddressesToAdd, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_GTPTLAs },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Transport_UP_Layer_Addresses_Info_To_Add_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Transport_UP_Layer_Addresses_Info_To_Add_Item, Transport_UP_Layer_Addresses_Info_To_Add_Item_sequence);

  return offset;
}


static const per_sequence_t Transport_UP_Layer_Addresses_Info_To_Add_List_sequence_of[1] = {
  { &hf_e1ap_Transport_UP_Layer_Addresses_Info_To_Add_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Transport_UP_Layer_Addresses_Info_To_Add_Item },
};

static int
dissect_e1ap_Transport_UP_Layer_Addresses_Info_To_Add_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_Transport_UP_Layer_Addresses_Info_To_Add_List, Transport_UP_Layer_Addresses_Info_To_Add_List_sequence_of,
                                                  1, maxnoofTLAs, false);

  return offset;
}


static const per_sequence_t Transport_UP_Layer_Addresses_Info_To_Remove_Item_sequence[] = {
  { &hf_e1ap_iP_SecTransportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_gTPTransportLayerAddressesToRemove, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_GTPTLAs },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Transport_UP_Layer_Addresses_Info_To_Remove_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Transport_UP_Layer_Addresses_Info_To_Remove_Item, Transport_UP_Layer_Addresses_Info_To_Remove_Item_sequence);

  return offset;
}


static const per_sequence_t Transport_UP_Layer_Addresses_Info_To_Remove_List_sequence_of[1] = {
  { &hf_e1ap_Transport_UP_Layer_Addresses_Info_To_Remove_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Transport_UP_Layer_Addresses_Info_To_Remove_Item },
};

static int
dissect_e1ap_Transport_UP_Layer_Addresses_Info_To_Remove_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_Transport_UP_Layer_Addresses_Info_To_Remove_List, Transport_UP_Layer_Addresses_Info_To_Remove_List_sequence_of,
                                                  1, maxnoofTLAs, false);

  return offset;
}


static const per_sequence_t Transport_Layer_Address_Info_sequence[] = {
  { &hf_e1ap_transport_UP_Layer_Addresses_Info_To_Add_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Transport_UP_Layer_Addresses_Info_To_Add_List },
  { &hf_e1ap_transport_UP_Layer_Addresses_Info_To_Remove_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Transport_UP_Layer_Addresses_Info_To_Remove_List },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Transport_Layer_Address_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Transport_Layer_Address_Info, Transport_Layer_Address_Info_sequence);

  return offset;
}


static const value_string e1ap_T_continueUDC_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_T_continueUDC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t UDC_Parameters_sequence[] = {
  { &hf_e1ap_bufferSize     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_BufferSize },
  { &hf_e1ap_dictionary     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_Dictionary },
  { &hf_e1ap_continueUDC    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_T_continueUDC },
  { &hf_e1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_UDC_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_UDC_Parameters, UDC_Parameters_sequence);

  return offset;
}



static int
dissect_e1ap_VersionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}


static const per_sequence_t UE_associatedLogicalE1_ConnectionItem_sequence[] = {
  { &hf_e1ap_gNB_CU_CP_UE_E1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_GNB_CU_CP_UE_E1AP_ID },
  { &hf_e1ap_gNB_CU_UP_UE_E1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_GNB_CU_UP_UE_E1AP_ID },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_UE_associatedLogicalE1_ConnectionItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_UE_associatedLogicalE1_ConnectionItem, UE_associatedLogicalE1_ConnectionItem_sequence);

  return offset;
}


static const per_sequence_t UESliceMaximumBitRateItem_sequence[] = {
  { &hf_e1ap_sNSSAI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_SNSSAI },
  { &hf_e1ap_uESliceMaximumBitRateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_BitRate },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_UESliceMaximumBitRateItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_UESliceMaximumBitRateItem, UESliceMaximumBitRateItem_sequence);

  return offset;
}


static const per_sequence_t UESliceMaximumBitRateList_sequence_of[1] = {
  { &hf_e1ap_UESliceMaximumBitRateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_UESliceMaximumBitRateItem },
};

static int
dissect_e1ap_UESliceMaximumBitRateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_UESliceMaximumBitRateList, UESliceMaximumBitRateList_sequence_of,
                                                  1, maxnoofSMBRValues, false);

  return offset;
}


static const per_sequence_t ULUPTNLAddressToUpdateItem_sequence[] = {
  { &hf_e1ap_oldTNLAdress   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_newTNLAdress   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_TransportLayerAddress },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ULUPTNLAddressToUpdateItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ULUPTNLAddressToUpdateItem, ULUPTNLAddressToUpdateItem_sequence);

  return offset;
}



static int
dissect_e1ap_URIaddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_VisibleString(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND, false,
                                          NULL);

  return offset;
}


static const value_string e1ap_UserPlaneErrorIndicator_vals[] = {
  {   0, "gTP-U-error-indication-received" },
  { 0, NULL }
};


static int
dissect_e1ap_UserPlaneErrorIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e1ap_UEInactivityInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 7200U, NULL, true);

  return offset;
}


static const value_string e1ap_UserPlaneFailureType_vals[] = {
  {   0, "gtp-u-error-indication-received" },
  {   1, "up-path-failure" },
  { 0, NULL }
};


static int
dissect_e1ap_UserPlaneFailureType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t UserPlaneFailureIndication_sequence[] = {
  { &hf_e1ap_userPlaneFailureType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UserPlaneFailureType },
  { &hf_e1ap_nG_DL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_nG_UL_UP_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_UP_TNL_Information },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_UserPlaneFailureIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_UserPlaneFailureIndication, UserPlaneFailureIndication_sequence);

  return offset;
}


static const per_sequence_t Reset_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Reset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Reset");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_Reset, Reset_sequence);

  return offset;
}


static const value_string e1ap_ResetAll_vals[] = {
  {   0, "reset-all" },
  { 0, NULL }
};


static int
dissect_e1ap_ResetAll(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t UE_associatedLogicalE1_ConnectionListRes_sequence_of[1] = {
  { &hf_e1ap_UE_associatedLogicalE1_ConnectionListRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_SingleContainer },
};

static int
dissect_e1ap_UE_associatedLogicalE1_ConnectionListRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_UE_associatedLogicalE1_ConnectionListRes, UE_associatedLogicalE1_ConnectionListRes_sequence_of,
                                                  1, maxnoofIndividualE1ConnectionsToReset, false);

  return offset;
}


static const value_string e1ap_ResetType_vals[] = {
  {   0, "e1-Interface" },
  {   1, "partOfE1-Interface" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ResetType_choice[] = {
  {   0, &hf_e1ap_e1_Interface   , ASN1_NO_EXTENSIONS     , dissect_e1ap_ResetAll },
  {   1, &hf_e1ap_partOfE1_Interface, ASN1_NO_EXTENSIONS     , dissect_e1ap_UE_associatedLogicalE1_ConnectionListRes },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_ResetType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_ResetType, ResetType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ResetAcknowledge_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ResetAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResetAcknowledge");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ResetAcknowledge, ResetAcknowledge_sequence);

  return offset;
}


static const per_sequence_t UE_associatedLogicalE1_ConnectionListResAck_sequence_of[1] = {
  { &hf_e1ap_UE_associatedLogicalE1_ConnectionListResAck_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_SingleContainer },
};

static int
dissect_e1ap_UE_associatedLogicalE1_ConnectionListResAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_UE_associatedLogicalE1_ConnectionListResAck, UE_associatedLogicalE1_ConnectionListResAck_sequence_of,
                                                  1, maxnoofIndividualE1ConnectionsToReset, false);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ErrorIndication");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_UP_E1SetupRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_UP_E1SetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-UP-E1SetupRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_UP_E1SetupRequest, GNB_CU_UP_E1SetupRequest_sequence);

  return offset;
}


static const per_sequence_t SupportedPLMNs_Item_sequence[] = {
  { &hf_e1ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PLMN_Identity },
  { &hf_e1ap_slice_Support_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_Slice_Support_List },
  { &hf_e1ap_nR_CGI_Support_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_NR_CGI_Support_List },
  { &hf_e1ap_qoS_Parameters_Support_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_QoS_Parameters_Support_List },
  { &hf_e1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_SupportedPLMNs_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_SupportedPLMNs_Item, SupportedPLMNs_Item_sequence);

  return offset;
}


static const per_sequence_t SupportedPLMNs_List_sequence_of[1] = {
  { &hf_e1ap_SupportedPLMNs_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_SupportedPLMNs_Item },
};

static int
dissect_e1ap_SupportedPLMNs_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_SupportedPLMNs_List, SupportedPLMNs_List_sequence_of,
                                                  1, maxnoofSPLMNs, false);

  return offset;
}


static const per_sequence_t GNB_CU_UP_E1SetupResponse_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_UP_E1SetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-UP-E1SetupResponse");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_UP_E1SetupResponse, GNB_CU_UP_E1SetupResponse_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_UP_E1SetupFailure_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_UP_E1SetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-UP-E1SetupFailure");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_UP_E1SetupFailure, GNB_CU_UP_E1SetupFailure_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_CP_E1SetupRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CP_E1SetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-CP-E1SetupRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_CP_E1SetupRequest, GNB_CU_CP_E1SetupRequest_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_CP_E1SetupResponse_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CP_E1SetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-CP-E1SetupResponse");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_CP_E1SetupResponse, GNB_CU_CP_E1SetupResponse_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_CP_E1SetupFailure_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CP_E1SetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-CP-E1SetupFailure");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_CP_E1SetupFailure, GNB_CU_CP_E1SetupFailure_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_UP_ConfigurationUpdate_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_UP_ConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-UP-ConfigurationUpdate");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_UP_ConfigurationUpdate, GNB_CU_UP_ConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_UP_TNLA_To_Remove_List_sequence_of[1] = {
  { &hf_e1ap_GNB_CU_UP_TNLA_To_Remove_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_GNB_CU_UP_TNLA_To_Remove_Item },
};

static int
dissect_e1ap_GNB_CU_UP_TNLA_To_Remove_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_GNB_CU_UP_TNLA_To_Remove_List, GNB_CU_UP_TNLA_To_Remove_List_sequence_of,
                                                  1, maxnoofTNLAssociations, false);

  return offset;
}


static const per_sequence_t GNB_CU_UP_ConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_UP_ConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-UP-ConfigurationUpdateAcknowledge");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_UP_ConfigurationUpdateAcknowledge, GNB_CU_UP_ConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_UP_ConfigurationUpdateFailure_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_UP_ConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-UP-ConfigurationUpdateFailure");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_UP_ConfigurationUpdateFailure, GNB_CU_UP_ConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_CP_ConfigurationUpdate_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CP_ConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-CP-ConfigurationUpdate");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_CP_ConfigurationUpdate, GNB_CU_CP_ConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_CP_TNLA_To_Add_List_sequence_of[1] = {
  { &hf_e1ap_GNB_CU_CP_TNLA_To_Add_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_GNB_CU_CP_TNLA_To_Add_Item },
};

static int
dissect_e1ap_GNB_CU_CP_TNLA_To_Add_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_GNB_CU_CP_TNLA_To_Add_List, GNB_CU_CP_TNLA_To_Add_List_sequence_of,
                                                  1, maxnoofTNLAssociations, false);

  return offset;
}


static const per_sequence_t GNB_CU_CP_TNLA_To_Remove_List_sequence_of[1] = {
  { &hf_e1ap_GNB_CU_CP_TNLA_To_Remove_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_GNB_CU_CP_TNLA_To_Remove_Item },
};

static int
dissect_e1ap_GNB_CU_CP_TNLA_To_Remove_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_GNB_CU_CP_TNLA_To_Remove_List, GNB_CU_CP_TNLA_To_Remove_List_sequence_of,
                                                  1, maxnoofTNLAssociations, false);

  return offset;
}


static const per_sequence_t GNB_CU_CP_TNLA_To_Update_List_sequence_of[1] = {
  { &hf_e1ap_GNB_CU_CP_TNLA_To_Update_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_GNB_CU_CP_TNLA_To_Update_Item },
};

static int
dissect_e1ap_GNB_CU_CP_TNLA_To_Update_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_GNB_CU_CP_TNLA_To_Update_List, GNB_CU_CP_TNLA_To_Update_List_sequence_of,
                                                  1, maxnoofTNLAssociations, false);

  return offset;
}


static const per_sequence_t GNB_CU_CP_ConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CP_ConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-CP-ConfigurationUpdateAcknowledge");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_CP_ConfigurationUpdateAcknowledge, GNB_CU_CP_ConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_CP_TNLA_Setup_List_sequence_of[1] = {
  { &hf_e1ap_GNB_CU_CP_TNLA_Setup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_GNB_CU_CP_TNLA_Setup_Item },
};

static int
dissect_e1ap_GNB_CU_CP_TNLA_Setup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_GNB_CU_CP_TNLA_Setup_List, GNB_CU_CP_TNLA_Setup_List_sequence_of,
                                                  1, maxnoofTNLAssociations, false);

  return offset;
}


static const per_sequence_t GNB_CU_CP_TNLA_Failed_To_Setup_List_sequence_of[1] = {
  { &hf_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_Item },
};

static int
dissect_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List, GNB_CU_CP_TNLA_Failed_To_Setup_List_sequence_of,
                                                  1, maxnoofTNLAssociations, false);

  return offset;
}


static const per_sequence_t GNB_CU_CP_ConfigurationUpdateFailure_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CP_ConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-CP-ConfigurationUpdateFailure");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_CP_ConfigurationUpdateFailure, GNB_CU_CP_ConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t E1ReleaseRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_E1ReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E1ReleaseRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_E1ReleaseRequest, E1ReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t E1ReleaseResponse_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_E1ReleaseResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E1ReleaseResponse");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_E1ReleaseResponse, E1ReleaseResponse_sequence);

  return offset;
}


static const per_sequence_t BearerContextSetupRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BearerContextSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BearerContextSetupRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BearerContextSetupRequest, BearerContextSetupRequest_sequence);

  return offset;
}


static const value_string e1ap_System_BearerContextSetupRequest_vals[] = {
  {   0, "e-UTRAN-BearerContextSetupRequest" },
  {   1, "nG-RAN-BearerContextSetupRequest" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t System_BearerContextSetupRequest_choice[] = {
  {   0, &hf_e1ap_e_UTRAN_BearerContextSetupRequest, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   1, &hf_e1ap_nG_RAN_BearerContextSetupRequest, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_System_BearerContextSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_System_BearerContextSetupRequest, System_BearerContextSetupRequest_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BearerContextSetupResponse_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BearerContextSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BearerContextSetupResponse");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BearerContextSetupResponse, BearerContextSetupResponse_sequence);

  return offset;
}


static const value_string e1ap_System_BearerContextSetupResponse_vals[] = {
  {   0, "e-UTRAN-BearerContextSetupResponse" },
  {   1, "nG-RAN-BearerContextSetupResponse" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t System_BearerContextSetupResponse_choice[] = {
  {   0, &hf_e1ap_e_UTRAN_BearerContextSetupResponse, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   1, &hf_e1ap_nG_RAN_BearerContextSetupResponse, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_System_BearerContextSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_System_BearerContextSetupResponse, System_BearerContextSetupResponse_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BearerContextSetupFailure_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BearerContextSetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BearerContextSetupFailure");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BearerContextSetupFailure, BearerContextSetupFailure_sequence);

  return offset;
}


static const per_sequence_t BearerContextModificationRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BearerContextModificationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BearerContextModificationRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BearerContextModificationRequest, BearerContextModificationRequest_sequence);

  return offset;
}


static const value_string e1ap_System_BearerContextModificationRequest_vals[] = {
  {   0, "e-UTRAN-BearerContextModificationRequest" },
  {   1, "nG-RAN-BearerContextModificationRequest" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t System_BearerContextModificationRequest_choice[] = {
  {   0, &hf_e1ap_e_UTRAN_BearerContextModificationRequest, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   1, &hf_e1ap_nG_RAN_BearerContextModificationRequest, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_System_BearerContextModificationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_System_BearerContextModificationRequest, System_BearerContextModificationRequest_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BearerContextModificationResponse_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BearerContextModificationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BearerContextModificationResponse");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BearerContextModificationResponse, BearerContextModificationResponse_sequence);

  return offset;
}


static const value_string e1ap_System_BearerContextModificationResponse_vals[] = {
  {   0, "e-UTRAN-BearerContextModificationResponse" },
  {   1, "nG-RAN-BearerContextModificationResponse" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t System_BearerContextModificationResponse_choice[] = {
  {   0, &hf_e1ap_e_UTRAN_BearerContextModificationResponse, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   1, &hf_e1ap_nG_RAN_BearerContextModificationResponse, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_System_BearerContextModificationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_System_BearerContextModificationResponse, System_BearerContextModificationResponse_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BearerContextModificationFailure_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BearerContextModificationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BearerContextModificationFailure");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BearerContextModificationFailure, BearerContextModificationFailure_sequence);

  return offset;
}


static const per_sequence_t BearerContextModificationRequired_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BearerContextModificationRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BearerContextModificationRequired");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BearerContextModificationRequired, BearerContextModificationRequired_sequence);

  return offset;
}


static const value_string e1ap_System_BearerContextModificationRequired_vals[] = {
  {   0, "e-UTRAN-BearerContextModificationRequired" },
  {   1, "nG-RAN-BearerContextModificationRequired" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t System_BearerContextModificationRequired_choice[] = {
  {   0, &hf_e1ap_e_UTRAN_BearerContextModificationRequired, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   1, &hf_e1ap_nG_RAN_BearerContextModificationRequired, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_System_BearerContextModificationRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_System_BearerContextModificationRequired, System_BearerContextModificationRequired_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BearerContextModificationConfirm_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BearerContextModificationConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BearerContextModificationConfirm");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BearerContextModificationConfirm, BearerContextModificationConfirm_sequence);

  return offset;
}


static const value_string e1ap_System_BearerContextModificationConfirm_vals[] = {
  {   0, "e-UTRAN-BearerContextModificationConfirm" },
  {   1, "nG-RAN-BearerContextModificationConfirm" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t System_BearerContextModificationConfirm_choice[] = {
  {   0, &hf_e1ap_e_UTRAN_BearerContextModificationConfirm, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   1, &hf_e1ap_nG_RAN_BearerContextModificationConfirm, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_System_BearerContextModificationConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_System_BearerContextModificationConfirm, System_BearerContextModificationConfirm_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BearerContextReleaseCommand_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BearerContextReleaseCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BearerContextReleaseCommand");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BearerContextReleaseCommand, BearerContextReleaseCommand_sequence);

  return offset;
}


static const per_sequence_t BearerContextReleaseComplete_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BearerContextReleaseComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BearerContextReleaseComplete");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BearerContextReleaseComplete, BearerContextReleaseComplete_sequence);

  return offset;
}


static const per_sequence_t BearerContextReleaseRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BearerContextReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BearerContextReleaseRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BearerContextReleaseRequest, BearerContextReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t DRB_Status_List_sequence_of[1] = {
  { &hf_e1ap_DRB_Status_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DRB_Status_Item },
};

static int
dissect_e1ap_DRB_Status_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DRB_Status_List, DRB_Status_List_sequence_of,
                                                  1, maxnoofDRBs, false);

  return offset;
}


static const per_sequence_t BearerContextInactivityNotification_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BearerContextInactivityNotification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BearerContextInactivityNotification");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BearerContextInactivityNotification, BearerContextInactivityNotification_sequence);

  return offset;
}


static const per_sequence_t DLDataNotification_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DLDataNotification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DLDataNotification");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DLDataNotification, DLDataNotification_sequence);

  return offset;
}


static const per_sequence_t ULDataNotification_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ULDataNotification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ULDataNotification");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ULDataNotification, ULDataNotification_sequence);

  return offset;
}


static const per_sequence_t DataUsageReport_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DataUsageReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DataUsageReport");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DataUsageReport, DataUsageReport_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_UP_CounterCheckRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_UP_CounterCheckRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-UP-CounterCheckRequest");
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-UP-CounterCheckRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_UP_CounterCheckRequest, GNB_CU_UP_CounterCheckRequest_sequence);

  return offset;
}


static const value_string e1ap_System_GNB_CU_UP_CounterCheckRequest_vals[] = {
  {   0, "e-UTRAN-GNB-CU-UP-CounterCheckRequest" },
  {   1, "nG-RAN-GNB-CU-UP-CounterCheckRequest" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t System_GNB_CU_UP_CounterCheckRequest_choice[] = {
  {   0, &hf_e1ap_e_UTRAN_GNB_CU_UP_CounterCheckRequest, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   1, &hf_e1ap_nG_RAN_GNB_CU_UP_CounterCheckRequest, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_Container },
  {   2, &hf_e1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_e1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_System_GNB_CU_UP_CounterCheckRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_System_GNB_CU_UP_CounterCheckRequest, System_GNB_CU_UP_CounterCheckRequest_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GNB_CU_UP_StatusIndication_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_UP_StatusIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_UP_StatusIndication, GNB_CU_UP_StatusIndication_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_CPMeasurementResultsInformation_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CPMeasurementResultsInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNB-CU-CPMeasurementResultsInformation");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_GNB_CU_CPMeasurementResultsInformation, GNB_CU_CPMeasurementResultsInformation_sequence);

  return offset;
}


static const per_sequence_t MRDC_DataUsageReport_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MRDC_DataUsageReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MRDC-DataUsageReport");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MRDC_DataUsageReport, MRDC_DataUsageReport_sequence);

  return offset;
}


static const per_sequence_t TraceStart_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_TraceStart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "TraceStart");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_TraceStart, TraceStart_sequence);

  return offset;
}


static const per_sequence_t DeactivateTrace_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_DeactivateTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DeactivateTrace");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_DeactivateTrace, DeactivateTrace_sequence);

  return offset;
}


static const per_sequence_t CellTrafficTrace_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_CellTrafficTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "CellTrafficTrace");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_CellTrafficTrace, CellTrafficTrace_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_e1ap_privateIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PrivateMessage");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}


static const per_sequence_t ResourceStatusRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ResourceStatusRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResourceStatusRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ResourceStatusRequest, ResourceStatusRequest_sequence);

  return offset;
}



static int
dissect_e1ap_Measurement_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4095U, NULL, true);

  return offset;
}


static const per_sequence_t ResourceStatusResponse_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ResourceStatusResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResourceStatusResponse");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ResourceStatusResponse, ResourceStatusResponse_sequence);

  return offset;
}


static const per_sequence_t ResourceStatusFailure_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ResourceStatusFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResourceStatusFailure");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ResourceStatusFailure, ResourceStatusFailure_sequence);

  return offset;
}


static const per_sequence_t ResourceStatusUpdate_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ResourceStatusUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResourceStatusUpdate");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_ResourceStatusUpdate, ResourceStatusUpdate_sequence);

  return offset;
}


static const per_sequence_t IAB_UPTNLAddressUpdate_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_IAB_UPTNLAddressUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "IAB-UPTNLAddressUpdate");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_IAB_UPTNLAddressUpdate, IAB_UPTNLAddressUpdate_sequence);

  return offset;
}


static const per_sequence_t DLUPTNLAddressToUpdateList_sequence_of[1] = {
  { &hf_e1ap_DLUPTNLAddressToUpdateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_DLUPTNLAddressToUpdateItem },
};

static int
dissect_e1ap_DLUPTNLAddressToUpdateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_DLUPTNLAddressToUpdateList, DLUPTNLAddressToUpdateList_sequence_of,
                                                  1, maxnoofTNLAddresses, false);

  return offset;
}


static const per_sequence_t IAB_UPTNLAddressUpdateAcknowledge_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_IAB_UPTNLAddressUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "IAB-UPTNLAddressUpdateAcknowledge");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_IAB_UPTNLAddressUpdateAcknowledge, IAB_UPTNLAddressUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t ULUPTNLAddressToUpdateList_sequence_of[1] = {
  { &hf_e1ap_ULUPTNLAddressToUpdateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_ULUPTNLAddressToUpdateItem },
};

static int
dissect_e1ap_ULUPTNLAddressToUpdateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_ULUPTNLAddressToUpdateList, ULUPTNLAddressToUpdateList_sequence_of,
                                                  1, maxnoofTNLAddresses, false);

  return offset;
}


static const per_sequence_t IAB_UPTNLAddressUpdateFailure_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_IAB_UPTNLAddressUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "IAB-UPTNLAddressUpdateFailure");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_IAB_UPTNLAddressUpdateFailure, IAB_UPTNLAddressUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t EarlyForwardingSNTransfer_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_EarlyForwardingSNTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "EarlyForwardingSNTransfer");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_EarlyForwardingSNTransfer, EarlyForwardingSNTransfer_sequence);

  return offset;
}


static const per_sequence_t IABPSKNotification_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_IABPSKNotification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "IABPSKNotification");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_IABPSKNotification, IABPSKNotification_sequence);

  return offset;
}


static const per_sequence_t IAB_Donor_CU_UPPSKInfo_sequence_of[1] = {
  { &hf_e1ap_IAB_Donor_CU_UPPSKInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_IAB_Donor_CU_UPPSKInfo_Item },
};

static int
dissect_e1ap_IAB_Donor_CU_UPPSKInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_IAB_Donor_CU_UPPSKInfo, IAB_Donor_CU_UPPSKInfo_sequence_of,
                                                  1, maxnoofPSKs, false);

  return offset;
}


static const per_sequence_t BCBearerContextSetupRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BCBearerContextSetupRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextSetupRequest, BCBearerContextSetupRequest_sequence);

  return offset;
}


static const per_sequence_t BCBearerContextSetupResponse_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BCBearerContextSetupResponse");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextSetupResponse, BCBearerContextSetupResponse_sequence);

  return offset;
}


static const per_sequence_t BCBearerContextSetupFailure_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextSetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BCBearerContextSetupFailure");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextSetupFailure, BCBearerContextSetupFailure_sequence);

  return offset;
}


static const per_sequence_t BCBearerContextModificationRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextModificationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BCBearerContextModificationRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextModificationRequest, BCBearerContextModificationRequest_sequence);

  return offset;
}


static const per_sequence_t BCBearerContextModificationResponse_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextModificationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BCBearerContextModificationResponse");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextModificationResponse, BCBearerContextModificationResponse_sequence);

  return offset;
}


static const per_sequence_t BCBearerContextModificationFailure_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextModificationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BCBearerContextModificationFailure");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextModificationFailure, BCBearerContextModificationFailure_sequence);

  return offset;
}


static const per_sequence_t BCBearerContextModificationRequired_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextModificationRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BCBearerContextModificationRequired");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextModificationRequired, BCBearerContextModificationRequired_sequence);

  return offset;
}


static const per_sequence_t BCBearerContextModificationConfirm_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextModificationConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BCBearerContextModificationConfirm");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextModificationConfirm, BCBearerContextModificationConfirm_sequence);

  return offset;
}


static const per_sequence_t BCBearerContextReleaseCommand_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextReleaseCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BCBearerContextReleaseCommand");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextReleaseCommand, BCBearerContextReleaseCommand_sequence);

  return offset;
}


static const per_sequence_t BCBearerContextReleaseComplete_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextReleaseComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BCBearerContextReleaseComplete");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextReleaseComplete, BCBearerContextReleaseComplete_sequence);

  return offset;
}


static const per_sequence_t BCBearerContextReleaseRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BCBearerContextReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "BCBearerContextReleaseRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_BCBearerContextReleaseRequest, BCBearerContextReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextSetupRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MCBearerContextSetupRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextSetupRequest, MCBearerContextSetupRequest_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextSetupResponse_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MCBearerContextSetupResponse");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextSetupResponse, MCBearerContextSetupResponse_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextSetupFailure_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextSetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MCBearerContextSetupFailure");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextSetupFailure, MCBearerContextSetupFailure_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextModificationRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextModificationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MCBearerContextModificationRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextModificationRequest, MCBearerContextModificationRequest_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextModificationResponse_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextModificationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MCBearerContextModificationResponse");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextModificationResponse, MCBearerContextModificationResponse_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextModificationFailure_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextModificationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MCBearerContextModificationFailure");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextModificationFailure, MCBearerContextModificationFailure_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextModificationRequired_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextModificationRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MCBearerContextModificationRequired");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextModificationRequired, MCBearerContextModificationRequired_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextModificationConfirm_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextModificationConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MCBearerContextModificationConfirm");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextModificationConfirm, MCBearerContextModificationConfirm_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextReleaseCommand_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextReleaseCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MCBearerContextReleaseCommand");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextReleaseCommand, MCBearerContextReleaseCommand_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextReleaseComplete_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextReleaseComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MCBearerContextReleaseComplete");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextReleaseComplete, MCBearerContextReleaseComplete_sequence);

  return offset;
}


static const per_sequence_t MCBearerContextReleaseRequest_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerContextReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MCBearerContextReleaseRequest");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerContextReleaseRequest, MCBearerContextReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t MCBearerNotification_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MCBearerNotification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MCBearerNotification");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MCBearerNotification, MCBearerNotification_sequence);

  return offset;
}



static int
dissect_e1ap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(actx->pinfo);
  e1ap_data->message_type = INITIATING_MESSAGE;
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_e1ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_ProcedureCode },
  { &hf_e1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Criticality },
  { &hf_e1ap_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_e1ap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(actx->pinfo);
  e1ap_data->message_type = SUCCESSFUL_OUTCOME;
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_e1ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_ProcedureCode },
  { &hf_e1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Criticality },
  { &hf_e1ap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_e1ap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(actx->pinfo);
  e1ap_data->message_type = UNSUCCESSFUL_OUTCOME;
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_e1ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_ProcedureCode },
  { &hf_e1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Criticality },
  { &hf_e1ap_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string e1ap_E1AP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t E1AP_PDU_choice[] = {
  {   0, &hf_e1ap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_e1ap_InitiatingMessage },
  {   1, &hf_e1ap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_e1ap_SuccessfulOutcome },
  {   2, &hf_e1ap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_e1ap_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_e1ap_E1AP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e1ap_E1AP_PDU, E1AP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_ActivityInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ActivityInformation(tvb, offset, &asn1_ctx, tree, hf_e1ap_ActivityInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ActivityNotificationLevel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ActivityNotificationLevel(tvb, offset, &asn1_ctx, tree, hf_e1ap_ActivityNotificationLevel_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AdditionalHandoverInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_AdditionalHandoverInfo(tvb, offset, &asn1_ctx, tree, hf_e1ap_AdditionalHandoverInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AdditionalPDCPduplicationInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_AdditionalPDCPduplicationInformation(tvb, offset, &asn1_ctx, tree, hf_e1ap_AdditionalPDCPduplicationInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AdditionalRRMPriorityIndex_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_AdditionalRRMPriorityIndex(tvb, offset, &asn1_ctx, tree, hf_e1ap_AdditionalRRMPriorityIndex_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AlternativeQoSParaSetList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_AlternativeQoSParaSetList(tvb, offset, &asn1_ctx, tree, hf_e1ap_AlternativeQoSParaSetList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AssociatedSessionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_AssociatedSessionID(tvb, offset, &asn1_ctx, tree, hf_e1ap_AssociatedSessionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextToSetup_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextToSetup(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextToSetup_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextToSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextToSetupResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextToSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextToModify_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextToModify(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextToModify_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextNGU_TNLInfoatNGRAN_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextNGU_TNLInfoatNGRAN_Request(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextNGU_TNLInfoatNGRAN_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextToModifyResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextToModifyResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextToModifyResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextToModifyRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextToModifyRequired(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextToModifyRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextToModifyConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextToModifyConfirm(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextToModifyConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextStatusChange_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BearerContextStatusChange(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextStatusChange_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BitRate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BitRate(tvb, offset, &asn1_ctx, tree, hf_e1ap_BitRate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_Cause(tvb, offset, &asn1_ctx, tree, hf_e1ap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CHOInitiation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_CHOInitiation(tvb, offset, &asn1_ctx, tree, hf_e1ap_CHOInitiation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Number_of_tunnels_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_Number_of_tunnels(tvb, offset, &asn1_ctx, tree, hf_e1ap_Number_of_tunnels_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CNSupport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_CNSupport(tvb, offset, &asn1_ctx, tree, hf_e1ap_CNSupport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CommonNetworkInstance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_CommonNetworkInstance(tvb, offset, &asn1_ctx, tree, hf_e1ap_CommonNetworkInstance_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CP_TNL_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_CP_TNL_Information(tvb, offset, &asn1_ctx, tree, hf_e1ap_CP_TNL_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_e1ap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DAPSRequestInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DAPSRequestInfo(tvb, offset, &asn1_ctx, tree, hf_e1ap_DAPSRequestInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Data_Forwarding_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_Data_Forwarding_Information(tvb, offset, &asn1_ctx, tree, hf_e1ap_Data_Forwarding_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataForwardingtoE_UTRANInformationList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DataForwardingtoE_UTRANInformationList(tvb, offset, &asn1_ctx, tree, hf_e1ap_DataForwardingtoE_UTRANInformationList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Data_Usage_Report_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_Data_Usage_Report_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_Data_Usage_Report_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DirectForwardingPathAvailability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DirectForwardingPathAvailability(tvb, offset, &asn1_ctx, tree, hf_e1ap_DirectForwardingPathAvailability_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DiscardTimerExtended_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DiscardTimerExtended(tvb, offset, &asn1_ctx, tree, hf_e1ap_DiscardTimerExtended_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PSIbasedDiscardTimer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PSIbasedDiscardTimer(tvb, offset, &asn1_ctx, tree, hf_e1ap_PSIbasedDiscardTimer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Confirm_Modified_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_Confirm_Modified_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Confirm_Modified_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Failed_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_Failed_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Failed_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Failed_Mod_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_Failed_Mod_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Failed_Mod_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Failed_To_Modify_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_Failed_To_Modify_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Failed_To_Modify_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Measurement_Results_Information_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_Measurement_Results_Information_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Measurement_Results_Information_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Modified_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_Modified_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Modified_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Required_To_Modify_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_Required_To_Modify_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Required_To_Modify_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Setup_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_Setup_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Setup_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Setup_Mod_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_Setup_Mod_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Setup_Mod_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Subject_To_Counter_Check_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Subject_To_Counter_Check_List_NG_RAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Subject_To_Early_Forwarding_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRBs_Subject_To_Early_Forwarding_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRBs_Subject_To_Early_Forwarding_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_To_Modify_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_To_Modify_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_To_Modify_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_To_Remove_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_To_Remove_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_To_Remove_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Required_To_Remove_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_Required_To_Remove_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Required_To_Remove_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_To_Setup_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_To_Setup_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_To_Setup_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_To_Setup_Mod_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_To_Setup_Mod_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_To_Setup_Mod_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataDiscardRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DataDiscardRequired(tvb, offset, &asn1_ctx, tree, hf_e1ap_DataDiscardRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EarlyDataForwardingIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_EarlyDataForwardingIndicator(tvb, offset, &asn1_ctx, tree, hf_e1ap_EarlyDataForwardingIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EarlyForwardingCOUNTInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_EarlyForwardingCOUNTInfo(tvb, offset, &asn1_ctx, tree, hf_e1ap_EarlyForwardingCOUNTInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EarlyForwardingCOUNTReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_EarlyForwardingCOUNTReq(tvb, offset, &asn1_ctx, tree, hf_e1ap_EarlyForwardingCOUNTReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ECNMarkingorCongestionInformationReportingRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ECNMarkingorCongestionInformationReportingRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_ECNMarkingorCongestionInformationReportingRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ECNMarkingorCongestionInformationReportingStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ECNMarkingorCongestionInformationReportingStatus(tvb, offset, &asn1_ctx, tree, hf_e1ap_ECNMarkingorCongestionInformationReportingStatus_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EHC_Parameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_EHC_Parameters(tvb, offset, &asn1_ctx, tree, hf_e1ap_EHC_Parameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Endpoint_IP_address_and_port_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_Endpoint_IP_address_and_port(tvb, offset, &asn1_ctx, tree, hf_e1ap_Endpoint_IP_address_and_port_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExtendedPacketDelayBudget_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ExtendedPacketDelayBudget(tvb, offset, &asn1_ctx, tree, hf_e1ap_ExtendedPacketDelayBudget_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ECGI_Support_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ECGI_Support_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_ECGI_Support_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExtendedSliceSupportList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ExtendedSliceSupportList(tvb, offset, &asn1_ctx, tree, hf_e1ap_ExtendedSliceSupportList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1U_TNL_InfoAdded_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_F1U_TNL_InfoAdded_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_F1U_TNL_InfoAdded_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1U_TNL_InfoToAdd_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_F1U_TNL_InfoToAdd_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_F1U_TNL_InfoToAdd_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1U_TNL_InfoAddedOrModified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_F1U_TNL_InfoAddedOrModified_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_F1U_TNL_InfoAddedOrModified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1U_TNL_InfoToAddOrModify_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_F1U_TNL_InfoToAddOrModify_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_F1U_TNL_InfoToAddOrModify_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1U_TNL_InfoToRelease_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_F1U_TNL_InfoToRelease_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_F1U_TNL_InfoToRelease_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalMBSSessionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GlobalMBSSessionID(tvb, offset, &asn1_ctx, tree, hf_e1ap_GlobalMBSSessionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_Name_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_Name(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_Name_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Extended_GNB_CU_CP_Name_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_Extended_GNB_CU_CP_Name(tvb, offset, &asn1_ctx, tree, hf_e1ap_Extended_GNB_CU_CP_Name_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_MBS_E1AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_MBS_E1AP_ID(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_MBS_E1AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_UE_E1AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_UE_E1AP_ID(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_UE_E1AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_Capacity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_Capacity(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_Capacity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_ID(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_MBS_Support_Info_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_MBS_Support_Info(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_MBS_Support_Info_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_Name_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_Name(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_Name_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Extended_GNB_CU_UP_Name_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_Extended_GNB_CU_UP_Name(tvb, offset, &asn1_ctx, tree, hf_e1ap_Extended_GNB_CU_UP_Name_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_MBS_E1AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_MBS_E1AP_ID(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_MBS_E1AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_UE_E1AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_UE_E1AP_ID(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_UE_E1AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GBR_QoSFlowInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GBR_QoSFlowInformation(tvb, offset, &asn1_ctx, tree, hf_e1ap_GBR_QoSFlowInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_OverloadInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_OverloadInformation(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_OverloadInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DU_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_DU_ID(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_DU_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HW_CapacityIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_HW_CapacityIndicator(tvb, offset, &asn1_ctx, tree, hf_e1ap_HW_CapacityIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IndirectPathIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_IndirectPathIndication(tvb, offset, &asn1_ctx, tree, hf_e1ap_IndirectPathIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IgnoreMappingRuleIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_IgnoreMappingRuleIndication(tvb, offset, &asn1_ctx, tree, hf_e1ap_IgnoreMappingRuleIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Inactivity_Timer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_Inactivity_Timer(tvb, offset, &asn1_ctx, tree, hf_e1ap_Inactivity_Timer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InactivityInformationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_InactivityInformationRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_InactivityInformationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MaxDataBurstVolume_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MaxDataBurstVolume(tvb, offset, &asn1_ctx, tree, hf_e1ap_MaxDataBurstVolume_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MaxCIDEHCDL_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MaxCIDEHCDL(tvb, offset, &asn1_ctx, tree, hf_e1ap_MaxCIDEHCDL_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBSAreaSessionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MBSAreaSessionID(tvb, offset, &asn1_ctx, tree, hf_e1ap_MBSAreaSessionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBSSessionAssociatedInfoNonSupportToSupport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MBSSessionAssociatedInfoNonSupportToSupport(tvb, offset, &asn1_ctx, tree, hf_e1ap_MBSSessionAssociatedInfoNonSupportToSupport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBSSessionResourceNotification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MBSSessionResourceNotification(tvb, offset, &asn1_ctx, tree, hf_e1ap_MBSSessionResourceNotification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextToSetup_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextToSetup(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextToSetup_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextStatusChange_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextStatusChange(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextStatusChange_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextToSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextToSetupResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextToSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextToModify_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextToModify(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextToModify_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBSMulticastF1UContextDescriptor_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MBSMulticastF1UContextDescriptor(tvb, offset, &asn1_ctx, tree, hf_e1ap_MBSMulticastF1UContextDescriptor_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextToModifyResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextToModifyResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextToModifyResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextToModifyRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextToModifyRequired(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextToModifyRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextToModifyConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextToModifyConfirm(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextToModifyConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCForwardingResourceRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCForwardingResourceRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCForwardingResourceRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCForwardingResourceIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCForwardingResourceIndication(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCForwardingResourceIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCForwardingResourceResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCForwardingResourceResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCForwardingResourceResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCForwardingResourceRelease_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCForwardingResourceRelease(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCForwardingResourceRelease_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCForwardingResourceReleaseIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCForwardingResourceReleaseIndication(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCForwardingResourceReleaseIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MDTPollutedMeasurementIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MDTPollutedMeasurementIndicator(tvb, offset, &asn1_ctx, tree, hf_e1ap_MDTPollutedMeasurementIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M4ReportAmount_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_M4ReportAmount(tvb, offset, &asn1_ctx, tree, hf_e1ap_M4ReportAmount_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M6ReportAmount_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_M6ReportAmount(tvb, offset, &asn1_ctx, tree, hf_e1ap_M6ReportAmount_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M7ReportAmount_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_M7ReportAmount(tvb, offset, &asn1_ctx, tree, hf_e1ap_M7ReportAmount_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MDT_Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MDT_Configuration(tvb, offset, &asn1_ctx, tree, hf_e1ap_MDT_Configuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MDTPLMNList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MDTPLMNList(tvb, offset, &asn1_ctx, tree, hf_e1ap_MDTPLMNList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MDTPLMNModificationList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MDTPLMNModificationList(tvb, offset, &asn1_ctx, tree, hf_e1ap_MDTPLMNModificationList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MT_SDT_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MT_SDT_Information(tvb, offset, &asn1_ctx, tree, hf_e1ap_MT_SDT_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MT_SDT_Information_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MT_SDT_Information_Request(tvb, offset, &asn1_ctx, tree, hf_e1ap_MT_SDT_Information_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBS_ServiceArea_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MBS_ServiceArea(tvb, offset, &asn1_ctx, tree, hf_e1ap_MBS_ServiceArea_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NetworkInstance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_NetworkInstance(tvb, offset, &asn1_ctx, tree, hf_e1ap_NetworkInstance_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_New_UL_TNL_Information_Required_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_New_UL_TNL_Information_Required(tvb, offset, &asn1_ctx, tree, hf_e1ap_New_UL_TNL_Information_Required_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NPNSupportInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_NPNSupportInfo(tvb, offset, &asn1_ctx, tree, hf_e1ap_NPNSupportInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NPNContextInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_NPNContextInfo(tvb, offset, &asn1_ctx, tree, hf_e1ap_NPNContextInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Extended_NR_CGI_Support_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_Extended_NR_CGI_Support_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_Extended_NR_CGI_Support_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_N6JitterInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_N6JitterInformation(tvb, offset, &asn1_ctx, tree, hf_e1ap_N6JitterInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDCPSNGapReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDCPSNGapReport(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDCPSNGapReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDCP_COUNT_Reset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDCP_COUNT_Reset(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDCP_COUNT_Reset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Data_Usage_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Data_Usage_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Data_Usage_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDCP_StatusReportIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDCP_StatusReportIndication(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDCP_StatusReportIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSession_PairID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDUSession_PairID(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDUSession_PairID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Confirm_Modified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Confirm_Modified_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Confirm_Modified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Failed_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Failed_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Failed_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Failed_Mod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Failed_Mod_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Failed_Mod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Failed_To_Modify_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Failed_To_Modify_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Failed_To_Modify_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Modified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Modified_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Modified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Required_To_Modify_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Required_To_Modify_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Required_To_Modify_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Setup_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Setup_Mod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Setup_Mod_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Setup_Mod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_To_Modify_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_To_Modify_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_To_Modify_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_To_Remove_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_To_Remove_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_To_Remove_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_To_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_To_Setup_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_To_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_To_Setup_Mod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_To_Setup_Mod_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_To_Setup_Mod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_To_Notify_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDU_Session_To_Notify_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_To_Notify_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSetbasedHandlingIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDUSetbasedHandlingIndicator(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDUSetbasedHandlingIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PLMN_Identity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PLMN_Identity(tvb, offset, &asn1_ctx, tree, hf_e1ap_PLMN_Identity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PPI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PPI(tvb, offset, &asn1_ctx, tree, hf_e1ap_PPI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivacyIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PrivacyIndicator(tvb, offset, &asn1_ctx, tree, hf_e1ap_PrivacyIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSetQoSParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PDUSetQoSParameters(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDUSetQoSParameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoS_Flow_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_QoS_Flow_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_QoS_Flow_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoS_Flow_Mapping_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_QoS_Flow_Mapping_Indication(tvb, offset, &asn1_ctx, tree, hf_e1ap_QoS_Flow_Mapping_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoS_Flows_DRB_Remapping_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_QoS_Flows_DRB_Remapping(tvb, offset, &asn1_ctx, tree, hf_e1ap_QoS_Flows_DRB_Remapping_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoSFlowLevelQoSParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_QoSFlowLevelQoSParameters(tvb, offset, &asn1_ctx, tree, hf_e1ap_QoSFlowLevelQoSParameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QosMonitoringRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_QosMonitoringRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_QosMonitoringRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QosMonitoringReportingFrequency_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_QosMonitoringReportingFrequency(tvb, offset, &asn1_ctx, tree, hf_e1ap_QosMonitoringReportingFrequency_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QosMonitoringDisabled_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_QosMonitoringDisabled(tvb, offset, &asn1_ctx, tree, hf_e1ap_QosMonitoringDisabled_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoS_Mapping_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_QoS_Mapping_Information(tvb, offset, &asn1_ctx, tree, hf_e1ap_QoS_Mapping_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataForwardingtoNG_RANQoSFlowInformationList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DataForwardingtoNG_RANQoSFlowInformationList(tvb, offset, &asn1_ctx, tree, hf_e1ap_DataForwardingtoNG_RANQoSFlowInformationList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANUEID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_RANUEID(tvb, offset, &asn1_ctx, tree, hf_e1ap_RANUEID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RedundantQoSFlowIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_RedundantQoSFlowIndicator(tvb, offset, &asn1_ctx, tree, hf_e1ap_RedundantQoSFlowIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RedundantPDUSessionInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_RedundantPDUSessionInformation(tvb, offset, &asn1_ctx, tree, hf_e1ap_RedundantPDUSessionInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RetainabilityMeasurementsInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_RetainabilityMeasurementsInfo(tvb, offset, &asn1_ctx, tree, hf_e1ap_RetainabilityMeasurementsInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RegistrationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_RegistrationRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_RegistrationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportCharacteristics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ReportCharacteristics(tvb, offset, &asn1_ctx, tree, hf_e1ap_ReportCharacteristics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingPeriodicity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ReportingPeriodicity(tvb, offset, &asn1_ctx, tree, hf_e1ap_ReportingPeriodicity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SDT_data_size_threshold_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SDT_data_size_threshold(tvb, offset, &asn1_ctx, tree, hf_e1ap_SDT_data_size_threshold_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SDT_data_size_threshold_Crossed_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SDT_data_size_threshold_Crossed(tvb, offset, &asn1_ctx, tree, hf_e1ap_SDT_data_size_threshold_Crossed_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCGActivationStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SCGActivationStatus(tvb, offset, &asn1_ctx, tree, hf_e1ap_SCGActivationStatus_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SecurityIndication(tvb, offset, &asn1_ctx, tree, hf_e1ap_SecurityIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SecurityInformation(tvb, offset, &asn1_ctx, tree, hf_e1ap_SecurityInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SecurityResult(tvb, offset, &asn1_ctx, tree, hf_e1ap_SecurityResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNSSAI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SNSSAI(tvb, offset, &asn1_ctx, tree, hf_e1ap_SNSSAI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SDTContinueROHC_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SDTContinueROHC(tvb, offset, &asn1_ctx, tree, hf_e1ap_SDTContinueROHC_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SDTindicatorSetup_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SDTindicatorSetup(tvb, offset, &asn1_ctx, tree, hf_e1ap_SDTindicatorSetup_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SDTindicatorMod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SDTindicatorMod(tvb, offset, &asn1_ctx, tree, hf_e1ap_SDTindicatorMod_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SubscriberProfileIDforRFP_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SubscriberProfileIDforRFP(tvb, offset, &asn1_ctx, tree, hf_e1ap_SubscriberProfileIDforRFP_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SurvivalTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SurvivalTime(tvb, offset, &asn1_ctx, tree, hf_e1ap_SurvivalTime_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SpecialTriggeringPurpose_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SpecialTriggeringPurpose(tvb, offset, &asn1_ctx, tree, hf_e1ap_SpecialTriggeringPurpose_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1UTunnelNotEstablished_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_F1UTunnelNotEstablished(tvb, offset, &asn1_ctx, tree, hf_e1ap_F1UTunnelNotEstablished_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToWait_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_TimeToWait(tvb, offset, &asn1_ctx, tree, hf_e1ap_TimeToWait_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TNL_AvailableCapacityIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_TNL_AvailableCapacityIndicator(tvb, offset, &asn1_ctx, tree, hf_e1ap_TNL_AvailableCapacityIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TSCTrafficCharacteristics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_TSCTrafficCharacteristics(tvb, offset, &asn1_ctx, tree, hf_e1ap_TSCTrafficCharacteristics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceActivation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_TraceActivation(tvb, offset, &asn1_ctx, tree, hf_e1ap_TraceActivation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_TraceID(tvb, offset, &asn1_ctx, tree, hf_e1ap_TraceID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransportLayerAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_TransportLayerAddress(tvb, offset, &asn1_ctx, tree, hf_e1ap_TransportLayerAddress_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransactionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_TransactionID(tvb, offset, &asn1_ctx, tree, hf_e1ap_TransactionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Transport_Layer_Address_Info_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_Transport_Layer_Address_Info(tvb, offset, &asn1_ctx, tree, hf_e1ap_Transport_Layer_Address_Info_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UDC_Parameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_UDC_Parameters(tvb, offset, &asn1_ctx, tree, hf_e1ap_UDC_Parameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_VersionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_VersionID(tvb, offset, &asn1_ctx, tree, hf_e1ap_VersionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_associatedLogicalE1_ConnectionItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_UE_associatedLogicalE1_ConnectionItem(tvb, offset, &asn1_ctx, tree, hf_e1ap_UE_associatedLogicalE1_ConnectionItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UESliceMaximumBitRateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_UESliceMaximumBitRateList(tvb, offset, &asn1_ctx, tree, hf_e1ap_UESliceMaximumBitRateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UP_TNL_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_UP_TNL_Information(tvb, offset, &asn1_ctx, tree, hf_e1ap_UP_TNL_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_URIaddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_URIaddress(tvb, offset, &asn1_ctx, tree, hf_e1ap_URIaddress_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UserPlaneErrorIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_UserPlaneErrorIndicator(tvb, offset, &asn1_ctx, tree, hf_e1ap_UserPlaneErrorIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEInactivityInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_UEInactivityInformation(tvb, offset, &asn1_ctx, tree, hf_e1ap_UEInactivityInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UserPlaneFailureIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_UserPlaneFailureIndication(tvb, offset, &asn1_ctx, tree, hf_e1ap_UserPlaneFailureIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_Reset(tvb, offset, &asn1_ctx, tree, hf_e1ap_Reset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ResetType(tvb, offset, &asn1_ctx, tree, hf_e1ap_ResetType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ResetAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e1ap_ResetAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_associatedLogicalE1_ConnectionListResAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_UE_associatedLogicalE1_ConnectionListResAck(tvb, offset, &asn1_ctx, tree, hf_e1ap_UE_associatedLogicalE1_ConnectionListResAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_e1ap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_E1SetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_E1SetupRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_E1SetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SupportedPLMNs_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_SupportedPLMNs_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_SupportedPLMNs_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_E1SetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_E1SetupResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_E1SetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_E1SetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_E1SetupFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_E1SetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_E1SetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_E1SetupRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_E1SetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_E1SetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_E1SetupResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_E1SetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_E1SetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_E1SetupFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_E1SetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_ConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_ConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_ConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_TNLA_To_Remove_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_TNLA_To_Remove_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_TNLA_To_Remove_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_ConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_ConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_ConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_ConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_ConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_ConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_ConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_ConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_ConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_TNLA_To_Add_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_TNLA_To_Add_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_TNLA_To_Add_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_TNLA_To_Remove_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_TNLA_To_Remove_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_TNLA_To_Remove_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_TNLA_To_Update_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_TNLA_To_Update_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_TNLA_To_Update_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_ConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_ConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_ConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_TNLA_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_TNLA_Setup_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_TNLA_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_TNLA_Failed_To_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_ConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_ConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_ConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E1ReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_E1ReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_E1ReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E1ReleaseResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_E1ReleaseResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_E1ReleaseResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BearerContextSetupRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_BearerContextSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_System_BearerContextSetupRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_BearerContextSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BearerContextSetupResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_BearerContextSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_System_BearerContextSetupResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_BearerContextSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextSetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BearerContextSetupFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextSetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BearerContextModificationRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_BearerContextModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_System_BearerContextModificationRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_BearerContextModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextModificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BearerContextModificationResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextModificationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_BearerContextModificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_System_BearerContextModificationResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_BearerContextModificationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextModificationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BearerContextModificationFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextModificationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextModificationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BearerContextModificationRequired(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextModificationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_BearerContextModificationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_System_BearerContextModificationRequired(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_BearerContextModificationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextModificationConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BearerContextModificationConfirm(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextModificationConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_BearerContextModificationConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_System_BearerContextModificationConfirm(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_BearerContextModificationConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BearerContextReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextReleaseComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BearerContextReleaseComplete(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextReleaseComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BearerContextReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Status_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DRB_Status_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Status_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextInactivityNotification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BearerContextInactivityNotification(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextInactivityNotification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DLDataNotification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DLDataNotification(tvb, offset, &asn1_ctx, tree, hf_e1ap_DLDataNotification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ULDataNotification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ULDataNotification(tvb, offset, &asn1_ctx, tree, hf_e1ap_ULDataNotification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataUsageReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DataUsageReport(tvb, offset, &asn1_ctx, tree, hf_e1ap_DataUsageReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_CounterCheckRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_CounterCheckRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_CounterCheckRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_GNB_CU_UP_CounterCheckRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_System_GNB_CU_UP_CounterCheckRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_GNB_CU_UP_CounterCheckRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_StatusIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_StatusIndication(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_StatusIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CPMeasurementResultsInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_GNB_CU_CPMeasurementResultsInformation(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CPMeasurementResultsInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MRDC_DataUsageReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MRDC_DataUsageReport(tvb, offset, &asn1_ctx, tree, hf_e1ap_MRDC_DataUsageReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceStart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_TraceStart(tvb, offset, &asn1_ctx, tree, hf_e1ap_TraceStart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DeactivateTrace_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DeactivateTrace(tvb, offset, &asn1_ctx, tree, hf_e1ap_DeactivateTrace_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellTrafficTrace_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_CellTrafficTrace(tvb, offset, &asn1_ctx, tree, hf_e1ap_CellTrafficTrace_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_e1ap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceStatusRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ResourceStatusRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_ResourceStatusRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Measurement_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_Measurement_ID(tvb, offset, &asn1_ctx, tree, hf_e1ap_Measurement_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceStatusResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ResourceStatusResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_ResourceStatusResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceStatusFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ResourceStatusFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_ResourceStatusFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceStatusUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ResourceStatusUpdate(tvb, offset, &asn1_ctx, tree, hf_e1ap_ResourceStatusUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IAB_UPTNLAddressUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_IAB_UPTNLAddressUpdate(tvb, offset, &asn1_ctx, tree, hf_e1ap_IAB_UPTNLAddressUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DLUPTNLAddressToUpdateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_DLUPTNLAddressToUpdateList(tvb, offset, &asn1_ctx, tree, hf_e1ap_DLUPTNLAddressToUpdateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IAB_UPTNLAddressUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_IAB_UPTNLAddressUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e1ap_IAB_UPTNLAddressUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ULUPTNLAddressToUpdateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_ULUPTNLAddressToUpdateList(tvb, offset, &asn1_ctx, tree, hf_e1ap_ULUPTNLAddressToUpdateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IAB_UPTNLAddressUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_IAB_UPTNLAddressUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_IAB_UPTNLAddressUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EarlyForwardingSNTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_EarlyForwardingSNTransfer(tvb, offset, &asn1_ctx, tree, hf_e1ap_EarlyForwardingSNTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IABPSKNotification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_IABPSKNotification(tvb, offset, &asn1_ctx, tree, hf_e1ap_IABPSKNotification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IAB_Donor_CU_UPPSKInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_IAB_Donor_CU_UPPSKInfo(tvb, offset, &asn1_ctx, tree, hf_e1ap_IAB_Donor_CU_UPPSKInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextSetupRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextSetupResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextSetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextSetupFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextSetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextModificationRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextModificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextModificationResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextModificationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextModificationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextModificationFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextModificationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextModificationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextModificationRequired(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextModificationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextModificationConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextModificationConfirm(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextModificationConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextReleaseComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextReleaseComplete(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextReleaseComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCBearerContextReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_BCBearerContextReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_BCBearerContextReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextSetupRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextSetupResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextSetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextSetupFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextSetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextModificationRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextModificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextModificationResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextModificationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextModificationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextModificationFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextModificationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextModificationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextModificationRequired(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextModificationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextModificationConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextModificationConfirm(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextModificationConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextReleaseComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextReleaseComplete(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextReleaseComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerContextReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerContextReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerContextReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MCBearerNotification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_MCBearerNotification(tvb, offset, &asn1_ctx, tree, hf_e1ap_MCBearerNotification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E1AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e1ap_E1AP_PDU(tvb, offset, &asn1_ctx, tree, hf_e1ap_E1AP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  e1ap_ctx_t e1ap_ctx;
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  e1ap_ctx.message_type        = e1ap_data->message_type;
  e1ap_ctx.ProcedureCode       = e1ap_data->procedure_code;
  e1ap_ctx.ProtocolIE_ID       = e1ap_data->protocol_ie_id;

  return (dissector_try_uint_new(e1ap_ies_dissector_table, e1ap_data->protocol_ie_id, tvb, pinfo, tree, false, &e1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  e1ap_ctx_t e1ap_ctx;
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  e1ap_ctx.message_type        = e1ap_data->message_type;
  e1ap_ctx.ProcedureCode       = e1ap_data->procedure_code;
  e1ap_ctx.ProtocolIE_ID       = e1ap_data->protocol_ie_id;

  return (dissector_try_uint_new(e1ap_extension_dissector_table, e1ap_data->protocol_ie_id, tvb, pinfo, tree, false, &e1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e1ap_proc_imsg_dissector_table, e1ap_data->procedure_code, tvb, pinfo, tree, false, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e1ap_proc_sout_dissector_table, e1ap_data->procedure_code, tvb, pinfo, tree, false, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e1ap_proc_uout_dissector_table, e1ap_data->procedure_code, tvb, pinfo, tree, false, data)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_e1ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *e1ap_item = NULL;
  proto_tree *e1ap_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "E1AP");
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the e1ap protocol tree */
  e1ap_item = proto_tree_add_item(tree, proto_e1ap, tvb, 0, -1, ENC_NA);
  e1ap_tree = proto_item_add_subtree(e1ap_item, ett_e1ap);

  dissect_E1AP_PDU_PDU(tvb, pinfo, e1ap_tree, NULL);
  return tvb_captured_length(tvb);
}

static unsigned
get_e1ap_tcp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                     int offset, void *data _U_)
{
  return tvb_get_ntohl(tvb, offset)+4;
}

static int
dissect_e1ap_tcp_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
  tvbuff_t *new_tvb;

  proto_tree_add_item(tree, hf_e1ap_tcp_pdu_len, tvb, 0, 4, ENC_NA);
  new_tvb = tvb_new_subset_remaining(tvb, 4);

  return dissect_e1ap(new_tvb, pinfo, tree, data);
}

static int
dissect_e1ap_tcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, true, 4,
                   get_e1ap_tcp_pdu_len, dissect_e1ap_tcp_pdu, data);
  return tvb_captured_length(tvb);
}

void proto_register_e1ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_e1ap_transportLayerAddressIPv4,
      { "IPv4 transportLayerAddress", "e1ap.transportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_transportLayerAddressIPv6,
      { "IPv6 transportLayerAddress", "e1ap.transportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_InterfacesToTrace_NG_C,
      { "NG-C", "e1ap.InterfacesToTrace.NG_C",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x80,
        NULL, HFILL }},
    { &hf_e1ap_InterfacesToTrace_Xn_C,
      { "Xn-C", "e1ap.InterfacesToTrace.Xn_C",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x40,
        NULL, HFILL }},
    { &hf_e1ap_InterfacesToTrace_Uu,
      { "Uu", "e1ap.InterfacesToTrace.Uu",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x20,
        NULL, HFILL }},
    { &hf_e1ap_InterfacesToTrace_F1_C,
      { "F1-C", "e1ap.InterfacesToTrace.F1_C",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x10,
        NULL, HFILL }},
    { &hf_e1ap_InterfacesToTrace_E1,
      { "E1", "e1ap.InterfacesToTrace.E1",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x08,
        NULL, HFILL }},
    { &hf_e1ap_InterfacesToTrace_Reserved,
      { "Reserved", "e1ap.InterfacesToTrace.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x07,
        NULL, HFILL }},
    { &hf_e1ap_MeasurementsToActivate_Reserved1,
      { "Reserved", "e1ap.MeasurementsToActivate.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0xe0,
        NULL, HFILL }},
    { &hf_e1ap_MeasurementsToActivate_M4,
      { "M4", "e1ap.MeasurementsToActivate.M4",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x10,
        NULL, HFILL }},
    { &hf_e1ap_MeasurementsToActivate_Reserved2,
      { "Reserved", "e1ap.MeasurementsToActivate.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x0c,
        NULL, HFILL }},
    { &hf_e1ap_MeasurementsToActivate_M6,
      { "M6", "e1ap.MeasurementsToActivate.M6",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x02,
        NULL, HFILL }},
    { &hf_e1ap_MeasurementsToActivate_M7,
      { "M7", "e1ap.MeasurementsToActivate.M7",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x01,
        NULL, HFILL }},
    { &hf_e1ap_ReportCharacteristics_TNLAvailableCapacityIndPeriodic,
      { "TNLAvailableCapacityIndPeriodic", "e1ap.ReportCharacteristics.TNLAvailableCapacityIndPeriodic",
        FT_BOOLEAN, 40, TFS(&tfs_requested_not_requested), 0x8000000000,
        NULL, HFILL }},
    { &hf_e1ap_ReportCharacteristics_HWCapacityIndPeriodic,
      { "HWCapacityIndPeriodic", "e1ap.ReportCharacteristics.HWCapacityIndPeriodic",
        FT_BOOLEAN, 40, TFS(&tfs_requested_not_requested), 0x4000000000,
        NULL, HFILL }},
    { &hf_e1ap_ReportCharacteristics_Reserved,
      { "Reserved", "e1ap.ReportCharacteristics.Reserved",
        FT_UINT40, BASE_HEX, NULL, 0x3ffffffff0,
        NULL, HFILL }},
    { &hf_e1ap_tcp_pdu_len,
      { "TCP PDU length", "e1ap.tcp_pdu_len",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_e1ap_ActivityInformation_PDU,
      { "ActivityInformation", "e1ap.ActivityInformation",
        FT_UINT32, BASE_DEC, VALS(e1ap_ActivityInformation_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_ActivityNotificationLevel_PDU,
      { "ActivityNotificationLevel", "e1ap.ActivityNotificationLevel",
        FT_UINT32, BASE_DEC, VALS(e1ap_ActivityNotificationLevel_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_AdditionalHandoverInfo_PDU,
      { "AdditionalHandoverInfo", "e1ap.AdditionalHandoverInfo",
        FT_UINT32, BASE_DEC, VALS(e1ap_AdditionalHandoverInfo_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_AdditionalPDCPduplicationInformation_PDU,
      { "AdditionalPDCPduplicationInformation", "e1ap.AdditionalPDCPduplicationInformation",
        FT_UINT32, BASE_DEC, VALS(e1ap_AdditionalPDCPduplicationInformation_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_AdditionalRRMPriorityIndex_PDU,
      { "AdditionalRRMPriorityIndex", "e1ap.AdditionalRRMPriorityIndex",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_AlternativeQoSParaSetList_PDU,
      { "AlternativeQoSParaSetList", "e1ap.AlternativeQoSParaSetList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_AssociatedSessionID_PDU,
      { "AssociatedSessionID", "e1ap.AssociatedSessionID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextToSetup_PDU,
      { "BCBearerContextToSetup", "e1ap.BCBearerContextToSetup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextToSetupResponse_PDU,
      { "BCBearerContextToSetupResponse", "e1ap.BCBearerContextToSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextToModify_PDU,
      { "BCBearerContextToModify", "e1ap.BCBearerContextToModify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextNGU_TNLInfoatNGRAN_Request_PDU,
      { "BCBearerContextNGU-TNLInfoatNGRAN-Request", "e1ap.BCBearerContextNGU_TNLInfoatNGRAN_Request",
        FT_UINT32, BASE_DEC, VALS(e1ap_BCBearerContextNGU_TNLInfoatNGRAN_Request_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextToModifyResponse_PDU,
      { "BCBearerContextToModifyResponse", "e1ap.BCBearerContextToModifyResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextToModifyRequired_PDU,
      { "BCBearerContextToModifyRequired", "e1ap.BCBearerContextToModifyRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextToModifyConfirm_PDU,
      { "BCBearerContextToModifyConfirm", "e1ap.BCBearerContextToModifyConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BearerContextStatusChange_PDU,
      { "BearerContextStatusChange", "e1ap.BearerContextStatusChange",
        FT_UINT32, BASE_DEC, VALS(e1ap_BearerContextStatusChange_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_BitRate_PDU,
      { "BitRate", "e1ap.BitRate",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        NULL, HFILL }},
    { &hf_e1ap_Cause_PDU,
      { "Cause", "e1ap.Cause",
        FT_UINT32, BASE_DEC, VALS(e1ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_CHOInitiation_PDU,
      { "CHOInitiation", "e1ap.CHOInitiation",
        FT_UINT32, BASE_DEC, VALS(e1ap_CHOInitiation_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_Number_of_tunnels_PDU,
      { "Number-of-tunnels", "e1ap.Number_of_tunnels",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_CNSupport_PDU,
      { "CNSupport", "e1ap.CNSupport",
        FT_UINT32, BASE_DEC, VALS(e1ap_CNSupport_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_CommonNetworkInstance_PDU,
      { "CommonNetworkInstance", "e1ap.CommonNetworkInstance",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_CP_TNL_Information_PDU,
      { "CP-TNL-Information", "e1ap.CP_TNL_Information",
        FT_UINT32, BASE_DEC, VALS(e1ap_CP_TNL_Information_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "e1ap.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DAPSRequestInfo_PDU,
      { "DAPSRequestInfo", "e1ap.DAPSRequestInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_Data_Forwarding_Information_PDU,
      { "Data-Forwarding-Information", "e1ap.Data_Forwarding_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DataForwardingtoE_UTRANInformationList_PDU,
      { "DataForwardingtoE-UTRANInformationList", "e1ap.DataForwardingtoE_UTRANInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_Data_Usage_Report_List_PDU,
      { "Data-Usage-Report-List", "e1ap.Data_Usage_Report_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DirectForwardingPathAvailability_PDU,
      { "DirectForwardingPathAvailability", "e1ap.DirectForwardingPathAvailability",
        FT_UINT32, BASE_DEC, VALS(e1ap_DirectForwardingPathAvailability_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_DiscardTimerExtended_PDU,
      { "DiscardTimerExtended", "e1ap.DiscardTimerExtended",
        FT_UINT32, BASE_DEC, VALS(e1ap_DiscardTimerExtended_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_PSIbasedDiscardTimer_PDU,
      { "PSIbasedDiscardTimer", "e1ap.PSIbasedDiscardTimer",
        FT_UINT32, BASE_DEC, VALS(e1ap_PSIbasedDiscardTimer_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Confirm_Modified_List_EUTRAN_PDU,
      { "DRB-Confirm-Modified-List-EUTRAN", "e1ap.DRB_Confirm_Modified_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Failed_List_EUTRAN_PDU,
      { "DRB-Failed-List-EUTRAN", "e1ap.DRB_Failed_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Failed_Mod_List_EUTRAN_PDU,
      { "DRB-Failed-Mod-List-EUTRAN", "e1ap.DRB_Failed_Mod_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Failed_To_Modify_List_EUTRAN_PDU,
      { "DRB-Failed-To-Modify-List-EUTRAN", "e1ap.DRB_Failed_To_Modify_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Measurement_Results_Information_List_PDU,
      { "DRB-Measurement-Results-Information-List", "e1ap.DRB_Measurement_Results_Information_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Modified_List_EUTRAN_PDU,
      { "DRB-Modified-List-EUTRAN", "e1ap.DRB_Modified_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Required_To_Modify_List_EUTRAN_PDU,
      { "DRB-Required-To-Modify-List-EUTRAN", "e1ap.DRB_Required_To_Modify_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Setup_List_EUTRAN_PDU,
      { "DRB-Setup-List-EUTRAN", "e1ap.DRB_Setup_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Setup_Mod_List_EUTRAN_PDU,
      { "DRB-Setup-Mod-List-EUTRAN", "e1ap.DRB_Setup_Mod_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN_PDU,
      { "DRBs-Subject-To-Counter-Check-List-EUTRAN", "e1ap.DRBs_Subject_To_Counter_Check_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN_PDU,
      { "DRBs-Subject-To-Counter-Check-List-NG-RAN", "e1ap.DRBs_Subject_To_Counter_Check_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRBs_Subject_To_Early_Forwarding_List_PDU,
      { "DRBs-Subject-To-Early-Forwarding-List", "e1ap.DRBs_Subject_To_Early_Forwarding_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_To_Modify_List_EUTRAN_PDU,
      { "DRB-To-Modify-List-EUTRAN", "e1ap.DRB_To_Modify_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_To_Remove_List_EUTRAN_PDU,
      { "DRB-To-Remove-List-EUTRAN", "e1ap.DRB_To_Remove_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Required_To_Remove_List_EUTRAN_PDU,
      { "DRB-Required-To-Remove-List-EUTRAN", "e1ap.DRB_Required_To_Remove_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_To_Setup_List_EUTRAN_PDU,
      { "DRB-To-Setup-List-EUTRAN", "e1ap.DRB_To_Setup_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_To_Setup_Mod_List_EUTRAN_PDU,
      { "DRB-To-Setup-Mod-List-EUTRAN", "e1ap.DRB_To_Setup_Mod_List_EUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DataDiscardRequired_PDU,
      { "DataDiscardRequired", "e1ap.DataDiscardRequired",
        FT_UINT32, BASE_DEC, VALS(e1ap_DataDiscardRequired_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_EarlyDataForwardingIndicator_PDU,
      { "EarlyDataForwardingIndicator", "e1ap.EarlyDataForwardingIndicator",
        FT_UINT32, BASE_DEC, VALS(e1ap_EarlyDataForwardingIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_EarlyForwardingCOUNTInfo_PDU,
      { "EarlyForwardingCOUNTInfo", "e1ap.EarlyForwardingCOUNTInfo",
        FT_UINT32, BASE_DEC, VALS(e1ap_EarlyForwardingCOUNTInfo_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_EarlyForwardingCOUNTReq_PDU,
      { "EarlyForwardingCOUNTReq", "e1ap.EarlyForwardingCOUNTReq",
        FT_UINT32, BASE_DEC, VALS(e1ap_EarlyForwardingCOUNTReq_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_ECNMarkingorCongestionInformationReportingRequest_PDU,
      { "ECNMarkingorCongestionInformationReportingRequest", "e1ap.ECNMarkingorCongestionInformationReportingRequest",
        FT_UINT32, BASE_DEC, VALS(e1ap_ECNMarkingorCongestionInformationReportingRequest_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_ECNMarkingorCongestionInformationReportingStatus_PDU,
      { "ECNMarkingorCongestionInformationReportingStatus", "e1ap.ECNMarkingorCongestionInformationReportingStatus",
        FT_UINT32, BASE_DEC, VALS(e1ap_ECNMarkingorCongestionInformationReportingStatus_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_EHC_Parameters_PDU,
      { "EHC-Parameters", "e1ap.EHC_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_Endpoint_IP_address_and_port_PDU,
      { "Endpoint-IP-address-and-port", "e1ap.Endpoint_IP_address_and_port_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ExtendedPacketDelayBudget_PDU,
      { "ExtendedPacketDelayBudget", "e1ap.ExtendedPacketDelayBudget",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(e1ap_ExtendedPacketDelayBudget_fmt), 0,
        NULL, HFILL }},
    { &hf_e1ap_ECGI_Support_List_PDU,
      { "ECGI-Support-List", "e1ap.ECGI_Support_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ExtendedSliceSupportList_PDU,
      { "ExtendedSliceSupportList", "e1ap.ExtendedSliceSupportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_F1U_TNL_InfoAdded_List_PDU,
      { "F1U-TNL-InfoAdded-List", "e1ap.F1U_TNL_InfoAdded_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_F1U_TNL_InfoToAdd_List_PDU,
      { "F1U-TNL-InfoToAdd-List", "e1ap.F1U_TNL_InfoToAdd_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_F1U_TNL_InfoAddedOrModified_List_PDU,
      { "F1U-TNL-InfoAddedOrModified-List", "e1ap.F1U_TNL_InfoAddedOrModified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_F1U_TNL_InfoToAddOrModify_List_PDU,
      { "F1U-TNL-InfoToAddOrModify-List", "e1ap.F1U_TNL_InfoToAddOrModify_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_F1U_TNL_InfoToRelease_List_PDU,
      { "F1U-TNL-InfoToRelease-List", "e1ap.F1U_TNL_InfoToRelease_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GlobalMBSSessionID_PDU,
      { "GlobalMBSSessionID", "e1ap.GlobalMBSSessionID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_Name_PDU,
      { "GNB-CU-CP-Name", "e1ap.GNB_CU_CP_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_Extended_GNB_CU_CP_Name_PDU,
      { "Extended-GNB-CU-CP-Name", "e1ap.Extended_GNB_CU_CP_Name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_MBS_E1AP_ID_PDU,
      { "GNB-CU-CP-MBS-E1AP-ID", "e1ap.GNB_CU_CP_MBS_E1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_UE_E1AP_ID_PDU,
      { "GNB-CU-CP-UE-E1AP-ID", "e1ap.GNB_CU_CP_UE_E1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_Capacity_PDU,
      { "GNB-CU-UP-Capacity", "e1ap.GNB_CU_UP_Capacity",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_ID_PDU,
      { "GNB-CU-UP-ID", "e1ap.GNB_CU_UP_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_MBS_Support_Info_PDU,
      { "GNB-CU-UP-MBS-Support-Info", "e1ap.GNB_CU_UP_MBS_Support_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_Name_PDU,
      { "GNB-CU-UP-Name", "e1ap.GNB_CU_UP_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_Extended_GNB_CU_UP_Name_PDU,
      { "Extended-GNB-CU-UP-Name", "e1ap.Extended_GNB_CU_UP_Name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_MBS_E1AP_ID_PDU,
      { "GNB-CU-UP-MBS-E1AP-ID", "e1ap.GNB_CU_UP_MBS_E1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_UE_E1AP_ID_PDU,
      { "GNB-CU-UP-UE-E1AP-ID", "e1ap.GNB_CU_UP_UE_E1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GBR_QoSFlowInformation_PDU,
      { "GBR-QoSFlowInformation", "e1ap.GBR_QoSFlowInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_OverloadInformation_PDU,
      { "GNB-CU-UP-OverloadInformation", "e1ap.GNB_CU_UP_OverloadInformation",
        FT_UINT32, BASE_DEC, VALS(e1ap_GNB_CU_UP_OverloadInformation_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_DU_ID_PDU,
      { "GNB-DU-ID", "e1ap.GNB_DU_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_HW_CapacityIndicator_PDU,
      { "HW-CapacityIndicator", "e1ap.HW_CapacityIndicator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_IndirectPathIndication_PDU,
      { "IndirectPathIndication", "e1ap.IndirectPathIndication",
        FT_UINT32, BASE_DEC, VALS(e1ap_IndirectPathIndication_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_IgnoreMappingRuleIndication_PDU,
      { "IgnoreMappingRuleIndication", "e1ap.IgnoreMappingRuleIndication",
        FT_UINT32, BASE_DEC, VALS(e1ap_IgnoreMappingRuleIndication_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_Inactivity_Timer_PDU,
      { "Inactivity-Timer", "e1ap.Inactivity_Timer",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_e1ap_InactivityInformationRequest_PDU,
      { "InactivityInformationRequest", "e1ap.InactivityInformationRequest",
        FT_UINT32, BASE_DEC, VALS(e1ap_InactivityInformationRequest_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_MaxDataBurstVolume_PDU,
      { "MaxDataBurstVolume", "e1ap.MaxDataBurstVolume",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0,
        NULL, HFILL }},
    { &hf_e1ap_MaxCIDEHCDL_PDU,
      { "MaxCIDEHCDL", "e1ap.MaxCIDEHCDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MBSAreaSessionID_PDU,
      { "MBSAreaSessionID", "e1ap.MBSAreaSessionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MBSSessionAssociatedInfoNonSupportToSupport_PDU,
      { "MBSSessionAssociatedInfoNonSupportToSupport", "e1ap.MBSSessionAssociatedInfoNonSupportToSupport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MBSSessionResourceNotification_PDU,
      { "MBSSessionResourceNotification", "e1ap.MBSSessionResourceNotification",
        FT_UINT32, BASE_DEC, VALS(e1ap_MBSSessionResourceNotification_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextToSetup_PDU,
      { "MCBearerContextToSetup", "e1ap.MCBearerContextToSetup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextStatusChange_PDU,
      { "MCBearerContextStatusChange", "e1ap.MCBearerContextStatusChange",
        FT_UINT32, BASE_DEC, VALS(e1ap_MCBearerContextStatusChange_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextToSetupResponse_PDU,
      { "MCBearerContextToSetupResponse", "e1ap.MCBearerContextToSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextToModify_PDU,
      { "MCBearerContextToModify", "e1ap.MCBearerContextToModify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MBSMulticastF1UContextDescriptor_PDU,
      { "MBSMulticastF1UContextDescriptor", "e1ap.MBSMulticastF1UContextDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextToModifyResponse_PDU,
      { "MCBearerContextToModifyResponse", "e1ap.MCBearerContextToModifyResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextToModifyRequired_PDU,
      { "MCBearerContextToModifyRequired", "e1ap.MCBearerContextToModifyRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextToModifyConfirm_PDU,
      { "MCBearerContextToModifyConfirm", "e1ap.MCBearerContextToModifyConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCForwardingResourceRequest_PDU,
      { "MCForwardingResourceRequest", "e1ap.MCForwardingResourceRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCForwardingResourceIndication_PDU,
      { "MCForwardingResourceIndication", "e1ap.MCForwardingResourceIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCForwardingResourceResponse_PDU,
      { "MCForwardingResourceResponse", "e1ap.MCForwardingResourceResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCForwardingResourceRelease_PDU,
      { "MCForwardingResourceRelease", "e1ap.MCForwardingResourceRelease_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCForwardingResourceReleaseIndication_PDU,
      { "MCForwardingResourceReleaseIndication", "e1ap.MCForwardingResourceReleaseIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MDTPollutedMeasurementIndicator_PDU,
      { "MDTPollutedMeasurementIndicator", "e1ap.MDTPollutedMeasurementIndicator",
        FT_UINT32, BASE_DEC, VALS(e1ap_MDTPollutedMeasurementIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_M4ReportAmount_PDU,
      { "M4ReportAmount", "e1ap.M4ReportAmount",
        FT_UINT32, BASE_DEC, VALS(e1ap_M4ReportAmount_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_M6ReportAmount_PDU,
      { "M6ReportAmount", "e1ap.M6ReportAmount",
        FT_UINT32, BASE_DEC, VALS(e1ap_M6ReportAmount_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_M7ReportAmount_PDU,
      { "M7ReportAmount", "e1ap.M7ReportAmount",
        FT_UINT32, BASE_DEC, VALS(e1ap_M7ReportAmount_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_MDT_Configuration_PDU,
      { "MDT-Configuration", "e1ap.MDT_Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MDTPLMNList_PDU,
      { "MDTPLMNList", "e1ap.MDTPLMNList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MDTPLMNModificationList_PDU,
      { "MDTPLMNModificationList", "e1ap.MDTPLMNModificationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MT_SDT_Information_PDU,
      { "MT-SDT-Information", "e1ap.MT_SDT_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MT_SDT_Information_Request_PDU,
      { "MT-SDT-Information-Request", "e1ap.MT_SDT_Information_Request",
        FT_UINT32, BASE_DEC, VALS(e1ap_MT_SDT_Information_Request_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_MBS_ServiceArea_PDU,
      { "MBS-ServiceArea", "e1ap.MBS_ServiceArea_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_NetworkInstance_PDU,
      { "NetworkInstance", "e1ap.NetworkInstance",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_New_UL_TNL_Information_Required_PDU,
      { "New-UL-TNL-Information-Required", "e1ap.New_UL_TNL_Information_Required",
        FT_UINT32, BASE_DEC, VALS(e1ap_New_UL_TNL_Information_Required_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_NPNSupportInfo_PDU,
      { "NPNSupportInfo", "e1ap.NPNSupportInfo",
        FT_UINT32, BASE_DEC, VALS(e1ap_NPNSupportInfo_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_NPNContextInfo_PDU,
      { "NPNContextInfo", "e1ap.NPNContextInfo",
        FT_UINT32, BASE_DEC, VALS(e1ap_NPNContextInfo_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_Extended_NR_CGI_Support_List_PDU,
      { "Extended-NR-CGI-Support-List", "e1ap.Extended_NR_CGI_Support_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_N6JitterInformation_PDU,
      { "N6JitterInformation", "e1ap.N6JitterInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDCPSNGapReport_PDU,
      { "PDCPSNGapReport", "e1ap.PDCPSNGapReport",
        FT_UINT32, BASE_DEC, VALS(e1ap_PDCPSNGapReport_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_PDCP_COUNT_Reset_PDU,
      { "PDCP-COUNT-Reset", "e1ap.PDCP_COUNT_Reset",
        FT_UINT32, BASE_DEC, VALS(e1ap_PDCP_COUNT_Reset_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Data_Usage_List_PDU,
      { "PDU-Session-Resource-Data-Usage-List", "e1ap.PDU_Session_Resource_Data_Usage_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDCP_StatusReportIndication_PDU,
      { "PDCP-StatusReportIndication", "e1ap.PDCP_StatusReportIndication",
        FT_UINT32, BASE_DEC, VALS(e1ap_PDCP_StatusReportIndication_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_PDUSession_PairID_PDU,
      { "PDUSession-PairID", "e1ap.PDUSession_PairID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Confirm_Modified_List_PDU,
      { "PDU-Session-Resource-Confirm-Modified-List", "e1ap.PDU_Session_Resource_Confirm_Modified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Failed_List_PDU,
      { "PDU-Session-Resource-Failed-List", "e1ap.PDU_Session_Resource_Failed_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Failed_Mod_List_PDU,
      { "PDU-Session-Resource-Failed-Mod-List", "e1ap.PDU_Session_Resource_Failed_Mod_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Failed_To_Modify_List_PDU,
      { "PDU-Session-Resource-Failed-To-Modify-List", "e1ap.PDU_Session_Resource_Failed_To_Modify_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Modified_List_PDU,
      { "PDU-Session-Resource-Modified-List", "e1ap.PDU_Session_Resource_Modified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Required_To_Modify_List_PDU,
      { "PDU-Session-Resource-Required-To-Modify-List", "e1ap.PDU_Session_Resource_Required_To_Modify_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Setup_List_PDU,
      { "PDU-Session-Resource-Setup-List", "e1ap.PDU_Session_Resource_Setup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Setup_Mod_List_PDU,
      { "PDU-Session-Resource-Setup-Mod-List", "e1ap.PDU_Session_Resource_Setup_Mod_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_To_Modify_List_PDU,
      { "PDU-Session-Resource-To-Modify-List", "e1ap.PDU_Session_Resource_To_Modify_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_To_Remove_List_PDU,
      { "PDU-Session-Resource-To-Remove-List", "e1ap.PDU_Session_Resource_To_Remove_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_To_Setup_List_PDU,
      { "PDU-Session-Resource-To-Setup-List", "e1ap.PDU_Session_Resource_To_Setup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_To_Setup_Mod_List_PDU,
      { "PDU-Session-Resource-To-Setup-Mod-List", "e1ap.PDU_Session_Resource_To_Setup_Mod_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_To_Notify_List_PDU,
      { "PDU-Session-To-Notify-List", "e1ap.PDU_Session_To_Notify_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDUSetbasedHandlingIndicator_PDU,
      { "PDUSetbasedHandlingIndicator", "e1ap.PDUSetbasedHandlingIndicator",
        FT_UINT32, BASE_DEC, VALS(e1ap_PDUSetbasedHandlingIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_PLMN_Identity_PDU,
      { "PLMN-Identity", "e1ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PPI_PDU,
      { "PPI", "e1ap.PPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PrivacyIndicator_PDU,
      { "PrivacyIndicator", "e1ap.PrivacyIndicator",
        FT_UINT32, BASE_DEC, VALS(e1ap_PrivacyIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_PDUSetQoSParameters_PDU,
      { "PDUSetQoSParameters", "e1ap.PDUSetQoSParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_QoS_Flow_List_PDU,
      { "QoS-Flow-List", "e1ap.QoS_Flow_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_QoS_Flow_Mapping_Indication_PDU,
      { "QoS-Flow-Mapping-Indication", "e1ap.QoS_Flow_Mapping_Indication",
        FT_UINT32, BASE_DEC, VALS(e1ap_QoS_Flow_Mapping_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_QoS_Flows_DRB_Remapping_PDU,
      { "QoS-Flows-DRB-Remapping", "e1ap.QoS_Flows_DRB_Remapping",
        FT_UINT32, BASE_DEC, VALS(e1ap_QoS_Flows_DRB_Remapping_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_QoSFlowLevelQoSParameters_PDU,
      { "QoSFlowLevelQoSParameters", "e1ap.QoSFlowLevelQoSParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_QosMonitoringRequest_PDU,
      { "QosMonitoringRequest", "e1ap.QosMonitoringRequest",
        FT_UINT32, BASE_DEC, VALS(e1ap_QosMonitoringRequest_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_QosMonitoringReportingFrequency_PDU,
      { "QosMonitoringReportingFrequency", "e1ap.QosMonitoringReportingFrequency",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_e1ap_QosMonitoringDisabled_PDU,
      { "QosMonitoringDisabled", "e1ap.QosMonitoringDisabled",
        FT_UINT32, BASE_DEC, VALS(e1ap_QosMonitoringDisabled_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_QoS_Mapping_Information_PDU,
      { "QoS-Mapping-Information", "e1ap.QoS_Mapping_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DataForwardingtoNG_RANQoSFlowInformationList_PDU,
      { "DataForwardingtoNG-RANQoSFlowInformationList", "e1ap.DataForwardingtoNG_RANQoSFlowInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_RANUEID_PDU,
      { "RANUEID", "e1ap.RANUEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_RedundantQoSFlowIndicator_PDU,
      { "RedundantQoSFlowIndicator", "e1ap.RedundantQoSFlowIndicator",
        FT_UINT32, BASE_DEC, VALS(e1ap_RedundantQoSFlowIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_RedundantPDUSessionInformation_PDU,
      { "RedundantPDUSessionInformation", "e1ap.RedundantPDUSessionInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_RetainabilityMeasurementsInfo_PDU,
      { "RetainabilityMeasurementsInfo", "e1ap.RetainabilityMeasurementsInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_RegistrationRequest_PDU,
      { "RegistrationRequest", "e1ap.RegistrationRequest",
        FT_UINT32, BASE_DEC, VALS(e1ap_RegistrationRequest_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_ReportCharacteristics_PDU,
      { "ReportCharacteristics", "e1ap.ReportCharacteristics",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ReportingPeriodicity_PDU,
      { "ReportingPeriodicity", "e1ap.ReportingPeriodicity",
        FT_UINT32, BASE_DEC, VALS(e1ap_ReportingPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_SDT_data_size_threshold_PDU,
      { "SDT-data-size-threshold", "e1ap.SDT_data_size_threshold",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0,
        NULL, HFILL }},
    { &hf_e1ap_SDT_data_size_threshold_Crossed_PDU,
      { "SDT-data-size-threshold-Crossed", "e1ap.SDT_data_size_threshold_Crossed",
        FT_UINT32, BASE_DEC, VALS(e1ap_SDT_data_size_threshold_Crossed_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_SCGActivationStatus_PDU,
      { "SCGActivationStatus", "e1ap.SCGActivationStatus",
        FT_UINT32, BASE_DEC, VALS(e1ap_SCGActivationStatus_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_SecurityIndication_PDU,
      { "SecurityIndication", "e1ap.SecurityIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_SecurityInformation_PDU,
      { "SecurityInformation", "e1ap.SecurityInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_SecurityResult_PDU,
      { "SecurityResult", "e1ap.SecurityResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_SNSSAI_PDU,
      { "SNSSAI", "e1ap.SNSSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_SDTContinueROHC_PDU,
      { "SDTContinueROHC", "e1ap.SDTContinueROHC",
        FT_UINT32, BASE_DEC, VALS(e1ap_SDTContinueROHC_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_SDTindicatorSetup_PDU,
      { "SDTindicatorSetup", "e1ap.SDTindicatorSetup",
        FT_UINT32, BASE_DEC, VALS(e1ap_SDTindicatorSetup_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_SDTindicatorMod_PDU,
      { "SDTindicatorMod", "e1ap.SDTindicatorMod",
        FT_UINT32, BASE_DEC, VALS(e1ap_SDTindicatorMod_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_SubscriberProfileIDforRFP_PDU,
      { "SubscriberProfileIDforRFP", "e1ap.SubscriberProfileIDforRFP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_SurvivalTime_PDU,
      { "SurvivalTime", "e1ap.SurvivalTime",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0,
        NULL, HFILL }},
    { &hf_e1ap_SpecialTriggeringPurpose_PDU,
      { "SpecialTriggeringPurpose", "e1ap.SpecialTriggeringPurpose",
        FT_UINT32, BASE_DEC, VALS(e1ap_SpecialTriggeringPurpose_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_F1UTunnelNotEstablished_PDU,
      { "F1UTunnelNotEstablished", "e1ap.F1UTunnelNotEstablished",
        FT_UINT32, BASE_DEC, VALS(e1ap_F1UTunnelNotEstablished_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_TimeToWait_PDU,
      { "TimeToWait", "e1ap.TimeToWait",
        FT_UINT32, BASE_DEC, VALS(e1ap_TimeToWait_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_TNL_AvailableCapacityIndicator_PDU,
      { "TNL-AvailableCapacityIndicator", "e1ap.TNL_AvailableCapacityIndicator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_TSCTrafficCharacteristics_PDU,
      { "TSCTrafficCharacteristics", "e1ap.TSCTrafficCharacteristics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_TraceActivation_PDU,
      { "TraceActivation", "e1ap.TraceActivation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_TraceID_PDU,
      { "TraceID", "e1ap.TraceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_TransportLayerAddress_PDU,
      { "TransportLayerAddress", "e1ap.TransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_TransactionID_PDU,
      { "TransactionID", "e1ap.TransactionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_Transport_Layer_Address_Info_PDU,
      { "Transport-Layer-Address-Info", "e1ap.Transport_Layer_Address_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_UDC_Parameters_PDU,
      { "UDC-Parameters", "e1ap.UDC_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_VersionID_PDU,
      { "VersionID", "e1ap.VersionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_UE_associatedLogicalE1_ConnectionItem_PDU,
      { "UE-associatedLogicalE1-ConnectionItem", "e1ap.UE_associatedLogicalE1_ConnectionItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_UESliceMaximumBitRateList_PDU,
      { "UESliceMaximumBitRateList", "e1ap.UESliceMaximumBitRateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_UP_TNL_Information_PDU,
      { "UP-TNL-Information", "e1ap.UP_TNL_Information",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_URIaddress_PDU,
      { "URIaddress", "e1ap.URIaddress",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_UserPlaneErrorIndicator_PDU,
      { "UserPlaneErrorIndicator", "e1ap.UserPlaneErrorIndicator",
        FT_UINT32, BASE_DEC, VALS(e1ap_UserPlaneErrorIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_UEInactivityInformation_PDU,
      { "UEInactivityInformation", "e1ap.UEInactivityInformation",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_e1ap_UserPlaneFailureIndication_PDU,
      { "UserPlaneFailureIndication", "e1ap.UserPlaneFailureIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_Reset_PDU,
      { "Reset", "e1ap.Reset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ResetType_PDU,
      { "ResetType", "e1ap.ResetType",
        FT_UINT32, BASE_DEC, VALS(e1ap_ResetType_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_ResetAcknowledge_PDU,
      { "ResetAcknowledge", "e1ap.ResetAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_UE_associatedLogicalE1_ConnectionListResAck_PDU,
      { "UE-associatedLogicalE1-ConnectionListResAck", "e1ap.UE_associatedLogicalE1_ConnectionListResAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ErrorIndication_PDU,
      { "ErrorIndication", "e1ap.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_E1SetupRequest_PDU,
      { "GNB-CU-UP-E1SetupRequest", "e1ap.GNB_CU_UP_E1SetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_SupportedPLMNs_List_PDU,
      { "SupportedPLMNs-List", "e1ap.SupportedPLMNs_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_E1SetupResponse_PDU,
      { "GNB-CU-UP-E1SetupResponse", "e1ap.GNB_CU_UP_E1SetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_E1SetupFailure_PDU,
      { "GNB-CU-UP-E1SetupFailure", "e1ap.GNB_CU_UP_E1SetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_E1SetupRequest_PDU,
      { "GNB-CU-CP-E1SetupRequest", "e1ap.GNB_CU_CP_E1SetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_E1SetupResponse_PDU,
      { "GNB-CU-CP-E1SetupResponse", "e1ap.GNB_CU_CP_E1SetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_E1SetupFailure_PDU,
      { "GNB-CU-CP-E1SetupFailure", "e1ap.GNB_CU_CP_E1SetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_ConfigurationUpdate_PDU,
      { "GNB-CU-UP-ConfigurationUpdate", "e1ap.GNB_CU_UP_ConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_TNLA_To_Remove_List_PDU,
      { "GNB-CU-UP-TNLA-To-Remove-List", "e1ap.GNB_CU_UP_TNLA_To_Remove_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_ConfigurationUpdateAcknowledge_PDU,
      { "GNB-CU-UP-ConfigurationUpdateAcknowledge", "e1ap.GNB_CU_UP_ConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_ConfigurationUpdateFailure_PDU,
      { "GNB-CU-UP-ConfigurationUpdateFailure", "e1ap.GNB_CU_UP_ConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_ConfigurationUpdate_PDU,
      { "GNB-CU-CP-ConfigurationUpdate", "e1ap.GNB_CU_CP_ConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_TNLA_To_Add_List_PDU,
      { "GNB-CU-CP-TNLA-To-Add-List", "e1ap.GNB_CU_CP_TNLA_To_Add_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_TNLA_To_Remove_List_PDU,
      { "GNB-CU-CP-TNLA-To-Remove-List", "e1ap.GNB_CU_CP_TNLA_To_Remove_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_TNLA_To_Update_List_PDU,
      { "GNB-CU-CP-TNLA-To-Update-List", "e1ap.GNB_CU_CP_TNLA_To_Update_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_ConfigurationUpdateAcknowledge_PDU,
      { "GNB-CU-CP-ConfigurationUpdateAcknowledge", "e1ap.GNB_CU_CP_ConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_TNLA_Setup_List_PDU,
      { "GNB-CU-CP-TNLA-Setup-List", "e1ap.GNB_CU_CP_TNLA_Setup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List_PDU,
      { "GNB-CU-CP-TNLA-Failed-To-Setup-List", "e1ap.GNB_CU_CP_TNLA_Failed_To_Setup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_ConfigurationUpdateFailure_PDU,
      { "GNB-CU-CP-ConfigurationUpdateFailure", "e1ap.GNB_CU_CP_ConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_E1ReleaseRequest_PDU,
      { "E1ReleaseRequest", "e1ap.E1ReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_E1ReleaseResponse_PDU,
      { "E1ReleaseResponse", "e1ap.E1ReleaseResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BearerContextSetupRequest_PDU,
      { "BearerContextSetupRequest", "e1ap.BearerContextSetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_System_BearerContextSetupRequest_PDU,
      { "System-BearerContextSetupRequest", "e1ap.System_BearerContextSetupRequest",
        FT_UINT32, BASE_DEC, VALS(e1ap_System_BearerContextSetupRequest_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_BearerContextSetupResponse_PDU,
      { "BearerContextSetupResponse", "e1ap.BearerContextSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_System_BearerContextSetupResponse_PDU,
      { "System-BearerContextSetupResponse", "e1ap.System_BearerContextSetupResponse",
        FT_UINT32, BASE_DEC, VALS(e1ap_System_BearerContextSetupResponse_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_BearerContextSetupFailure_PDU,
      { "BearerContextSetupFailure", "e1ap.BearerContextSetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BearerContextModificationRequest_PDU,
      { "BearerContextModificationRequest", "e1ap.BearerContextModificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_System_BearerContextModificationRequest_PDU,
      { "System-BearerContextModificationRequest", "e1ap.System_BearerContextModificationRequest",
        FT_UINT32, BASE_DEC, VALS(e1ap_System_BearerContextModificationRequest_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_BearerContextModificationResponse_PDU,
      { "BearerContextModificationResponse", "e1ap.BearerContextModificationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_System_BearerContextModificationResponse_PDU,
      { "System-BearerContextModificationResponse", "e1ap.System_BearerContextModificationResponse",
        FT_UINT32, BASE_DEC, VALS(e1ap_System_BearerContextModificationResponse_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_BearerContextModificationFailure_PDU,
      { "BearerContextModificationFailure", "e1ap.BearerContextModificationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BearerContextModificationRequired_PDU,
      { "BearerContextModificationRequired", "e1ap.BearerContextModificationRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_System_BearerContextModificationRequired_PDU,
      { "System-BearerContextModificationRequired", "e1ap.System_BearerContextModificationRequired",
        FT_UINT32, BASE_DEC, VALS(e1ap_System_BearerContextModificationRequired_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_BearerContextModificationConfirm_PDU,
      { "BearerContextModificationConfirm", "e1ap.BearerContextModificationConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_System_BearerContextModificationConfirm_PDU,
      { "System-BearerContextModificationConfirm", "e1ap.System_BearerContextModificationConfirm",
        FT_UINT32, BASE_DEC, VALS(e1ap_System_BearerContextModificationConfirm_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_BearerContextReleaseCommand_PDU,
      { "BearerContextReleaseCommand", "e1ap.BearerContextReleaseCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BearerContextReleaseComplete_PDU,
      { "BearerContextReleaseComplete", "e1ap.BearerContextReleaseComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BearerContextReleaseRequest_PDU,
      { "BearerContextReleaseRequest", "e1ap.BearerContextReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Status_List_PDU,
      { "DRB-Status-List", "e1ap.DRB_Status_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BearerContextInactivityNotification_PDU,
      { "BearerContextInactivityNotification", "e1ap.BearerContextInactivityNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DLDataNotification_PDU,
      { "DLDataNotification", "e1ap.DLDataNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ULDataNotification_PDU,
      { "ULDataNotification", "e1ap.ULDataNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DataUsageReport_PDU,
      { "DataUsageReport", "e1ap.DataUsageReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_CounterCheckRequest_PDU,
      { "GNB-CU-UP-CounterCheckRequest", "e1ap.GNB_CU_UP_CounterCheckRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_System_GNB_CU_UP_CounterCheckRequest_PDU,
      { "System-GNB-CU-UP-CounterCheckRequest", "e1ap.System_GNB_CU_UP_CounterCheckRequest",
        FT_UINT32, BASE_DEC, VALS(e1ap_System_GNB_CU_UP_CounterCheckRequest_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_StatusIndication_PDU,
      { "GNB-CU-UP-StatusIndication", "e1ap.GNB_CU_UP_StatusIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CPMeasurementResultsInformation_PDU,
      { "GNB-CU-CPMeasurementResultsInformation", "e1ap.GNB_CU_CPMeasurementResultsInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MRDC_DataUsageReport_PDU,
      { "MRDC-DataUsageReport", "e1ap.MRDC_DataUsageReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_TraceStart_PDU,
      { "TraceStart", "e1ap.TraceStart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DeactivateTrace_PDU,
      { "DeactivateTrace", "e1ap.DeactivateTrace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_CellTrafficTrace_PDU,
      { "CellTrafficTrace", "e1ap.CellTrafficTrace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PrivateMessage_PDU,
      { "PrivateMessage", "e1ap.PrivateMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ResourceStatusRequest_PDU,
      { "ResourceStatusRequest", "e1ap.ResourceStatusRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_Measurement_ID_PDU,
      { "Measurement-ID", "e1ap.Measurement_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ResourceStatusResponse_PDU,
      { "ResourceStatusResponse", "e1ap.ResourceStatusResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ResourceStatusFailure_PDU,
      { "ResourceStatusFailure", "e1ap.ResourceStatusFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ResourceStatusUpdate_PDU,
      { "ResourceStatusUpdate", "e1ap.ResourceStatusUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_IAB_UPTNLAddressUpdate_PDU,
      { "IAB-UPTNLAddressUpdate", "e1ap.IAB_UPTNLAddressUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DLUPTNLAddressToUpdateList_PDU,
      { "DLUPTNLAddressToUpdateList", "e1ap.DLUPTNLAddressToUpdateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_IAB_UPTNLAddressUpdateAcknowledge_PDU,
      { "IAB-UPTNLAddressUpdateAcknowledge", "e1ap.IAB_UPTNLAddressUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ULUPTNLAddressToUpdateList_PDU,
      { "ULUPTNLAddressToUpdateList", "e1ap.ULUPTNLAddressToUpdateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_IAB_UPTNLAddressUpdateFailure_PDU,
      { "IAB-UPTNLAddressUpdateFailure", "e1ap.IAB_UPTNLAddressUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_EarlyForwardingSNTransfer_PDU,
      { "EarlyForwardingSNTransfer", "e1ap.EarlyForwardingSNTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_IABPSKNotification_PDU,
      { "IABPSKNotification", "e1ap.IABPSKNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_IAB_Donor_CU_UPPSKInfo_PDU,
      { "IAB-Donor-CU-UPPSKInfo", "e1ap.IAB_Donor_CU_UPPSKInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextSetupRequest_PDU,
      { "BCBearerContextSetupRequest", "e1ap.BCBearerContextSetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextSetupResponse_PDU,
      { "BCBearerContextSetupResponse", "e1ap.BCBearerContextSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextSetupFailure_PDU,
      { "BCBearerContextSetupFailure", "e1ap.BCBearerContextSetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextModificationRequest_PDU,
      { "BCBearerContextModificationRequest", "e1ap.BCBearerContextModificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextModificationResponse_PDU,
      { "BCBearerContextModificationResponse", "e1ap.BCBearerContextModificationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextModificationFailure_PDU,
      { "BCBearerContextModificationFailure", "e1ap.BCBearerContextModificationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextModificationRequired_PDU,
      { "BCBearerContextModificationRequired", "e1ap.BCBearerContextModificationRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextModificationConfirm_PDU,
      { "BCBearerContextModificationConfirm", "e1ap.BCBearerContextModificationConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextReleaseCommand_PDU,
      { "BCBearerContextReleaseCommand", "e1ap.BCBearerContextReleaseCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextReleaseComplete_PDU,
      { "BCBearerContextReleaseComplete", "e1ap.BCBearerContextReleaseComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCBearerContextReleaseRequest_PDU,
      { "BCBearerContextReleaseRequest", "e1ap.BCBearerContextReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextSetupRequest_PDU,
      { "MCBearerContextSetupRequest", "e1ap.MCBearerContextSetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextSetupResponse_PDU,
      { "MCBearerContextSetupResponse", "e1ap.MCBearerContextSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextSetupFailure_PDU,
      { "MCBearerContextSetupFailure", "e1ap.MCBearerContextSetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextModificationRequest_PDU,
      { "MCBearerContextModificationRequest", "e1ap.MCBearerContextModificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextModificationResponse_PDU,
      { "MCBearerContextModificationResponse", "e1ap.MCBearerContextModificationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextModificationFailure_PDU,
      { "MCBearerContextModificationFailure", "e1ap.MCBearerContextModificationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextModificationRequired_PDU,
      { "MCBearerContextModificationRequired", "e1ap.MCBearerContextModificationRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextModificationConfirm_PDU,
      { "MCBearerContextModificationConfirm", "e1ap.MCBearerContextModificationConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextReleaseCommand_PDU,
      { "MCBearerContextReleaseCommand", "e1ap.MCBearerContextReleaseCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextReleaseComplete_PDU,
      { "MCBearerContextReleaseComplete", "e1ap.MCBearerContextReleaseComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerContextReleaseRequest_PDU,
      { "MCBearerContextReleaseRequest", "e1ap.MCBearerContextReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCBearerNotification_PDU,
      { "MCBearerNotification", "e1ap.MCBearerNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_E1AP_PDU_PDU,
      { "E1AP-PDU", "e1ap.E1AP_PDU",
        FT_UINT32, BASE_DEC, VALS(e1ap_E1AP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_local,
      { "local", "e1ap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxPrivateIEs", HFILL }},
    { &hf_e1ap_global,
      { "global", "e1ap.global",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "e1ap.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_id,
      { "id", "e1ap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &e1ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_e1ap_criticality,
      { "criticality", "e1ap.criticality",
        FT_UINT32, BASE_DEC, VALS(e1ap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_ie_field_value,
      { "value", "e1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_e1ap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "e1ap.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ext_id,
      { "id", "e1ap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &e1ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_e1ap_extensionValue,
      { "extensionValue", "e1ap.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PrivateIE_Container_item,
      { "PrivateIE-Field", "e1ap.PrivateIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_private_id,
      { "id", "e1ap.id",
        FT_UINT32, BASE_DEC, VALS(e1ap_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_e1ap_value,
      { "value", "e1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_Activity_List,
      { "dRB-Activity-List", "e1ap.dRB_Activity_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pDU_Session_Resource_Activity_List,
      { "pDU-Session-Resource-Activity-List", "e1ap.pDU_Session_Resource_Activity_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_uE_Activity,
      { "uE-Activity", "e1ap.uE_Activity",
        FT_UINT32, BASE_DEC, VALS(e1ap_UE_Activity_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_choice_extension,
      { "choice-extension", "e1ap.choice_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_SingleContainer", HFILL }},
    { &hf_e1ap_AlternativeQoSParaSetList_item,
      { "AlternativeQoSParaSetItem", "e1ap.AlternativeQoSParaSetItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_alternativeQoSParameterIndex,
      { "alternativeQoSParameterIndex", "e1ap.alternativeQoSParameterIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8_", HFILL }},
    { &hf_e1ap_guaranteedFlowBitRateDL,
      { "guaranteedFlowBitRateDL", "e1ap.guaranteedFlowBitRateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_e1ap_guaranteedFlowBitRateUL,
      { "guaranteedFlowBitRateUL", "e1ap.guaranteedFlowBitRateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_e1ap_packetDelayBudget,
      { "packetDelayBudget", "e1ap.packetDelayBudget",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(e1ap_PacketDelayBudget_uL_D1_Result_fmt), 0,
        NULL, HFILL }},
    { &hf_e1ap_packetErrorRate,
      { "packetErrorRate", "e1ap.packetErrorRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_iE_Extensions,
      { "iE-Extensions", "e1ap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_e1ap_snssai,
      { "snssai", "e1ap.snssai_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_bcBearerContextNGU_TNLInfoat5GC,
      { "bcBearerContextNGU-TNLInfoat5GC", "e1ap.bcBearerContextNGU_TNLInfoat5GC",
        FT_UINT32, BASE_DEC, VALS(e1ap_BCBearerContextNGU_TNLInfoat5GC_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_bcMRBToSetupList,
      { "bcMRBToSetupList", "e1ap.bcMRBToSetupList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BCMRBSetupConfiguration", HFILL }},
    { &hf_e1ap_requestedAction,
      { "requestedAction", "e1ap.requestedAction",
        FT_UINT32, BASE_DEC, VALS(e1ap_RequestedAction4AvailNGUTermination_vals), 0,
        "RequestedAction4AvailNGUTermination", HFILL }},
    { &hf_e1ap_locationindependent,
      { "locationindependent", "e1ap.locationindependent",
        FT_UINT32, BASE_DEC, VALS(e1ap_MBSNGUInformationAt5GC_vals), 0,
        "MBSNGUInformationAt5GC", HFILL }},
    { &hf_e1ap_locationdependent,
      { "locationdependent", "e1ap.locationdependent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocationDependentMBSNGUInformationAt5GC", HFILL }},
    { &hf_e1ap_BCMRBSetupConfiguration_item,
      { "BCMRBSetupConfiguration-Item", "e1ap.BCMRBSetupConfiguration_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mrb_ID,
      { "mrb-ID", "e1ap.mrb_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mbs_pdcp_config,
      { "mbs-pdcp-config", "e1ap.mbs_pdcp_config_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDCP_Configuration", HFILL }},
    { &hf_e1ap_qoS_Flow_QoS_Parameter_List,
      { "qoS-Flow-QoS-Parameter-List", "e1ap.qoS_Flow_QoS_Parameter_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_qoSFlowLevelQoSParameters,
      { "qoSFlowLevelQoSParameters", "e1ap.qoSFlowLevelQoSParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_bcBearerContextNGU_TNLInfoatNGRAN,
      { "bcBearerContextNGU-TNLInfoatNGRAN", "e1ap.bcBearerContextNGU_TNLInfoatNGRAN",
        FT_UINT32, BASE_DEC, VALS(e1ap_BCBearerContextNGU_TNLInfoatNGRAN_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_bcMRBSetupResponseList,
      { "bcMRBSetupResponseList", "e1ap.bcMRBSetupResponseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_bcMRBFailedList,
      { "bcMRBFailedList", "e1ap.bcMRBFailedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_availableBCMRBConfig,
      { "availableBCMRBConfig", "e1ap.availableBCMRBConfig",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BCMRBSetupConfiguration", HFILL }},
    { &hf_e1ap_locationindependent_01,
      { "locationindependent", "e1ap.locationindependent",
        FT_UINT32, BASE_DEC, VALS(e1ap_MBSNGUInformationAtNGRAN_vals), 0,
        "MBSNGUInformationAtNGRAN", HFILL }},
    { &hf_e1ap_locationdependent_01,
      { "locationdependent", "e1ap.locationdependent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocationDependentMBSNGUInformationAtNGRAN", HFILL }},
    { &hf_e1ap_BCMRBSetupResponseList_item,
      { "BCMRBSetupResponseList-Item", "e1ap.BCMRBSetupResponseList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_qosflow_setup,
      { "qosflow-setup", "e1ap.qosflow_setup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoS_Flow_List", HFILL }},
    { &hf_e1ap_qosflow_failed,
      { "qosflow-failed", "e1ap.qosflow_failed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoS_Flow_Failed_List", HFILL }},
    { &hf_e1ap_bcBearerContextF1U_TNLInfoatCU,
      { "bcBearerContextF1U-TNLInfoatCU", "e1ap.bcBearerContextF1U_TNLInfoatCU",
        FT_UINT32, BASE_DEC, VALS(e1ap_BCBearerContextF1U_TNLInfoatCU_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_locationindependent_02,
      { "locationindependent", "e1ap.locationindependent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MBSF1UInformationAtCU", HFILL }},
    { &hf_e1ap_locationdependent_02,
      { "locationdependent", "e1ap.locationdependent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocationDependentMBSF1UInformationAtCU", HFILL }},
    { &hf_e1ap_BCMRBFailedList_item,
      { "BCMRBFailedList-Item", "e1ap.BCMRBFailedList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_cause,
      { "cause", "e1ap.cause",
        FT_UINT32, BASE_DEC, VALS(e1ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_bcMRBToModifyList,
      { "bcMRBToModifyList", "e1ap.bcMRBToModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BCMRBModifyConfiguration", HFILL }},
    { &hf_e1ap_bcMRBToRemoveList,
      { "bcMRBToRemoveList", "e1ap.bcMRBToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BCMRBRemoveConfiguration", HFILL }},
    { &hf_e1ap_locationindependent_03,
      { "locationindependent", "e1ap.locationindependent",
        FT_UINT32, BASE_DEC, VALS(e1ap_MBSNGUInformationAtNGRAN_Request_vals), 0,
        "MBSNGUInformationAtNGRAN_Request", HFILL }},
    { &hf_e1ap_locationdependent_03,
      { "locationdependent", "e1ap.locationdependent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MBSNGUInformationAtNGRAN_Request_List", HFILL }},
    { &hf_e1ap_BCMRBModifyConfiguration_item,
      { "BCMRBModifyConfiguration-Item", "e1ap.BCMRBModifyConfiguration_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_bcBearerContextF1U_TNLInfoatDU,
      { "bcBearerContextF1U-TNLInfoatDU", "e1ap.bcBearerContextF1U_TNLInfoatDU",
        FT_UINT32, BASE_DEC, VALS(e1ap_BCBearerContextF1U_TNLInfoatDU_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_locationindependent_04,
      { "locationindependent", "e1ap.locationindependent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MBSF1UInformationAtDU", HFILL }},
    { &hf_e1ap_locationdependent_04,
      { "locationdependent", "e1ap.locationdependent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocationDependentMBSF1UInformationAtDU", HFILL }},
    { &hf_e1ap_BCMRBRemoveConfiguration_item,
      { "MRB-ID", "e1ap.MRB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_bcMRBSetupModifyResponseList,
      { "bcMRBSetupModifyResponseList", "e1ap.bcMRBSetupModifyResponseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_BCMRBSetupModifyResponseList_item,
      { "BCMRBSetupModifyResponseList-Item", "e1ap.BCMRBSetupModifyResponseList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_radioNetwork,
      { "radioNetwork", "e1ap.radioNetwork",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &e1ap_CauseRadioNetwork_vals_ext, 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_e1ap_transport,
      { "transport", "e1ap.transport",
        FT_UINT32, BASE_DEC, VALS(e1ap_CauseTransport_vals), 0,
        "CauseTransport", HFILL }},
    { &hf_e1ap_protocol,
      { "protocol", "e1ap.protocol",
        FT_UINT32, BASE_DEC, VALS(e1ap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_e1ap_misc,
      { "misc", "e1ap.misc",
        FT_UINT32, BASE_DEC, VALS(e1ap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_e1ap_Cell_Group_Information_item,
      { "Cell-Group-Information-Item", "e1ap.Cell_Group_Information_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_cell_Group_ID,
      { "cell-Group-ID", "e1ap.cell_Group_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_uL_Configuration,
      { "uL-Configuration", "e1ap.uL_Configuration",
        FT_UINT32, BASE_DEC, VALS(e1ap_UL_Configuration_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_dL_TX_Stop,
      { "dL-TX-Stop", "e1ap.dL_TX_Stop",
        FT_UINT32, BASE_DEC, VALS(e1ap_DL_TX_Stop_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_rAT_Type,
      { "rAT-Type", "e1ap.rAT_Type",
        FT_UINT32, BASE_DEC, VALS(e1ap_RAT_Type_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_endpoint_IP_Address,
      { "endpoint-IP-Address", "e1ap.endpoint_IP_Address",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_e1ap_procedureCode,
      { "procedureCode", "e1ap.procedureCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &e1ap_ProcedureCode_vals_ext, 0,
        NULL, HFILL }},
    { &hf_e1ap_triggeringMessage,
      { "triggeringMessage", "e1ap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(e1ap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_procedureCriticality,
      { "procedureCriticality", "e1ap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(e1ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_e1ap_transactionID,
      { "transactionID", "e1ap.transactionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "e1ap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_e1ap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "e1ap.CriticalityDiagnostics_IE_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_iECriticality,
      { "iECriticality", "e1ap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(e1ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_e1ap_iE_ID,
      { "iE-ID", "e1ap.iE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &e1ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_e1ap_typeOfError,
      { "typeOfError", "e1ap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(e1ap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_dapsIndicator,
      { "dapsIndicator", "e1ap.dapsIndicator",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_dapsIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_data_Forwarding_Request,
      { "data-Forwarding-Request", "e1ap.data_Forwarding_Request",
        FT_UINT32, BASE_DEC, VALS(e1ap_Data_Forwarding_Request_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_qoS_Flows_Forwarded_On_Fwd_Tunnels,
      { "qoS-Flows-Forwarded-On-Fwd-Tunnels", "e1ap.qoS_Flows_Forwarded_On_Fwd_Tunnels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoS_Flow_Mapping_List", HFILL }},
    { &hf_e1ap_uL_Data_Forwarding,
      { "uL-Data-Forwarding", "e1ap.uL_Data_Forwarding",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_dL_Data_Forwarding,
      { "dL-Data-Forwarding", "e1ap.dL_Data_Forwarding",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_DataForwardingtoE_UTRANInformationList_item,
      { "DataForwardingtoE-UTRANInformationListItem", "e1ap.DataForwardingtoE_UTRANInformationListItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_data_forwarding_tunnel_information,
      { "data-forwarding-tunnel-information", "e1ap.data_forwarding_tunnel_information",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_qoS_Flows_to_be_forwarded_List,
      { "qoS-Flows-to-be-forwarded-List", "e1ap.qoS_Flows_to_be_forwarded_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_secondaryRATType,
      { "secondaryRATType", "e1ap.secondaryRATType",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_secondaryRATType_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_pDU_session_Timed_Report_List,
      { "pDU-session-Timed-Report-List", "e1ap.pDU_session_Timed_Report_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item", HFILL }},
    { &hf_e1ap_pDU_session_Timed_Report_List_item,
      { "MRDC-Data-Usage-Report-Item", "e1ap.MRDC_Data_Usage_Report_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_Data_Usage_per_QoS_Flow_List_item,
      { "Data-Usage-per-QoS-Flow-Item", "e1ap.Data_Usage_per_QoS_Flow_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_qoS_Flow_Identifier,
      { "qoS-Flow-Identifier", "e1ap.qoS_Flow_Identifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_secondaryRATType_01,
      { "secondaryRATType", "e1ap.secondaryRATType",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_secondaryRATType_01_vals), 0,
        "T_secondaryRATType_01", HFILL }},
    { &hf_e1ap_qoS_Flow_Timed_Report_List,
      { "qoS-Flow-Timed-Report-List", "e1ap.qoS_Flow_Timed_Report_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item", HFILL }},
    { &hf_e1ap_qoS_Flow_Timed_Report_List_item,
      { "MRDC-Data-Usage-Report-Item", "e1ap.MRDC_Data_Usage_Report_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_Data_Usage_Report_List_item,
      { "Data-Usage-Report-Item", "e1ap.Data_Usage_Report_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_ID,
      { "dRB-ID", "e1ap.dRB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_Usage_Report_List,
      { "dRB-Usage-Report-List", "e1ap.dRB_Usage_Report_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dLDiscardingCountVal,
      { "dLDiscardingCountVal", "e1ap.dLDiscardingCountVal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDCP_Count", HFILL }},
    { &hf_e1ap_oldTNLAdress,
      { "oldTNLAdress", "e1ap.oldTNLAdress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_e1ap_newTNLAdress,
      { "newTNLAdress", "e1ap.newTNLAdress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_e1ap_DRB_Activity_List_item,
      { "DRB-Activity-Item", "e1ap.DRB_Activity_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_Activity,
      { "dRB-Activity", "e1ap.dRB_Activity",
        FT_UINT32, BASE_DEC, VALS(e1ap_DRB_Activity_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Confirm_Modified_List_EUTRAN_item,
      { "DRB-Confirm-Modified-Item-EUTRAN", "e1ap.DRB_Confirm_Modified_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_cell_Group_Information,
      { "cell-Group-Information", "e1ap.cell_Group_Information",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Confirm_Modified_List_NG_RAN_item,
      { "DRB-Confirm-Modified-Item-NG-RAN", "e1ap.DRB_Confirm_Modified_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Failed_List_EUTRAN_item,
      { "DRB-Failed-Item-EUTRAN", "e1ap.DRB_Failed_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Failed_Mod_List_EUTRAN_item,
      { "DRB-Failed-Mod-Item-EUTRAN", "e1ap.DRB_Failed_Mod_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Failed_List_NG_RAN_item,
      { "DRB-Failed-Item-NG-RAN", "e1ap.DRB_Failed_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Failed_Mod_List_NG_RAN_item,
      { "DRB-Failed-Mod-Item-NG-RAN", "e1ap.DRB_Failed_Mod_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Failed_To_Modify_List_EUTRAN_item,
      { "DRB-Failed-To-Modify-Item-EUTRAN", "e1ap.DRB_Failed_To_Modify_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Failed_To_Modify_List_NG_RAN_item,
      { "DRB-Failed-To-Modify-Item-NG-RAN", "e1ap.DRB_Failed_To_Modify_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Measurement_Results_Information_List_item,
      { "DRB-Measurement-Results-Information-Item", "e1ap.DRB_Measurement_Results_Information_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_uL_D1_Result,
      { "uL-D1-Result", "e1ap.uL_D1_Result",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(e1ap_PacketDelayBudget_uL_D1_Result_fmt), 0,
        "INTEGER_0_10000_", HFILL }},
    { &hf_e1ap_DRB_Modified_List_EUTRAN_item,
      { "DRB-Modified-Item-EUTRAN", "e1ap.DRB_Modified_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_s1_DL_UP_TNL_Information,
      { "s1-DL-UP-TNL-Information", "e1ap.s1_DL_UP_TNL_Information",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_pDCP_SN_Status_Information,
      { "pDCP-SN-Status-Information", "e1ap.pDCP_SN_Status_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_uL_UP_Transport_Parameters,
      { "uL-UP-Transport-Parameters", "e1ap.uL_UP_Transport_Parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UP_Parameters", HFILL }},
    { &hf_e1ap_DRB_Modified_List_NG_RAN_item,
      { "DRB-Modified-Item-NG-RAN", "e1ap.DRB_Modified_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_flow_Setup_List,
      { "flow-Setup-List", "e1ap.flow_Setup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoS_Flow_List", HFILL }},
    { &hf_e1ap_flow_Failed_List,
      { "flow-Failed-List", "e1ap.flow_Failed_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoS_Flow_Failed_List", HFILL }},
    { &hf_e1ap_dRB_Released_In_Session,
      { "dRB-Released-In-Session", "e1ap.dRB_Released_In_Session",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_dRB_Released_In_Session_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_Accumulated_Session_Time,
      { "dRB-Accumulated-Session-Time", "e1ap.dRB_Accumulated_Session_Time",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_5", HFILL }},
    { &hf_e1ap_qoS_Flow_Removed_List,
      { "qoS-Flow-Removed-List", "e1ap.qoS_Flow_Removed_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_QoS_Flow_Removed_Item", HFILL }},
    { &hf_e1ap_qoS_Flow_Removed_List_item,
      { "QoS-Flow-Removed-Item", "e1ap.QoS_Flow_Removed_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Required_To_Modify_List_EUTRAN_item,
      { "DRB-Required-To-Modify-Item-EUTRAN", "e1ap.DRB_Required_To_Modify_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_gNB_CU_UP_CellGroupRelatedConfiguration,
      { "gNB-CU-UP-CellGroupRelatedConfiguration", "e1ap.gNB_CU_UP_CellGroupRelatedConfiguration",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Required_To_Modify_List_NG_RAN_item,
      { "DRB-Required-To-Modify-Item-NG-RAN", "e1ap.DRB_Required_To_Modify_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_flow_To_Remove,
      { "flow-To-Remove", "e1ap.flow_To_Remove",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoS_Flow_List", HFILL }},
    { &hf_e1ap_DRB_Setup_List_EUTRAN_item,
      { "DRB-Setup-Item-EUTRAN", "e1ap.DRB_Setup_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_data_Forwarding_Information_Response,
      { "data-Forwarding-Information-Response", "e1ap.data_Forwarding_Information_Response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Data_Forwarding_Information", HFILL }},
    { &hf_e1ap_s1_DL_UP_Unchanged,
      { "s1-DL-UP-Unchanged", "e1ap.s1_DL_UP_Unchanged",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_s1_DL_UP_Unchanged_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Setup_Mod_List_EUTRAN_item,
      { "DRB-Setup-Mod-Item-EUTRAN", "e1ap.DRB_Setup_Mod_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Setup_List_NG_RAN_item,
      { "DRB-Setup-Item-NG-RAN", "e1ap.DRB_Setup_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_data_Forwarding_Information_Response,
      { "dRB-data-Forwarding-Information-Response", "e1ap.dRB_data_Forwarding_Information_Response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Data_Forwarding_Information", HFILL }},
    { &hf_e1ap_DRB_Setup_Mod_List_NG_RAN_item,
      { "DRB-Setup-Mod-Item-NG-RAN", "e1ap.DRB_Setup_Mod_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pDCP_DL_Count,
      { "pDCP-DL-Count", "e1ap.pDCP_DL_Count_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDCP_Count", HFILL }},
    { &hf_e1ap_pDCP_UL_Count,
      { "pDCP-UL-Count", "e1ap.pDCP_UL_Count_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDCP_Count", HFILL }},
    { &hf_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN_item,
      { "DRBs-Subject-To-Counter-Check-Item-EUTRAN", "e1ap.DRBs_Subject_To_Counter_Check_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN_item,
      { "DRBs-Subject-To-Counter-Check-Item-NG-RAN", "e1ap.DRBs_Subject_To_Counter_Check_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pDU_Session_ID,
      { "pDU-Session-ID", "e1ap.pDU_Session_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRBs_Subject_To_Early_Forwarding_List_item,
      { "DRBs-Subject-To-Early-Forwarding-Item", "e1ap.DRBs_Subject_To_Early_Forwarding_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dLCountValue,
      { "dLCountValue", "e1ap.dLCountValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDCP_Count", HFILL }},
    { &hf_e1ap_DRB_To_Modify_List_EUTRAN_item,
      { "DRB-To-Modify-Item-EUTRAN", "e1ap.DRB_To_Modify_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pDCP_Configuration,
      { "pDCP-Configuration", "e1ap.pDCP_Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_eUTRAN_QoS,
      { "eUTRAN-QoS", "e1ap.eUTRAN_QoS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_s1_UL_UP_TNL_Information,
      { "s1-UL-UP-TNL-Information", "e1ap.s1_UL_UP_TNL_Information",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_data_Forwarding_Information,
      { "data-Forwarding-Information", "e1ap.data_Forwarding_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pDCP_SN_Status_Request,
      { "pDCP-SN-Status-Request", "e1ap.pDCP_SN_Status_Request",
        FT_UINT32, BASE_DEC, VALS(e1ap_PDCP_SN_Status_Request_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_dL_UP_Parameters,
      { "dL-UP-Parameters", "e1ap.dL_UP_Parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UP_Parameters", HFILL }},
    { &hf_e1ap_cell_Group_To_Add,
      { "cell-Group-To-Add", "e1ap.cell_Group_To_Add",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Cell_Group_Information", HFILL }},
    { &hf_e1ap_cell_Group_To_Modify,
      { "cell-Group-To-Modify", "e1ap.cell_Group_To_Modify",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Cell_Group_Information", HFILL }},
    { &hf_e1ap_cell_Group_To_Remove,
      { "cell-Group-To-Remove", "e1ap.cell_Group_To_Remove",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Cell_Group_Information", HFILL }},
    { &hf_e1ap_dRB_Inactivity_Timer,
      { "dRB-Inactivity-Timer", "e1ap.dRB_Inactivity_Timer",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "Inactivity_Timer", HFILL }},
    { &hf_e1ap_DRB_To_Modify_List_NG_RAN_item,
      { "DRB-To-Modify-Item-NG-RAN", "e1ap.DRB_To_Modify_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_sDAP_Configuration,
      { "sDAP-Configuration", "e1ap.sDAP_Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_Data_Forwarding_Information,
      { "dRB-Data-Forwarding-Information", "e1ap.dRB_Data_Forwarding_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Data_Forwarding_Information", HFILL }},
    { &hf_e1ap_pdcp_SN_Status_Information,
      { "pdcp-SN-Status-Information", "e1ap.pdcp_SN_Status_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_flow_Mapping_Information,
      { "flow-Mapping-Information", "e1ap.flow_Mapping_Information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoS_Flow_QoS_Parameter_List", HFILL }},
    { &hf_e1ap_DRB_To_Remove_List_EUTRAN_item,
      { "DRB-To-Remove-Item-EUTRAN", "e1ap.DRB_To_Remove_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Required_To_Remove_List_EUTRAN_item,
      { "DRB-Required-To-Remove-Item-EUTRAN", "e1ap.DRB_Required_To_Remove_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_To_Remove_List_NG_RAN_item,
      { "DRB-To-Remove-Item-NG-RAN", "e1ap.DRB_To_Remove_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Required_To_Remove_List_NG_RAN_item,
      { "DRB-Required-To-Remove-Item-NG-RAN", "e1ap.DRB_Required_To_Remove_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_To_Setup_List_EUTRAN_item,
      { "DRB-To-Setup-Item-EUTRAN", "e1ap.DRB_To_Setup_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_data_Forwarding_Information_Request,
      { "data-Forwarding-Information-Request", "e1ap.data_Forwarding_Information_Request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_existing_Allocated_S1_DL_UP_TNL_Info,
      { "existing-Allocated-S1-DL-UP-TNL-Info", "e1ap.existing_Allocated_S1_DL_UP_TNL_Info",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_DRB_To_Setup_Mod_List_EUTRAN_item,
      { "DRB-To-Setup-Mod-Item-EUTRAN", "e1ap.DRB_To_Setup_Mod_Item_EUTRAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_To_Setup_List_NG_RAN_item,
      { "DRB-To-Setup-Item-NG-RAN", "e1ap.DRB_To_Setup_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_qos_flow_Information_To_Be_Setup,
      { "qos-flow-Information-To-Be-Setup", "e1ap.qos_flow_Information_To_Be_Setup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoS_Flow_QoS_Parameter_List", HFILL }},
    { &hf_e1ap_dRB_Data_Forwarding_Information_Request,
      { "dRB-Data-Forwarding-Information-Request", "e1ap.dRB_Data_Forwarding_Information_Request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Data_Forwarding_Information_Request", HFILL }},
    { &hf_e1ap_DRB_To_Setup_Mod_List_NG_RAN_item,
      { "DRB-To-Setup-Mod-Item-NG-RAN", "e1ap.DRB_To_Setup_Mod_Item_NG_RAN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_DRB_Usage_Report_List_item,
      { "DRB-Usage-Report-Item", "e1ap.DRB_Usage_Report_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_startTimeStamp,
      { "startTimeStamp", "e1ap.startTimeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_endTimeStamp,
      { "endTimeStamp", "e1ap.endTimeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_usageCountUL,
      { "usageCountUL", "e1ap.usageCountUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0,
        "INTEGER_0_18446744073709551615", HFILL }},
    { &hf_e1ap_usageCountDL,
      { "usageCountDL", "e1ap.usageCountDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0,
        "INTEGER_0_18446744073709551615", HFILL }},
    { &hf_e1ap_qoSPriorityLevel,
      { "qoSPriorityLevel", "e1ap.qoSPriorityLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_fiveQI,
      { "fiveQI", "e1ap.fiveQI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255_", HFILL }},
    { &hf_e1ap_delayCritical,
      { "delayCritical", "e1ap.delayCritical",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_delayCritical_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_averagingWindow,
      { "averagingWindow", "e1ap.averagingWindow",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0,
        NULL, HFILL }},
    { &hf_e1ap_maxDataBurstVolume,
      { "maxDataBurstVolume", "e1ap.maxDataBurstVolume",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0,
        NULL, HFILL }},
    { &hf_e1ap_firstDLCount,
      { "firstDLCount", "e1ap.firstDLCount_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dLDiscardingCount,
      { "dLDiscardingCount", "e1ap.dLDiscardingCount_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DLDiscarding", HFILL }},
    { &hf_e1ap_choice_Extension,
      { "choice-Extension", "e1ap.choice_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_SingleContainer", HFILL }},
    { &hf_e1ap_eCNMarkingatNGRAN,
      { "eCNMarkingatNGRAN", "e1ap.eCNMarkingatNGRAN",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_eCNMarkingatNGRAN_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_eCNMarkingatUPF,
      { "eCNMarkingatUPF", "e1ap.eCNMarkingatUPF",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_eCNMarkingatUPF_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_congestionInformation,
      { "congestionInformation", "e1ap.congestionInformation",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_congestionInformation_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_ehc_CID_Length,
      { "ehc-CID-Length", "e1ap.ehc_CID_Length",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_ehc_CID_Length_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_drb_ContinueEHC_DL,
      { "drb-ContinueEHC-DL", "e1ap.drb_ContinueEHC_DL",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_drb_ContinueEHC_DL_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_drb_ContinueEHC_UL,
      { "drb-ContinueEHC-UL", "e1ap.drb_ContinueEHC_UL",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_drb_ContinueEHC_UL_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_ehc_Common,
      { "ehc-Common", "e1ap.ehc_Common_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EHC_Common_Parameters", HFILL }},
    { &hf_e1ap_ehc_Downlink,
      { "ehc-Downlink", "e1ap.ehc_Downlink_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EHC_Downlink_Parameters", HFILL }},
    { &hf_e1ap_ehc_Uplink,
      { "ehc-Uplink", "e1ap.ehc_Uplink_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EHC_Uplink_Parameters", HFILL }},
    { &hf_e1ap_portNumber,
      { "portNumber", "e1ap.portNumber",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_priorityLevel,
      { "priorityLevel", "e1ap.priorityLevel",
        FT_UINT32, BASE_DEC, VALS(e1ap_PriorityLevel_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_pre_emptionCapability,
      { "pre-emptionCapability", "e1ap.pre_emptionCapability",
        FT_UINT32, BASE_DEC, VALS(e1ap_Pre_emptionCapability_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_pre_emptionVulnerability,
      { "pre-emptionVulnerability", "e1ap.pre_emptionVulnerability",
        FT_UINT32, BASE_DEC, VALS(e1ap_Pre_emptionVulnerability_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_pLMN_Identity,
      { "pLMN-Identity", "e1ap.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_eUTRAN_Cell_Identity,
      { "eUTRAN-Cell-Identity", "e1ap.eUTRAN_Cell_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "E_UTRAN_Cell_Identity", HFILL }},
    { &hf_e1ap_ECGI_Support_List_item,
      { "ECGI-Support-Item", "e1ap.ECGI_Support_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_eCGI,
      { "eCGI", "e1ap.eCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_EUTRAN_QoS_Support_List_item,
      { "EUTRAN-QoS-Support-Item", "e1ap.EUTRAN_QoS_Support_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_qCI,
      { "qCI", "e1ap.qCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_eUTRANallocationAndRetentionPriority,
      { "eUTRANallocationAndRetentionPriority", "e1ap.eUTRANallocationAndRetentionPriority_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_gbrQosInformation,
      { "gbrQosInformation", "e1ap.gbrQosInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GBR_QosInformation", HFILL }},
    { &hf_e1ap_ExtendedSliceSupportList_item,
      { "Slice-Support-Item", "e1ap.Slice_Support_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_firstDLCountVal,
      { "firstDLCountVal", "e1ap.firstDLCountVal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDCP_Count", HFILL }},
    { &hf_e1ap_F1U_TNL_InfoAdded_List_item,
      { "F1U-TNL-InfoAdded-Item", "e1ap.F1U_TNL_InfoAdded_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_broadcastF1U_ContextReferenceE1,
      { "broadcastF1U-ContextReferenceE1", "e1ap.broadcastF1U_ContextReferenceE1",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_F1U_TNL_InfoToAdd_List_item,
      { "F1U-TNL-InfoToAdd-Item", "e1ap.F1U_TNL_InfoToAdd_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_F1U_TNL_InfoAddedOrModified_List_item,
      { "F1U-TNL-InfoAddedOrModified-Item", "e1ap.F1U_TNL_InfoAddedOrModified_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_F1U_TNL_InfoToAddOrModify_List_item,
      { "F1U-TNL-InfoToAddOrModify-Item", "e1ap.F1U_TNL_InfoToAddOrModify_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_F1U_TNL_InfoToRelease_List_item,
      { "F1U-TNL-InfoToRelease-Item", "e1ap.F1U_TNL_InfoToRelease_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_tmgi,
      { "tmgi", "e1ap.tmgi",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_6", HFILL }},
    { &hf_e1ap_nid,
      { "nid", "e1ap.nid",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_gNB_CU_CP_NameVisibleString,
      { "gNB-CU-CP-NameVisibleString", "e1ap.gNB_CU_CP_NameVisibleString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_gNB_CU_CP_NameUTF8String,
      { "gNB-CU-CP-NameUTF8String", "e1ap.gNB_CU_CP_NameUTF8String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration_item,
      { "GNB-CU-UP-CellGroupRelatedConfiguration-Item", "e1ap.GNB_CU_UP_CellGroupRelatedConfiguration_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_uP_TNL_Information,
      { "uP-TNL-Information", "e1ap.uP_TNL_Information",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_mbs_Support_Info_ToAdd_List,
      { "mbs-Support-Info-ToAdd-List", "e1ap.mbs_Support_Info_ToAdd_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mbs_Support_Info_ToRemove_List,
      { "mbs-Support-Info-ToRemove-List", "e1ap.mbs_Support_Info_ToRemove_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_gNB_CU_UP_NameVisibleString,
      { "gNB-CU-UP-NameVisibleString", "e1ap.gNB_CU_UP_NameVisibleString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_gNB_CU_UP_NameUTF8String,
      { "gNB-CU-UP-NameUTF8String", "e1ap.gNB_CU_UP_NameUTF8String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_tNLAssociationTransportLayerAddress,
      { "tNLAssociationTransportLayerAddress", "e1ap.tNLAssociationTransportLayerAddress",
        FT_UINT32, BASE_DEC, VALS(e1ap_CP_TNL_Information_vals), 0,
        "CP_TNL_Information", HFILL }},
    { &hf_e1ap_tNLAssociationUsage,
      { "tNLAssociationUsage", "e1ap.tNLAssociationUsage",
        FT_UINT32, BASE_DEC, VALS(e1ap_TNLAssociationUsage_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_tNLAssociationTransportLayerAddressgNBCUCP,
      { "tNLAssociationTransportLayerAddressgNBCUCP", "e1ap.tNLAssociationTransportLayerAddressgNBCUCP",
        FT_UINT32, BASE_DEC, VALS(e1ap_CP_TNL_Information_vals), 0,
        "CP_TNL_Information", HFILL }},
    { &hf_e1ap_e_RAB_MaximumBitrateDL,
      { "e-RAB-MaximumBitrateDL", "e1ap.e_RAB_MaximumBitrateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_e1ap_e_RAB_MaximumBitrateUL,
      { "e-RAB-MaximumBitrateUL", "e1ap.e_RAB_MaximumBitrateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_e1ap_e_RAB_GuaranteedBitrateDL,
      { "e-RAB-GuaranteedBitrateDL", "e1ap.e_RAB_GuaranteedBitrateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_e1ap_e_RAB_GuaranteedBitrateUL,
      { "e-RAB-GuaranteedBitrateUL", "e1ap.e_RAB_GuaranteedBitrateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_e1ap_maxFlowBitRateDownlink,
      { "maxFlowBitRateDownlink", "e1ap.maxFlowBitRateDownlink",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_e1ap_maxFlowBitRateUplink,
      { "maxFlowBitRateUplink", "e1ap.maxFlowBitRateUplink",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_e1ap_guaranteedFlowBitRateDownlink,
      { "guaranteedFlowBitRateDownlink", "e1ap.guaranteedFlowBitRateDownlink",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_e1ap_guaranteedFlowBitRateUplink,
      { "guaranteedFlowBitRateUplink", "e1ap.guaranteedFlowBitRateUplink",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_e1ap_maxPacketLossRateDownlink,
      { "maxPacketLossRateDownlink", "e1ap.maxPacketLossRateDownlink",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(e1ap_MaxPacketLossRate_fmt), 0,
        "MaxPacketLossRate", HFILL }},
    { &hf_e1ap_maxPacketLossRateUplink,
      { "maxPacketLossRateUplink", "e1ap.maxPacketLossRateUplink",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(e1ap_MaxPacketLossRate_fmt), 0,
        "MaxPacketLossRate", HFILL }},
    { &hf_e1ap_GTPTLAs_item,
      { "GTPTLA-Item", "e1ap.GTPTLA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_gTPTransportLayerAddresses,
      { "gTPTransportLayerAddresses", "e1ap.gTPTransportLayerAddresses",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_e1ap_transportLayerAddress,
      { "transportLayerAddress", "e1ap.transportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_gTP_TEID,
      { "gTP-TEID", "e1ap.gTP_TEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_offeredThroughput,
      { "offeredThroughput", "e1ap.offeredThroughput",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_kbps, 0,
        "INTEGER_1_16777216_", HFILL }},
    { &hf_e1ap_availableThroughput,
      { "availableThroughput", "e1ap.availableThroughput",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100_", HFILL }},
    { &hf_e1ap_measurementsToActivate,
      { "measurementsToActivate", "e1ap.measurementsToActivate",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_measurementFour,
      { "measurementFour", "e1ap.measurementFour_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "M4Configuration", HFILL }},
    { &hf_e1ap_measurementSix,
      { "measurementSix", "e1ap.measurementSix_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "M6Configuration", HFILL }},
    { &hf_e1ap_measurementSeven,
      { "measurementSeven", "e1ap.measurementSeven_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "M7Configuration", HFILL }},
    { &hf_e1ap_iAB_donor_CU_UPPSK,
      { "iAB-donor-CU-UPPSK", "e1ap.iAB_donor_CU_UPPSK",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_iAB_donor_CU_UPIPAddress,
      { "iAB-donor-CU-UPIPAddress", "e1ap.iAB_donor_CU_UPIPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_e1ap_iAB_DUIPAddress,
      { "iAB-DUIPAddress", "e1ap.iAB_DUIPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_e1ap_LocationDependentMBSNGUInformationAt5GC_item,
      { "LocationDependentMBSNGUInformationAt5GC-Item", "e1ap.LocationDependentMBSNGUInformationAt5GC_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mbsAreaSession_ID,
      { "mbsAreaSession-ID", "e1ap.mbsAreaSession_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MBSAreaSessionID", HFILL }},
    { &hf_e1ap_mbsNGUInformationAt5GC,
      { "mbsNGUInformationAt5GC", "e1ap.mbsNGUInformationAt5GC",
        FT_UINT32, BASE_DEC, VALS(e1ap_MBSNGUInformationAt5GC_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_LocationDependentMBSF1UInformationAtCU_item,
      { "LocationDependentMBSF1UInformationAtCU-Item", "e1ap.LocationDependentMBSF1UInformationAtCU_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mbs_f1u_info_at_CU,
      { "mbs-f1u-info-at-CU", "e1ap.mbs_f1u_info_at_CU",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_LocationDependentMBSF1UInformationAtDU_item,
      { "LocationDependentMBSF1UInformationAtDU-Item", "e1ap.LocationDependentMBSF1UInformationAtDU_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mbs_f1u_info_at_DU,
      { "mbs-f1u-info-at-DU", "e1ap.mbs_f1u_info_at_DU",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_LocationDependentMBSNGUInformationAtNGRAN_item,
      { "LocationDependentMBSNGUInformationAtNGRAN-Item", "e1ap.LocationDependentMBSNGUInformationAtNGRAN_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mbsNGUInformationAtNGRAN,
      { "mbsNGUInformationAtNGRAN", "e1ap.mbsNGUInformationAtNGRAN",
        FT_UINT32, BASE_DEC, VALS(e1ap_MBSNGUInformationAtNGRAN_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_maxIPrate,
      { "maxIPrate", "e1ap.maxIPrate",
        FT_UINT32, BASE_DEC, VALS(e1ap_MaxIPrate_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_multicast,
      { "multicast", "e1ap.multicast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MBSNGUInformationAt5GC_Multicast", HFILL }},
    { &hf_e1ap_ipmcAddress,
      { "ipmcAddress", "e1ap.ipmcAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_e1ap_ipsourceAddress,
      { "ipsourceAddress", "e1ap.ipsourceAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_e1ap_gtpDLTEID,
      { "gtpDLTEID", "e1ap.gtpDLTEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GTP_TEID", HFILL }},
    { &hf_e1ap_unicast,
      { "unicast", "e1ap.unicast",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_MBSNGUInformationAtNGRAN_Request_List_item,
      { "MBSNGUInformationAtNGRAN-Request-Item", "e1ap.MBSNGUInformationAtNGRAN_Request_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mbsNGUInformationAtNGRAN_Request,
      { "mbsNGUInformationAtNGRAN-Request", "e1ap.mbsNGUInformationAtNGRAN_Request",
        FT_UINT32, BASE_DEC, VALS(e1ap_MBSNGUInformationAtNGRAN_Request_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_ue_Reference_ID,
      { "ue-Reference-ID", "e1ap.ue_Reference_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GNB_CU_CP_UE_E1AP_ID", HFILL }},
    { &hf_e1ap_associatedQoSFlowInformationList,
      { "associatedQoSFlowInformationList", "e1ap.associatedQoSFlowInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MBSSessionAssociatedInformationList", HFILL }},
    { &hf_e1ap_mbsSessionAssociatedInformationList,
      { "mbsSessionAssociatedInformationList", "e1ap.mbsSessionAssociatedInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mbsSessionForwardingAddress,
      { "mbsSessionForwardingAddress", "e1ap.mbsSessionForwardingAddress",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_MBSSessionAssociatedInformationList_item,
      { "MBSSessionAssociatedInformation-Item", "e1ap.MBSSessionAssociatedInformation_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mbs_QoS_Flow_Identifier,
      { "mbs-QoS-Flow-Identifier", "e1ap.mbs_QoS_Flow_Identifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoS_Flow_Identifier", HFILL }},
    { &hf_e1ap_associated_unicast_QoS_Flow_Identifier,
      { "associated-unicast-QoS-Flow-Identifier", "e1ap.associated_unicast_QoS_Flow_Identifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoS_Flow_Identifier", HFILL }},
    { &hf_e1ap_MBS_Support_Info_ToAdd_List_item,
      { "MBS-Support-Info-ToAdd-Item", "e1ap.MBS_Support_Info_ToAdd_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_globalMBSSessionID,
      { "globalMBSSessionID", "e1ap.globalMBSSessionID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MBS_Support_Info_ToRemove_List_item,
      { "MBS-Support-Info-ToRemove-Item", "e1ap.MBS_Support_Info_ToRemove_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mbs_DL_Data_Arrival,
      { "mbs-DL-Data-Arrival", "e1ap.mbs_DL_Data_Arrival_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_inactivity,
      { "inactivity", "e1ap.inactivity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MCBearerContext_Inactivity", HFILL }},
    { &hf_e1ap_dlDataArrival,
      { "dlDataArrival", "e1ap.dlDataArrival",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_dlDataArrival_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_ppi,
      { "ppi", "e1ap.ppi",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mcBearerContext_Inactivity_Indication,
      { "mcBearerContext-Inactivity-Indication", "e1ap.mcBearerContext_Inactivity_Indication",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_mcBearerContext_Inactivity_Indication_vals), 0,
        "T_mcBearerContext_Inactivity_Indication", HFILL }},
    { &hf_e1ap_mcMRBToSetupList,
      { "mcMRBToSetupList", "e1ap.mcMRBToSetupList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MCMRBSetupConfiguration", HFILL }},
    { &hf_e1ap_MCMRBSetupConfiguration_item,
      { "MCMRBSetupConfiguration-Item", "e1ap.MCMRBSetupConfiguration_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mcBearerContextNGU_TNLInfoatNGRAN,
      { "mcBearerContextNGU-TNLInfoatNGRAN", "e1ap.mcBearerContextNGU_TNLInfoatNGRAN",
        FT_UINT32, BASE_DEC, VALS(e1ap_MCBearerContextNGU_TNLInfoatNGRAN_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_mcMRBSetupResponseList,
      { "mcMRBSetupResponseList", "e1ap.mcMRBSetupResponseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mcMRBFailedList,
      { "mcMRBFailedList", "e1ap.mcMRBFailedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_availableMCMRBConfig,
      { "availableMCMRBConfig", "e1ap.availableMCMRBConfig",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MCMRBSetupConfiguration", HFILL }},
    { &hf_e1ap_MCMRBSetupResponseList_item,
      { "MCMRBSetupResponseList-Item", "e1ap.MCMRBSetupResponseList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mBS_PDCP_COUNT,
      { "mBS-PDCP-COUNT", "e1ap.mBS_PDCP_COUNT",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCMRBFailedList_item,
      { "MCMRBFailedList-Item", "e1ap.MCMRBFailedList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mcBearerContextNGUTNLInfoat5GC,
      { "mcBearerContextNGUTNLInfoat5GC", "e1ap.mcBearerContextNGUTNLInfoat5GC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mcBearerContextNGUTnlInfoatNGRANRequest,
      { "mcBearerContextNGUTnlInfoatNGRANRequest", "e1ap.mcBearerContextNGUTnlInfoatNGRANRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mbsMulticastF1UContextDescriptor,
      { "mbsMulticastF1UContextDescriptor", "e1ap.mbsMulticastF1UContextDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mcMRBToSetupModifyList,
      { "mcMRBToSetupModifyList", "e1ap.mcMRBToSetupModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MCMRBSetupModifyConfiguration", HFILL }},
    { &hf_e1ap_mcMRBToRemoveList,
      { "mcMRBToRemoveList", "e1ap.mcMRBToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MCMRBRemoveConfiguration", HFILL }},
    { &hf_e1ap_ngRANNGUTNLRequested,
      { "ngRANNGUTNLRequested", "e1ap.ngRANNGUTNLRequested",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_ngRANNGUTNLRequested_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_MCMRBSetupModifyConfiguration_item,
      { "MCMRBSetupModifyConfiguration-Item", "e1ap.MCMRBSetupModifyConfiguration_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_f1uTNLatDU,
      { "f1uTNLatDU", "e1ap.f1uTNLatDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MCBearerContextF1UTNLInfoatDU", HFILL }},
    { &hf_e1ap_mrbQoS,
      { "mrbQoS", "e1ap.mrbQoS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "QoSFlowLevelQoSParameters", HFILL }},
    { &hf_e1ap_mbs_PDCP_COUNT_Req,
      { "mbs-PDCP-COUNT-Req", "e1ap.mbs_PDCP_COUNT_Req",
        FT_UINT32, BASE_DEC, VALS(e1ap_MBS_PDCP_COUNT_Req_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_mbsF1UInfoatDU,
      { "mbsF1UInfoatDU", "e1ap.mbsF1UInfoatDU",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_multicastF1UContextReferenceE1,
      { "multicastF1UContextReferenceE1", "e1ap.multicastF1UContextReferenceE1",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mc_F1UCtxtusage,
      { "mc-F1UCtxtusage", "e1ap.mc_F1UCtxtusage",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_mc_F1UCtxtusage_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_mbsAreaSession,
      { "mbsAreaSession", "e1ap.mbsAreaSession",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MBSAreaSessionID", HFILL }},
    { &hf_e1ap_MCMRBRemoveConfiguration_item,
      { "MRB-ID", "e1ap.MRB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mcBearerContextNGU_TNLInfoatNGRANModifyResponse,
      { "mcBearerContextNGU-TNLInfoatNGRANModifyResponse", "e1ap.mcBearerContextNGU_TNLInfoatNGRANModifyResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mcMRBModifySetupResponseList,
      { "mcMRBModifySetupResponseList", "e1ap.mcMRBModifySetupResponseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MCMRBSetupModifyResponseList", HFILL }},
    { &hf_e1ap_mbs_NGU_InfoatNGRAN,
      { "mbs-NGU-InfoatNGRAN", "e1ap.mbs_NGU_InfoatNGRAN",
        FT_UINT32, BASE_DEC, VALS(e1ap_MBSNGUInformationAtNGRAN_vals), 0,
        "MBSNGUInformationAtNGRAN", HFILL }},
    { &hf_e1ap_MCMRBSetupModifyResponseList_item,
      { "MCMRBSetupModifyResponseList-Item", "e1ap.MCMRBSetupModifyResponseList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mcBearerContextF1UTNLInfoatCU,
      { "mcBearerContextF1UTNLInfoatCU", "e1ap.mcBearerContextF1UTNLInfoatCU",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_mcMRBToRemoveRequiredList,
      { "mcMRBToRemoveRequiredList", "e1ap.mcMRBToRemoveRequiredList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MCMRBRemoveConfiguration", HFILL }},
    { &hf_e1ap_mcMRBToModifyRequiredList,
      { "mcMRBToModifyRequiredList", "e1ap.mcMRBToModifyRequiredList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MCMRBModifyRequiredConfiguration", HFILL }},
    { &hf_e1ap_MCMRBModifyRequiredConfiguration_item,
      { "MCMRBModifyRequiredConfiguration-Item", "e1ap.MCMRBModifyRequiredConfiguration_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mcMRBModifyConfirmList,
      { "mcMRBModifyConfirmList", "e1ap.mcMRBModifyConfirmList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MCMRBModifyConfirmList_item,
      { "MCMRBModifyConfirmList-Item", "e1ap.MCMRBModifyConfirmList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mcForwardingResourceID,
      { "mcForwardingResourceID", "e1ap.mcForwardingResourceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mrbForwardingResourceRequestList,
      { "mrbForwardingResourceRequestList", "e1ap.mrbForwardingResourceRequestList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MRBForwardingResourceRequestList_item,
      { "MRBForwardingResourceRequest-Item", "e1ap.MRBForwardingResourceRequest_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mrbProgressRequestType,
      { "mrbProgressRequestType", "e1ap.mrbProgressRequestType",
        FT_UINT32, BASE_DEC, VALS(e1ap_MRB_ProgressInformationType_vals), 0,
        "MRB_ProgressInformationType", HFILL }},
    { &hf_e1ap_mrbForwardingAddressRequest,
      { "mrbForwardingAddressRequest", "e1ap.mrbForwardingAddressRequest",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_mrbForwardingAddressRequest_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_mrbForwardingResourceIndicationList,
      { "mrbForwardingResourceIndicationList", "e1ap.mrbForwardingResourceIndicationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mbsSessionAssociatedInformation,
      { "mbsSessionAssociatedInformation", "e1ap.mbsSessionAssociatedInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MRBForwardingResourceIndicationList_item,
      { "MRBForwardingResourceIndication-Item", "e1ap.MRBForwardingResourceIndication_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mrb_ProgressInformation,
      { "mrb-ProgressInformation", "e1ap.mrb_ProgressInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mrbForwardingAddress,
      { "mrbForwardingAddress", "e1ap.mrbForwardingAddress",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_mrbForwardingResourceResponseList,
      { "mrbForwardingResourceResponseList", "e1ap.mrbForwardingResourceResponseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MRBForwardingResourceResponseList_item,
      { "MRBForwardingResourceResponse-Item", "e1ap.MRBForwardingResourceResponse_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mrb_ProgressInformationSNs,
      { "mrb-ProgressInformationSNs", "e1ap.mrb_ProgressInformationSNs",
        FT_UINT32, BASE_DEC, VALS(e1ap_MRB_ProgressInformationSNs_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_mrb_ProgressInformationType,
      { "mrb-ProgressInformationType", "e1ap.mrb_ProgressInformationType",
        FT_UINT32, BASE_DEC, VALS(e1ap_MRB_ProgressInformationType_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_pdcp_SN12,
      { "pdcp-SN12", "e1ap.pdcp_SN12",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_e1ap_pdcp_SN18,
      { "pdcp-SN18", "e1ap.pdcp_SN18",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_262143", HFILL }},
    { &hf_e1ap_startTimeStamp_01,
      { "startTimeStamp", "e1ap.startTimeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_startTimeStamp_01", HFILL }},
    { &hf_e1ap_endTimeStamp_01,
      { "endTimeStamp", "e1ap.endTimeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_endTimeStamp_01", HFILL }},
    { &hf_e1ap_data_Usage_per_PDU_Session_Report,
      { "data-Usage-per-PDU-Session-Report", "e1ap.data_Usage_per_PDU_Session_Report_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_data_Usage_per_QoS_Flow_List,
      { "data-Usage-per-QoS-Flow-List", "e1ap.data_Usage_per_QoS_Flow_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_m4period,
      { "m4period", "e1ap.m4period",
        FT_UINT32, BASE_DEC, VALS(e1ap_M4period_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_m4_links_to_log,
      { "m4-links-to-log", "e1ap.m4_links_to_log",
        FT_UINT32, BASE_DEC, VALS(e1ap_Links_to_log_vals), 0,
        "Links_to_log", HFILL }},
    { &hf_e1ap_m6report_Interval,
      { "m6report-Interval", "e1ap.m6report_Interval",
        FT_UINT32, BASE_DEC, VALS(e1ap_M6report_Interval_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_m6_links_to_log,
      { "m6-links-to-log", "e1ap.m6_links_to_log",
        FT_UINT32, BASE_DEC, VALS(e1ap_Links_to_log_vals), 0,
        "Links_to_log", HFILL }},
    { &hf_e1ap_m7period,
      { "m7period", "e1ap.m7period",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_minutes, 0,
        NULL, HFILL }},
    { &hf_e1ap_m7_links_to_log,
      { "m7-links-to-log", "e1ap.m7_links_to_log",
        FT_UINT32, BASE_DEC, VALS(e1ap_Links_to_log_vals), 0,
        "Links_to_log", HFILL }},
    { &hf_e1ap_mdt_Activation,
      { "mdt-Activation", "e1ap.mdt_Activation",
        FT_UINT32, BASE_DEC, VALS(e1ap_MDT_Activation_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_mDTMode,
      { "mDTMode", "e1ap.mDTMode",
        FT_UINT32, BASE_DEC, VALS(e1ap_MDTMode_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_immediateMDT,
      { "immediateMDT", "e1ap.immediateMDT_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MDTPLMNList_item,
      { "PLMN-Identity", "e1ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MDTPLMNModificationList_item,
      { "PLMN-Identity", "e1ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mT_SDT_Data_Size,
      { "mT-SDT-Data-Size", "e1ap.mT_SDT_Data_Size",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0,
        NULL, HFILL }},
    { &hf_e1ap_mBS_ServiceAreaInformationList,
      { "mBS-ServiceAreaInformationList", "e1ap.mBS_ServiceAreaInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mBS_ServiceAreaCellList,
      { "mBS-ServiceAreaCellList", "e1ap.mBS_ServiceAreaCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mBS_ServiceAreaTAIList,
      { "mBS-ServiceAreaTAIList", "e1ap.mBS_ServiceAreaTAIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MBS_ServiceAreaCellList_item,
      { "NR-CGI", "e1ap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MBS_ServiceAreaTAIList_item,
      { "MBS-ServiceAreaTAIList-Item", "e1ap.MBS_ServiceAreaTAIList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_plmn_ID,
      { "plmn-ID", "e1ap.plmn_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Identity", HFILL }},
    { &hf_e1ap_fiveGS_TAC,
      { "fiveGS-TAC", "e1ap.fiveGS_TAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_MBS_ServiceAreaInformationList_item,
      { "MBS-ServiceAreaInformationItem", "e1ap.MBS_ServiceAreaInformationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mBS_AreaSessionID,
      { "mBS-AreaSessionID", "e1ap.mBS_AreaSessionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MBSAreaSessionID", HFILL }},
    { &hf_e1ap_mBS_ServiceAreaInformation,
      { "mBS-ServiceAreaInformation", "e1ap.mBS_ServiceAreaInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_NG_RAN_QoS_Support_List_item,
      { "NG-RAN-QoS-Support-Item", "e1ap.NG_RAN_QoS_Support_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_non_Dynamic5QIDescriptor,
      { "non-Dynamic5QIDescriptor", "e1ap.non_Dynamic5QIDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_sNPN,
      { "sNPN", "e1ap.sNPN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NPNSupportInfo_SNPN", HFILL }},
    { &hf_e1ap_nID,
      { "nID", "e1ap.nID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_sNPN_01,
      { "sNPN", "e1ap.sNPN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NPNContextInfo_SNPN", HFILL }},
    { &hf_e1ap_nR_Cell_Identity,
      { "nR-Cell-Identity", "e1ap.nR_Cell_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_NR_CGI_Support_List_item,
      { "NR-CGI-Support-Item", "e1ap.NR_CGI_Support_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_nR_CGI,
      { "nR-CGI", "e1ap.nR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_Extended_NR_CGI_Support_List_item,
      { "Extended-NR-CGI-Support-Item", "e1ap.Extended_NR_CGI_Support_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_n6JitterLowerBound,
      { "n6JitterLowerBound", "e1ap.n6JitterLowerBound",
        FT_INT32, BASE_CUSTOM, CF_FUNC(e1ap_N6Jitter_fmt), 0,
        "INTEGER_M127_127", HFILL }},
    { &hf_e1ap_n6JitterUpperBound,
      { "n6JitterUpperBound", "e1ap.n6JitterUpperBound",
        FT_INT32, BASE_CUSTOM, CF_FUNC(e1ap_N6Jitter_fmt), 0,
        "INTEGER_M127_127", HFILL }},
    { &hf_e1ap_pER_Scalar,
      { "pER-Scalar", "e1ap.pER_Scalar",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pER_Exponent,
      { "pER-Exponent", "e1ap.pER_Exponent",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pDCP_SN_Size_UL,
      { "pDCP-SN-Size-UL", "e1ap.pDCP_SN_Size_UL",
        FT_UINT32, BASE_DEC, VALS(e1ap_PDCP_SN_Size_vals), 0,
        "PDCP_SN_Size", HFILL }},
    { &hf_e1ap_pDCP_SN_Size_DL,
      { "pDCP-SN-Size-DL", "e1ap.pDCP_SN_Size_DL",
        FT_UINT32, BASE_DEC, VALS(e1ap_PDCP_SN_Size_vals), 0,
        "PDCP_SN_Size", HFILL }},
    { &hf_e1ap_rLC_Mode,
      { "rLC-Mode", "e1ap.rLC_Mode",
        FT_UINT32, BASE_DEC, VALS(e1ap_RLC_Mode_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_rOHC_Parameters,
      { "rOHC-Parameters", "e1ap.rOHC_Parameters",
        FT_UINT32, BASE_DEC, VALS(e1ap_ROHC_Parameters_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_t_ReorderingTimer,
      { "t-ReorderingTimer", "e1ap.t_ReorderingTimer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_discardTimer,
      { "discardTimer", "e1ap.discardTimer",
        FT_UINT32, BASE_DEC, VALS(e1ap_DiscardTimer_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_uLDataSplitThreshold,
      { "uLDataSplitThreshold", "e1ap.uLDataSplitThreshold",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &e1ap_ULDataSplitThreshold_vals_ext, 0,
        NULL, HFILL }},
    { &hf_e1ap_pDCP_Duplication,
      { "pDCP-Duplication", "e1ap.pDCP_Duplication",
        FT_UINT32, BASE_DEC, VALS(e1ap_PDCP_Duplication_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_pDCP_Reestablishment,
      { "pDCP-Reestablishment", "e1ap.pDCP_Reestablishment",
        FT_UINT32, BASE_DEC, VALS(e1ap_PDCP_Reestablishment_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_pDCP_DataRecovery,
      { "pDCP-DataRecovery", "e1ap.pDCP_DataRecovery",
        FT_UINT32, BASE_DEC, VALS(e1ap_PDCP_DataRecovery_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_duplication_Activation,
      { "duplication-Activation", "e1ap.duplication_Activation",
        FT_UINT32, BASE_DEC, VALS(e1ap_Duplication_Activation_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_outOfOrderDelivery,
      { "outOfOrderDelivery", "e1ap.outOfOrderDelivery",
        FT_UINT32, BASE_DEC, VALS(e1ap_OutOfOrderDelivery_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_pDCP_SN,
      { "pDCP-SN", "e1ap.pDCP_SN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_hFN,
      { "hFN", "e1ap.hFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Data_Usage_List_item,
      { "PDU-Session-Resource-Data-Usage-Item", "e1ap.PDU_Session_Resource_Data_Usage_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_mRDC_Usage_Information,
      { "mRDC-Usage-Information", "e1ap.mRDC_Usage_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pdcpStatusTransfer_UL,
      { "pdcpStatusTransfer-UL", "e1ap.pdcpStatusTransfer_UL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DRBBStatusTransfer", HFILL }},
    { &hf_e1ap_pdcpStatusTransfer_DL,
      { "pdcpStatusTransfer-DL", "e1ap.pdcpStatusTransfer_DL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDCP_Count", HFILL }},
    { &hf_e1ap_iE_Extension,
      { "iE-Extension", "e1ap.iE_Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_e1ap_receiveStatusofPDCPSDU,
      { "receiveStatusofPDCPSDU", "e1ap.receiveStatusofPDCPSDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1_131072", HFILL }},
    { &hf_e1ap_countValue,
      { "countValue", "e1ap.countValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDCP_Count", HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Activity_List_item,
      { "PDU-Session-Resource-Activity-Item", "e1ap.PDU_Session_Resource_Activity_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pDU_Session_Resource_Activity,
      { "pDU-Session-Resource-Activity", "e1ap.pDU_Session_Resource_Activity",
        FT_UINT32, BASE_DEC, VALS(e1ap_PDU_Session_Resource_Activity_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Confirm_Modified_List_item,
      { "PDU-Session-Resource-Confirm-Modified-Item", "e1ap.PDU_Session_Resource_Confirm_Modified_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_Confirm_Modified_List_NG_RAN,
      { "dRB-Confirm-Modified-List-NG-RAN", "e1ap.dRB_Confirm_Modified_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Failed_List_item,
      { "PDU-Session-Resource-Failed-Item", "e1ap.PDU_Session_Resource_Failed_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Failed_Mod_List_item,
      { "PDU-Session-Resource-Failed-Mod-Item", "e1ap.PDU_Session_Resource_Failed_Mod_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Failed_To_Modify_List_item,
      { "PDU-Session-Resource-Failed-To-Modify-Item", "e1ap.PDU_Session_Resource_Failed_To_Modify_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Modified_List_item,
      { "PDU-Session-Resource-Modified-Item", "e1ap.PDU_Session_Resource_Modified_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_nG_DL_UP_TNL_Information,
      { "nG-DL-UP-TNL-Information", "e1ap.nG_DL_UP_TNL_Information",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_securityResult,
      { "securityResult", "e1ap.securityResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pDU_Session_Data_Forwarding_Information_Response,
      { "pDU-Session-Data-Forwarding-Information-Response", "e1ap.pDU_Session_Data_Forwarding_Information_Response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Data_Forwarding_Information", HFILL }},
    { &hf_e1ap_dRB_Setup_List_NG_RAN,
      { "dRB-Setup-List-NG-RAN", "e1ap.dRB_Setup_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_Failed_List_NG_RAN,
      { "dRB-Failed-List-NG-RAN", "e1ap.dRB_Failed_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_Modified_List_NG_RAN,
      { "dRB-Modified-List-NG-RAN", "e1ap.dRB_Modified_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_Failed_To_Modify_List_NG_RAN,
      { "dRB-Failed-To-Modify-List-NG-RAN", "e1ap.dRB_Failed_To_Modify_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Required_To_Modify_List_item,
      { "PDU-Session-Resource-Required-To-Modify-Item", "e1ap.PDU_Session_Resource_Required_To_Modify_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_Required_To_Modify_List_NG_RAN,
      { "dRB-Required-To-Modify-List-NG-RAN", "e1ap.dRB_Required_To_Modify_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_Required_To_Remove_List_NG_RAN,
      { "dRB-Required-To-Remove-List-NG-RAN", "e1ap.dRB_Required_To_Remove_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Setup_List_item,
      { "PDU-Session-Resource-Setup-Item", "e1ap.PDU_Session_Resource_Setup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_nG_DL_UP_Unchanged,
      { "nG-DL-UP-Unchanged", "e1ap.nG_DL_UP_Unchanged",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_nG_DL_UP_Unchanged_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Setup_Mod_List_item,
      { "PDU-Session-Resource-Setup-Mod-Item", "e1ap.PDU_Session_Resource_Setup_Mod_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_Setup_Mod_List_NG_RAN,
      { "dRB-Setup-Mod-List-NG-RAN", "e1ap.dRB_Setup_Mod_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_Failed_Mod_List_NG_RAN,
      { "dRB-Failed-Mod-List-NG-RAN", "e1ap.dRB_Failed_Mod_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_To_Modify_List_item,
      { "PDU-Session-Resource-To-Modify-Item", "e1ap.PDU_Session_Resource_To_Modify_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_securityIndication,
      { "securityIndication", "e1ap.securityIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pDU_Session_Resource_DL_AMBR,
      { "pDU-Session-Resource-DL-AMBR", "e1ap.pDU_Session_Resource_DL_AMBR",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_e1ap_nG_UL_UP_TNL_Information,
      { "nG-UL-UP-TNL-Information", "e1ap.nG_UL_UP_TNL_Information",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_pDU_Session_Data_Forwarding_Information_Request,
      { "pDU-Session-Data-Forwarding-Information-Request", "e1ap.pDU_Session_Data_Forwarding_Information_Request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Data_Forwarding_Information_Request", HFILL }},
    { &hf_e1ap_pDU_Session_Data_Forwarding_Information,
      { "pDU-Session-Data-Forwarding-Information", "e1ap.pDU_Session_Data_Forwarding_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Data_Forwarding_Information", HFILL }},
    { &hf_e1ap_pDU_Session_Inactivity_Timer,
      { "pDU-Session-Inactivity-Timer", "e1ap.pDU_Session_Inactivity_Timer",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "Inactivity_Timer", HFILL }},
    { &hf_e1ap_networkInstance,
      { "networkInstance", "e1ap.networkInstance",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_To_Setup_List_NG_RAN,
      { "dRB-To-Setup-List-NG-RAN", "e1ap.dRB_To_Setup_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_To_Modify_List_NG_RAN,
      { "dRB-To-Modify-List-NG-RAN", "e1ap.dRB_To_Modify_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dRB_To_Remove_List_NG_RAN,
      { "dRB-To-Remove-List-NG-RAN", "e1ap.dRB_To_Remove_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_To_Remove_List_item,
      { "PDU-Session-Resource-To-Remove-Item", "e1ap.PDU_Session_Resource_To_Remove_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_To_Setup_List_item,
      { "PDU-Session-Resource-To-Setup-Item", "e1ap.PDU_Session_Resource_To_Setup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pDU_Session_Type,
      { "pDU-Session-Type", "e1ap.pDU_Session_Type",
        FT_UINT32, BASE_DEC, VALS(e1ap_PDU_Session_Type_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_sNSSAI,
      { "sNSSAI", "e1ap.sNSSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_existing_Allocated_NG_DL_UP_TNL_Info,
      { "existing-Allocated-NG-DL-UP-TNL-Info", "e1ap.existing_Allocated_NG_DL_UP_TNL_Info",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
        "UP_TNL_Information", HFILL }},
    { &hf_e1ap_PDU_Session_Resource_To_Setup_Mod_List_item,
      { "PDU-Session-Resource-To-Setup-Mod-Item", "e1ap.PDU_Session_Resource_To_Setup_Mod_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pDU_Session_Resource_AMBR,
      { "pDU-Session-Resource-AMBR", "e1ap.pDU_Session_Resource_AMBR",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_e1ap_dRB_To_Setup_Mod_List_NG_RAN,
      { "dRB-To-Setup-Mod-List-NG-RAN", "e1ap.dRB_To_Setup_Mod_List_NG_RAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_To_Notify_List_item,
      { "PDU-Session-To-Notify-Item", "e1ap.PDU_Session_To_Notify_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_qoS_Flow_List,
      { "qoS-Flow-List", "e1ap.qoS_Flow_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ulPDUSetQoSInformation,
      { "ulPDUSetQoSInformation", "e1ap.ulPDUSetQoSInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSetQoSInformation", HFILL }},
    { &hf_e1ap_dlPDUSetQoSInformation,
      { "dlPDUSetQoSInformation", "e1ap.dlPDUSetQoSInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSetQoSInformation", HFILL }},
    { &hf_e1ap_pduSetDelayBudget,
      { "pduSetDelayBudget", "e1ap.pduSetDelayBudget",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(e1ap_ExtendedPacketDelayBudget_fmt), 0,
        "ExtendedPacketDelayBudget", HFILL }},
    { &hf_e1ap_pduSetErrorRate,
      { "pduSetErrorRate", "e1ap.pduSetErrorRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PacketErrorRate", HFILL }},
    { &hf_e1ap_pduSetIntegratedHandlingInformation,
      { "pduSetIntegratedHandlingInformation", "e1ap.pduSetIntegratedHandlingInformation",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_pduSetIntegratedHandlingInformation_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_non_Dynamic_5QI,
      { "non-Dynamic-5QI", "e1ap.non_Dynamic_5QI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Non_Dynamic5QIDescriptor", HFILL }},
    { &hf_e1ap_dynamic_5QI,
      { "dynamic-5QI", "e1ap.dynamic_5QI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dynamic5QIDescriptor", HFILL }},
    { &hf_e1ap_QoS_Flow_List_item,
      { "QoS-Flow-Item", "e1ap.QoS_Flow_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_QoS_Flow_Failed_List_item,
      { "QoS-Flow-Failed-Item", "e1ap.QoS_Flow_Failed_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_QoS_Flow_Mapping_List_item,
      { "QoS-Flow-Mapping-Item", "e1ap.QoS_Flow_Mapping_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_qoSFlowMappingIndication,
      { "qoSFlowMappingIndication", "e1ap.qoSFlowMappingIndication",
        FT_UINT32, BASE_DEC, VALS(e1ap_QoS_Flow_Mapping_Indication_vals), 0,
        "QoS_Flow_Mapping_Indication", HFILL }},
    { &hf_e1ap_eUTRAN_QoS_Support_List,
      { "eUTRAN-QoS-Support-List", "e1ap.eUTRAN_QoS_Support_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_nG_RAN_QoS_Support_List,
      { "nG-RAN-QoS-Support-List", "e1ap.nG_RAN_QoS_Support_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_QoS_Flow_QoS_Parameter_List_item,
      { "QoS-Flow-QoS-Parameter-Item", "e1ap.QoS_Flow_QoS_Parameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_qoS_Characteristics,
      { "qoS-Characteristics", "e1ap.qoS_Characteristics",
        FT_UINT32, BASE_DEC, VALS(e1ap_QoS_Characteristics_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_nGRANallocationRetentionPriority,
      { "nGRANallocationRetentionPriority", "e1ap.nGRANallocationRetentionPriority_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NGRANAllocationAndRetentionPriority", HFILL }},
    { &hf_e1ap_gBR_QoS_Flow_Information,
      { "gBR-QoS-Flow-Information", "e1ap.gBR_QoS_Flow_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GBR_QoSFlowInformation", HFILL }},
    { &hf_e1ap_reflective_QoS_Attribute,
      { "reflective-QoS-Attribute", "e1ap.reflective_QoS_Attribute",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_reflective_QoS_Attribute_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_additional_QoS_Information,
      { "additional-QoS-Information", "e1ap.additional_QoS_Information",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_additional_QoS_Information_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_paging_Policy_Index,
      { "paging-Policy-Index", "e1ap.paging_Policy_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8_", HFILL }},
    { &hf_e1ap_reflective_QoS_Indicator,
      { "reflective-QoS-Indicator", "e1ap.reflective_QoS_Indicator",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_reflective_QoS_Indicator_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_qoS_Flow_Released_In_Session,
      { "qoS-Flow-Released-In-Session", "e1ap.qoS_Flow_Released_In_Session",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_qoS_Flow_Released_In_Session_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_qoS_Flow_Accumulated_Session_Time,
      { "qoS-Flow-Accumulated-Session-Time", "e1ap.qoS_Flow_Accumulated_Session_Time",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_5", HFILL }},
    { &hf_e1ap_QoS_Flows_to_be_forwarded_List_item,
      { "QoS-Flows-to-be-forwarded-Item", "e1ap.QoS_Flows_to_be_forwarded_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_dscp,
      { "dscp", "e1ap.dscp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_e1ap_flow_label,
      { "flow-label", "e1ap.flow_label",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_e1ap_DataForwardingtoNG_RANQoSFlowInformationList_item,
      { "DataForwardingtoNG-RANQoSFlowInformationList-Item", "e1ap.DataForwardingtoNG_RANQoSFlowInformationList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_rSN,
      { "rSN", "e1ap.rSN",
        FT_UINT32, BASE_DEC, VALS(e1ap_RSN_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_RetainabilityMeasurementsInfo_item,
      { "DRB-Removed-Item", "e1ap.DRB_Removed_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_rOHC,
      { "rOHC", "e1ap.rOHC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_uPlinkOnlyROHC,
      { "uPlinkOnlyROHC", "e1ap.uPlinkOnlyROHC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_maxCID,
      { "maxCID", "e1ap.maxCID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383_", HFILL }},
    { &hf_e1ap_rOHC_Profiles,
      { "rOHC-Profiles", "e1ap.rOHC_Profiles",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_511_", HFILL }},
    { &hf_e1ap_continueROHC,
      { "continueROHC", "e1ap.continueROHC",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_continueROHC_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_cipheringAlgorithm,
      { "cipheringAlgorithm", "e1ap.cipheringAlgorithm",
        FT_UINT32, BASE_DEC, VALS(e1ap_CipheringAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_integrityProtectionAlgorithm,
      { "integrityProtectionAlgorithm", "e1ap.integrityProtectionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(e1ap_IntegrityProtectionAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_integrityProtectionIndication,
      { "integrityProtectionIndication", "e1ap.integrityProtectionIndication",
        FT_UINT32, BASE_DEC, VALS(e1ap_IntegrityProtectionIndication_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_confidentialityProtectionIndication,
      { "confidentialityProtectionIndication", "e1ap.confidentialityProtectionIndication",
        FT_UINT32, BASE_DEC, VALS(e1ap_ConfidentialityProtectionIndication_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_maximumIPdatarate,
      { "maximumIPdatarate", "e1ap.maximumIPdatarate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_securityAlgorithm,
      { "securityAlgorithm", "e1ap.securityAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_uPSecuritykey,
      { "uPSecuritykey", "e1ap.uPSecuritykey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_integrityProtectionResult,
      { "integrityProtectionResult", "e1ap.integrityProtectionResult",
        FT_UINT32, BASE_DEC, VALS(e1ap_IntegrityProtectionResult_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_confidentialityProtectionResult,
      { "confidentialityProtectionResult", "e1ap.confidentialityProtectionResult",
        FT_UINT32, BASE_DEC, VALS(e1ap_ConfidentialityProtectionResult_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_Slice_Support_List_item,
      { "Slice-Support-Item", "e1ap.Slice_Support_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_sST,
      { "sST", "e1ap.sST",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_e1ap_sD,
      { "sD", "e1ap.sD",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_e1ap_defaultDRB,
      { "defaultDRB", "e1ap.defaultDRB",
        FT_UINT32, BASE_DEC, VALS(e1ap_DefaultDRB_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_sDAP_Header_UL,
      { "sDAP-Header-UL", "e1ap.sDAP_Header_UL",
        FT_UINT32, BASE_DEC, VALS(e1ap_SDAP_Header_UL_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_sDAP_Header_DL,
      { "sDAP-Header-DL", "e1ap.sDAP_Header_DL",
        FT_UINT32, BASE_DEC, VALS(e1ap_SDAP_Header_DL_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_dL_TNL_OfferedCapacity,
      { "dL-TNL-OfferedCapacity", "e1ap.dL_TNL_OfferedCapacity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777216_", HFILL }},
    { &hf_e1ap_dL_TNL_AvailableCapacity,
      { "dL-TNL-AvailableCapacity", "e1ap.dL_TNL_AvailableCapacity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100_", HFILL }},
    { &hf_e1ap_uL_TNL_OfferedCapacity,
      { "uL-TNL-OfferedCapacity", "e1ap.uL_TNL_OfferedCapacity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777216_", HFILL }},
    { &hf_e1ap_uL_TNL_AvailableCapacity,
      { "uL-TNL-AvailableCapacity", "e1ap.uL_TNL_AvailableCapacity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100_", HFILL }},
    { &hf_e1ap_tSCTrafficCharacteristicsUL,
      { "tSCTrafficCharacteristicsUL", "e1ap.tSCTrafficCharacteristicsUL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TSCAssistanceInformation", HFILL }},
    { &hf_e1ap_tSCTrafficCharacteristicsDL,
      { "tSCTrafficCharacteristicsDL", "e1ap.tSCTrafficCharacteristicsDL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TSCAssistanceInformation", HFILL }},
    { &hf_e1ap_periodicity,
      { "periodicity", "e1ap.periodicity",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0,
        NULL, HFILL }},
    { &hf_e1ap_burstArrivalTime,
      { "burstArrivalTime", "e1ap.burstArrivalTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_traceID,
      { "traceID", "e1ap.traceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_interfacesToTrace,
      { "interfacesToTrace", "e1ap.interfacesToTrace",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_traceDepth,
      { "traceDepth", "e1ap.traceDepth",
        FT_UINT32, BASE_DEC, VALS(e1ap_TraceDepth_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_traceCollectionEntityIPAddress,
      { "traceCollectionEntityIPAddress", "e1ap.traceCollectionEntityIPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_e1ap_t_Reordering,
      { "t-Reordering", "e1ap.t_Reordering",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &e1ap_T_Reordering_vals_ext, 0,
        NULL, HFILL }},
    { &hf_e1ap_transport_UP_Layer_Addresses_Info_To_Add_List,
      { "transport-UP-Layer-Addresses-Info-To-Add-List", "e1ap.transport_UP_Layer_Addresses_Info_To_Add_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_transport_UP_Layer_Addresses_Info_To_Remove_List,
      { "transport-UP-Layer-Addresses-Info-To-Remove-List", "e1ap.transport_UP_Layer_Addresses_Info_To_Remove_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_Transport_UP_Layer_Addresses_Info_To_Add_List_item,
      { "Transport-UP-Layer-Addresses-Info-To-Add-Item", "e1ap.Transport_UP_Layer_Addresses_Info_To_Add_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_iP_SecTransportLayerAddress,
      { "iP-SecTransportLayerAddress", "e1ap.iP_SecTransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_e1ap_gTPTransportLayerAddressesToAdd,
      { "gTPTransportLayerAddressesToAdd", "e1ap.gTPTransportLayerAddressesToAdd",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GTPTLAs", HFILL }},
    { &hf_e1ap_Transport_UP_Layer_Addresses_Info_To_Remove_List_item,
      { "Transport-UP-Layer-Addresses-Info-To-Remove-Item", "e1ap.Transport_UP_Layer_Addresses_Info_To_Remove_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_gTPTransportLayerAddressesToRemove,
      { "gTPTransportLayerAddressesToRemove", "e1ap.gTPTransportLayerAddressesToRemove",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GTPTLAs", HFILL }},
    { &hf_e1ap_bufferSize,
      { "bufferSize", "e1ap.bufferSize",
        FT_UINT32, BASE_DEC, VALS(e1ap_BufferSize_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_dictionary,
      { "dictionary", "e1ap.dictionary",
        FT_UINT32, BASE_DEC, VALS(e1ap_Dictionary_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_continueUDC,
      { "continueUDC", "e1ap.continueUDC",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_continueUDC_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_gNB_CU_CP_UE_E1AP_ID,
      { "gNB-CU-CP-UE-E1AP-ID", "e1ap.gNB_CU_CP_UE_E1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_gNB_CU_UP_UE_E1AP_ID,
      { "gNB-CU-UP-UE-E1AP-ID", "e1ap.gNB_CU_UP_UE_E1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_UESliceMaximumBitRateList_item,
      { "UESliceMaximumBitRateItem", "e1ap.UESliceMaximumBitRateItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_uESliceMaximumBitRateDL,
      { "uESliceMaximumBitRateDL", "e1ap.uESliceMaximumBitRateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_e1ap_UP_Parameters_item,
      { "UP-Parameters-Item", "e1ap.UP_Parameters_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_encryptionKey,
      { "encryptionKey", "e1ap.encryptionKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_integrityProtectionKey,
      { "integrityProtectionKey", "e1ap.integrityProtectionKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_gTPTunnel,
      { "gTPTunnel", "e1ap.gTPTunnel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_continueROHC_01,
      { "continueROHC", "e1ap.continueROHC",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_continueROHC_01_vals), 0,
        "T_continueROHC_01", HFILL }},
    { &hf_e1ap_userPlaneFailureType,
      { "userPlaneFailureType", "e1ap.userPlaneFailureType",
        FT_UINT32, BASE_DEC, VALS(e1ap_UserPlaneFailureType_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_protocolIEs,
      { "protocolIEs", "e1ap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_e1_Interface,
      { "e1-Interface", "e1ap.e1_Interface",
        FT_UINT32, BASE_DEC, VALS(e1ap_ResetAll_vals), 0,
        "ResetAll", HFILL }},
    { &hf_e1ap_partOfE1_Interface,
      { "partOfE1-Interface", "e1ap.partOfE1_Interface",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UE_associatedLogicalE1_ConnectionListRes", HFILL }},
    { &hf_e1ap_UE_associatedLogicalE1_ConnectionListRes_item,
      { "ProtocolIE-SingleContainer", "e1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_UE_associatedLogicalE1_ConnectionListResAck_item,
      { "ProtocolIE-SingleContainer", "e1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_SupportedPLMNs_List_item,
      { "SupportedPLMNs-Item", "e1ap.SupportedPLMNs_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_slice_Support_List,
      { "slice-Support-List", "e1ap.slice_Support_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_nR_CGI_Support_List,
      { "nR-CGI-Support-List", "e1ap.nR_CGI_Support_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_qoS_Parameters_Support_List,
      { "qoS-Parameters-Support-List", "e1ap.qoS_Parameters_Support_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_TNLA_To_Remove_List_item,
      { "GNB-CU-UP-TNLA-To-Remove-Item", "e1ap.GNB_CU_UP_TNLA_To_Remove_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_TNLA_To_Add_List_item,
      { "GNB-CU-CP-TNLA-To-Add-Item", "e1ap.GNB_CU_CP_TNLA_To_Add_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_TNLA_To_Remove_List_item,
      { "GNB-CU-CP-TNLA-To-Remove-Item", "e1ap.GNB_CU_CP_TNLA_To_Remove_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_TNLA_To_Update_List_item,
      { "GNB-CU-CP-TNLA-To-Update-Item", "e1ap.GNB_CU_CP_TNLA_To_Update_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_TNLA_Setup_List_item,
      { "GNB-CU-CP-TNLA-Setup-Item", "e1ap.GNB_CU_CP_TNLA_Setup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List_item,
      { "GNB-CU-CP-TNLA-Failed-To-Setup-Item", "e1ap.GNB_CU_CP_TNLA_Failed_To_Setup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_e_UTRAN_BearerContextSetupRequest,
      { "e-UTRAN-BearerContextSetupRequest", "e1ap.e_UTRAN_BearerContextSetupRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_nG_RAN_BearerContextSetupRequest,
      { "nG-RAN-BearerContextSetupRequest", "e1ap.nG_RAN_BearerContextSetupRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_e_UTRAN_BearerContextSetupResponse,
      { "e-UTRAN-BearerContextSetupResponse", "e1ap.e_UTRAN_BearerContextSetupResponse",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_nG_RAN_BearerContextSetupResponse,
      { "nG-RAN-BearerContextSetupResponse", "e1ap.nG_RAN_BearerContextSetupResponse",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_e_UTRAN_BearerContextModificationRequest,
      { "e-UTRAN-BearerContextModificationRequest", "e1ap.e_UTRAN_BearerContextModificationRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_nG_RAN_BearerContextModificationRequest,
      { "nG-RAN-BearerContextModificationRequest", "e1ap.nG_RAN_BearerContextModificationRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_e_UTRAN_BearerContextModificationResponse,
      { "e-UTRAN-BearerContextModificationResponse", "e1ap.e_UTRAN_BearerContextModificationResponse",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_nG_RAN_BearerContextModificationResponse,
      { "nG-RAN-BearerContextModificationResponse", "e1ap.nG_RAN_BearerContextModificationResponse",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_e_UTRAN_BearerContextModificationRequired,
      { "e-UTRAN-BearerContextModificationRequired", "e1ap.e_UTRAN_BearerContextModificationRequired",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_nG_RAN_BearerContextModificationRequired,
      { "nG-RAN-BearerContextModificationRequired", "e1ap.nG_RAN_BearerContextModificationRequired",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_e_UTRAN_BearerContextModificationConfirm,
      { "e-UTRAN-BearerContextModificationConfirm", "e1ap.e_UTRAN_BearerContextModificationConfirm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_nG_RAN_BearerContextModificationConfirm,
      { "nG-RAN-BearerContextModificationConfirm", "e1ap.nG_RAN_BearerContextModificationConfirm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_DRB_Status_List_item,
      { "DRB-Status-Item", "e1ap.DRB_Status_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_e_UTRAN_GNB_CU_UP_CounterCheckRequest,
      { "e-UTRAN-GNB-CU-UP-CounterCheckRequest", "e1ap.e_UTRAN_GNB_CU_UP_CounterCheckRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_nG_RAN_GNB_CU_UP_CounterCheckRequest,
      { "nG-RAN-GNB-CU-UP-CounterCheckRequest", "e1ap.nG_RAN_GNB_CU_UP_CounterCheckRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e1ap_privateIEs,
      { "privateIEs", "e1ap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_e1ap_DLUPTNLAddressToUpdateList_item,
      { "DLUPTNLAddressToUpdateItem", "e1ap.DLUPTNLAddressToUpdateItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_ULUPTNLAddressToUpdateList_item,
      { "ULUPTNLAddressToUpdateItem", "e1ap.ULUPTNLAddressToUpdateItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_IAB_Donor_CU_UPPSKInfo_item,
      { "IAB-Donor-CU-UPPSKInfo-Item", "e1ap.IAB_Donor_CU_UPPSKInfo_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_initiatingMessage,
      { "initiatingMessage", "e1ap.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_successfulOutcome,
      { "successfulOutcome", "e1ap.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "e1ap.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_initiatingMessagevalue,
      { "value", "e1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_e1ap_successfulOutcome_value,
      { "value", "e1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_e1ap_unsuccessfulOutcome_value,
      { "value", "e1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_e1ap,
    &ett_e1ap_PLMN_Identity,
    &ett_e1ap_TransportLayerAddress,
    &ett_e1ap_InterfacesToTrace,
    &ett_e1ap_MeasurementsToActivate,
    &ett_e1ap_ReportCharacteristics,
    &ett_e1ap_BurstArrivalTime,
    &ett_e1ap_PrivateIE_ID,
    &ett_e1ap_ProtocolIE_Container,
    &ett_e1ap_ProtocolIE_Field,
    &ett_e1ap_ProtocolExtensionContainer,
    &ett_e1ap_ProtocolExtensionField,
    &ett_e1ap_PrivateIE_Container,
    &ett_e1ap_PrivateIE_Field,
    &ett_e1ap_ActivityInformation,
    &ett_e1ap_AlternativeQoSParaSetList,
    &ett_e1ap_AlternativeQoSParaSetItem,
    &ett_e1ap_BCBearerContextToSetup,
    &ett_e1ap_BCBearerContextNGU_TNLInfoat5GC,
    &ett_e1ap_BCMRBSetupConfiguration,
    &ett_e1ap_BCMRBSetupConfiguration_Item,
    &ett_e1ap_BCBearerContextToSetupResponse,
    &ett_e1ap_BCBearerContextNGU_TNLInfoatNGRAN,
    &ett_e1ap_BCMRBSetupResponseList,
    &ett_e1ap_BCMRBSetupResponseList_Item,
    &ett_e1ap_BCBearerContextF1U_TNLInfoatCU,
    &ett_e1ap_BCMRBFailedList,
    &ett_e1ap_BCMRBFailedList_Item,
    &ett_e1ap_BCBearerContextToModify,
    &ett_e1ap_BCBearerContextNGU_TNLInfoatNGRAN_Request,
    &ett_e1ap_BCMRBModifyConfiguration,
    &ett_e1ap_BCMRBModifyConfiguration_Item,
    &ett_e1ap_BCBearerContextF1U_TNLInfoatDU,
    &ett_e1ap_BCMRBRemoveConfiguration,
    &ett_e1ap_BCBearerContextToModifyResponse,
    &ett_e1ap_BCMRBSetupModifyResponseList,
    &ett_e1ap_BCMRBSetupModifyResponseList_Item,
    &ett_e1ap_BCBearerContextToModifyRequired,
    &ett_e1ap_BCBearerContextToModifyConfirm,
    &ett_e1ap_Cause,
    &ett_e1ap_Cell_Group_Information,
    &ett_e1ap_Cell_Group_Information_Item,
    &ett_e1ap_CP_TNL_Information,
    &ett_e1ap_CriticalityDiagnostics,
    &ett_e1ap_CriticalityDiagnostics_IE_List,
    &ett_e1ap_CriticalityDiagnostics_IE_List_item,
    &ett_e1ap_DAPSRequestInfo,
    &ett_e1ap_Data_Forwarding_Information_Request,
    &ett_e1ap_Data_Forwarding_Information,
    &ett_e1ap_DataForwardingtoE_UTRANInformationList,
    &ett_e1ap_DataForwardingtoE_UTRANInformationListItem,
    &ett_e1ap_Data_Usage_per_PDU_Session_Report,
    &ett_e1ap_SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item,
    &ett_e1ap_Data_Usage_per_QoS_Flow_List,
    &ett_e1ap_Data_Usage_per_QoS_Flow_Item,
    &ett_e1ap_Data_Usage_Report_List,
    &ett_e1ap_Data_Usage_Report_Item,
    &ett_e1ap_DLDiscarding,
    &ett_e1ap_DLUPTNLAddressToUpdateItem,
    &ett_e1ap_DRB_Activity_List,
    &ett_e1ap_DRB_Activity_Item,
    &ett_e1ap_DRB_Confirm_Modified_List_EUTRAN,
    &ett_e1ap_DRB_Confirm_Modified_Item_EUTRAN,
    &ett_e1ap_DRB_Confirm_Modified_List_NG_RAN,
    &ett_e1ap_DRB_Confirm_Modified_Item_NG_RAN,
    &ett_e1ap_DRB_Failed_List_EUTRAN,
    &ett_e1ap_DRB_Failed_Item_EUTRAN,
    &ett_e1ap_DRB_Failed_Mod_List_EUTRAN,
    &ett_e1ap_DRB_Failed_Mod_Item_EUTRAN,
    &ett_e1ap_DRB_Failed_List_NG_RAN,
    &ett_e1ap_DRB_Failed_Item_NG_RAN,
    &ett_e1ap_DRB_Failed_Mod_List_NG_RAN,
    &ett_e1ap_DRB_Failed_Mod_Item_NG_RAN,
    &ett_e1ap_DRB_Failed_To_Modify_List_EUTRAN,
    &ett_e1ap_DRB_Failed_To_Modify_Item_EUTRAN,
    &ett_e1ap_DRB_Failed_To_Modify_List_NG_RAN,
    &ett_e1ap_DRB_Failed_To_Modify_Item_NG_RAN,
    &ett_e1ap_DRB_Measurement_Results_Information_List,
    &ett_e1ap_DRB_Measurement_Results_Information_Item,
    &ett_e1ap_DRB_Modified_List_EUTRAN,
    &ett_e1ap_DRB_Modified_Item_EUTRAN,
    &ett_e1ap_DRB_Modified_List_NG_RAN,
    &ett_e1ap_DRB_Modified_Item_NG_RAN,
    &ett_e1ap_DRB_Removed_Item,
    &ett_e1ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_QoS_Flow_Removed_Item,
    &ett_e1ap_DRB_Required_To_Modify_List_EUTRAN,
    &ett_e1ap_DRB_Required_To_Modify_Item_EUTRAN,
    &ett_e1ap_DRB_Required_To_Modify_List_NG_RAN,
    &ett_e1ap_DRB_Required_To_Modify_Item_NG_RAN,
    &ett_e1ap_DRB_Setup_List_EUTRAN,
    &ett_e1ap_DRB_Setup_Item_EUTRAN,
    &ett_e1ap_DRB_Setup_Mod_List_EUTRAN,
    &ett_e1ap_DRB_Setup_Mod_Item_EUTRAN,
    &ett_e1ap_DRB_Setup_List_NG_RAN,
    &ett_e1ap_DRB_Setup_Item_NG_RAN,
    &ett_e1ap_DRB_Setup_Mod_List_NG_RAN,
    &ett_e1ap_DRB_Setup_Mod_Item_NG_RAN,
    &ett_e1ap_DRB_Status_Item,
    &ett_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN,
    &ett_e1ap_DRBs_Subject_To_Counter_Check_Item_EUTRAN,
    &ett_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN,
    &ett_e1ap_DRBs_Subject_To_Counter_Check_Item_NG_RAN,
    &ett_e1ap_DRBs_Subject_To_Early_Forwarding_List,
    &ett_e1ap_DRBs_Subject_To_Early_Forwarding_Item,
    &ett_e1ap_DRB_To_Modify_List_EUTRAN,
    &ett_e1ap_DRB_To_Modify_Item_EUTRAN,
    &ett_e1ap_DRB_To_Modify_List_NG_RAN,
    &ett_e1ap_DRB_To_Modify_Item_NG_RAN,
    &ett_e1ap_DRB_To_Remove_List_EUTRAN,
    &ett_e1ap_DRB_To_Remove_Item_EUTRAN,
    &ett_e1ap_DRB_Required_To_Remove_List_EUTRAN,
    &ett_e1ap_DRB_Required_To_Remove_Item_EUTRAN,
    &ett_e1ap_DRB_To_Remove_List_NG_RAN,
    &ett_e1ap_DRB_To_Remove_Item_NG_RAN,
    &ett_e1ap_DRB_Required_To_Remove_List_NG_RAN,
    &ett_e1ap_DRB_Required_To_Remove_Item_NG_RAN,
    &ett_e1ap_DRB_To_Setup_List_EUTRAN,
    &ett_e1ap_DRB_To_Setup_Item_EUTRAN,
    &ett_e1ap_DRB_To_Setup_Mod_List_EUTRAN,
    &ett_e1ap_DRB_To_Setup_Mod_Item_EUTRAN,
    &ett_e1ap_DRB_To_Setup_List_NG_RAN,
    &ett_e1ap_DRB_To_Setup_Item_NG_RAN,
    &ett_e1ap_DRB_To_Setup_Mod_List_NG_RAN,
    &ett_e1ap_DRB_To_Setup_Mod_Item_NG_RAN,
    &ett_e1ap_DRB_Usage_Report_List,
    &ett_e1ap_DRB_Usage_Report_Item,
    &ett_e1ap_Dynamic5QIDescriptor,
    &ett_e1ap_EarlyForwardingCOUNTInfo,
    &ett_e1ap_ECNMarkingorCongestionInformationReportingRequest,
    &ett_e1ap_EHC_Common_Parameters,
    &ett_e1ap_EHC_Downlink_Parameters,
    &ett_e1ap_EHC_Uplink_Parameters,
    &ett_e1ap_EHC_Parameters,
    &ett_e1ap_Endpoint_IP_address_and_port,
    &ett_e1ap_EUTRANAllocationAndRetentionPriority,
    &ett_e1ap_ECGI,
    &ett_e1ap_ECGI_Support_List,
    &ett_e1ap_ECGI_Support_Item,
    &ett_e1ap_EUTRAN_QoS_Support_List,
    &ett_e1ap_EUTRAN_QoS_Support_Item,
    &ett_e1ap_EUTRAN_QoS,
    &ett_e1ap_ExtendedSliceSupportList,
    &ett_e1ap_FirstDLCount,
    &ett_e1ap_F1U_TNL_InfoAdded_List,
    &ett_e1ap_F1U_TNL_InfoAdded_Item,
    &ett_e1ap_F1U_TNL_InfoToAdd_List,
    &ett_e1ap_F1U_TNL_InfoToAdd_Item,
    &ett_e1ap_F1U_TNL_InfoAddedOrModified_List,
    &ett_e1ap_F1U_TNL_InfoAddedOrModified_Item,
    &ett_e1ap_F1U_TNL_InfoToAddOrModify_List,
    &ett_e1ap_F1U_TNL_InfoToAddOrModify_Item,
    &ett_e1ap_F1U_TNL_InfoToRelease_List,
    &ett_e1ap_F1U_TNL_InfoToRelease_Item,
    &ett_e1ap_GlobalMBSSessionID,
    &ett_e1ap_Extended_GNB_CU_CP_Name,
    &ett_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration,
    &ett_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration_Item,
    &ett_e1ap_GNB_CU_UP_MBS_Support_Info,
    &ett_e1ap_Extended_GNB_CU_UP_Name,
    &ett_e1ap_GNB_CU_CP_TNLA_Setup_Item,
    &ett_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_Item,
    &ett_e1ap_GNB_CU_CP_TNLA_To_Add_Item,
    &ett_e1ap_GNB_CU_CP_TNLA_To_Remove_Item,
    &ett_e1ap_GNB_CU_CP_TNLA_To_Update_Item,
    &ett_e1ap_GNB_CU_UP_TNLA_To_Remove_Item,
    &ett_e1ap_GBR_QosInformation,
    &ett_e1ap_GBR_QoSFlowInformation,
    &ett_e1ap_GTPTLAs,
    &ett_e1ap_GTPTLA_Item,
    &ett_e1ap_GTPTunnel,
    &ett_e1ap_HW_CapacityIndicator,
    &ett_e1ap_ImmediateMDT,
    &ett_e1ap_IAB_Donor_CU_UPPSKInfo_Item,
    &ett_e1ap_LocationDependentMBSNGUInformationAt5GC,
    &ett_e1ap_LocationDependentMBSNGUInformationAt5GC_Item,
    &ett_e1ap_LocationDependentMBSF1UInformationAtCU,
    &ett_e1ap_LocationDependentMBSF1UInformationAtCU_Item,
    &ett_e1ap_LocationDependentMBSF1UInformationAtDU,
    &ett_e1ap_LocationDependentMBSF1UInformationAtDU_Item,
    &ett_e1ap_LocationDependentMBSNGUInformationAtNGRAN,
    &ett_e1ap_LocationDependentMBSNGUInformationAtNGRAN_Item,
    &ett_e1ap_MaximumIPdatarate,
    &ett_e1ap_MBSF1UInformationAtCU,
    &ett_e1ap_MBSF1UInformationAtDU,
    &ett_e1ap_MBSNGUInformationAt5GC,
    &ett_e1ap_MBSNGUInformationAt5GC_Multicast,
    &ett_e1ap_MBSNGUInformationAtNGRAN,
    &ett_e1ap_MBSNGUInformationAtNGRAN_Request_List,
    &ett_e1ap_MBSNGUInformationAtNGRAN_Request_Item,
    &ett_e1ap_MBSSessionAssociatedInfoNonSupportToSupport,
    &ett_e1ap_MBSSessionAssociatedInformation,
    &ett_e1ap_MBSSessionAssociatedInformationList,
    &ett_e1ap_MBSSessionAssociatedInformation_Item,
    &ett_e1ap_MBS_Support_Info_ToAdd_List,
    &ett_e1ap_MBS_Support_Info_ToAdd_Item,
    &ett_e1ap_MBS_Support_Info_ToRemove_List,
    &ett_e1ap_MBSSessionResourceNotification,
    &ett_e1ap_MBS_DL_Data_Arrival,
    &ett_e1ap_MCBearerContext_Inactivity,
    &ett_e1ap_MBS_Support_Info_ToRemove_Item,
    &ett_e1ap_MCBearerContextToSetup,
    &ett_e1ap_MCMRBSetupConfiguration,
    &ett_e1ap_MCMRBSetupConfiguration_Item,
    &ett_e1ap_MCBearerContextToSetupResponse,
    &ett_e1ap_MCBearerContextNGU_TNLInfoatNGRAN,
    &ett_e1ap_MCMRBSetupResponseList,
    &ett_e1ap_MCMRBSetupResponseList_Item,
    &ett_e1ap_MCMRBFailedList,
    &ett_e1ap_MCMRBFailedList_Item,
    &ett_e1ap_MCBearerContextToModify,
    &ett_e1ap_MCBearerContextNGUTNLInfoat5GC,
    &ett_e1ap_MCBearerContextNGUTnlInfoatNGRANRequest,
    &ett_e1ap_MCMRBSetupModifyConfiguration,
    &ett_e1ap_MCMRBSetupModifyConfiguration_Item,
    &ett_e1ap_MCBearerContextF1UTNLInfoatDU,
    &ett_e1ap_MBSMulticastF1UContextDescriptor,
    &ett_e1ap_MCMRBRemoveConfiguration,
    &ett_e1ap_MCBearerContextToModifyResponse,
    &ett_e1ap_MCBearerContextNGU_TNLInfoatNGRANModifyResponse,
    &ett_e1ap_MCMRBSetupModifyResponseList,
    &ett_e1ap_MCMRBSetupModifyResponseList_Item,
    &ett_e1ap_MCBearerContextToModifyRequired,
    &ett_e1ap_MCMRBModifyRequiredConfiguration,
    &ett_e1ap_MCMRBModifyRequiredConfiguration_Item,
    &ett_e1ap_MCBearerContextToModifyConfirm,
    &ett_e1ap_MCMRBModifyConfirmList,
    &ett_e1ap_MCMRBModifyConfirmList_Item,
    &ett_e1ap_MCForwardingResourceRequest,
    &ett_e1ap_MRBForwardingResourceRequestList,
    &ett_e1ap_MRBForwardingResourceRequest_Item,
    &ett_e1ap_MCForwardingResourceIndication,
    &ett_e1ap_MRBForwardingResourceIndicationList,
    &ett_e1ap_MRBForwardingResourceIndication_Item,
    &ett_e1ap_MCForwardingResourceResponse,
    &ett_e1ap_MRBForwardingResourceResponseList,
    &ett_e1ap_MRBForwardingResourceResponse_Item,
    &ett_e1ap_MCForwardingResourceRelease,
    &ett_e1ap_MCForwardingResourceReleaseIndication,
    &ett_e1ap_MRB_ProgressInformation,
    &ett_e1ap_MRB_ProgressInformationSNs,
    &ett_e1ap_MRDC_Data_Usage_Report_Item,
    &ett_e1ap_MRDC_Usage_Information,
    &ett_e1ap_M4Configuration,
    &ett_e1ap_M6Configuration,
    &ett_e1ap_M7Configuration,
    &ett_e1ap_MDT_Configuration,
    &ett_e1ap_MDTMode,
    &ett_e1ap_MDTPLMNList,
    &ett_e1ap_MDTPLMNModificationList,
    &ett_e1ap_MT_SDT_Information,
    &ett_e1ap_MBS_ServiceArea,
    &ett_e1ap_MBS_ServiceAreaInformation,
    &ett_e1ap_MBS_ServiceAreaCellList,
    &ett_e1ap_MBS_ServiceAreaTAIList,
    &ett_e1ap_MBS_ServiceAreaTAIList_Item,
    &ett_e1ap_MBS_ServiceAreaInformationList,
    &ett_e1ap_MBS_ServiceAreaInformationItem,
    &ett_e1ap_NGRANAllocationAndRetentionPriority,
    &ett_e1ap_NG_RAN_QoS_Support_List,
    &ett_e1ap_NG_RAN_QoS_Support_Item,
    &ett_e1ap_Non_Dynamic5QIDescriptor,
    &ett_e1ap_NPNSupportInfo,
    &ett_e1ap_NPNSupportInfo_SNPN,
    &ett_e1ap_NPNContextInfo,
    &ett_e1ap_NPNContextInfo_SNPN,
    &ett_e1ap_NR_CGI,
    &ett_e1ap_NR_CGI_Support_List,
    &ett_e1ap_NR_CGI_Support_Item,
    &ett_e1ap_Extended_NR_CGI_Support_List,
    &ett_e1ap_Extended_NR_CGI_Support_Item,
    &ett_e1ap_N6JitterInformation,
    &ett_e1ap_PacketErrorRate,
    &ett_e1ap_PDCP_Configuration,
    &ett_e1ap_PDCP_Count,
    &ett_e1ap_PDU_Session_Resource_Data_Usage_List,
    &ett_e1ap_PDU_Session_Resource_Data_Usage_Item,
    &ett_e1ap_PDCP_SN_Status_Information,
    &ett_e1ap_DRBBStatusTransfer,
    &ett_e1ap_PDU_Session_Resource_Activity_List,
    &ett_e1ap_PDU_Session_Resource_Activity_Item,
    &ett_e1ap_PDU_Session_Resource_Confirm_Modified_List,
    &ett_e1ap_PDU_Session_Resource_Confirm_Modified_Item,
    &ett_e1ap_PDU_Session_Resource_Failed_List,
    &ett_e1ap_PDU_Session_Resource_Failed_Item,
    &ett_e1ap_PDU_Session_Resource_Failed_Mod_List,
    &ett_e1ap_PDU_Session_Resource_Failed_Mod_Item,
    &ett_e1ap_PDU_Session_Resource_Failed_To_Modify_List,
    &ett_e1ap_PDU_Session_Resource_Failed_To_Modify_Item,
    &ett_e1ap_PDU_Session_Resource_Modified_List,
    &ett_e1ap_PDU_Session_Resource_Modified_Item,
    &ett_e1ap_PDU_Session_Resource_Required_To_Modify_List,
    &ett_e1ap_PDU_Session_Resource_Required_To_Modify_Item,
    &ett_e1ap_PDU_Session_Resource_Setup_List,
    &ett_e1ap_PDU_Session_Resource_Setup_Item,
    &ett_e1ap_PDU_Session_Resource_Setup_Mod_List,
    &ett_e1ap_PDU_Session_Resource_Setup_Mod_Item,
    &ett_e1ap_PDU_Session_Resource_To_Modify_List,
    &ett_e1ap_PDU_Session_Resource_To_Modify_Item,
    &ett_e1ap_PDU_Session_Resource_To_Remove_List,
    &ett_e1ap_PDU_Session_Resource_To_Remove_Item,
    &ett_e1ap_PDU_Session_Resource_To_Setup_List,
    &ett_e1ap_PDU_Session_Resource_To_Setup_Item,
    &ett_e1ap_PDU_Session_Resource_To_Setup_Mod_List,
    &ett_e1ap_PDU_Session_Resource_To_Setup_Mod_Item,
    &ett_e1ap_PDU_Session_To_Notify_List,
    &ett_e1ap_PDU_Session_To_Notify_Item,
    &ett_e1ap_PDUSetQoSParameters,
    &ett_e1ap_PDUSetQoSInformation,
    &ett_e1ap_QoS_Characteristics,
    &ett_e1ap_QoS_Flow_List,
    &ett_e1ap_QoS_Flow_Item,
    &ett_e1ap_QoS_Flow_Failed_List,
    &ett_e1ap_QoS_Flow_Failed_Item,
    &ett_e1ap_QoS_Flow_Mapping_List,
    &ett_e1ap_QoS_Flow_Mapping_Item,
    &ett_e1ap_QoS_Parameters_Support_List,
    &ett_e1ap_QoS_Flow_QoS_Parameter_List,
    &ett_e1ap_QoS_Flow_QoS_Parameter_Item,
    &ett_e1ap_QoSFlowLevelQoSParameters,
    &ett_e1ap_QoS_Flow_Removed_Item,
    &ett_e1ap_QoS_Flows_to_be_forwarded_List,
    &ett_e1ap_QoS_Flows_to_be_forwarded_Item,
    &ett_e1ap_QoS_Mapping_Information,
    &ett_e1ap_DataForwardingtoNG_RANQoSFlowInformationList,
    &ett_e1ap_DataForwardingtoNG_RANQoSFlowInformationList_Item,
    &ett_e1ap_RedundantPDUSessionInformation,
    &ett_e1ap_RetainabilityMeasurementsInfo,
    &ett_e1ap_ROHC_Parameters,
    &ett_e1ap_ROHC,
    &ett_e1ap_SecurityAlgorithm,
    &ett_e1ap_SecurityIndication,
    &ett_e1ap_SecurityInformation,
    &ett_e1ap_SecurityResult,
    &ett_e1ap_Slice_Support_List,
    &ett_e1ap_Slice_Support_Item,
    &ett_e1ap_SNSSAI,
    &ett_e1ap_SDAP_Configuration,
    &ett_e1ap_TNL_AvailableCapacityIndicator,
    &ett_e1ap_TSCTrafficCharacteristics,
    &ett_e1ap_TSCAssistanceInformation,
    &ett_e1ap_TraceActivation,
    &ett_e1ap_T_ReorderingTimer,
    &ett_e1ap_Transport_Layer_Address_Info,
    &ett_e1ap_Transport_UP_Layer_Addresses_Info_To_Add_List,
    &ett_e1ap_Transport_UP_Layer_Addresses_Info_To_Add_Item,
    &ett_e1ap_Transport_UP_Layer_Addresses_Info_To_Remove_List,
    &ett_e1ap_Transport_UP_Layer_Addresses_Info_To_Remove_Item,
    &ett_e1ap_UDC_Parameters,
    &ett_e1ap_UE_associatedLogicalE1_ConnectionItem,
    &ett_e1ap_UESliceMaximumBitRateList,
    &ett_e1ap_UESliceMaximumBitRateItem,
    &ett_e1ap_ULUPTNLAddressToUpdateItem,
    &ett_e1ap_UP_Parameters,
    &ett_e1ap_UP_Parameters_Item,
    &ett_e1ap_UPSecuritykey,
    &ett_e1ap_UP_TNL_Information,
    &ett_e1ap_UplinkOnlyROHC,
    &ett_e1ap_UserPlaneFailureIndication,
    &ett_e1ap_Reset,
    &ett_e1ap_ResetType,
    &ett_e1ap_UE_associatedLogicalE1_ConnectionListRes,
    &ett_e1ap_ResetAcknowledge,
    &ett_e1ap_UE_associatedLogicalE1_ConnectionListResAck,
    &ett_e1ap_ErrorIndication,
    &ett_e1ap_GNB_CU_UP_E1SetupRequest,
    &ett_e1ap_SupportedPLMNs_List,
    &ett_e1ap_SupportedPLMNs_Item,
    &ett_e1ap_GNB_CU_UP_E1SetupResponse,
    &ett_e1ap_GNB_CU_UP_E1SetupFailure,
    &ett_e1ap_GNB_CU_CP_E1SetupRequest,
    &ett_e1ap_GNB_CU_CP_E1SetupResponse,
    &ett_e1ap_GNB_CU_CP_E1SetupFailure,
    &ett_e1ap_GNB_CU_UP_ConfigurationUpdate,
    &ett_e1ap_GNB_CU_UP_TNLA_To_Remove_List,
    &ett_e1ap_GNB_CU_UP_ConfigurationUpdateAcknowledge,
    &ett_e1ap_GNB_CU_UP_ConfigurationUpdateFailure,
    &ett_e1ap_GNB_CU_CP_ConfigurationUpdate,
    &ett_e1ap_GNB_CU_CP_TNLA_To_Add_List,
    &ett_e1ap_GNB_CU_CP_TNLA_To_Remove_List,
    &ett_e1ap_GNB_CU_CP_TNLA_To_Update_List,
    &ett_e1ap_GNB_CU_CP_ConfigurationUpdateAcknowledge,
    &ett_e1ap_GNB_CU_CP_TNLA_Setup_List,
    &ett_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List,
    &ett_e1ap_GNB_CU_CP_ConfigurationUpdateFailure,
    &ett_e1ap_E1ReleaseRequest,
    &ett_e1ap_E1ReleaseResponse,
    &ett_e1ap_BearerContextSetupRequest,
    &ett_e1ap_System_BearerContextSetupRequest,
    &ett_e1ap_BearerContextSetupResponse,
    &ett_e1ap_System_BearerContextSetupResponse,
    &ett_e1ap_BearerContextSetupFailure,
    &ett_e1ap_BearerContextModificationRequest,
    &ett_e1ap_System_BearerContextModificationRequest,
    &ett_e1ap_BearerContextModificationResponse,
    &ett_e1ap_System_BearerContextModificationResponse,
    &ett_e1ap_BearerContextModificationFailure,
    &ett_e1ap_BearerContextModificationRequired,
    &ett_e1ap_System_BearerContextModificationRequired,
    &ett_e1ap_BearerContextModificationConfirm,
    &ett_e1ap_System_BearerContextModificationConfirm,
    &ett_e1ap_BearerContextReleaseCommand,
    &ett_e1ap_BearerContextReleaseComplete,
    &ett_e1ap_BearerContextReleaseRequest,
    &ett_e1ap_DRB_Status_List,
    &ett_e1ap_BearerContextInactivityNotification,
    &ett_e1ap_DLDataNotification,
    &ett_e1ap_ULDataNotification,
    &ett_e1ap_DataUsageReport,
    &ett_e1ap_GNB_CU_UP_CounterCheckRequest,
    &ett_e1ap_System_GNB_CU_UP_CounterCheckRequest,
    &ett_e1ap_GNB_CU_UP_StatusIndication,
    &ett_e1ap_GNB_CU_CPMeasurementResultsInformation,
    &ett_e1ap_MRDC_DataUsageReport,
    &ett_e1ap_TraceStart,
    &ett_e1ap_DeactivateTrace,
    &ett_e1ap_CellTrafficTrace,
    &ett_e1ap_PrivateMessage,
    &ett_e1ap_ResourceStatusRequest,
    &ett_e1ap_ResourceStatusResponse,
    &ett_e1ap_ResourceStatusFailure,
    &ett_e1ap_ResourceStatusUpdate,
    &ett_e1ap_IAB_UPTNLAddressUpdate,
    &ett_e1ap_DLUPTNLAddressToUpdateList,
    &ett_e1ap_IAB_UPTNLAddressUpdateAcknowledge,
    &ett_e1ap_ULUPTNLAddressToUpdateList,
    &ett_e1ap_IAB_UPTNLAddressUpdateFailure,
    &ett_e1ap_EarlyForwardingSNTransfer,
    &ett_e1ap_IABPSKNotification,
    &ett_e1ap_IAB_Donor_CU_UPPSKInfo,
    &ett_e1ap_BCBearerContextSetupRequest,
    &ett_e1ap_BCBearerContextSetupResponse,
    &ett_e1ap_BCBearerContextSetupFailure,
    &ett_e1ap_BCBearerContextModificationRequest,
    &ett_e1ap_BCBearerContextModificationResponse,
    &ett_e1ap_BCBearerContextModificationFailure,
    &ett_e1ap_BCBearerContextModificationRequired,
    &ett_e1ap_BCBearerContextModificationConfirm,
    &ett_e1ap_BCBearerContextReleaseCommand,
    &ett_e1ap_BCBearerContextReleaseComplete,
    &ett_e1ap_BCBearerContextReleaseRequest,
    &ett_e1ap_MCBearerContextSetupRequest,
    &ett_e1ap_MCBearerContextSetupResponse,
    &ett_e1ap_MCBearerContextSetupFailure,
    &ett_e1ap_MCBearerContextModificationRequest,
    &ett_e1ap_MCBearerContextModificationResponse,
    &ett_e1ap_MCBearerContextModificationFailure,
    &ett_e1ap_MCBearerContextModificationRequired,
    &ett_e1ap_MCBearerContextModificationConfirm,
    &ett_e1ap_MCBearerContextReleaseCommand,
    &ett_e1ap_MCBearerContextReleaseComplete,
    &ett_e1ap_MCBearerContextReleaseRequest,
    &ett_e1ap_MCBearerNotification,
    &ett_e1ap_E1AP_PDU,
    &ett_e1ap_InitiatingMessage,
    &ett_e1ap_SuccessfulOutcome,
    &ett_e1ap_UnsuccessfulOutcome,
  };

  /* Register protocol */
  proto_e1ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_e1ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  e1ap_handle = register_dissector("e1ap", dissect_e1ap, proto_e1ap);
  e1ap_tcp_handle = register_dissector("e1ap_tcp", dissect_e1ap_tcp, proto_e1ap);

  /* Register dissector tables */
  e1ap_ies_dissector_table = register_dissector_table("e1ap.ies", "E1AP-PROTOCOL-IES", proto_e1ap, FT_UINT32, BASE_DEC);
  e1ap_extension_dissector_table = register_dissector_table("e1ap.extension", "E1AP-PROTOCOL-EXTENSION", proto_e1ap, FT_UINT32, BASE_DEC);
  e1ap_proc_imsg_dissector_table = register_dissector_table("e1ap.proc.imsg", "E1AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_e1ap, FT_UINT32, BASE_DEC);
  e1ap_proc_sout_dissector_table = register_dissector_table("e1ap.proc.sout", "E1AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_e1ap, FT_UINT32, BASE_DEC);
  e1ap_proc_uout_dissector_table = register_dissector_table("e1ap.proc.uout", "E1AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_e1ap, FT_UINT32, BASE_DEC);
}

void
proto_reg_handoff_e1ap(void)
{
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_E1AP, e1ap_handle);
  dissector_add_uint_with_preference("tcp.port", 0, e1ap_tcp_handle);
  dissector_add_uint("sctp.ppi", E1AP_PROTOCOL_ID, e1ap_handle);
  dissector_add_uint("e1ap.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_gNB_CU_CP_UE_E1AP_ID, create_dissector_handle(dissect_GNB_CU_CP_UE_E1AP_ID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_gNB_CU_UP_UE_E1AP_ID, create_dissector_handle(dissect_GNB_CU_UP_UE_E1AP_ID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_ResetType, create_dissector_handle(dissect_ResetType_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_UE_associatedLogicalE1_ConnectionItem, create_dissector_handle(dissect_UE_associatedLogicalE1_ConnectionItem_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_UE_associatedLogicalE1_ConnectionListResAck, create_dissector_handle(dissect_UE_associatedLogicalE1_ConnectionListResAck_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_gNB_CU_UP_ID, create_dissector_handle(dissect_GNB_CU_UP_ID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_gNB_CU_UP_Name, create_dissector_handle(dissect_GNB_CU_UP_Name_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_gNB_CU_CP_Name, create_dissector_handle(dissect_GNB_CU_CP_Name_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_CNSupport, create_dissector_handle(dissect_CNSupport_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_SupportedPLMNs, create_dissector_handle(dissect_SupportedPLMNs_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_TimeToWait, create_dissector_handle(dissect_TimeToWait_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_SecurityInformation, create_dissector_handle(dissect_SecurityInformation_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_UEDLAggregateMaximumBitRate, create_dissector_handle(dissect_BitRate_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_System_BearerContextSetupRequest, create_dissector_handle(dissect_System_BearerContextSetupRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_System_BearerContextSetupResponse, create_dissector_handle(dissect_System_BearerContextSetupResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_BearerContextStatusChange, create_dissector_handle(dissect_BearerContextStatusChange_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_System_BearerContextModificationRequest, create_dissector_handle(dissect_System_BearerContextModificationRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_System_BearerContextModificationResponse, create_dissector_handle(dissect_System_BearerContextModificationResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_System_BearerContextModificationConfirm, create_dissector_handle(dissect_System_BearerContextModificationConfirm_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_System_BearerContextModificationRequired, create_dissector_handle(dissect_System_BearerContextModificationRequired_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_Status_List, create_dissector_handle(dissect_DRB_Status_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_ActivityNotificationLevel, create_dissector_handle(dissect_ActivityNotificationLevel_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_ActivityInformation, create_dissector_handle(dissect_ActivityInformation_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_Data_Usage_Report_List, create_dissector_handle(dissect_Data_Usage_Report_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_New_UL_TNL_Information_Required, create_dissector_handle(dissect_New_UL_TNL_Information_Required_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_GNB_CU_CP_TNLA_To_Add_List, create_dissector_handle(dissect_GNB_CU_CP_TNLA_To_Add_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_GNB_CU_CP_TNLA_To_Remove_List, create_dissector_handle(dissect_GNB_CU_CP_TNLA_To_Remove_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_GNB_CU_CP_TNLA_To_Update_List, create_dissector_handle(dissect_GNB_CU_CP_TNLA_To_Update_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_GNB_CU_CP_TNLA_Setup_List, create_dissector_handle(dissect_GNB_CU_CP_TNLA_Setup_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_GNB_CU_CP_TNLA_Failed_To_Setup_List, create_dissector_handle(dissect_GNB_CU_CP_TNLA_Failed_To_Setup_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_To_Setup_List_EUTRAN, create_dissector_handle(dissect_DRB_To_Setup_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_To_Modify_List_EUTRAN, create_dissector_handle(dissect_DRB_To_Modify_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_To_Remove_List_EUTRAN, create_dissector_handle(dissect_DRB_To_Remove_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_Required_To_Modify_List_EUTRAN, create_dissector_handle(dissect_DRB_Required_To_Modify_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_Required_To_Remove_List_EUTRAN, create_dissector_handle(dissect_DRB_Required_To_Remove_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_Setup_List_EUTRAN, create_dissector_handle(dissect_DRB_Setup_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_Failed_List_EUTRAN, create_dissector_handle(dissect_DRB_Failed_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_Modified_List_EUTRAN, create_dissector_handle(dissect_DRB_Modified_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_Failed_To_Modify_List_EUTRAN, create_dissector_handle(dissect_DRB_Failed_To_Modify_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_Confirm_Modified_List_EUTRAN, create_dissector_handle(dissect_DRB_Confirm_Modified_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_Resource_To_Setup_List, create_dissector_handle(dissect_PDU_Session_Resource_To_Setup_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_Resource_To_Modify_List, create_dissector_handle(dissect_PDU_Session_Resource_To_Modify_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_Resource_To_Remove_List, create_dissector_handle(dissect_PDU_Session_Resource_To_Remove_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_Resource_Required_To_Modify_List, create_dissector_handle(dissect_PDU_Session_Resource_Required_To_Modify_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_Resource_Setup_List, create_dissector_handle(dissect_PDU_Session_Resource_Setup_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_Resource_Failed_List, create_dissector_handle(dissect_PDU_Session_Resource_Failed_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_Resource_Modified_List, create_dissector_handle(dissect_PDU_Session_Resource_Modified_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_Resource_Failed_To_Modify_List, create_dissector_handle(dissect_PDU_Session_Resource_Failed_To_Modify_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_Resource_Confirm_Modified_List, create_dissector_handle(dissect_PDU_Session_Resource_Confirm_Modified_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_To_Setup_Mod_List_EUTRAN, create_dissector_handle(dissect_DRB_To_Setup_Mod_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_Setup_Mod_List_EUTRAN, create_dissector_handle(dissect_DRB_Setup_Mod_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_Failed_Mod_List_EUTRAN, create_dissector_handle(dissect_DRB_Failed_Mod_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_Resource_Setup_Mod_List, create_dissector_handle(dissect_PDU_Session_Resource_Setup_Mod_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_Resource_Failed_Mod_List, create_dissector_handle(dissect_PDU_Session_Resource_Failed_Mod_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_Resource_To_Setup_Mod_List, create_dissector_handle(dissect_PDU_Session_Resource_To_Setup_Mod_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_TransactionID, create_dissector_handle(dissect_TransactionID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_Serving_PLMN, create_dissector_handle(dissect_PLMN_Identity_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_UE_Inactivity_Timer, create_dissector_handle(dissect_Inactivity_Timer_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_System_GNB_CU_UP_CounterCheckRequest, create_dissector_handle(dissect_System_GNB_CU_UP_CounterCheckRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRBs_Subject_To_Counter_Check_List_EUTRAN, create_dissector_handle(dissect_DRBs_Subject_To_Counter_Check_List_EUTRAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRBs_Subject_To_Counter_Check_List_NG_RAN, create_dissector_handle(dissect_DRBs_Subject_To_Counter_Check_List_NG_RAN_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PPI, create_dissector_handle(dissect_PPI_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_gNB_CU_UP_Capacity, create_dissector_handle(dissect_GNB_CU_UP_Capacity_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_GNB_CU_UP_OverloadInformation, create_dissector_handle(dissect_GNB_CU_UP_OverloadInformation_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_UEDLMaximumIntegrityProtectedDataRate, create_dissector_handle(dissect_BitRate_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_To_Notify_List, create_dissector_handle(dissect_PDU_Session_To_Notify_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PDU_Session_Resource_Data_Usage_List, create_dissector_handle(dissect_PDU_Session_Resource_Data_Usage_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DataDiscardRequired, create_dissector_handle(dissect_DataDiscardRequired_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_GNB_CU_UP_TNLA_To_Remove_List, create_dissector_handle(dissect_GNB_CU_UP_TNLA_To_Remove_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_endpoint_IP_Address_and_Port, create_dissector_handle(dissect_Endpoint_IP_address_and_port_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_RANUEID, create_dissector_handle(dissect_RANUEID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_GNB_DU_ID, create_dissector_handle(dissect_GNB_DU_ID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_TraceActivation, create_dissector_handle(dissect_TraceActivation_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_TraceID, create_dissector_handle(dissect_TraceID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_SubscriberProfileIDforRFP, create_dissector_handle(dissect_SubscriberProfileIDforRFP_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_AdditionalRRMPriorityIndex, create_dissector_handle(dissect_AdditionalRRMPriorityIndex_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_RetainabilityMeasurementsInfo, create_dissector_handle(dissect_RetainabilityMeasurementsInfo_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_Transport_Layer_Address_Info, create_dissector_handle(dissect_Transport_Layer_Address_Info_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_gNB_CU_CP_Measurement_ID, create_dissector_handle(dissect_Measurement_ID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_gNB_CU_UP_Measurement_ID, create_dissector_handle(dissect_Measurement_ID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_RegistrationRequest, create_dissector_handle(dissect_RegistrationRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_ReportCharacteristics, create_dissector_handle(dissect_ReportCharacteristics_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_ReportingPeriodicity, create_dissector_handle(dissect_ReportingPeriodicity_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_TNL_AvailableCapacityIndicator, create_dissector_handle(dissect_TNL_AvailableCapacityIndicator_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_HW_CapacityIndicator, create_dissector_handle(dissect_HW_CapacityIndicator_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DLUPTNLAddressToUpdateList, create_dissector_handle(dissect_DLUPTNLAddressToUpdateList_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_ULUPTNLAddressToUpdateList, create_dissector_handle(dissect_ULUPTNLAddressToUpdateList_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_NPNContextInfo, create_dissector_handle(dissect_NPNContextInfo_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_ManagementBasedMDTPLMNList, create_dissector_handle(dissect_MDTPLMNList_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_TraceCollectionEntityIPAddress, create_dissector_handle(dissect_TransportLayerAddress_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_PrivacyIndicator, create_dissector_handle(dissect_PrivacyIndicator_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_URIaddress, create_dissector_handle(dissect_URIaddress_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRBs_Subject_To_Early_Forwarding_List, create_dissector_handle(dissect_DRBs_Subject_To_Early_Forwarding_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_CHOInitiation, create_dissector_handle(dissect_CHOInitiation_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DRB_Measurement_Results_Information_List, create_dissector_handle(dissect_DRB_Measurement_Results_Information_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_Extended_GNB_CU_CP_Name, create_dissector_handle(dissect_Extended_GNB_CU_CP_Name_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_Extended_GNB_CU_UP_Name, create_dissector_handle(dissect_Extended_GNB_CU_UP_Name_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_AdditionalHandoverInfo, create_dissector_handle(dissect_AdditionalHandoverInfo_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_DirectForwardingPathAvailability, create_dissector_handle(dissect_DirectForwardingPathAvailability_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_IAB_Donor_CU_UPPSKInfo, create_dissector_handle(dissect_IAB_Donor_CU_UPPSKInfo_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_MDTPollutedMeasurementIndicator, create_dissector_handle(dissect_MDTPollutedMeasurementIndicator_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_UESliceMaximumBitRateList, create_dissector_handle(dissect_UESliceMaximumBitRateList_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_SCGActivationStatus, create_dissector_handle(dissect_SCGActivationStatus_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_GNB_CU_CP_MBS_E1AP_ID, create_dissector_handle(dissect_GNB_CU_CP_MBS_E1AP_ID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_GNB_CU_UP_MBS_E1AP_ID, create_dissector_handle(dissect_GNB_CU_UP_MBS_E1AP_ID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_GlobalMBSSessionID, create_dissector_handle(dissect_GlobalMBSSessionID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_BCBearerContextToSetup, create_dissector_handle(dissect_BCBearerContextToSetup_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_BCBearerContextToSetupResponse, create_dissector_handle(dissect_BCBearerContextToSetupResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_BCBearerContextToModify, create_dissector_handle(dissect_BCBearerContextToModify_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_BCBearerContextToModifyResponse, create_dissector_handle(dissect_BCBearerContextToModifyResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_BCBearerContextToModifyRequired, create_dissector_handle(dissect_BCBearerContextToModifyRequired_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_BCBearerContextToModifyConfirm, create_dissector_handle(dissect_BCBearerContextToModifyConfirm_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_MCBearerContextToSetup, create_dissector_handle(dissect_MCBearerContextToSetup_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_MCBearerContextToSetupResponse, create_dissector_handle(dissect_MCBearerContextToSetupResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_MCBearerContextToModify, create_dissector_handle(dissect_MCBearerContextToModify_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_MCBearerContextToModifyResponse, create_dissector_handle(dissect_MCBearerContextToModifyResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_MCBearerContextToModifyRequired, create_dissector_handle(dissect_MCBearerContextToModifyRequired_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_MCBearerContextToModifyConfirm, create_dissector_handle(dissect_MCBearerContextToModifyConfirm_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_MBSMulticastF1UContextDescriptor, create_dissector_handle(dissect_MBSMulticastF1UContextDescriptor_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_gNB_CU_UP_MBS_Support_Info, create_dissector_handle(dissect_GNB_CU_UP_MBS_Support_Info_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_SDTContinueROHC, create_dissector_handle(dissect_SDTContinueROHC_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_ManagementBasedMDTPLMNModificationList, create_dissector_handle(dissect_MDTPLMNModificationList_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_InactivityInformationRequest, create_dissector_handle(dissect_InactivityInformationRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_UEInactivityInformation, create_dissector_handle(dissect_UEInactivityInformation_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_MBSSessionResourceNotification, create_dissector_handle(dissect_MBSSessionResourceNotification_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_MT_SDT_Information, create_dissector_handle(dissect_MT_SDT_Information_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_MT_SDT_Information_Request, create_dissector_handle(dissect_MT_SDT_Information_Request_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_SDT_data_size_threshold, create_dissector_handle(dissect_SDT_data_size_threshold_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_SDT_data_size_threshold_Crossed, create_dissector_handle(dissect_SDT_data_size_threshold_Crossed_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_AssociatedSessionID, create_dissector_handle(dissect_AssociatedSessionID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.ies", id_MBS_ServiceArea, create_dissector_handle(dissect_MBS_ServiceArea_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_SNSSAI, create_dissector_handle(dissect_SNSSAI_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_OldQoSFlowMap_ULendmarkerexpected, create_dissector_handle(dissect_QoS_Flow_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_DRB_QoS, create_dissector_handle(dissect_QoSFlowLevelQoSParameters_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_TNLAssociationTransportLayerAddressgNBCUUP, create_dissector_handle(dissect_CP_TNL_Information_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_CommonNetworkInstance, create_dissector_handle(dissect_CommonNetworkInstance_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_NetworkInstance, create_dissector_handle(dissect_NetworkInstance_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_QoSFlowMappingIndication, create_dissector_handle(dissect_QoS_Flow_Mapping_Indication_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_QoSMonitoringRequest, create_dissector_handle(dissect_QosMonitoringRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_PDCP_StatusReportIndication, create_dissector_handle(dissect_PDCP_StatusReportIndication_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_RedundantCommonNetworkInstance, create_dissector_handle(dissect_CommonNetworkInstance_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_redundant_nG_UL_UP_TNL_Information, create_dissector_handle(dissect_UP_TNL_Information_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_redundant_nG_DL_UP_TNL_Information, create_dissector_handle(dissect_UP_TNL_Information_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_RedundantQosFlowIndicator, create_dissector_handle(dissect_RedundantQoSFlowIndicator_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_TSCTrafficCharacteristics, create_dissector_handle(dissect_TSCTrafficCharacteristics_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_CNPacketDelayBudgetDownlink, create_dissector_handle(dissect_ExtendedPacketDelayBudget_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_CNPacketDelayBudgetUplink, create_dissector_handle(dissect_ExtendedPacketDelayBudget_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_ExtendedPacketDelayBudget, create_dissector_handle(dissect_ExtendedPacketDelayBudget_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_AdditionalPDCPduplicationInformation, create_dissector_handle(dissect_AdditionalPDCPduplicationInformation_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_RedundantPDUSessionInformation, create_dissector_handle(dissect_RedundantPDUSessionInformation_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_RedundantPDUSessionInformation_used, create_dissector_handle(dissect_RedundantPDUSessionInformation_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_QoS_Mapping_Information, create_dissector_handle(dissect_QoS_Mapping_Information_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_NPNSupportInfo, create_dissector_handle(dissect_NPNSupportInfo_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_MDTConfiguration, create_dissector_handle(dissect_MDT_Configuration_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_TraceCollectionEntityURI, create_dissector_handle(dissect_URIaddress_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_EHC_Parameters, create_dissector_handle(dissect_EHC_Parameters_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_DAPSRequestInfo, create_dissector_handle(dissect_DAPSRequestInfo_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_EarlyForwardingCOUNTReq, create_dissector_handle(dissect_EarlyForwardingCOUNTReq_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_EarlyForwardingCOUNTInfo, create_dissector_handle(dissect_EarlyForwardingCOUNTInfo_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_AlternativeQoSParaSetList, create_dissector_handle(dissect_AlternativeQoSParaSetList_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_ExtendedSliceSupportList, create_dissector_handle(dissect_ExtendedSliceSupportList_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_MCG_OfferedGBRQoSFlowInfo, create_dissector_handle(dissect_GBR_QoSFlowInformation_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_Number_of_tunnels, create_dissector_handle(dissect_Number_of_tunnels_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_DataForwardingtoE_UTRANInformationList, create_dissector_handle(dissect_DataForwardingtoE_UTRANInformationList_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_QosMonitoringReportingFrequency, create_dissector_handle(dissect_QosMonitoringReportingFrequency_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_QoSMonitoringDisabled, create_dissector_handle(dissect_QosMonitoringDisabled_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_Extended_NR_CGI_Support_List, create_dissector_handle(dissect_Extended_NR_CGI_Support_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_DataForwardingtoNG_RANQoSFlowInformationList, create_dissector_handle(dissect_DataForwardingtoNG_RANQoSFlowInformationList_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_MaxCIDEHCDL, create_dissector_handle(dissect_MaxCIDEHCDL_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_ignoreMappingRuleIndication, create_dissector_handle(dissect_IgnoreMappingRuleIndication_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_EarlyDataForwardingIndicator, create_dissector_handle(dissect_EarlyDataForwardingIndicator_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_QoSFlowsDRBRemapping, create_dissector_handle(dissect_QoS_Flows_DRB_Remapping_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_DataForwardingSourceIPAddress, create_dissector_handle(dissect_TransportLayerAddress_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_SecurityIndicationModify, create_dissector_handle(dissect_SecurityIndication_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_ECGI_Support_List, create_dissector_handle(dissect_ECGI_Support_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_M4ReportAmount, create_dissector_handle(dissect_M4ReportAmount_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_M6ReportAmount, create_dissector_handle(dissect_M6ReportAmount_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_M7ReportAmount, create_dissector_handle(dissect_M7ReportAmount_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_PDUSession_PairID, create_dissector_handle(dissect_PDUSession_PairID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_SurvivalTime, create_dissector_handle(dissect_SurvivalTime_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_UDC_Parameters, create_dissector_handle(dissect_UDC_Parameters_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_SecurityIndication, create_dissector_handle(dissect_SecurityIndication_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_SecurityResult, create_dissector_handle(dissect_SecurityResult_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_SDTindicatorSetup, create_dissector_handle(dissect_SDTindicatorSetup_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_SDTindicatorMod, create_dissector_handle(dissect_SDTindicatorMod_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_DiscardTimerExtended, create_dissector_handle(dissect_DiscardTimerExtended_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_MCForwardingResourceRequest, create_dissector_handle(dissect_MCForwardingResourceRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_MCForwardingResourceIndication, create_dissector_handle(dissect_MCForwardingResourceIndication_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_MCForwardingResourceResponse, create_dissector_handle(dissect_MCForwardingResourceResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_MCForwardingResourceRelease, create_dissector_handle(dissect_MCForwardingResourceRelease_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_MCForwardingResourceReleaseIndication, create_dissector_handle(dissect_MCForwardingResourceReleaseIndication_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_PDCP_COUNT_Reset, create_dissector_handle(dissect_PDCP_COUNT_Reset_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_MBSSessionAssociatedInfoNonSupportToSupport, create_dissector_handle(dissect_MBSSessionAssociatedInfoNonSupportToSupport_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_VersionID, create_dissector_handle(dissect_VersionID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_MBSAreaSessionID, create_dissector_handle(dissect_MBSAreaSessionID_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_Secondary_PDU_Session_Data_Forwarding_Information, create_dissector_handle(dissect_Data_Forwarding_Information_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_MCBearerContextInactivityTimer, create_dissector_handle(dissect_Inactivity_Timer_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_MCBearerContextStatusChange, create_dissector_handle(dissect_MCBearerContextStatusChange_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_SpecialTriggeringPurpose, create_dissector_handle(dissect_SpecialTriggeringPurpose_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_PDUSetQoSParameters, create_dissector_handle(dissect_PDUSetQoSParameters_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_N6JitterInformation, create_dissector_handle(dissect_N6JitterInformation_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_ECNMarkingorCongestionInformationReportingRequest, create_dissector_handle(dissect_ECNMarkingorCongestionInformationReportingRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_ECNMarkingorCongestionInformationReportingStatus, create_dissector_handle(dissect_ECNMarkingorCongestionInformationReportingStatus_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_PDUSetbasedHandlingIndicator, create_dissector_handle(dissect_PDUSetbasedHandlingIndicator_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_IndirectPathIndication, create_dissector_handle(dissect_IndirectPathIndication_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_F1UTunnelNotEstablished, create_dissector_handle(dissect_F1UTunnelNotEstablished_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_F1U_TNL_InfoToAdd_List, create_dissector_handle(dissect_F1U_TNL_InfoToAdd_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_F1U_TNL_InfoAdded_List, create_dissector_handle(dissect_F1U_TNL_InfoAdded_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_F1U_TNL_InfoToAddOrModify_List, create_dissector_handle(dissect_F1U_TNL_InfoToAddOrModify_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_F1U_TNL_InfoAddedOrModified_List, create_dissector_handle(dissect_F1U_TNL_InfoAddedOrModified_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_F1U_TNL_InfoToRelease_List, create_dissector_handle(dissect_F1U_TNL_InfoToRelease_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_PSIbasedDiscardTimer, create_dissector_handle(dissect_PSIbasedDiscardTimer_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_UserPlaneErrorIndicator, create_dissector_handle(dissect_UserPlaneErrorIndicator_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_MaximumDataBurstVolume, create_dissector_handle(dissect_MaxDataBurstVolume_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_BCBearerContextNGU_TNLInfoatNGRAN_Request, create_dissector_handle(dissect_BCBearerContextNGU_TNLInfoatNGRAN_Request_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_PDCPSNGapReport, create_dissector_handle(dissect_PDCPSNGapReport_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_UserPlaneFailureIndication, create_dissector_handle(dissect_UserPlaneFailureIndication_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_reset, create_dissector_handle(dissect_Reset_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_reset, create_dissector_handle(dissect_ResetAcknowledge_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_errorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_gNB_CU_UP_E1Setup, create_dissector_handle(dissect_GNB_CU_UP_E1SetupRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_gNB_CU_UP_E1Setup, create_dissector_handle(dissect_GNB_CU_UP_E1SetupResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.uout", id_gNB_CU_UP_E1Setup, create_dissector_handle(dissect_GNB_CU_UP_E1SetupFailure_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_gNB_CU_CP_E1Setup, create_dissector_handle(dissect_GNB_CU_CP_E1SetupRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_gNB_CU_CP_E1Setup, create_dissector_handle(dissect_GNB_CU_CP_E1SetupResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.uout", id_gNB_CU_CP_E1Setup, create_dissector_handle(dissect_GNB_CU_CP_E1SetupFailure_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_gNB_CU_UP_ConfigurationUpdate, create_dissector_handle(dissect_GNB_CU_UP_ConfigurationUpdate_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_gNB_CU_UP_ConfigurationUpdate, create_dissector_handle(dissect_GNB_CU_UP_ConfigurationUpdateAcknowledge_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.uout", id_gNB_CU_UP_ConfigurationUpdate, create_dissector_handle(dissect_GNB_CU_UP_ConfigurationUpdateFailure_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_gNB_CU_CP_ConfigurationUpdate, create_dissector_handle(dissect_GNB_CU_CP_ConfigurationUpdate_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_gNB_CU_CP_ConfigurationUpdate, create_dissector_handle(dissect_GNB_CU_CP_ConfigurationUpdateAcknowledge_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.uout", id_gNB_CU_CP_ConfigurationUpdate, create_dissector_handle(dissect_GNB_CU_CP_ConfigurationUpdateFailure_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_e1Release, create_dissector_handle(dissect_E1ReleaseRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_e1Release, create_dissector_handle(dissect_E1ReleaseResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_bearerContextSetup, create_dissector_handle(dissect_BearerContextSetupRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_bearerContextSetup, create_dissector_handle(dissect_BearerContextSetupResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.uout", id_bearerContextSetup, create_dissector_handle(dissect_BearerContextSetupFailure_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_bearerContextModification, create_dissector_handle(dissect_BearerContextModificationRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_bearerContextModification, create_dissector_handle(dissect_BearerContextModificationResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.uout", id_bearerContextModification, create_dissector_handle(dissect_BearerContextModificationFailure_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_bearerContextModificationRequired, create_dissector_handle(dissect_BearerContextModificationRequired_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_bearerContextModificationRequired, create_dissector_handle(dissect_BearerContextModificationConfirm_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_bearerContextRelease, create_dissector_handle(dissect_BearerContextReleaseCommand_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_bearerContextRelease, create_dissector_handle(dissect_BearerContextReleaseComplete_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_bearerContextReleaseRequest, create_dissector_handle(dissect_BearerContextReleaseRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_bearerContextInactivityNotification, create_dissector_handle(dissect_BearerContextInactivityNotification_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_dLDataNotification, create_dissector_handle(dissect_DLDataNotification_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_uLDataNotification, create_dissector_handle(dissect_ULDataNotification_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_dataUsageReport, create_dissector_handle(dissect_DataUsageReport_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_gNB_CU_UP_CounterCheck, create_dissector_handle(dissect_GNB_CU_UP_CounterCheckRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_gNB_CU_UP_StatusIndication, create_dissector_handle(dissect_GNB_CU_UP_StatusIndication_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_privateMessage, create_dissector_handle(dissect_PrivateMessage_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_gNB_CU_CPMeasurementResultsInformation, create_dissector_handle(dissect_GNB_CU_CPMeasurementResultsInformation_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_mRDC_DataUsageReport, create_dissector_handle(dissect_MRDC_DataUsageReport_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_DeactivateTrace, create_dissector_handle(dissect_DeactivateTrace_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_TraceStart, create_dissector_handle(dissect_TraceStart_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_resourceStatusReportingInitiation, create_dissector_handle(dissect_ResourceStatusRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_resourceStatusReportingInitiation, create_dissector_handle(dissect_ResourceStatusResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.uout", id_resourceStatusReportingInitiation, create_dissector_handle(dissect_ResourceStatusFailure_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_resourceStatusReporting, create_dissector_handle(dissect_ResourceStatusUpdate_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_iAB_UPTNLAddressUpdate, create_dissector_handle(dissect_IAB_UPTNLAddressUpdate_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_iAB_UPTNLAddressUpdate, create_dissector_handle(dissect_IAB_UPTNLAddressUpdateAcknowledge_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.uout", id_iAB_UPTNLAddressUpdate, create_dissector_handle(dissect_IAB_UPTNLAddressUpdateFailure_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_CellTrafficTrace, create_dissector_handle(dissect_CellTrafficTrace_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_earlyForwardingSNTransfer, create_dissector_handle(dissect_EarlyForwardingSNTransfer_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_iABPSKNotification, create_dissector_handle(dissect_IABPSKNotification_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_BCBearerContextSetup, create_dissector_handle(dissect_BCBearerContextSetupRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_BCBearerContextSetup, create_dissector_handle(dissect_BCBearerContextSetupResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.uout", id_BCBearerContextSetup, create_dissector_handle(dissect_BCBearerContextSetupFailure_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_BCBearerContextModification, create_dissector_handle(dissect_BCBearerContextModificationRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_BCBearerContextModification, create_dissector_handle(dissect_BCBearerContextModificationResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.uout", id_BCBearerContextModification, create_dissector_handle(dissect_BCBearerContextModificationFailure_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_BCBearerContextModificationRequired, create_dissector_handle(dissect_BCBearerContextModificationRequired_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_BCBearerContextModificationRequired, create_dissector_handle(dissect_BCBearerContextModificationConfirm_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_BCBearerContextRelease, create_dissector_handle(dissect_BCBearerContextReleaseCommand_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_BCBearerContextRelease, create_dissector_handle(dissect_BCBearerContextReleaseComplete_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_BCBearerContextReleaseRequest, create_dissector_handle(dissect_BCBearerContextReleaseRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_MCBearerContextSetup, create_dissector_handle(dissect_MCBearerContextSetupRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_MCBearerContextSetup, create_dissector_handle(dissect_MCBearerContextSetupResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.uout", id_MCBearerContextSetup, create_dissector_handle(dissect_MCBearerContextSetupFailure_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_MCBearerContextModification, create_dissector_handle(dissect_MCBearerContextModificationRequest_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_MCBearerContextModification, create_dissector_handle(dissect_MCBearerContextModificationResponse_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.uout", id_MCBearerContextModification, create_dissector_handle(dissect_MCBearerContextModificationFailure_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_MCBearerContextModificationRequired, create_dissector_handle(dissect_MCBearerContextModificationRequired_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_MCBearerContextModificationRequired, create_dissector_handle(dissect_MCBearerContextModificationConfirm_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_MCBearerNotification, create_dissector_handle(dissect_MCBearerNotification_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_MCBearerContextRelease, create_dissector_handle(dissect_MCBearerContextReleaseCommand_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.sout", id_MCBearerContextRelease, create_dissector_handle(dissect_MCBearerContextReleaseComplete_PDU, proto_e1ap));
  dissector_add_uint("e1ap.proc.imsg", id_MCBearerContextReleaseRequest, create_dissector_handle(dissect_MCBearerContextReleaseRequest_PDU, proto_e1ap));

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
