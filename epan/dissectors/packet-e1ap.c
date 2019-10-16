/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-e1ap.c                                                              */
/* asn2wrs.py -p e1ap -c ./e1ap.cnf -s ./packet-e1ap-template -D . -O ../.. E1AP-CommonDataTypes.asn E1AP-Constants.asn E1AP-Containers.asn E1AP-IEs.asn E1AP-PDU-Contents.asn E1AP-PDU-Descriptions.asn */

/* Input file: packet-e1ap-template.c */

#line 1 "./asn1/e1ap/packet-e1ap-template.c"
/* packet-e1ap.c
 * Routines for E-UTRAN E1 Application Protocol (E1AP) packet dissection
 * Copyright 2018-2019, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 38.463 V15.4.0 (2019-07)
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

#define PNAME  "E1 Application Protocol"
#define PSNAME "E1AP"
#define PFNAME "e1ap"

#define SCTP_PORT_E1AP 38462

void proto_register_e1ap(void);
void proto_reg_handoff_e1ap(void);


/*--- Included file: packet-e1ap-val.h ---*/
#line 1 "./asn1/e1ap/packet-e1ap-val.h"
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
  id_mRDC_DataUsageReport =  19
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
  id_QoSFlowMappingIndication =  80
} ProtocolIE_ID_enum;

/*--- End of included file: packet-e1ap-val.h ---*/
#line 37 "./asn1/e1ap/packet-e1ap-template.c"

/* Initialize the protocol and registered fields */
static int proto_e1ap = -1;

static int hf_e1ap_transportLayerAddressIPv4 = -1;
static int hf_e1ap_transportLayerAddressIPv6 = -1;

/*--- Included file: packet-e1ap-hf.c ---*/
#line 1 "./asn1/e1ap/packet-e1ap-hf.c"
static int hf_e1ap_ActivityInformation_PDU = -1;  /* ActivityInformation */
static int hf_e1ap_ActivityNotificationLevel_PDU = -1;  /* ActivityNotificationLevel */
static int hf_e1ap_BearerContextStatusChange_PDU = -1;  /* BearerContextStatusChange */
static int hf_e1ap_BitRate_PDU = -1;              /* BitRate */
static int hf_e1ap_Cause_PDU = -1;                /* Cause */
static int hf_e1ap_CNSupport_PDU = -1;            /* CNSupport */
static int hf_e1ap_CommonNetworkInstance_PDU = -1;  /* CommonNetworkInstance */
static int hf_e1ap_CP_TNL_Information_PDU = -1;   /* CP_TNL_Information */
static int hf_e1ap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_e1ap_Data_Usage_Report_List_PDU = -1;  /* Data_Usage_Report_List */
static int hf_e1ap_DRB_Confirm_Modified_List_EUTRAN_PDU = -1;  /* DRB_Confirm_Modified_List_EUTRAN */
static int hf_e1ap_DRB_Failed_List_EUTRAN_PDU = -1;  /* DRB_Failed_List_EUTRAN */
static int hf_e1ap_DRB_Failed_Mod_List_EUTRAN_PDU = -1;  /* DRB_Failed_Mod_List_EUTRAN */
static int hf_e1ap_DRB_Failed_To_Modify_List_EUTRAN_PDU = -1;  /* DRB_Failed_To_Modify_List_EUTRAN */
static int hf_e1ap_DRB_Modified_List_EUTRAN_PDU = -1;  /* DRB_Modified_List_EUTRAN */
static int hf_e1ap_DRB_Required_To_Modify_List_EUTRAN_PDU = -1;  /* DRB_Required_To_Modify_List_EUTRAN */
static int hf_e1ap_DRB_Setup_List_EUTRAN_PDU = -1;  /* DRB_Setup_List_EUTRAN */
static int hf_e1ap_DRB_Setup_Mod_List_EUTRAN_PDU = -1;  /* DRB_Setup_Mod_List_EUTRAN */
static int hf_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN_PDU = -1;  /* DRBs_Subject_To_Counter_Check_List_EUTRAN */
static int hf_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN_PDU = -1;  /* DRBs_Subject_To_Counter_Check_List_NG_RAN */
static int hf_e1ap_DRB_To_Modify_List_EUTRAN_PDU = -1;  /* DRB_To_Modify_List_EUTRAN */
static int hf_e1ap_DRB_To_Remove_List_EUTRAN_PDU = -1;  /* DRB_To_Remove_List_EUTRAN */
static int hf_e1ap_DRB_Required_To_Remove_List_EUTRAN_PDU = -1;  /* DRB_Required_To_Remove_List_EUTRAN */
static int hf_e1ap_DRB_To_Setup_List_EUTRAN_PDU = -1;  /* DRB_To_Setup_List_EUTRAN */
static int hf_e1ap_DRB_To_Setup_Mod_List_EUTRAN_PDU = -1;  /* DRB_To_Setup_Mod_List_EUTRAN */
static int hf_e1ap_DataDiscardRequired_PDU = -1;  /* DataDiscardRequired */
static int hf_e1ap_Endpoint_IP_address_and_port_PDU = -1;  /* Endpoint_IP_address_and_port */
static int hf_e1ap_GNB_CU_CP_Name_PDU = -1;       /* GNB_CU_CP_Name */
static int hf_e1ap_GNB_CU_CP_UE_E1AP_ID_PDU = -1;  /* GNB_CU_CP_UE_E1AP_ID */
static int hf_e1ap_GNB_CU_UP_Capacity_PDU = -1;   /* GNB_CU_UP_Capacity */
static int hf_e1ap_GNB_CU_UP_ID_PDU = -1;         /* GNB_CU_UP_ID */
static int hf_e1ap_GNB_CU_UP_Name_PDU = -1;       /* GNB_CU_UP_Name */
static int hf_e1ap_GNB_CU_UP_UE_E1AP_ID_PDU = -1;  /* GNB_CU_UP_UE_E1AP_ID */
static int hf_e1ap_GNB_CU_UP_OverloadInformation_PDU = -1;  /* GNB_CU_UP_OverloadInformation */
static int hf_e1ap_GNB_DU_ID_PDU = -1;            /* GNB_DU_ID */
static int hf_e1ap_Inactivity_Timer_PDU = -1;     /* Inactivity_Timer */
static int hf_e1ap_NetworkInstance_PDU = -1;      /* NetworkInstance */
static int hf_e1ap_New_UL_TNL_Information_Required_PDU = -1;  /* New_UL_TNL_Information_Required */
static int hf_e1ap_PDU_Session_Resource_Data_Usage_List_PDU = -1;  /* PDU_Session_Resource_Data_Usage_List */
static int hf_e1ap_PDU_Session_Resource_Confirm_Modified_List_PDU = -1;  /* PDU_Session_Resource_Confirm_Modified_List */
static int hf_e1ap_PDU_Session_Resource_Failed_List_PDU = -1;  /* PDU_Session_Resource_Failed_List */
static int hf_e1ap_PDU_Session_Resource_Failed_Mod_List_PDU = -1;  /* PDU_Session_Resource_Failed_Mod_List */
static int hf_e1ap_PDU_Session_Resource_Failed_To_Modify_List_PDU = -1;  /* PDU_Session_Resource_Failed_To_Modify_List */
static int hf_e1ap_PDU_Session_Resource_Modified_List_PDU = -1;  /* PDU_Session_Resource_Modified_List */
static int hf_e1ap_PDU_Session_Resource_Required_To_Modify_List_PDU = -1;  /* PDU_Session_Resource_Required_To_Modify_List */
static int hf_e1ap_PDU_Session_Resource_Setup_List_PDU = -1;  /* PDU_Session_Resource_Setup_List */
static int hf_e1ap_PDU_Session_Resource_Setup_Mod_List_PDU = -1;  /* PDU_Session_Resource_Setup_Mod_List */
static int hf_e1ap_PDU_Session_Resource_To_Modify_List_PDU = -1;  /* PDU_Session_Resource_To_Modify_List */
static int hf_e1ap_PDU_Session_Resource_To_Remove_List_PDU = -1;  /* PDU_Session_Resource_To_Remove_List */
static int hf_e1ap_PDU_Session_Resource_To_Setup_List_PDU = -1;  /* PDU_Session_Resource_To_Setup_List */
static int hf_e1ap_PDU_Session_Resource_To_Setup_Mod_List_PDU = -1;  /* PDU_Session_Resource_To_Setup_Mod_List */
static int hf_e1ap_PDU_Session_To_Notify_List_PDU = -1;  /* PDU_Session_To_Notify_List */
static int hf_e1ap_PLMN_Identity_PDU = -1;        /* PLMN_Identity */
static int hf_e1ap_PPI_PDU = -1;                  /* PPI */
static int hf_e1ap_QoS_Flow_List_PDU = -1;        /* QoS_Flow_List */
static int hf_e1ap_QoS_Flow_Mapping_Indication_PDU = -1;  /* QoS_Flow_Mapping_Indication */
static int hf_e1ap_QoSFlowLevelQoSParameters_PDU = -1;  /* QoSFlowLevelQoSParameters */
static int hf_e1ap_RANUEID_PDU = -1;              /* RANUEID */
static int hf_e1ap_SecurityInformation_PDU = -1;  /* SecurityInformation */
static int hf_e1ap_SNSSAI_PDU = -1;               /* SNSSAI */
static int hf_e1ap_TimeToWait_PDU = -1;           /* TimeToWait */
static int hf_e1ap_TransactionID_PDU = -1;        /* TransactionID */
static int hf_e1ap_UE_associatedLogicalE1_ConnectionItem_PDU = -1;  /* UE_associatedLogicalE1_ConnectionItem */
static int hf_e1ap_Reset_PDU = -1;                /* Reset */
static int hf_e1ap_ResetType_PDU = -1;            /* ResetType */
static int hf_e1ap_ResetAcknowledge_PDU = -1;     /* ResetAcknowledge */
static int hf_e1ap_UE_associatedLogicalE1_ConnectionListResAck_PDU = -1;  /* UE_associatedLogicalE1_ConnectionListResAck */
static int hf_e1ap_ErrorIndication_PDU = -1;      /* ErrorIndication */
static int hf_e1ap_GNB_CU_UP_E1SetupRequest_PDU = -1;  /* GNB_CU_UP_E1SetupRequest */
static int hf_e1ap_SupportedPLMNs_List_PDU = -1;  /* SupportedPLMNs_List */
static int hf_e1ap_GNB_CU_UP_E1SetupResponse_PDU = -1;  /* GNB_CU_UP_E1SetupResponse */
static int hf_e1ap_GNB_CU_UP_E1SetupFailure_PDU = -1;  /* GNB_CU_UP_E1SetupFailure */
static int hf_e1ap_GNB_CU_CP_E1SetupRequest_PDU = -1;  /* GNB_CU_CP_E1SetupRequest */
static int hf_e1ap_GNB_CU_CP_E1SetupResponse_PDU = -1;  /* GNB_CU_CP_E1SetupResponse */
static int hf_e1ap_GNB_CU_CP_E1SetupFailure_PDU = -1;  /* GNB_CU_CP_E1SetupFailure */
static int hf_e1ap_GNB_CU_UP_ConfigurationUpdate_PDU = -1;  /* GNB_CU_UP_ConfigurationUpdate */
static int hf_e1ap_GNB_CU_UP_TNLA_To_Remove_List_PDU = -1;  /* GNB_CU_UP_TNLA_To_Remove_List */
static int hf_e1ap_GNB_CU_UP_ConfigurationUpdateAcknowledge_PDU = -1;  /* GNB_CU_UP_ConfigurationUpdateAcknowledge */
static int hf_e1ap_GNB_CU_UP_ConfigurationUpdateFailure_PDU = -1;  /* GNB_CU_UP_ConfigurationUpdateFailure */
static int hf_e1ap_GNB_CU_CP_ConfigurationUpdate_PDU = -1;  /* GNB_CU_CP_ConfigurationUpdate */
static int hf_e1ap_GNB_CU_CP_TNLA_To_Add_List_PDU = -1;  /* GNB_CU_CP_TNLA_To_Add_List */
static int hf_e1ap_GNB_CU_CP_TNLA_To_Remove_List_PDU = -1;  /* GNB_CU_CP_TNLA_To_Remove_List */
static int hf_e1ap_GNB_CU_CP_TNLA_To_Update_List_PDU = -1;  /* GNB_CU_CP_TNLA_To_Update_List */
static int hf_e1ap_GNB_CU_CP_ConfigurationUpdateAcknowledge_PDU = -1;  /* GNB_CU_CP_ConfigurationUpdateAcknowledge */
static int hf_e1ap_GNB_CU_CP_TNLA_Setup_List_PDU = -1;  /* GNB_CU_CP_TNLA_Setup_List */
static int hf_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List_PDU = -1;  /* GNB_CU_CP_TNLA_Failed_To_Setup_List */
static int hf_e1ap_GNB_CU_CP_ConfigurationUpdateFailure_PDU = -1;  /* GNB_CU_CP_ConfigurationUpdateFailure */
static int hf_e1ap_E1ReleaseRequest_PDU = -1;     /* E1ReleaseRequest */
static int hf_e1ap_E1ReleaseResponse_PDU = -1;    /* E1ReleaseResponse */
static int hf_e1ap_BearerContextSetupRequest_PDU = -1;  /* BearerContextSetupRequest */
static int hf_e1ap_System_BearerContextSetupRequest_PDU = -1;  /* System_BearerContextSetupRequest */
static int hf_e1ap_BearerContextSetupResponse_PDU = -1;  /* BearerContextSetupResponse */
static int hf_e1ap_System_BearerContextSetupResponse_PDU = -1;  /* System_BearerContextSetupResponse */
static int hf_e1ap_BearerContextSetupFailure_PDU = -1;  /* BearerContextSetupFailure */
static int hf_e1ap_BearerContextModificationRequest_PDU = -1;  /* BearerContextModificationRequest */
static int hf_e1ap_System_BearerContextModificationRequest_PDU = -1;  /* System_BearerContextModificationRequest */
static int hf_e1ap_BearerContextModificationResponse_PDU = -1;  /* BearerContextModificationResponse */
static int hf_e1ap_System_BearerContextModificationResponse_PDU = -1;  /* System_BearerContextModificationResponse */
static int hf_e1ap_BearerContextModificationFailure_PDU = -1;  /* BearerContextModificationFailure */
static int hf_e1ap_BearerContextModificationRequired_PDU = -1;  /* BearerContextModificationRequired */
static int hf_e1ap_System_BearerContextModificationRequired_PDU = -1;  /* System_BearerContextModificationRequired */
static int hf_e1ap_BearerContextModificationConfirm_PDU = -1;  /* BearerContextModificationConfirm */
static int hf_e1ap_System_BearerContextModificationConfirm_PDU = -1;  /* System_BearerContextModificationConfirm */
static int hf_e1ap_BearerContextReleaseCommand_PDU = -1;  /* BearerContextReleaseCommand */
static int hf_e1ap_BearerContextReleaseComplete_PDU = -1;  /* BearerContextReleaseComplete */
static int hf_e1ap_BearerContextReleaseRequest_PDU = -1;  /* BearerContextReleaseRequest */
static int hf_e1ap_DRB_Status_List_PDU = -1;      /* DRB_Status_List */
static int hf_e1ap_BearerContextInactivityNotification_PDU = -1;  /* BearerContextInactivityNotification */
static int hf_e1ap_DLDataNotification_PDU = -1;   /* DLDataNotification */
static int hf_e1ap_ULDataNotification_PDU = -1;   /* ULDataNotification */
static int hf_e1ap_DataUsageReport_PDU = -1;      /* DataUsageReport */
static int hf_e1ap_GNB_CU_UP_CounterCheckRequest_PDU = -1;  /* GNB_CU_UP_CounterCheckRequest */
static int hf_e1ap_System_GNB_CU_UP_CounterCheckRequest_PDU = -1;  /* System_GNB_CU_UP_CounterCheckRequest */
static int hf_e1ap_GNB_CU_UP_StatusIndication_PDU = -1;  /* GNB_CU_UP_StatusIndication */
static int hf_e1ap_MRDC_DataUsageReport_PDU = -1;  /* MRDC_DataUsageReport */
static int hf_e1ap_PrivateMessage_PDU = -1;       /* PrivateMessage */
static int hf_e1ap_E1AP_PDU_PDU = -1;             /* E1AP_PDU */
static int hf_e1ap_local = -1;                    /* INTEGER_0_maxPrivateIEs */
static int hf_e1ap_global = -1;                   /* T_global */
static int hf_e1ap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_e1ap_id = -1;                       /* ProtocolIE_ID */
static int hf_e1ap_criticality = -1;              /* Criticality */
static int hf_e1ap_ie_field_value = -1;           /* T_ie_field_value */
static int hf_e1ap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_e1ap_ext_id = -1;                   /* ProtocolIE_ID */
static int hf_e1ap_extensionValue = -1;           /* T_extensionValue */
static int hf_e1ap_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_e1ap_private_id = -1;               /* PrivateIE_ID */
static int hf_e1ap_value = -1;                    /* T_value */
static int hf_e1ap_dRB_Activity_List = -1;        /* DRB_Activity_List */
static int hf_e1ap_pDU_Session_Resource_Activity_List = -1;  /* PDU_Session_Resource_Activity_List */
static int hf_e1ap_uE_Activity = -1;              /* UE_Activity */
static int hf_e1ap_choice_extension = -1;         /* ProtocolIE_SingleContainer */
static int hf_e1ap_radioNetwork = -1;             /* CauseRadioNetwork */
static int hf_e1ap_transport = -1;                /* CauseTransport */
static int hf_e1ap_protocol = -1;                 /* CauseProtocol */
static int hf_e1ap_misc = -1;                     /* CauseMisc */
static int hf_e1ap_Cell_Group_Information_item = -1;  /* Cell_Group_Information_Item */
static int hf_e1ap_cell_Group_ID = -1;            /* Cell_Group_ID */
static int hf_e1ap_uL_Configuration = -1;         /* UL_Configuration */
static int hf_e1ap_dL_TX_Stop = -1;               /* DL_TX_Stop */
static int hf_e1ap_rAT_Type = -1;                 /* RAT_Type */
static int hf_e1ap_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_e1ap_endpoint_IP_Address = -1;      /* TransportLayerAddress */
static int hf_e1ap_procedureCode = -1;            /* ProcedureCode */
static int hf_e1ap_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_e1ap_procedureCriticality = -1;     /* Criticality */
static int hf_e1ap_transactionID = -1;            /* TransactionID */
static int hf_e1ap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_e1ap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_e1ap_iECriticality = -1;            /* Criticality */
static int hf_e1ap_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_e1ap_typeOfError = -1;              /* TypeOfError */
static int hf_e1ap_data_Forwarding_Request = -1;  /* Data_Forwarding_Request */
static int hf_e1ap_qoS_Flows_Forwarded_On_Fwd_Tunnels = -1;  /* QoS_Flow_Mapping_List */
static int hf_e1ap_uL_Data_Forwarding = -1;       /* UP_TNL_Information */
static int hf_e1ap_dL_Data_Forwarding = -1;       /* UP_TNL_Information */
static int hf_e1ap_secondaryRATType = -1;         /* T_secondaryRATType */
static int hf_e1ap_pDU_session_Timed_Report_List = -1;  /* SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item */
static int hf_e1ap_pDU_session_Timed_Report_List_item = -1;  /* MRDC_Data_Usage_Report_Item */
static int hf_e1ap_Data_Usage_per_QoS_Flow_List_item = -1;  /* Data_Usage_per_QoS_Flow_Item */
static int hf_e1ap_qoS_Flow_Identifier = -1;      /* QoS_Flow_Identifier */
static int hf_e1ap_secondaryRATType_01 = -1;      /* T_secondaryRATType_01 */
static int hf_e1ap_qoS_Flow_Timed_Report_List = -1;  /* SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item */
static int hf_e1ap_qoS_Flow_Timed_Report_List_item = -1;  /* MRDC_Data_Usage_Report_Item */
static int hf_e1ap_Data_Usage_Report_List_item = -1;  /* Data_Usage_Report_Item */
static int hf_e1ap_dRB_ID = -1;                   /* DRB_ID */
static int hf_e1ap_dRB_Usage_Report_List = -1;    /* DRB_Usage_Report_List */
static int hf_e1ap_DRB_Activity_List_item = -1;   /* DRB_Activity_Item */
static int hf_e1ap_dRB_Activity = -1;             /* DRB_Activity */
static int hf_e1ap_DRB_Confirm_Modified_List_EUTRAN_item = -1;  /* DRB_Confirm_Modified_Item_EUTRAN */
static int hf_e1ap_cell_Group_Information = -1;   /* Cell_Group_Information */
static int hf_e1ap_DRB_Confirm_Modified_List_NG_RAN_item = -1;  /* DRB_Confirm_Modified_Item_NG_RAN */
static int hf_e1ap_DRB_Failed_List_EUTRAN_item = -1;  /* DRB_Failed_Item_EUTRAN */
static int hf_e1ap_cause = -1;                    /* Cause */
static int hf_e1ap_DRB_Failed_Mod_List_EUTRAN_item = -1;  /* DRB_Failed_Mod_Item_EUTRAN */
static int hf_e1ap_DRB_Failed_List_NG_RAN_item = -1;  /* DRB_Failed_Item_NG_RAN */
static int hf_e1ap_DRB_Failed_Mod_List_NG_RAN_item = -1;  /* DRB_Failed_Mod_Item_NG_RAN */
static int hf_e1ap_DRB_Failed_To_Modify_List_EUTRAN_item = -1;  /* DRB_Failed_To_Modify_Item_EUTRAN */
static int hf_e1ap_DRB_Failed_To_Modify_List_NG_RAN_item = -1;  /* DRB_Failed_To_Modify_Item_NG_RAN */
static int hf_e1ap_DRB_Modified_List_EUTRAN_item = -1;  /* DRB_Modified_Item_EUTRAN */
static int hf_e1ap_s1_DL_UP_TNL_Information = -1;  /* UP_TNL_Information */
static int hf_e1ap_pDCP_SN_Status_Information = -1;  /* PDCP_SN_Status_Information */
static int hf_e1ap_uL_UP_Transport_Parameters = -1;  /* UP_Parameters */
static int hf_e1ap_DRB_Modified_List_NG_RAN_item = -1;  /* DRB_Modified_Item_NG_RAN */
static int hf_e1ap_flow_Setup_List = -1;          /* QoS_Flow_List */
static int hf_e1ap_flow_Failed_List = -1;         /* QoS_Flow_Failed_List */
static int hf_e1ap_DRB_Required_To_Modify_List_EUTRAN_item = -1;  /* DRB_Required_To_Modify_Item_EUTRAN */
static int hf_e1ap_gNB_CU_UP_CellGroupRelatedConfiguration = -1;  /* GNB_CU_UP_CellGroupRelatedConfiguration */
static int hf_e1ap_DRB_Required_To_Modify_List_NG_RAN_item = -1;  /* DRB_Required_To_Modify_Item_NG_RAN */
static int hf_e1ap_flow_To_Remove = -1;           /* QoS_Flow_List */
static int hf_e1ap_DRB_Setup_List_EUTRAN_item = -1;  /* DRB_Setup_Item_EUTRAN */
static int hf_e1ap_data_Forwarding_Information_Response = -1;  /* Data_Forwarding_Information */
static int hf_e1ap_s1_DL_UP_Unchanged = -1;       /* T_s1_DL_UP_Unchanged */
static int hf_e1ap_DRB_Setup_Mod_List_EUTRAN_item = -1;  /* DRB_Setup_Mod_Item_EUTRAN */
static int hf_e1ap_DRB_Setup_List_NG_RAN_item = -1;  /* DRB_Setup_Item_NG_RAN */
static int hf_e1ap_dRB_data_Forwarding_Information_Response = -1;  /* Data_Forwarding_Information */
static int hf_e1ap_DRB_Setup_Mod_List_NG_RAN_item = -1;  /* DRB_Setup_Mod_Item_NG_RAN */
static int hf_e1ap_pDCP_DL_Count = -1;            /* PDCP_Count */
static int hf_e1ap_pDCP_UL_Count = -1;            /* PDCP_Count */
static int hf_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN_item = -1;  /* DRBs_Subject_To_Counter_Check_Item_EUTRAN */
static int hf_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN_item = -1;  /* DRBs_Subject_To_Counter_Check_Item_NG_RAN */
static int hf_e1ap_pDU_Session_ID = -1;           /* PDU_Session_ID */
static int hf_e1ap_DRB_To_Modify_List_EUTRAN_item = -1;  /* DRB_To_Modify_Item_EUTRAN */
static int hf_e1ap_pDCP_Configuration = -1;       /* PDCP_Configuration */
static int hf_e1ap_eUTRAN_QoS = -1;               /* EUTRAN_QoS */
static int hf_e1ap_s1_UL_UP_TNL_Information = -1;  /* UP_TNL_Information */
static int hf_e1ap_data_Forwarding_Information = -1;  /* Data_Forwarding_Information */
static int hf_e1ap_pDCP_SN_Status_Request = -1;   /* PDCP_SN_Status_Request */
static int hf_e1ap_dL_UP_Parameters = -1;         /* UP_Parameters */
static int hf_e1ap_cell_Group_To_Add = -1;        /* Cell_Group_Information */
static int hf_e1ap_cell_Group_To_Modify = -1;     /* Cell_Group_Information */
static int hf_e1ap_cell_Group_To_Remove = -1;     /* Cell_Group_Information */
static int hf_e1ap_dRB_Inactivity_Timer = -1;     /* Inactivity_Timer */
static int hf_e1ap_DRB_To_Modify_List_NG_RAN_item = -1;  /* DRB_To_Modify_Item_NG_RAN */
static int hf_e1ap_sDAP_Configuration = -1;       /* SDAP_Configuration */
static int hf_e1ap_dRB_Data_Forwarding_Information = -1;  /* Data_Forwarding_Information */
static int hf_e1ap_pdcp_SN_Status_Information = -1;  /* PDCP_SN_Status_Information */
static int hf_e1ap_flow_Mapping_Information = -1;  /* QoS_Flow_QoS_Parameter_List */
static int hf_e1ap_DRB_To_Remove_List_EUTRAN_item = -1;  /* DRB_To_Remove_Item_EUTRAN */
static int hf_e1ap_DRB_Required_To_Remove_List_EUTRAN_item = -1;  /* DRB_Required_To_Remove_Item_EUTRAN */
static int hf_e1ap_DRB_To_Remove_List_NG_RAN_item = -1;  /* DRB_To_Remove_Item_NG_RAN */
static int hf_e1ap_DRB_Required_To_Remove_List_NG_RAN_item = -1;  /* DRB_Required_To_Remove_Item_NG_RAN */
static int hf_e1ap_DRB_To_Setup_List_EUTRAN_item = -1;  /* DRB_To_Setup_Item_EUTRAN */
static int hf_e1ap_data_Forwarding_Information_Request = -1;  /* Data_Forwarding_Information_Request */
static int hf_e1ap_existing_Allocated_S1_DL_UP_TNL_Info = -1;  /* UP_TNL_Information */
static int hf_e1ap_DRB_To_Setup_Mod_List_EUTRAN_item = -1;  /* DRB_To_Setup_Mod_Item_EUTRAN */
static int hf_e1ap_DRB_To_Setup_List_NG_RAN_item = -1;  /* DRB_To_Setup_Item_NG_RAN */
static int hf_e1ap_qos_flow_Information_To_Be_Setup = -1;  /* QoS_Flow_QoS_Parameter_List */
static int hf_e1ap_dRB_Data_Forwarding_Information_Request = -1;  /* Data_Forwarding_Information_Request */
static int hf_e1ap_DRB_To_Setup_Mod_List_NG_RAN_item = -1;  /* DRB_To_Setup_Mod_Item_NG_RAN */
static int hf_e1ap_DRB_Usage_Report_List_item = -1;  /* DRB_Usage_Report_Item */
static int hf_e1ap_startTimeStamp = -1;           /* T_startTimeStamp */
static int hf_e1ap_endTimeStamp = -1;             /* T_endTimeStamp */
static int hf_e1ap_usageCountUL = -1;             /* INTEGER_0_18446744073709551615 */
static int hf_e1ap_usageCountDL = -1;             /* INTEGER_0_18446744073709551615 */
static int hf_e1ap_qoSPriorityLevel = -1;         /* QoSPriorityLevel */
static int hf_e1ap_packetDelayBudget = -1;        /* PacketDelayBudget */
static int hf_e1ap_packetErrorRate = -1;          /* PacketErrorRate */
static int hf_e1ap_fiveQI = -1;                   /* INTEGER_0_255_ */
static int hf_e1ap_delayCritical = -1;            /* T_delayCritical */
static int hf_e1ap_averagingWindow = -1;          /* AveragingWindow */
static int hf_e1ap_maxDataBurstVolume = -1;       /* MaxDataBurstVolume */
static int hf_e1ap_portNumber = -1;               /* PortNumber */
static int hf_e1ap_priorityLevel = -1;            /* PriorityLevel */
static int hf_e1ap_pre_emptionCapability = -1;    /* Pre_emptionCapability */
static int hf_e1ap_pre_emptionVulnerability = -1;  /* Pre_emptionVulnerability */
static int hf_e1ap_EUTRAN_QoS_Support_List_item = -1;  /* EUTRAN_QoS_Support_Item */
static int hf_e1ap_qCI = -1;                      /* QCI */
static int hf_e1ap_eUTRANallocationAndRetentionPriority = -1;  /* EUTRANAllocationAndRetentionPriority */
static int hf_e1ap_gbrQosInformation = -1;        /* GBR_QosInformation */
static int hf_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration_item = -1;  /* GNB_CU_UP_CellGroupRelatedConfiguration_Item */
static int hf_e1ap_uP_TNL_Information = -1;       /* UP_TNL_Information */
static int hf_e1ap_tNLAssociationTransportLayerAddress = -1;  /* CP_TNL_Information */
static int hf_e1ap_tNLAssociationUsage = -1;      /* TNLAssociationUsage */
static int hf_e1ap_tNLAssociationTransportLayerAddressgNBCUCP = -1;  /* CP_TNL_Information */
static int hf_e1ap_e_RAB_MaximumBitrateDL = -1;   /* BitRate */
static int hf_e1ap_e_RAB_MaximumBitrateUL = -1;   /* BitRate */
static int hf_e1ap_e_RAB_GuaranteedBitrateDL = -1;  /* BitRate */
static int hf_e1ap_e_RAB_GuaranteedBitrateUL = -1;  /* BitRate */
static int hf_e1ap_maxFlowBitRateDownlink = -1;   /* BitRate */
static int hf_e1ap_maxFlowBitRateUplink = -1;     /* BitRate */
static int hf_e1ap_guaranteedFlowBitRateDownlink = -1;  /* BitRate */
static int hf_e1ap_guaranteedFlowBitRateUplink = -1;  /* BitRate */
static int hf_e1ap_maxPacketLossRateDownlink = -1;  /* MaxPacketLossRate */
static int hf_e1ap_maxPacketLossRateUplink = -1;  /* MaxPacketLossRate */
static int hf_e1ap_transportLayerAddress = -1;    /* TransportLayerAddress */
static int hf_e1ap_gTP_TEID = -1;                 /* GTP_TEID */
static int hf_e1ap_maxIPrate = -1;                /* MaxIPrate */
static int hf_e1ap_startTimeStamp_01 = -1;        /* T_startTimeStamp_01 */
static int hf_e1ap_endTimeStamp_01 = -1;          /* T_endTimeStamp_01 */
static int hf_e1ap_data_Usage_per_PDU_Session_Report = -1;  /* Data_Usage_per_PDU_Session_Report */
static int hf_e1ap_data_Usage_per_QoS_Flow_List = -1;  /* Data_Usage_per_QoS_Flow_List */
static int hf_e1ap_NG_RAN_QoS_Support_List_item = -1;  /* NG_RAN_QoS_Support_Item */
static int hf_e1ap_non_Dynamic5QIDescriptor = -1;  /* Non_Dynamic5QIDescriptor */
static int hf_e1ap_pLMN_Identity = -1;            /* PLMN_Identity */
static int hf_e1ap_nR_Cell_Identity = -1;         /* NR_Cell_Identity */
static int hf_e1ap_NR_CGI_Support_List_item = -1;  /* NR_CGI_Support_Item */
static int hf_e1ap_nR_CGI = -1;                   /* NR_CGI */
static int hf_e1ap_pER_Scalar = -1;               /* PER_Scalar */
static int hf_e1ap_pER_Exponent = -1;             /* PER_Exponent */
static int hf_e1ap_pDCP_SN_Size_UL = -1;          /* PDCP_SN_Size */
static int hf_e1ap_pDCP_SN_Size_DL = -1;          /* PDCP_SN_Size */
static int hf_e1ap_rLC_Mode = -1;                 /* RLC_Mode */
static int hf_e1ap_rOHC_Parameters = -1;          /* ROHC_Parameters */
static int hf_e1ap_t_ReorderingTimer = -1;        /* T_ReorderingTimer */
static int hf_e1ap_discardTimer = -1;             /* DiscardTimer */
static int hf_e1ap_uLDataSplitThreshold = -1;     /* ULDataSplitThreshold */
static int hf_e1ap_pDCP_Duplication = -1;         /* PDCP_Duplication */
static int hf_e1ap_pDCP_Reestablishment = -1;     /* PDCP_Reestablishment */
static int hf_e1ap_pDCP_DataRecovery = -1;        /* PDCP_DataRecovery */
static int hf_e1ap_duplication_Activation = -1;   /* Duplication_Activation */
static int hf_e1ap_outOfOrderDelivery = -1;       /* OutOfOrderDelivery */
static int hf_e1ap_pDCP_SN = -1;                  /* PDCP_SN */
static int hf_e1ap_hFN = -1;                      /* HFN */
static int hf_e1ap_PDU_Session_Resource_Data_Usage_List_item = -1;  /* PDU_Session_Resource_Data_Usage_Item */
static int hf_e1ap_mRDC_Usage_Information = -1;   /* MRDC_Usage_Information */
static int hf_e1ap_pdcpStatusTransfer_UL = -1;    /* DRBBStatusTransfer */
static int hf_e1ap_pdcpStatusTransfer_DL = -1;    /* PDCP_Count */
static int hf_e1ap_iE_Extension = -1;             /* ProtocolExtensionContainer */
static int hf_e1ap_receiveStatusofPDCPSDU = -1;   /* BIT_STRING_SIZE_1_131072 */
static int hf_e1ap_countValue = -1;               /* PDCP_Count */
static int hf_e1ap_PDU_Session_Resource_Activity_List_item = -1;  /* PDU_Session_Resource_Activity_Item */
static int hf_e1ap_pDU_Session_Resource_Activity = -1;  /* PDU_Session_Resource_Activity */
static int hf_e1ap_PDU_Session_Resource_Confirm_Modified_List_item = -1;  /* PDU_Session_Resource_Confirm_Modified_Item */
static int hf_e1ap_dRB_Confirm_Modified_List_NG_RAN = -1;  /* DRB_Confirm_Modified_List_NG_RAN */
static int hf_e1ap_PDU_Session_Resource_Failed_List_item = -1;  /* PDU_Session_Resource_Failed_Item */
static int hf_e1ap_PDU_Session_Resource_Failed_Mod_List_item = -1;  /* PDU_Session_Resource_Failed_Mod_Item */
static int hf_e1ap_PDU_Session_Resource_Failed_To_Modify_List_item = -1;  /* PDU_Session_Resource_Failed_To_Modify_Item */
static int hf_e1ap_PDU_Session_Resource_Modified_List_item = -1;  /* PDU_Session_Resource_Modified_Item */
static int hf_e1ap_nG_DL_UP_TNL_Information = -1;  /* UP_TNL_Information */
static int hf_e1ap_securityResult = -1;           /* SecurityResult */
static int hf_e1ap_pDU_Session_Data_Forwarding_Information_Response = -1;  /* Data_Forwarding_Information */
static int hf_e1ap_dRB_Setup_List_NG_RAN = -1;    /* DRB_Setup_List_NG_RAN */
static int hf_e1ap_dRB_Failed_List_NG_RAN = -1;   /* DRB_Failed_List_NG_RAN */
static int hf_e1ap_dRB_Modified_List_NG_RAN = -1;  /* DRB_Modified_List_NG_RAN */
static int hf_e1ap_dRB_Failed_To_Modify_List_NG_RAN = -1;  /* DRB_Failed_To_Modify_List_NG_RAN */
static int hf_e1ap_PDU_Session_Resource_Required_To_Modify_List_item = -1;  /* PDU_Session_Resource_Required_To_Modify_Item */
static int hf_e1ap_dRB_Required_To_Modify_List_NG_RAN = -1;  /* DRB_Required_To_Modify_List_NG_RAN */
static int hf_e1ap_dRB_Required_To_Remove_List_NG_RAN = -1;  /* DRB_Required_To_Remove_List_NG_RAN */
static int hf_e1ap_PDU_Session_Resource_Setup_List_item = -1;  /* PDU_Session_Resource_Setup_Item */
static int hf_e1ap_nG_DL_UP_Unchanged = -1;       /* T_nG_DL_UP_Unchanged */
static int hf_e1ap_PDU_Session_Resource_Setup_Mod_List_item = -1;  /* PDU_Session_Resource_Setup_Mod_Item */
static int hf_e1ap_dRB_Setup_Mod_List_NG_RAN = -1;  /* DRB_Setup_Mod_List_NG_RAN */
static int hf_e1ap_dRB_Failed_Mod_List_NG_RAN = -1;  /* DRB_Failed_Mod_List_NG_RAN */
static int hf_e1ap_PDU_Session_Resource_To_Modify_List_item = -1;  /* PDU_Session_Resource_To_Modify_Item */
static int hf_e1ap_securityIndication = -1;       /* SecurityIndication */
static int hf_e1ap_pDU_Session_Resource_DL_AMBR = -1;  /* BitRate */
static int hf_e1ap_nG_UL_UP_TNL_Information = -1;  /* UP_TNL_Information */
static int hf_e1ap_pDU_Session_Data_Forwarding_Information_Request = -1;  /* Data_Forwarding_Information_Request */
static int hf_e1ap_pDU_Session_Data_Forwarding_Information = -1;  /* Data_Forwarding_Information */
static int hf_e1ap_pDU_Session_Inactivity_Timer = -1;  /* Inactivity_Timer */
static int hf_e1ap_networkInstance = -1;          /* NetworkInstance */
static int hf_e1ap_dRB_To_Setup_List_NG_RAN = -1;  /* DRB_To_Setup_List_NG_RAN */
static int hf_e1ap_dRB_To_Modify_List_NG_RAN = -1;  /* DRB_To_Modify_List_NG_RAN */
static int hf_e1ap_dRB_To_Remove_List_NG_RAN = -1;  /* DRB_To_Remove_List_NG_RAN */
static int hf_e1ap_PDU_Session_Resource_To_Remove_List_item = -1;  /* PDU_Session_Resource_To_Remove_Item */
static int hf_e1ap_PDU_Session_Resource_To_Setup_List_item = -1;  /* PDU_Session_Resource_To_Setup_Item */
static int hf_e1ap_pDU_Session_Type = -1;         /* PDU_Session_Type */
static int hf_e1ap_sNSSAI = -1;                   /* SNSSAI */
static int hf_e1ap_existing_Allocated_NG_DL_UP_TNL_Info = -1;  /* UP_TNL_Information */
static int hf_e1ap_PDU_Session_Resource_To_Setup_Mod_List_item = -1;  /* PDU_Session_Resource_To_Setup_Mod_Item */
static int hf_e1ap_pDU_Session_Resource_AMBR = -1;  /* BitRate */
static int hf_e1ap_dRB_To_Setup_Mod_List_NG_RAN = -1;  /* DRB_To_Setup_Mod_List_NG_RAN */
static int hf_e1ap_PDU_Session_To_Notify_List_item = -1;  /* PDU_Session_To_Notify_Item */
static int hf_e1ap_qoS_Flow_List = -1;            /* QoS_Flow_List */
static int hf_e1ap_non_Dynamic_5QI = -1;          /* Non_Dynamic5QIDescriptor */
static int hf_e1ap_dynamic_5QI = -1;              /* Dynamic5QIDescriptor */
static int hf_e1ap_QoS_Flow_List_item = -1;       /* QoS_Flow_Item */
static int hf_e1ap_QoS_Flow_Failed_List_item = -1;  /* QoS_Flow_Failed_Item */
static int hf_e1ap_QoS_Flow_Mapping_List_item = -1;  /* QoS_Flow_Mapping_Item */
static int hf_e1ap_qoSFlowMappingIndication = -1;  /* QoS_Flow_Mapping_Indication */
static int hf_e1ap_eUTRAN_QoS_Support_List = -1;  /* EUTRAN_QoS_Support_List */
static int hf_e1ap_nG_RAN_QoS_Support_List = -1;  /* NG_RAN_QoS_Support_List */
static int hf_e1ap_QoS_Flow_QoS_Parameter_List_item = -1;  /* QoS_Flow_QoS_Parameter_Item */
static int hf_e1ap_qoSFlowLevelQoSParameters = -1;  /* QoSFlowLevelQoSParameters */
static int hf_e1ap_qoS_Characteristics = -1;      /* QoS_Characteristics */
static int hf_e1ap_nGRANallocationRetentionPriority = -1;  /* NGRANAllocationAndRetentionPriority */
static int hf_e1ap_gBR_QoS_Flow_Information = -1;  /* GBR_QoSFlowInformation */
static int hf_e1ap_reflective_QoS_Attribute = -1;  /* T_reflective_QoS_Attribute */
static int hf_e1ap_additional_QoS_Information = -1;  /* T_additional_QoS_Information */
static int hf_e1ap_paging_Policy_Indicator = -1;  /* INTEGER_1_8_ */
static int hf_e1ap_reflective_QoS_Indicator = -1;  /* T_reflective_QoS_Indicator */
static int hf_e1ap_rOHC = -1;                     /* ROHC */
static int hf_e1ap_uPlinkOnlyROHC = -1;           /* UplinkOnlyROHC */
static int hf_e1ap_choice_Extension = -1;         /* ProtocolIE_SingleContainer */
static int hf_e1ap_maxCID = -1;                   /* INTEGER_0_16383_ */
static int hf_e1ap_rOHC_Profiles = -1;            /* INTEGER_0_511_ */
static int hf_e1ap_continueROHC = -1;             /* T_continueROHC */
static int hf_e1ap_cipheringAlgorithm = -1;       /* CipheringAlgorithm */
static int hf_e1ap_integrityProtectionAlgorithm = -1;  /* IntegrityProtectionAlgorithm */
static int hf_e1ap_integrityProtectionIndication = -1;  /* IntegrityProtectionIndication */
static int hf_e1ap_confidentialityProtectionIndication = -1;  /* ConfidentialityProtectionIndication */
static int hf_e1ap_maximumIPdatarate = -1;        /* MaximumIPdatarate */
static int hf_e1ap_securityAlgorithm = -1;        /* SecurityAlgorithm */
static int hf_e1ap_uPSecuritykey = -1;            /* UPSecuritykey */
static int hf_e1ap_integrityProtectionResult = -1;  /* IntegrityProtectionResult */
static int hf_e1ap_confidentialityProtectionResult = -1;  /* ConfidentialityProtectionResult */
static int hf_e1ap_Slice_Support_List_item = -1;  /* Slice_Support_Item */
static int hf_e1ap_sST = -1;                      /* OCTET_STRING_SIZE_1 */
static int hf_e1ap_sD = -1;                       /* OCTET_STRING_SIZE_3 */
static int hf_e1ap_defaultDRB = -1;               /* DefaultDRB */
static int hf_e1ap_sDAP_Header_UL = -1;           /* SDAP_Header_UL */
static int hf_e1ap_sDAP_Header_DL = -1;           /* SDAP_Header_DL */
static int hf_e1ap_t_Reordering = -1;             /* T_Reordering */
static int hf_e1ap_gNB_CU_CP_UE_E1AP_ID = -1;     /* GNB_CU_CP_UE_E1AP_ID */
static int hf_e1ap_gNB_CU_UP_UE_E1AP_ID = -1;     /* GNB_CU_UP_UE_E1AP_ID */
static int hf_e1ap_UP_Parameters_item = -1;       /* UP_Parameters_Item */
static int hf_e1ap_encryptionKey = -1;            /* EncryptionKey */
static int hf_e1ap_integrityProtectionKey = -1;   /* IntegrityProtectionKey */
static int hf_e1ap_gTPTunnel = -1;                /* GTPTunnel */
static int hf_e1ap_continueROHC_01 = -1;          /* T_continueROHC_01 */
static int hf_e1ap_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_e1ap_e1_Interface = -1;             /* ResetAll */
static int hf_e1ap_partOfE1_Interface = -1;       /* UE_associatedLogicalE1_ConnectionListRes */
static int hf_e1ap_UE_associatedLogicalE1_ConnectionListRes_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e1ap_UE_associatedLogicalE1_ConnectionListResAck_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e1ap_SupportedPLMNs_List_item = -1;  /* SupportedPLMNs_Item */
static int hf_e1ap_slice_Support_List = -1;       /* Slice_Support_List */
static int hf_e1ap_nR_CGI_Support_List = -1;      /* NR_CGI_Support_List */
static int hf_e1ap_qoS_Parameters_Support_List = -1;  /* QoS_Parameters_Support_List */
static int hf_e1ap_GNB_CU_UP_TNLA_To_Remove_List_item = -1;  /* GNB_CU_UP_TNLA_To_Remove_Item */
static int hf_e1ap_GNB_CU_CP_TNLA_To_Add_List_item = -1;  /* GNB_CU_CP_TNLA_To_Add_Item */
static int hf_e1ap_GNB_CU_CP_TNLA_To_Remove_List_item = -1;  /* GNB_CU_CP_TNLA_To_Remove_Item */
static int hf_e1ap_GNB_CU_CP_TNLA_To_Update_List_item = -1;  /* GNB_CU_CP_TNLA_To_Update_Item */
static int hf_e1ap_GNB_CU_CP_TNLA_Setup_List_item = -1;  /* GNB_CU_CP_TNLA_Setup_Item */
static int hf_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List_item = -1;  /* GNB_CU_CP_TNLA_Failed_To_Setup_Item */
static int hf_e1ap_e_UTRAN_BearerContextSetupRequest = -1;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_BearerContextSetupRequest = -1;  /* ProtocolIE_Container */
static int hf_e1ap_e_UTRAN_BearerContextSetupResponse = -1;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_BearerContextSetupResponse = -1;  /* ProtocolIE_Container */
static int hf_e1ap_e_UTRAN_BearerContextModificationRequest = -1;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_BearerContextModificationRequest = -1;  /* ProtocolIE_Container */
static int hf_e1ap_e_UTRAN_BearerContextModificationResponse = -1;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_BearerContextModificationResponse = -1;  /* ProtocolIE_Container */
static int hf_e1ap_e_UTRAN_BearerContextModificationRequired = -1;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_BearerContextModificationRequired = -1;  /* ProtocolIE_Container */
static int hf_e1ap_e_UTRAN_BearerContextModificationConfirm = -1;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_BearerContextModificationConfirm = -1;  /* ProtocolIE_Container */
static int hf_e1ap_DRB_Status_List_item = -1;     /* DRB_Status_Item */
static int hf_e1ap_e_UTRAN_GNB_CU_UP_CounterCheckRequest = -1;  /* ProtocolIE_Container */
static int hf_e1ap_nG_RAN_GNB_CU_UP_CounterCheckRequest = -1;  /* ProtocolIE_Container */
static int hf_e1ap_privateIEs = -1;               /* PrivateIE_Container */
static int hf_e1ap_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_e1ap_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_e1ap_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_e1ap_initiatingMessagevalue = -1;   /* InitiatingMessage_value */
static int hf_e1ap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_e1ap_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-e1ap-hf.c ---*/
#line 44 "./asn1/e1ap/packet-e1ap-template.c"

/* Initialize the subtree pointers */
static gint ett_e1ap = -1;
static gint ett_e1ap_PLMN_Identity = -1;
static gint ett_e1ap_TransportLayerAddress = -1;

/*--- Included file: packet-e1ap-ett.c ---*/
#line 1 "./asn1/e1ap/packet-e1ap-ett.c"
static gint ett_e1ap_PrivateIE_ID = -1;
static gint ett_e1ap_ProtocolIE_Container = -1;
static gint ett_e1ap_ProtocolIE_Field = -1;
static gint ett_e1ap_ProtocolExtensionContainer = -1;
static gint ett_e1ap_ProtocolExtensionField = -1;
static gint ett_e1ap_PrivateIE_Container = -1;
static gint ett_e1ap_PrivateIE_Field = -1;
static gint ett_e1ap_ActivityInformation = -1;
static gint ett_e1ap_Cause = -1;
static gint ett_e1ap_Cell_Group_Information = -1;
static gint ett_e1ap_Cell_Group_Information_Item = -1;
static gint ett_e1ap_CP_TNL_Information = -1;
static gint ett_e1ap_CriticalityDiagnostics = -1;
static gint ett_e1ap_CriticalityDiagnostics_IE_List = -1;
static gint ett_e1ap_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_e1ap_Data_Forwarding_Information_Request = -1;
static gint ett_e1ap_Data_Forwarding_Information = -1;
static gint ett_e1ap_Data_Usage_per_PDU_Session_Report = -1;
static gint ett_e1ap_SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item = -1;
static gint ett_e1ap_Data_Usage_per_QoS_Flow_List = -1;
static gint ett_e1ap_Data_Usage_per_QoS_Flow_Item = -1;
static gint ett_e1ap_Data_Usage_Report_List = -1;
static gint ett_e1ap_Data_Usage_Report_Item = -1;
static gint ett_e1ap_DRB_Activity_List = -1;
static gint ett_e1ap_DRB_Activity_Item = -1;
static gint ett_e1ap_DRB_Confirm_Modified_List_EUTRAN = -1;
static gint ett_e1ap_DRB_Confirm_Modified_Item_EUTRAN = -1;
static gint ett_e1ap_DRB_Confirm_Modified_List_NG_RAN = -1;
static gint ett_e1ap_DRB_Confirm_Modified_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_Failed_List_EUTRAN = -1;
static gint ett_e1ap_DRB_Failed_Item_EUTRAN = -1;
static gint ett_e1ap_DRB_Failed_Mod_List_EUTRAN = -1;
static gint ett_e1ap_DRB_Failed_Mod_Item_EUTRAN = -1;
static gint ett_e1ap_DRB_Failed_List_NG_RAN = -1;
static gint ett_e1ap_DRB_Failed_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_Failed_Mod_List_NG_RAN = -1;
static gint ett_e1ap_DRB_Failed_Mod_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_Failed_To_Modify_List_EUTRAN = -1;
static gint ett_e1ap_DRB_Failed_To_Modify_Item_EUTRAN = -1;
static gint ett_e1ap_DRB_Failed_To_Modify_List_NG_RAN = -1;
static gint ett_e1ap_DRB_Failed_To_Modify_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_Modified_List_EUTRAN = -1;
static gint ett_e1ap_DRB_Modified_Item_EUTRAN = -1;
static gint ett_e1ap_DRB_Modified_List_NG_RAN = -1;
static gint ett_e1ap_DRB_Modified_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_Required_To_Modify_List_EUTRAN = -1;
static gint ett_e1ap_DRB_Required_To_Modify_Item_EUTRAN = -1;
static gint ett_e1ap_DRB_Required_To_Modify_List_NG_RAN = -1;
static gint ett_e1ap_DRB_Required_To_Modify_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_Setup_List_EUTRAN = -1;
static gint ett_e1ap_DRB_Setup_Item_EUTRAN = -1;
static gint ett_e1ap_DRB_Setup_Mod_List_EUTRAN = -1;
static gint ett_e1ap_DRB_Setup_Mod_Item_EUTRAN = -1;
static gint ett_e1ap_DRB_Setup_List_NG_RAN = -1;
static gint ett_e1ap_DRB_Setup_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_Setup_Mod_List_NG_RAN = -1;
static gint ett_e1ap_DRB_Setup_Mod_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_Status_Item = -1;
static gint ett_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN = -1;
static gint ett_e1ap_DRBs_Subject_To_Counter_Check_Item_EUTRAN = -1;
static gint ett_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN = -1;
static gint ett_e1ap_DRBs_Subject_To_Counter_Check_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_To_Modify_List_EUTRAN = -1;
static gint ett_e1ap_DRB_To_Modify_Item_EUTRAN = -1;
static gint ett_e1ap_DRB_To_Modify_List_NG_RAN = -1;
static gint ett_e1ap_DRB_To_Modify_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_To_Remove_List_EUTRAN = -1;
static gint ett_e1ap_DRB_To_Remove_Item_EUTRAN = -1;
static gint ett_e1ap_DRB_Required_To_Remove_List_EUTRAN = -1;
static gint ett_e1ap_DRB_Required_To_Remove_Item_EUTRAN = -1;
static gint ett_e1ap_DRB_To_Remove_List_NG_RAN = -1;
static gint ett_e1ap_DRB_To_Remove_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_Required_To_Remove_List_NG_RAN = -1;
static gint ett_e1ap_DRB_Required_To_Remove_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_To_Setup_List_EUTRAN = -1;
static gint ett_e1ap_DRB_To_Setup_Item_EUTRAN = -1;
static gint ett_e1ap_DRB_To_Setup_Mod_List_EUTRAN = -1;
static gint ett_e1ap_DRB_To_Setup_Mod_Item_EUTRAN = -1;
static gint ett_e1ap_DRB_To_Setup_List_NG_RAN = -1;
static gint ett_e1ap_DRB_To_Setup_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_To_Setup_Mod_List_NG_RAN = -1;
static gint ett_e1ap_DRB_To_Setup_Mod_Item_NG_RAN = -1;
static gint ett_e1ap_DRB_Usage_Report_List = -1;
static gint ett_e1ap_DRB_Usage_Report_Item = -1;
static gint ett_e1ap_Dynamic5QIDescriptor = -1;
static gint ett_e1ap_Endpoint_IP_address_and_port = -1;
static gint ett_e1ap_EUTRANAllocationAndRetentionPriority = -1;
static gint ett_e1ap_EUTRAN_QoS_Support_List = -1;
static gint ett_e1ap_EUTRAN_QoS_Support_Item = -1;
static gint ett_e1ap_EUTRAN_QoS = -1;
static gint ett_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration = -1;
static gint ett_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration_Item = -1;
static gint ett_e1ap_GNB_CU_CP_TNLA_Setup_Item = -1;
static gint ett_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_Item = -1;
static gint ett_e1ap_GNB_CU_CP_TNLA_To_Add_Item = -1;
static gint ett_e1ap_GNB_CU_CP_TNLA_To_Remove_Item = -1;
static gint ett_e1ap_GNB_CU_CP_TNLA_To_Update_Item = -1;
static gint ett_e1ap_GNB_CU_UP_TNLA_To_Remove_Item = -1;
static gint ett_e1ap_GBR_QosInformation = -1;
static gint ett_e1ap_GBR_QoSFlowInformation = -1;
static gint ett_e1ap_GTPTunnel = -1;
static gint ett_e1ap_MaximumIPdatarate = -1;
static gint ett_e1ap_MRDC_Data_Usage_Report_Item = -1;
static gint ett_e1ap_MRDC_Usage_Information = -1;
static gint ett_e1ap_NGRANAllocationAndRetentionPriority = -1;
static gint ett_e1ap_NG_RAN_QoS_Support_List = -1;
static gint ett_e1ap_NG_RAN_QoS_Support_Item = -1;
static gint ett_e1ap_Non_Dynamic5QIDescriptor = -1;
static gint ett_e1ap_NR_CGI = -1;
static gint ett_e1ap_NR_CGI_Support_List = -1;
static gint ett_e1ap_NR_CGI_Support_Item = -1;
static gint ett_e1ap_PacketErrorRate = -1;
static gint ett_e1ap_PDCP_Configuration = -1;
static gint ett_e1ap_PDCP_Count = -1;
static gint ett_e1ap_PDU_Session_Resource_Data_Usage_List = -1;
static gint ett_e1ap_PDU_Session_Resource_Data_Usage_Item = -1;
static gint ett_e1ap_PDCP_SN_Status_Information = -1;
static gint ett_e1ap_DRBBStatusTransfer = -1;
static gint ett_e1ap_PDU_Session_Resource_Activity_List = -1;
static gint ett_e1ap_PDU_Session_Resource_Activity_Item = -1;
static gint ett_e1ap_PDU_Session_Resource_Confirm_Modified_List = -1;
static gint ett_e1ap_PDU_Session_Resource_Confirm_Modified_Item = -1;
static gint ett_e1ap_PDU_Session_Resource_Failed_List = -1;
static gint ett_e1ap_PDU_Session_Resource_Failed_Item = -1;
static gint ett_e1ap_PDU_Session_Resource_Failed_Mod_List = -1;
static gint ett_e1ap_PDU_Session_Resource_Failed_Mod_Item = -1;
static gint ett_e1ap_PDU_Session_Resource_Failed_To_Modify_List = -1;
static gint ett_e1ap_PDU_Session_Resource_Failed_To_Modify_Item = -1;
static gint ett_e1ap_PDU_Session_Resource_Modified_List = -1;
static gint ett_e1ap_PDU_Session_Resource_Modified_Item = -1;
static gint ett_e1ap_PDU_Session_Resource_Required_To_Modify_List = -1;
static gint ett_e1ap_PDU_Session_Resource_Required_To_Modify_Item = -1;
static gint ett_e1ap_PDU_Session_Resource_Setup_List = -1;
static gint ett_e1ap_PDU_Session_Resource_Setup_Item = -1;
static gint ett_e1ap_PDU_Session_Resource_Setup_Mod_List = -1;
static gint ett_e1ap_PDU_Session_Resource_Setup_Mod_Item = -1;
static gint ett_e1ap_PDU_Session_Resource_To_Modify_List = -1;
static gint ett_e1ap_PDU_Session_Resource_To_Modify_Item = -1;
static gint ett_e1ap_PDU_Session_Resource_To_Remove_List = -1;
static gint ett_e1ap_PDU_Session_Resource_To_Remove_Item = -1;
static gint ett_e1ap_PDU_Session_Resource_To_Setup_List = -1;
static gint ett_e1ap_PDU_Session_Resource_To_Setup_Item = -1;
static gint ett_e1ap_PDU_Session_Resource_To_Setup_Mod_List = -1;
static gint ett_e1ap_PDU_Session_Resource_To_Setup_Mod_Item = -1;
static gint ett_e1ap_PDU_Session_To_Notify_List = -1;
static gint ett_e1ap_PDU_Session_To_Notify_Item = -1;
static gint ett_e1ap_QoS_Characteristics = -1;
static gint ett_e1ap_QoS_Flow_List = -1;
static gint ett_e1ap_QoS_Flow_Item = -1;
static gint ett_e1ap_QoS_Flow_Failed_List = -1;
static gint ett_e1ap_QoS_Flow_Failed_Item = -1;
static gint ett_e1ap_QoS_Flow_Mapping_List = -1;
static gint ett_e1ap_QoS_Flow_Mapping_Item = -1;
static gint ett_e1ap_QoS_Parameters_Support_List = -1;
static gint ett_e1ap_QoS_Flow_QoS_Parameter_List = -1;
static gint ett_e1ap_QoS_Flow_QoS_Parameter_Item = -1;
static gint ett_e1ap_QoSFlowLevelQoSParameters = -1;
static gint ett_e1ap_ROHC_Parameters = -1;
static gint ett_e1ap_ROHC = -1;
static gint ett_e1ap_SecurityAlgorithm = -1;
static gint ett_e1ap_SecurityIndication = -1;
static gint ett_e1ap_SecurityInformation = -1;
static gint ett_e1ap_SecurityResult = -1;
static gint ett_e1ap_Slice_Support_List = -1;
static gint ett_e1ap_Slice_Support_Item = -1;
static gint ett_e1ap_SNSSAI = -1;
static gint ett_e1ap_SDAP_Configuration = -1;
static gint ett_e1ap_T_ReorderingTimer = -1;
static gint ett_e1ap_UE_associatedLogicalE1_ConnectionItem = -1;
static gint ett_e1ap_UP_Parameters = -1;
static gint ett_e1ap_UP_Parameters_Item = -1;
static gint ett_e1ap_UPSecuritykey = -1;
static gint ett_e1ap_UP_TNL_Information = -1;
static gint ett_e1ap_UplinkOnlyROHC = -1;
static gint ett_e1ap_Reset = -1;
static gint ett_e1ap_ResetType = -1;
static gint ett_e1ap_UE_associatedLogicalE1_ConnectionListRes = -1;
static gint ett_e1ap_ResetAcknowledge = -1;
static gint ett_e1ap_UE_associatedLogicalE1_ConnectionListResAck = -1;
static gint ett_e1ap_ErrorIndication = -1;
static gint ett_e1ap_GNB_CU_UP_E1SetupRequest = -1;
static gint ett_e1ap_SupportedPLMNs_List = -1;
static gint ett_e1ap_SupportedPLMNs_Item = -1;
static gint ett_e1ap_GNB_CU_UP_E1SetupResponse = -1;
static gint ett_e1ap_GNB_CU_UP_E1SetupFailure = -1;
static gint ett_e1ap_GNB_CU_CP_E1SetupRequest = -1;
static gint ett_e1ap_GNB_CU_CP_E1SetupResponse = -1;
static gint ett_e1ap_GNB_CU_CP_E1SetupFailure = -1;
static gint ett_e1ap_GNB_CU_UP_ConfigurationUpdate = -1;
static gint ett_e1ap_GNB_CU_UP_TNLA_To_Remove_List = -1;
static gint ett_e1ap_GNB_CU_UP_ConfigurationUpdateAcknowledge = -1;
static gint ett_e1ap_GNB_CU_UP_ConfigurationUpdateFailure = -1;
static gint ett_e1ap_GNB_CU_CP_ConfigurationUpdate = -1;
static gint ett_e1ap_GNB_CU_CP_TNLA_To_Add_List = -1;
static gint ett_e1ap_GNB_CU_CP_TNLA_To_Remove_List = -1;
static gint ett_e1ap_GNB_CU_CP_TNLA_To_Update_List = -1;
static gint ett_e1ap_GNB_CU_CP_ConfigurationUpdateAcknowledge = -1;
static gint ett_e1ap_GNB_CU_CP_TNLA_Setup_List = -1;
static gint ett_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List = -1;
static gint ett_e1ap_GNB_CU_CP_ConfigurationUpdateFailure = -1;
static gint ett_e1ap_E1ReleaseRequest = -1;
static gint ett_e1ap_E1ReleaseResponse = -1;
static gint ett_e1ap_BearerContextSetupRequest = -1;
static gint ett_e1ap_System_BearerContextSetupRequest = -1;
static gint ett_e1ap_BearerContextSetupResponse = -1;
static gint ett_e1ap_System_BearerContextSetupResponse = -1;
static gint ett_e1ap_BearerContextSetupFailure = -1;
static gint ett_e1ap_BearerContextModificationRequest = -1;
static gint ett_e1ap_System_BearerContextModificationRequest = -1;
static gint ett_e1ap_BearerContextModificationResponse = -1;
static gint ett_e1ap_System_BearerContextModificationResponse = -1;
static gint ett_e1ap_BearerContextModificationFailure = -1;
static gint ett_e1ap_BearerContextModificationRequired = -1;
static gint ett_e1ap_System_BearerContextModificationRequired = -1;
static gint ett_e1ap_BearerContextModificationConfirm = -1;
static gint ett_e1ap_System_BearerContextModificationConfirm = -1;
static gint ett_e1ap_BearerContextReleaseCommand = -1;
static gint ett_e1ap_BearerContextReleaseComplete = -1;
static gint ett_e1ap_BearerContextReleaseRequest = -1;
static gint ett_e1ap_DRB_Status_List = -1;
static gint ett_e1ap_BearerContextInactivityNotification = -1;
static gint ett_e1ap_DLDataNotification = -1;
static gint ett_e1ap_ULDataNotification = -1;
static gint ett_e1ap_DataUsageReport = -1;
static gint ett_e1ap_GNB_CU_UP_CounterCheckRequest = -1;
static gint ett_e1ap_System_GNB_CU_UP_CounterCheckRequest = -1;
static gint ett_e1ap_GNB_CU_UP_StatusIndication = -1;
static gint ett_e1ap_MRDC_DataUsageReport = -1;
static gint ett_e1ap_PrivateMessage = -1;
static gint ett_e1ap_E1AP_PDU = -1;
static gint ett_e1ap_InitiatingMessage = -1;
static gint ett_e1ap_SuccessfulOutcome = -1;
static gint ett_e1ap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-e1ap-ett.c ---*/
#line 50 "./asn1/e1ap/packet-e1ap-template.c"

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

typedef struct {
  guint32 message_type;
  guint32 procedure_code;
  guint32 protocol_ie_id;
  const char *obj_id;
} e1ap_private_data_t;

/* Global variables */
static dissector_handle_t e1ap_handle;

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
e1ap_MaxPacketLossRate_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f%% (%u)", (float)v/10, v);
}

static void
e1ap_PacketDelayBudget_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/2, v);
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


/*--- Included file: packet-e1ap-fn.c ---*/
#line 1 "./asn1/e1ap/packet-e1ap-fn.c"

static const value_string e1ap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_e1ap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_INTEGER_0_maxPrivateIEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxPrivateIEs, NULL, FALSE);

  return offset;
}



static int
dissect_e1ap_T_global(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 109 "./asn1/e1ap/e1ap.cnf"
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
#line 105 "./asn1/e1ap/e1ap.cnf"
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
  { 0, NULL }
};

static value_string_ext e1ap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(e1ap_ProcedureCode_vals);


static int
dissect_e1ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 86 "./asn1/e1ap/e1ap.cnf"
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &e1ap_data->procedure_code, FALSE);



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
  { 0, NULL }
};

static value_string_ext e1ap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(e1ap_ProtocolIE_ID_vals);


static int
dissect_e1ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 68 "./asn1/e1ap/e1ap.cnf"
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &e1ap_data->protocol_ie_id, FALSE);




#line 72 "./asn1/e1ap/e1ap.cnf"
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
                                     3, NULL, FALSE, 0, NULL);

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
                                                  0, maxProtocolIEs, FALSE);

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
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_e1ap_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 113 "./asn1/e1ap/e1ap.cnf"
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
                                                  1, maxPrivateIEs, FALSE);

  return offset;
}



static int
dissect_e1ap_DRB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, TRUE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}



static int
dissect_e1ap_PDU_Session_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_AveragingWindow(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}


static const value_string e1ap_BearerContextStatusChange_vals[] = {
  {   0, "suspend" },
  {   1, "resume" },
  { 0, NULL }
};


static int
dissect_e1ap_BearerContextStatusChange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_BitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(4000000000000), NULL, TRUE);

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
  { 0, NULL }
};

static value_string_ext e1ap_CauseRadioNetwork_vals_ext = VALUE_STRING_EXT_INIT(e1ap_CauseRadioNetwork_vals);


static int
dissect_e1ap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     25, NULL, TRUE, 3, NULL);

  return offset;
}


static const value_string e1ap_CauseTransport_vals[] = {
  {   0, "unspecified" },
  {   1, "transport-resource-unavailable" },
  { 0, NULL }
};


static int
dissect_e1ap_CauseTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

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
                                     7, NULL, TRUE, 0, NULL);

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
                                     5, NULL, TRUE, 0, NULL);

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



static int
dissect_e1ap_Cell_Group_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, TRUE);

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
                                     3, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofCellGroups, FALSE);

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
                                     4, NULL, TRUE, 0, NULL);

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
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_CommonNetworkInstance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

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
                                     3, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_TransportLayerAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 432 "./asn1/e1ap/e1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, NULL, 0, &param_tvb, NULL);

  if (param_tvb) {
    proto_tree *subtree;
    gint tvb_len;

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
                                                            0U, 255U, NULL, TRUE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofErrors, FALSE);

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


static const value_string e1ap_Data_Forwarding_Request_vals[] = {
  {   0, "uL" },
  {   1, "dL" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_e1ap_Data_Forwarding_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_QoS_Flow_Identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofQoSFlows, FALSE);

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



static int
dissect_e1ap_GTP_TEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

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


static const value_string e1ap_T_secondaryRATType_vals[] = {
  {   0, "nR" },
  {   1, "e-UTRA" },
  { 0, NULL }
};


static int
dissect_e1ap_T_secondaryRATType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_T_startTimeStamp_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 455 "./asn1/e1ap/e1ap.cnf"
  tvbuff_t *timestamp_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, &timestamp_tvb);




#line 459 "./asn1/e1ap/e1ap.cnf"
  if (timestamp_tvb) {
    proto_item_append_text(actx->created_item, " (%s)", tvb_ntp_fmt_ts_sec(timestamp_tvb, 0));
  }


  return offset;
}



static int
dissect_e1ap_T_endTimeStamp_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 464 "./asn1/e1ap/e1ap.cnf"
  tvbuff_t *timestamp_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, &timestamp_tvb);




#line 468 "./asn1/e1ap/e1ap.cnf"
  if (timestamp_tvb) {
    proto_item_append_text(actx->created_item, " (%s)", tvb_ntp_fmt_ts_sec(timestamp_tvb, 0));
  }


  return offset;
}



static int
dissect_e1ap_INTEGER_0_18446744073709551615(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(18446744073709551615), NULL, FALSE);

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
                                                  1, maxnooftimeperiods, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}



static int
dissect_e1ap_T_startTimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 393 "./asn1/e1ap/e1ap.cnf"
  tvbuff_t *timestamp_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, &timestamp_tvb);




#line 397 "./asn1/e1ap/e1ap.cnf"
  if (timestamp_tvb) {
    proto_item_append_text(actx->created_item, " (%s)", tvb_ntp_fmt_ts_sec(timestamp_tvb, 0));
  }


  return offset;
}



static int
dissect_e1ap_T_endTimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 402 "./asn1/e1ap/e1ap.cnf"
  tvbuff_t *timestamp_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, &timestamp_tvb);




#line 406 "./asn1/e1ap/e1ap.cnf"
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
                                                  1, maxnooftimeperiods, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     16, NULL, FALSE, 0, NULL);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}



static int
dissect_e1ap_BIT_STRING_SIZE_1_131072(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 131072, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e1ap_PDCP_SN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 262143U, NULL, FALSE);

  return offset;
}



static int
dissect_e1ap_HFN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

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
                                                  1, maxnoofUPParameters, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofQoSFlows, FALSE);

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
                                                  1, maxnoofQoSFlows, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofUPParameters, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const value_string e1ap_T_s1_DL_UP_Unchanged_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_T_s1_DL_UP_Unchanged(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const value_string e1ap_PDCP_SN_Size_vals[] = {
  {   0, "s-12" },
  {   1, "s-18" },
  { 0, NULL }
};


static int
dissect_e1ap_PDCP_SN_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

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
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_INTEGER_0_16383_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, TRUE);

  return offset;
}



static int
dissect_e1ap_INTEGER_0_511_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, TRUE);

  return offset;
}


static const value_string e1ap_T_continueROHC_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_T_continueROHC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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
                                     1, NULL, TRUE, 0, NULL);

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
                                     36, NULL, TRUE, 0, NULL);

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
                                     24, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e1ap_PDCP_Duplication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_PDCP_Duplication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e1ap_PDCP_Reestablishment_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_PDCP_Reestablishment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e1ap_PDCP_DataRecovery_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_PDCP_DataRecovery(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e1ap_OutOfOrderDelivery_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_OutOfOrderDelivery(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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
dissect_e1ap_QCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

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
                                                            0U, 15U, NULL, FALSE);

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
                                     2, NULL, FALSE, 0, NULL);

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
                                     2, NULL, FALSE, 0, NULL);

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
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_Inactivity_Timer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 7200U, NULL, TRUE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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



static int
dissect_e1ap_INTEGER_0_255_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, TRUE);

  return offset;
}



static int
dissect_e1ap_QoSPriorityLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, TRUE);

  return offset;
}



static int
dissect_e1ap_MaxDataBurstVolume(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

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



static int
dissect_e1ap_PacketDelayBudget(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, TRUE);

  return offset;
}



static int
dissect_e1ap_PER_Scalar(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, TRUE);

  return offset;
}



static int
dissect_e1ap_PER_Exponent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, TRUE);

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


static const value_string e1ap_T_delayCritical_vals[] = {
  {   0, "delay-critical" },
  {   1, "non-delay-critical" },
  { 0, NULL }
};


static int
dissect_e1ap_T_delayCritical(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

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
                                                            0U, 1000U, NULL, TRUE);

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
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e1ap_T_additional_QoS_Information_vals[] = {
  {   0, "more-likely" },
  { 0, NULL }
};


static int
dissect_e1ap_T_additional_QoS_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_INTEGER_1_8_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8U, NULL, TRUE);

  return offset;
}


static const value_string e1ap_T_reflective_QoS_Indicator_vals[] = {
  {   0, "enabled" },
  { 0, NULL }
};


static int
dissect_e1ap_T_reflective_QoS_Indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t QoSFlowLevelQoSParameters_sequence[] = {
  { &hf_e1ap_qoS_Characteristics, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_QoS_Characteristics },
  { &hf_e1ap_nGRANallocationRetentionPriority, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_NGRANAllocationAndRetentionPriority },
  { &hf_e1ap_gBR_QoS_Flow_Information, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_GBR_QoSFlowInformation },
  { &hf_e1ap_reflective_QoS_Attribute, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_T_reflective_QoS_Attribute },
  { &hf_e1ap_additional_QoS_Information, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_T_additional_QoS_Information },
  { &hf_e1ap_paging_Policy_Indicator, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e1ap_INTEGER_1_8_ },
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
                                                  1, maxnoofQoSFlows, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

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
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const value_string e1ap_DataDiscardRequired_vals[] = {
  {   0, "required" },
  { 0, NULL }
};


static int
dissect_e1ap_DataDiscardRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_EncryptionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_e1ap_PortNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 383 "./asn1/e1ap/e1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     16, 16, FALSE, NULL, 0, &parameter_tvb, NULL);

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
                                                  1, maxnoofEUTRANQOSParameters, FALSE);

  return offset;
}



static int
dissect_e1ap_GNB_CU_CP_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}



static int
dissect_e1ap_GNB_CU_CP_UE_E1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_e1ap_GNB_CU_UP_Capacity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_e1ap_GNB_CU_UP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(68719476735), NULL, FALSE);

  return offset;
}



static int
dissect_e1ap_GNB_CU_UP_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}



static int
dissect_e1ap_GNB_CU_UP_UE_E1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

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
                                     3, NULL, TRUE, 0, NULL);

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


static const value_string e1ap_GNB_CU_UP_OverloadInformation_vals[] = {
  {   0, "overloaded" },
  {   1, "not-overloaded" },
  { 0, NULL }
};


static int
dissect_e1ap_GNB_CU_UP_OverloadInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_GNB_DU_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(68719476735), NULL, FALSE);

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
                                     3, NULL, TRUE, 0, NULL);

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
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_IntegrityProtectionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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



static int
dissect_e1ap_NetworkInstance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, TRUE);

  return offset;
}


static const value_string e1ap_New_UL_TNL_Information_Required_vals[] = {
  {   0, "required" },
  { 0, NULL }
};


static int
dissect_e1ap_New_UL_TNL_Information_Required(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofNGRANQOSParameters, FALSE);

  return offset;
}



static int
dissect_e1ap_NR_Cell_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e1ap_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 372 "./asn1/e1ap/e1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_e1ap_PLMN_Identity);
    dissect_e212_mcc_mnc(param_tvb, actx->pinfo, subtree, 0, E212_NONE, FALSE);
  }



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
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_NR_CGI, NR_CGI_sequence);

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
                                                  1, maxnoofNRCGI, FALSE);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

  return offset;
}


static const value_string e1ap_T_nG_DL_UP_Unchanged_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e1ap_T_nG_DL_UP_Unchanged(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

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
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e1ap_OCTET_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}



static int
dissect_e1ap_OCTET_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

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
                                                  1, maxnoofPDUSessionResource, FALSE);

  return offset;
}



static int
dissect_e1ap_PPI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, TRUE);

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



static int
dissect_e1ap_RANUEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, NULL);

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


static const per_sequence_t Slice_Support_List_sequence_of[1] = {
  { &hf_e1ap_Slice_Support_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_Slice_Support_Item },
};

static int
dissect_e1ap_Slice_Support_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_Slice_Support_List, Slice_Support_List_sequence_of,
                                                  1, maxnoofSliceItems, FALSE);

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
                                     6, NULL, TRUE, 0, NULL);

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


static const per_sequence_t Reset_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_Reset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 479 "./asn1/e1ap/e1ap.cnf"
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
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UE_associatedLogicalE1_ConnectionListRes_sequence_of[1] = {
  { &hf_e1ap_UE_associatedLogicalE1_ConnectionListRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_SingleContainer },
};

static int
dissect_e1ap_UE_associatedLogicalE1_ConnectionListRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_UE_associatedLogicalE1_ConnectionListRes, UE_associatedLogicalE1_ConnectionListRes_sequence_of,
                                                  1, maxnoofIndividualE1ConnectionsToReset, FALSE);

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
#line 481 "./asn1/e1ap/e1ap.cnf"
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
                                                  1, maxnoofIndividualE1ConnectionsToReset, FALSE);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 483 "./asn1/e1ap/e1ap.cnf"
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
#line 485 "./asn1/e1ap/e1ap.cnf"
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
                                                  1, maxnoofSPLMNs, FALSE);

  return offset;
}


static const per_sequence_t GNB_CU_UP_E1SetupResponse_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_UP_E1SetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 487 "./asn1/e1ap/e1ap.cnf"
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
#line 489 "./asn1/e1ap/e1ap.cnf"
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
#line 491 "./asn1/e1ap/e1ap.cnf"
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
#line 493 "./asn1/e1ap/e1ap.cnf"
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
#line 495 "./asn1/e1ap/e1ap.cnf"
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
#line 497 "./asn1/e1ap/e1ap.cnf"
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
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t GNB_CU_UP_ConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_UP_ConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 499 "./asn1/e1ap/e1ap.cnf"
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
#line 501 "./asn1/e1ap/e1ap.cnf"
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
#line 503 "./asn1/e1ap/e1ap.cnf"
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
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t GNB_CU_CP_TNLA_To_Remove_List_sequence_of[1] = {
  { &hf_e1ap_GNB_CU_CP_TNLA_To_Remove_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_GNB_CU_CP_TNLA_To_Remove_Item },
};

static int
dissect_e1ap_GNB_CU_CP_TNLA_To_Remove_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_GNB_CU_CP_TNLA_To_Remove_List, GNB_CU_CP_TNLA_To_Remove_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t GNB_CU_CP_TNLA_To_Update_List_sequence_of[1] = {
  { &hf_e1ap_GNB_CU_CP_TNLA_To_Update_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_GNB_CU_CP_TNLA_To_Update_Item },
};

static int
dissect_e1ap_GNB_CU_CP_TNLA_To_Update_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_GNB_CU_CP_TNLA_To_Update_List, GNB_CU_CP_TNLA_To_Update_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t GNB_CU_CP_ConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CP_ConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 505 "./asn1/e1ap/e1ap.cnf"
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
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t GNB_CU_CP_TNLA_Failed_To_Setup_List_sequence_of[1] = {
  { &hf_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_Item },
};

static int
dissect_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List, GNB_CU_CP_TNLA_Failed_To_Setup_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t GNB_CU_CP_ConfigurationUpdateFailure_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_GNB_CU_CP_ConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 507 "./asn1/e1ap/e1ap.cnf"
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
#line 509 "./asn1/e1ap/e1ap.cnf"
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
#line 511 "./asn1/e1ap/e1ap.cnf"
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
#line 513 "./asn1/e1ap/e1ap.cnf"
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
#line 515 "./asn1/e1ap/e1ap.cnf"
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
#line 517 "./asn1/e1ap/e1ap.cnf"
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
#line 519 "./asn1/e1ap/e1ap.cnf"
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
#line 521 "./asn1/e1ap/e1ap.cnf"
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
#line 523 "./asn1/e1ap/e1ap.cnf"
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
#line 525 "./asn1/e1ap/e1ap.cnf"
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
#line 527 "./asn1/e1ap/e1ap.cnf"
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
#line 529 "./asn1/e1ap/e1ap.cnf"
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
#line 531 "./asn1/e1ap/e1ap.cnf"
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
#line 533 "./asn1/e1ap/e1ap.cnf"
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
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t BearerContextInactivityNotification_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_BearerContextInactivityNotification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 535 "./asn1/e1ap/e1ap.cnf"
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
#line 537 "./asn1/e1ap/e1ap.cnf"
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
#line 539 "./asn1/e1ap/e1ap.cnf"
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
#line 541 "./asn1/e1ap/e1ap.cnf"
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
#line 543 "./asn1/e1ap/e1ap.cnf"
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


static const per_sequence_t MRDC_DataUsageReport_sequence[] = {
  { &hf_e1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_MRDC_DataUsageReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 549 "./asn1/e1ap/e1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MRDC-DataUsageReport");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_MRDC_DataUsageReport, MRDC_DataUsageReport_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_e1ap_privateIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e1ap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e1ap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 547 "./asn1/e1ap/e1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PrivateMessage");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e1ap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}



static int
dissect_e1ap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 92 "./asn1/e1ap/e1ap.cnf"
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
#line 96 "./asn1/e1ap/e1ap.cnf"
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
#line 100 "./asn1/e1ap/e1ap.cnf"
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
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_ActivityInformation(tvb, offset, &asn1_ctx, tree, hf_e1ap_ActivityInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ActivityNotificationLevel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_ActivityNotificationLevel(tvb, offset, &asn1_ctx, tree, hf_e1ap_ActivityNotificationLevel_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextStatusChange_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BearerContextStatusChange(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextStatusChange_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BitRate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BitRate(tvb, offset, &asn1_ctx, tree, hf_e1ap_BitRate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_Cause(tvb, offset, &asn1_ctx, tree, hf_e1ap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CNSupport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_CNSupport(tvb, offset, &asn1_ctx, tree, hf_e1ap_CNSupport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CommonNetworkInstance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_CommonNetworkInstance(tvb, offset, &asn1_ctx, tree, hf_e1ap_CommonNetworkInstance_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CP_TNL_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_CP_TNL_Information(tvb, offset, &asn1_ctx, tree, hf_e1ap_CP_TNL_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_e1ap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Data_Usage_Report_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_Data_Usage_Report_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_Data_Usage_Report_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Confirm_Modified_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_Confirm_Modified_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Confirm_Modified_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Failed_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_Failed_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Failed_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Failed_Mod_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_Failed_Mod_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Failed_Mod_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Failed_To_Modify_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_Failed_To_Modify_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Failed_To_Modify_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Modified_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_Modified_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Modified_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Required_To_Modify_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_Required_To_Modify_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Required_To_Modify_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Setup_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_Setup_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Setup_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Setup_Mod_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_Setup_Mod_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Setup_Mod_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Subject_To_Counter_Check_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRBs_Subject_To_Counter_Check_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Subject_To_Counter_Check_List_NG_RAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRBs_Subject_To_Counter_Check_List_NG_RAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_To_Modify_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_To_Modify_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_To_Modify_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_To_Remove_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_To_Remove_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_To_Remove_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Required_To_Remove_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_Required_To_Remove_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Required_To_Remove_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_To_Setup_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_To_Setup_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_To_Setup_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_To_Setup_Mod_List_EUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_To_Setup_Mod_List_EUTRAN(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_To_Setup_Mod_List_EUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataDiscardRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DataDiscardRequired(tvb, offset, &asn1_ctx, tree, hf_e1ap_DataDiscardRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Endpoint_IP_address_and_port_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_Endpoint_IP_address_and_port(tvb, offset, &asn1_ctx, tree, hf_e1ap_Endpoint_IP_address_and_port_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_Name_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_Name(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_Name_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_UE_E1AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_UE_E1AP_ID(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_UE_E1AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_Capacity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_Capacity(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_Capacity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_ID(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_Name_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_Name(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_Name_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_UE_E1AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_UE_E1AP_ID(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_UE_E1AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_OverloadInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_OverloadInformation(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_OverloadInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DU_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_DU_ID(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_DU_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Inactivity_Timer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_Inactivity_Timer(tvb, offset, &asn1_ctx, tree, hf_e1ap_Inactivity_Timer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NetworkInstance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_NetworkInstance(tvb, offset, &asn1_ctx, tree, hf_e1ap_NetworkInstance_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_New_UL_TNL_Information_Required_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_New_UL_TNL_Information_Required(tvb, offset, &asn1_ctx, tree, hf_e1ap_New_UL_TNL_Information_Required_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Data_Usage_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Data_Usage_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Data_Usage_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Confirm_Modified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Confirm_Modified_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Confirm_Modified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Failed_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Failed_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Failed_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Failed_Mod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Failed_Mod_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Failed_Mod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Failed_To_Modify_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Failed_To_Modify_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Failed_To_Modify_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Modified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Modified_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Modified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Required_To_Modify_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Required_To_Modify_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Required_To_Modify_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Setup_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_Setup_Mod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_Setup_Mod_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_Setup_Mod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_To_Modify_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_To_Modify_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_To_Modify_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_To_Remove_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_To_Remove_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_To_Remove_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_To_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_To_Setup_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_To_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_Resource_To_Setup_Mod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_Resource_To_Setup_Mod_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_Resource_To_Setup_Mod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDU_Session_To_Notify_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PDU_Session_To_Notify_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_PDU_Session_To_Notify_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PLMN_Identity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PLMN_Identity(tvb, offset, &asn1_ctx, tree, hf_e1ap_PLMN_Identity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PPI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PPI(tvb, offset, &asn1_ctx, tree, hf_e1ap_PPI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoS_Flow_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_QoS_Flow_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_QoS_Flow_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoS_Flow_Mapping_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_QoS_Flow_Mapping_Indication(tvb, offset, &asn1_ctx, tree, hf_e1ap_QoS_Flow_Mapping_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoSFlowLevelQoSParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_QoSFlowLevelQoSParameters(tvb, offset, &asn1_ctx, tree, hf_e1ap_QoSFlowLevelQoSParameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANUEID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_RANUEID(tvb, offset, &asn1_ctx, tree, hf_e1ap_RANUEID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_SecurityInformation(tvb, offset, &asn1_ctx, tree, hf_e1ap_SecurityInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNSSAI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_SNSSAI(tvb, offset, &asn1_ctx, tree, hf_e1ap_SNSSAI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToWait_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_TimeToWait(tvb, offset, &asn1_ctx, tree, hf_e1ap_TimeToWait_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransactionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_TransactionID(tvb, offset, &asn1_ctx, tree, hf_e1ap_TransactionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_associatedLogicalE1_ConnectionItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_UE_associatedLogicalE1_ConnectionItem(tvb, offset, &asn1_ctx, tree, hf_e1ap_UE_associatedLogicalE1_ConnectionItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_Reset(tvb, offset, &asn1_ctx, tree, hf_e1ap_Reset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_ResetType(tvb, offset, &asn1_ctx, tree, hf_e1ap_ResetType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_ResetAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e1ap_ResetAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_associatedLogicalE1_ConnectionListResAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_UE_associatedLogicalE1_ConnectionListResAck(tvb, offset, &asn1_ctx, tree, hf_e1ap_UE_associatedLogicalE1_ConnectionListResAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_e1ap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_E1SetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_E1SetupRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_E1SetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SupportedPLMNs_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_SupportedPLMNs_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_SupportedPLMNs_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_E1SetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_E1SetupResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_E1SetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_E1SetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_E1SetupFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_E1SetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_E1SetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_E1SetupRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_E1SetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_E1SetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_E1SetupResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_E1SetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_E1SetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_E1SetupFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_E1SetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_ConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_ConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_ConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_TNLA_To_Remove_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_TNLA_To_Remove_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_TNLA_To_Remove_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_ConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_ConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_ConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_ConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_ConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_ConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_ConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_ConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_ConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_TNLA_To_Add_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_TNLA_To_Add_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_TNLA_To_Add_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_TNLA_To_Remove_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_TNLA_To_Remove_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_TNLA_To_Remove_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_TNLA_To_Update_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_TNLA_To_Update_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_TNLA_To_Update_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_ConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_ConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_ConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_TNLA_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_TNLA_Setup_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_TNLA_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_TNLA_Failed_To_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_CP_ConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_CP_ConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_CP_ConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E1ReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_E1ReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_E1ReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E1ReleaseResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_E1ReleaseResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_E1ReleaseResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BearerContextSetupRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_BearerContextSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_System_BearerContextSetupRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_BearerContextSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BearerContextSetupResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_BearerContextSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_System_BearerContextSetupResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_BearerContextSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextSetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BearerContextSetupFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextSetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BearerContextModificationRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_BearerContextModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_System_BearerContextModificationRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_BearerContextModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextModificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BearerContextModificationResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextModificationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_BearerContextModificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_System_BearerContextModificationResponse(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_BearerContextModificationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextModificationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BearerContextModificationFailure(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextModificationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextModificationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BearerContextModificationRequired(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextModificationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_BearerContextModificationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_System_BearerContextModificationRequired(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_BearerContextModificationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextModificationConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BearerContextModificationConfirm(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextModificationConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_BearerContextModificationConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_System_BearerContextModificationConfirm(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_BearerContextModificationConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BearerContextReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextReleaseComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BearerContextReleaseComplete(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextReleaseComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BearerContextReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Status_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DRB_Status_List(tvb, offset, &asn1_ctx, tree, hf_e1ap_DRB_Status_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerContextInactivityNotification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_BearerContextInactivityNotification(tvb, offset, &asn1_ctx, tree, hf_e1ap_BearerContextInactivityNotification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DLDataNotification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DLDataNotification(tvb, offset, &asn1_ctx, tree, hf_e1ap_DLDataNotification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ULDataNotification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_ULDataNotification(tvb, offset, &asn1_ctx, tree, hf_e1ap_ULDataNotification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataUsageReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_DataUsageReport(tvb, offset, &asn1_ctx, tree, hf_e1ap_DataUsageReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_CounterCheckRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_CounterCheckRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_CounterCheckRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_System_GNB_CU_UP_CounterCheckRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_System_GNB_CU_UP_CounterCheckRequest(tvb, offset, &asn1_ctx, tree, hf_e1ap_System_GNB_CU_UP_CounterCheckRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UP_StatusIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_GNB_CU_UP_StatusIndication(tvb, offset, &asn1_ctx, tree, hf_e1ap_GNB_CU_UP_StatusIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MRDC_DataUsageReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_MRDC_DataUsageReport(tvb, offset, &asn1_ctx, tree, hf_e1ap_MRDC_DataUsageReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_e1ap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E1AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e1ap_E1AP_PDU(tvb, offset, &asn1_ctx, tree, hf_e1ap_E1AP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-e1ap-fn.c ---*/
#line 104 "./asn1/e1ap/packet-e1ap-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  e1ap_ctx_t e1ap_ctx;
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  e1ap_ctx.message_type        = e1ap_data->message_type;
  e1ap_ctx.ProcedureCode       = e1ap_data->procedure_code;
  e1ap_ctx.ProtocolIE_ID       = e1ap_data->protocol_ie_id;

  return (dissector_try_uint_new(e1ap_ies_dissector_table, e1ap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, &e1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  e1ap_ctx_t e1ap_ctx;
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  e1ap_ctx.message_type        = e1ap_data->message_type;
  e1ap_ctx.ProcedureCode       = e1ap_data->procedure_code;
  e1ap_ctx.ProtocolIE_ID       = e1ap_data->protocol_ie_id;

  return (dissector_try_uint_new(e1ap_extension_dissector_table, e1ap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, &e1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e1ap_proc_imsg_dissector_table, e1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e1ap_proc_sout_dissector_table, e1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  e1ap_private_data_t *e1ap_data = e1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e1ap_proc_uout_dissector_table, e1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
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

/*--- Included file: packet-e1ap-hfarr.c ---*/
#line 1 "./asn1/e1ap/packet-e1ap-hfarr.c"
    { &hf_e1ap_ActivityInformation_PDU,
      { "ActivityInformation", "e1ap.ActivityInformation",
        FT_UINT32, BASE_DEC, VALS(e1ap_ActivityInformation_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_ActivityNotificationLevel_PDU,
      { "ActivityNotificationLevel", "e1ap.ActivityNotificationLevel",
        FT_UINT32, BASE_DEC, VALS(e1ap_ActivityNotificationLevel_vals), 0,
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
    { &hf_e1ap_Data_Usage_Report_List_PDU,
      { "Data-Usage-Report-List", "e1ap.Data_Usage_Report_List",
        FT_UINT32, BASE_DEC, NULL, 0,
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
    { &hf_e1ap_Endpoint_IP_address_and_port_PDU,
      { "Endpoint-IP-address-and-port", "e1ap.Endpoint_IP_address_and_port_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_CP_Name_PDU,
      { "GNB-CU-CP-Name", "e1ap.GNB_CU_CP_Name",
        FT_STRING, BASE_NONE, NULL, 0,
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
    { &hf_e1ap_GNB_CU_UP_Name_PDU,
      { "GNB-CU-UP-Name", "e1ap.GNB_CU_UP_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_UE_E1AP_ID_PDU,
      { "GNB-CU-UP-UE-E1AP-ID", "e1ap.GNB_CU_UP_UE_E1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_CU_UP_OverloadInformation_PDU,
      { "GNB-CU-UP-OverloadInformation", "e1ap.GNB_CU_UP_OverloadInformation",
        FT_UINT32, BASE_DEC, VALS(e1ap_GNB_CU_UP_OverloadInformation_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_GNB_DU_ID_PDU,
      { "GNB-DU-ID", "e1ap.GNB_DU_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_Inactivity_Timer_PDU,
      { "Inactivity-Timer", "e1ap.Inactivity_Timer",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_e1ap_NetworkInstance_PDU,
      { "NetworkInstance", "e1ap.NetworkInstance",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_New_UL_TNL_Information_Required_PDU,
      { "New-UL-TNL-Information-Required", "e1ap.New_UL_TNL_Information_Required",
        FT_UINT32, BASE_DEC, VALS(e1ap_New_UL_TNL_Information_Required_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_PDU_Session_Resource_Data_Usage_List_PDU,
      { "PDU-Session-Resource-Data-Usage-List", "e1ap.PDU_Session_Resource_Data_Usage_List",
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
    { &hf_e1ap_PLMN_Identity_PDU,
      { "PLMN-Identity", "e1ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PPI_PDU,
      { "PPI", "e1ap.PPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_QoS_Flow_List_PDU,
      { "QoS-Flow-List", "e1ap.QoS_Flow_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_QoS_Flow_Mapping_Indication_PDU,
      { "QoS-Flow-Mapping-Indication", "e1ap.QoS_Flow_Mapping_Indication",
        FT_UINT32, BASE_DEC, VALS(e1ap_QoS_Flow_Mapping_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_QoSFlowLevelQoSParameters_PDU,
      { "QoSFlowLevelQoSParameters", "e1ap.QoSFlowLevelQoSParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_RANUEID_PDU,
      { "RANUEID", "e1ap.RANUEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_SecurityInformation_PDU,
      { "SecurityInformation", "e1ap.SecurityInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_SNSSAI_PDU,
      { "SNSSAI", "e1ap.SNSSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_TimeToWait_PDU,
      { "TimeToWait", "e1ap.TimeToWait",
        FT_UINT32, BASE_DEC, VALS(e1ap_TimeToWait_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_TransactionID_PDU,
      { "TransactionID", "e1ap.TransactionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_UE_associatedLogicalE1_ConnectionItem_PDU,
      { "UE-associatedLogicalE1-ConnectionItem", "e1ap.UE_associatedLogicalE1_ConnectionItem_element",
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
    { &hf_e1ap_MRDC_DataUsageReport_PDU,
      { "MRDC-DataUsageReport", "e1ap.MRDC_DataUsageReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_PrivateMessage_PDU,
      { "PrivateMessage", "e1ap.PrivateMessage_element",
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
    { &hf_e1ap_iE_Extensions,
      { "iE-Extensions", "e1ap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
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
    { &hf_e1ap_cause,
      { "cause", "e1ap.cause",
        FT_UINT32, BASE_DEC, VALS(e1ap_Cause_vals), 0,
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
    { &hf_e1ap_packetDelayBudget,
      { "packetDelayBudget", "e1ap.packetDelayBudget",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(e1ap_PacketDelayBudget_fmt), 0,
        NULL, HFILL }},
    { &hf_e1ap_packetErrorRate,
      { "packetErrorRate", "e1ap.packetErrorRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
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
    { &hf_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration_item,
      { "GNB-CU-UP-CellGroupRelatedConfiguration-Item", "e1ap.GNB_CU_UP_CellGroupRelatedConfiguration_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_uP_TNL_Information,
      { "uP-TNL-Information", "e1ap.uP_TNL_Information",
        FT_UINT32, BASE_DEC, VALS(e1ap_UP_TNL_Information_vals), 0,
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
    { &hf_e1ap_transportLayerAddress,
      { "transportLayerAddress", "e1ap.transportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_gTP_TEID,
      { "gTP-TEID", "e1ap.gTP_TEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_maxIPrate,
      { "maxIPrate", "e1ap.maxIPrate",
        FT_UINT32, BASE_DEC, VALS(e1ap_MaxIPrate_vals), 0,
        NULL, HFILL }},
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
    { &hf_e1ap_NG_RAN_QoS_Support_List_item,
      { "NG-RAN-QoS-Support-Item", "e1ap.NG_RAN_QoS_Support_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_non_Dynamic5QIDescriptor,
      { "non-Dynamic5QIDescriptor", "e1ap.non_Dynamic5QIDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_pLMN_Identity,
      { "pLMN-Identity", "e1ap.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
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
    { &hf_e1ap_qoSFlowLevelQoSParameters,
      { "qoSFlowLevelQoSParameters", "e1ap.qoSFlowLevelQoSParameters_element",
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
    { &hf_e1ap_paging_Policy_Indicator,
      { "paging-Policy-Indicator", "e1ap.paging_Policy_Indicator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8_", HFILL }},
    { &hf_e1ap_reflective_QoS_Indicator,
      { "reflective-QoS-Indicator", "e1ap.reflective_QoS_Indicator",
        FT_UINT32, BASE_DEC, VALS(e1ap_T_reflective_QoS_Indicator_vals), 0,
        NULL, HFILL }},
    { &hf_e1ap_rOHC,
      { "rOHC", "e1ap.rOHC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_uPlinkOnlyROHC,
      { "uPlinkOnlyROHC", "e1ap.uPlinkOnlyROHC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_choice_Extension,
      { "choice-Extension", "e1ap.choice_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_SingleContainer", HFILL }},
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
    { &hf_e1ap_t_Reordering,
      { "t-Reordering", "e1ap.t_Reordering",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &e1ap_T_Reordering_vals_ext, 0,
        NULL, HFILL }},
    { &hf_e1ap_gNB_CU_CP_UE_E1AP_ID,
      { "gNB-CU-CP-UE-E1AP-ID", "e1ap.gNB_CU_CP_UE_E1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e1ap_gNB_CU_UP_UE_E1AP_ID,
      { "gNB-CU-UP-UE-E1AP-ID", "e1ap.gNB_CU_UP_UE_E1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
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

/*--- End of included file: packet-e1ap-hfarr.c ---*/
#line 183 "./asn1/e1ap/packet-e1ap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_e1ap,
    &ett_e1ap_PLMN_Identity,
    &ett_e1ap_TransportLayerAddress,

/*--- Included file: packet-e1ap-ettarr.c ---*/
#line 1 "./asn1/e1ap/packet-e1ap-ettarr.c"
    &ett_e1ap_PrivateIE_ID,
    &ett_e1ap_ProtocolIE_Container,
    &ett_e1ap_ProtocolIE_Field,
    &ett_e1ap_ProtocolExtensionContainer,
    &ett_e1ap_ProtocolExtensionField,
    &ett_e1ap_PrivateIE_Container,
    &ett_e1ap_PrivateIE_Field,
    &ett_e1ap_ActivityInformation,
    &ett_e1ap_Cause,
    &ett_e1ap_Cell_Group_Information,
    &ett_e1ap_Cell_Group_Information_Item,
    &ett_e1ap_CP_TNL_Information,
    &ett_e1ap_CriticalityDiagnostics,
    &ett_e1ap_CriticalityDiagnostics_IE_List,
    &ett_e1ap_CriticalityDiagnostics_IE_List_item,
    &ett_e1ap_Data_Forwarding_Information_Request,
    &ett_e1ap_Data_Forwarding_Information,
    &ett_e1ap_Data_Usage_per_PDU_Session_Report,
    &ett_e1ap_SEQUENCE_SIZE_1_maxnooftimeperiods_OF_MRDC_Data_Usage_Report_Item,
    &ett_e1ap_Data_Usage_per_QoS_Flow_List,
    &ett_e1ap_Data_Usage_per_QoS_Flow_Item,
    &ett_e1ap_Data_Usage_Report_List,
    &ett_e1ap_Data_Usage_Report_Item,
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
    &ett_e1ap_DRB_Modified_List_EUTRAN,
    &ett_e1ap_DRB_Modified_Item_EUTRAN,
    &ett_e1ap_DRB_Modified_List_NG_RAN,
    &ett_e1ap_DRB_Modified_Item_NG_RAN,
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
    &ett_e1ap_Endpoint_IP_address_and_port,
    &ett_e1ap_EUTRANAllocationAndRetentionPriority,
    &ett_e1ap_EUTRAN_QoS_Support_List,
    &ett_e1ap_EUTRAN_QoS_Support_Item,
    &ett_e1ap_EUTRAN_QoS,
    &ett_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration,
    &ett_e1ap_GNB_CU_UP_CellGroupRelatedConfiguration_Item,
    &ett_e1ap_GNB_CU_CP_TNLA_Setup_Item,
    &ett_e1ap_GNB_CU_CP_TNLA_Failed_To_Setup_Item,
    &ett_e1ap_GNB_CU_CP_TNLA_To_Add_Item,
    &ett_e1ap_GNB_CU_CP_TNLA_To_Remove_Item,
    &ett_e1ap_GNB_CU_CP_TNLA_To_Update_Item,
    &ett_e1ap_GNB_CU_UP_TNLA_To_Remove_Item,
    &ett_e1ap_GBR_QosInformation,
    &ett_e1ap_GBR_QoSFlowInformation,
    &ett_e1ap_GTPTunnel,
    &ett_e1ap_MaximumIPdatarate,
    &ett_e1ap_MRDC_Data_Usage_Report_Item,
    &ett_e1ap_MRDC_Usage_Information,
    &ett_e1ap_NGRANAllocationAndRetentionPriority,
    &ett_e1ap_NG_RAN_QoS_Support_List,
    &ett_e1ap_NG_RAN_QoS_Support_Item,
    &ett_e1ap_Non_Dynamic5QIDescriptor,
    &ett_e1ap_NR_CGI,
    &ett_e1ap_NR_CGI_Support_List,
    &ett_e1ap_NR_CGI_Support_Item,
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
    &ett_e1ap_T_ReorderingTimer,
    &ett_e1ap_UE_associatedLogicalE1_ConnectionItem,
    &ett_e1ap_UP_Parameters,
    &ett_e1ap_UP_Parameters_Item,
    &ett_e1ap_UPSecuritykey,
    &ett_e1ap_UP_TNL_Information,
    &ett_e1ap_UplinkOnlyROHC,
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
    &ett_e1ap_MRDC_DataUsageReport,
    &ett_e1ap_PrivateMessage,
    &ett_e1ap_E1AP_PDU,
    &ett_e1ap_InitiatingMessage,
    &ett_e1ap_SuccessfulOutcome,
    &ett_e1ap_UnsuccessfulOutcome,

/*--- End of included file: packet-e1ap-ettarr.c ---*/
#line 191 "./asn1/e1ap/packet-e1ap-template.c"
  };

  /* Register protocol */
  proto_e1ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_e1ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  e1ap_handle = register_dissector("e1ap", dissect_e1ap, proto_e1ap);

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
  dissector_add_uint("sctp.ppi", E1AP_PROTOCOL_ID, e1ap_handle);

/*--- Included file: packet-e1ap-dis-tab.c ---*/
#line 1 "./asn1/e1ap/packet-e1ap-dis-tab.c"
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
  dissector_add_uint("e1ap.extension", id_SNSSAI, create_dissector_handle(dissect_SNSSAI_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_OldQoSFlowMap_ULendmarkerexpected, create_dissector_handle(dissect_QoS_Flow_List_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_DRB_QoS, create_dissector_handle(dissect_QoSFlowLevelQoSParameters_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_TNLAssociationTransportLayerAddressgNBCUUP, create_dissector_handle(dissect_CP_TNL_Information_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_CommonNetworkInstance, create_dissector_handle(dissect_CommonNetworkInstance_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_NetworkInstance, create_dissector_handle(dissect_NetworkInstance_PDU, proto_e1ap));
  dissector_add_uint("e1ap.extension", id_QoSFlowMappingIndication, create_dissector_handle(dissect_QoS_Flow_Mapping_Indication_PDU, proto_e1ap));
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
  dissector_add_uint("e1ap.proc.imsg", id_mRDC_DataUsageReport, create_dissector_handle(dissect_MRDC_DataUsageReport_PDU, proto_e1ap));


/*--- End of included file: packet-e1ap-dis-tab.c ---*/
#line 216 "./asn1/e1ap/packet-e1ap-template.c"
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
