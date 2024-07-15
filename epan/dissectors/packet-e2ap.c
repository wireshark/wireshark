/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-e2ap.c                                                              */
/* asn2wrs.py -q -L -p e2ap -c ./e2ap.cnf -s ./packet-e2ap-template -D . -O ../.. E2AP-CommonDataTypes.asn E2AP-Constants.asn E2AP-Containers.asn E2AP-IEs.asn E2AP-PDU-Contents.asn E2AP-PDU-Descriptions.asn e2sm-v3.01.asn e2sm-rc-v1.03.asn e2sm-kpm-v3.00.asn e2sm-ni-v1.00.asn */

/* packet-e2ap.c
 * Routines for E2APApplication Protocol (e2ap) packet dissection
 * Copyright 2021, Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: ORAN-WG3.E2AP-v03.00, ORAN-WG3.E2SM-KPM-v03.00, ORAN-WG3.E2SM-RC.03.00
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/to_str.h>
#include <epan/oids.h>
#include <epan/tap.h>
#include <epan/stats_tree.h>

#include "packet-e2ap.h"
#include "packet-per.h"
#include "packet-ntp.h"

#define PNAME  "E2 Application Protocol"
#define PSNAME "E2AP"
#define PFNAME "e2ap"

/* Dissector will use SCTP PPID 70, 71 or 72 or SCTP port 37464. */
#define SCTP_PORT_E2AP 37464

void proto_register_e2ap(void);
void proto_reg_handoff_e2ap(void);

static dissector_handle_t e2ap_handle;

#define maxProtocolIEs                 65535
#define maxnoofErrors                  256
#define maxofE2nodeComponents          1024
#define maxofRANfunctionID             256
#define maxofRICactionID               16
#define maxofTNLA                      32
#define maxofRICrequestID              1024
#define maxE1APid                      65535
#define maxF1APid                      4
#define maxEARFCN                      65535
#define maxNRARFCN                     3279165
#define maxnoofNrCellBands             32
#define maxnoofMessages                65535
#define maxnoofE2InfoChanges           65535
#define maxnoofUEInfoChanges           65535
#define maxnoofRRCstate                8
#define maxnoofParametersToReport      65535
#define maxnoofPolicyConditions        65535
#define maxnoofAssociatedRANParameters 65535
#define maxnoofUEID                    65535
#define maxnoofCellID                  65535
#define maxnoofRANOutcomeParameters    255
#define maxnoofParametersinStructure   65535
#define maxnoofItemsinList             65535
#define maxnoofUEInfo                  65535
#define maxnoofCellInfo                65535
#define maxnoofUEeventInfo             65535
#define maxnoofRANparamTest            255
#define maxnoofNeighbourCell           65535
#define maxnoofRICStyles               63
#define maxnoofCallProcessTypes        65535
#define maxnoofCallProcessBreakpoints  65535
#define maxnoofInsertIndication        65535
#define maxnoofControlAction           65535
#define maxnoofPolicyAction            65535
#define maxnoofInsertIndicationActions 63
#define maxnoofMulCtrlActions          63
#define maxnoofCells                   16384
#define maxnoofMeasurementInfo         65535
#define maxnoofLabelInfo               2147483647
#define maxnoofMeasurementRecord       65535
#define maxnoofMeasurementValue        2147483647
#define maxnoofConditionInfo           32768
#define maxnoofConditionInfoPerSub     32768
#define maxnoofUEIDPerSub              65535
#define maxnoofUEMeasReport            65535
#define maxnoofBin                     65535
#define maxofInterfaceProtocolTests    15
#define maxofRANueGroups               255
#define maxofActionParameters          255
#define maxofRANparameters             65535
#define maxofNItypes                   63
#define maxofRICstyles                 63

typedef enum _ProcedureCode_enum {
  id_E2setup   =   1,
  id_ErrorIndication =   2,
  id_Reset     =   3,
  id_RICcontrol =   4,
  id_RICindication =   5,
  id_RICserviceQuery =   6,
  id_RICserviceUpdate =   7,
  id_RICsubscription =   8,
  id_RICsubscriptionDelete =   9,
  id_E2nodeConfigurationUpdate =  10,
  id_E2connectionUpdate =  11,
  id_RICsubscriptionDeleteRequired =  12,
  id_E2removal =  13,
  id_RICsubscriptionModification =  14,
  id_RICsubscriptionModificationRequired =  15,
  id_RICquery  =  16
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_Cause     =   1,
  id_CriticalityDiagnostics =   2,
  id_GlobalE2node_ID =   3,
  id_GlobalRIC_ID =   4,
  id_RANfunctionID =   5,
  id_RANfunctionID_Item =   6,
  id_RANfunctionIEcause_Item =   7,
  id_RANfunction_Item =   8,
  id_RANfunctionsAccepted =   9,
  id_RANfunctionsAdded =  10,
  id_RANfunctionsDeleted =  11,
  id_RANfunctionsModified =  12,
  id_RANfunctionsRejected =  13,
  id_RICaction_Admitted_Item =  14,
  id_RICactionID =  15,
  id_RICaction_NotAdmitted_Item =  16,
  id_RICactions_Admitted =  17,
  id_RICactions_NotAdmitted =  18,
  id_RICaction_ToBeSetup_Item =  19,
  id_RICcallProcessID =  20,
  id_RICcontrolAckRequest =  21,
  id_RICcontrolHeader =  22,
  id_RICcontrolMessage =  23,
  id_RICcontrolStatus =  24,
  id_RICindicationHeader =  25,
  id_RICindicationMessage =  26,
  id_RICindicationSN =  27,
  id_RICindicationType =  28,
  id_RICrequestID =  29,
  id_RICsubscriptionDetails =  30,
  id_TimeToWait =  31,
  id_RICcontrolOutcome =  32,
  id_E2nodeComponentConfigUpdate =  33,
  id_E2nodeComponentConfigUpdate_Item =  34,
  id_E2nodeComponentConfigUpdateAck =  35,
  id_E2nodeComponentConfigUpdateAck_Item =  36,
  id_E2connectionSetup =  39,
  id_E2connectionSetupFailed =  40,
  id_E2connectionSetupFailed_Item =  41,
  id_E2connectionFailed_Item =  42,
  id_E2connectionUpdate_Item =  43,
  id_E2connectionUpdateAdd =  44,
  id_E2connectionUpdateModify =  45,
  id_E2connectionUpdateRemove =  46,
  id_E2connectionUpdateRemove_Item =  47,
  id_TNLinformation =  48,
  id_TransactionID =  49,
  id_E2nodeComponentConfigAddition =  50,
  id_E2nodeComponentConfigAddition_Item =  51,
  id_E2nodeComponentConfigAdditionAck =  52,
  id_E2nodeComponentConfigAdditionAck_Item =  53,
  id_E2nodeComponentConfigRemoval =  54,
  id_E2nodeComponentConfigRemoval_Item =  55,
  id_E2nodeComponentConfigRemovalAck =  56,
  id_E2nodeComponentConfigRemovalAck_Item =  57,
  id_E2nodeTNLassociationRemoval =  58,
  id_E2nodeTNLassociationRemoval_Item =  59,
  id_RICsubscriptionToBeRemoved =  60,
  id_RICsubscription_withCause_Item =  61,
  id_RICsubscriptionStartTime =  62,
  id_RICsubscriptionEndTime =  63,
  id_RICeventTriggerDefinitionToBeModified =  64,
  id_RICactionsToBeRemovedForModification_List =  65,
  id_RICaction_ToBeRemovedForModification_Item =  66,
  id_RICactionsToBeModifiedForModification_List =  67,
  id_RICaction_ToBeModifiedForModification_Item =  68,
  id_RICactionsToBeAddedForModification_List =  69,
  id_RICaction_ToBeAddedForModification_Item =  70,
  id_RICactionsRemovedForModification_List =  71,
  id_RICaction_RemovedForModification_Item =  72,
  id_RICactionsFailedToBeRemovedForModification_List =  73,
  id_RICaction_FailedToBeRemovedForModification_Item =  74,
  id_RICactionsModifiedForModification_List =  75,
  id_RICaction_ModifiedForModification_Item =  76,
  id_RICactionsFailedToBeModifiedForModification_List =  77,
  id_RICaction_FailedToBeModifiedForModification_Item =  78,
  id_RICactionsAddedForModification_List =  79,
  id_RICaction_AddedForModification_Item =  80,
  id_RICactionsFailedToBeAddedForModification_List =  81,
  id_RICaction_FailedToBeAddedForModification_Item =  82,
  id_RICactionsRequiredToBeModified_List =  83,
  id_RICaction_RequiredToBeModified_Item =  84,
  id_RICactionsRequiredToBeRemoved_List =  85,
  id_RICaction_RequiredToBeRemoved_Item =  86,
  id_RICactionsConfirmedForModification_List =  87,
  id_RICaction_ConfirmedForModification_Item =  88,
  id_RICactionsRefusedToBeModified_List =  89,
  id_RICaction_RefusedToBeModified_Item =  90,
  id_RICactionsConfirmedForRemoval_List =  91,
  id_RICaction_ConfirmedForRemoval_Item =  92,
  id_RICactionsRefusedToBeRemoved_List =  93,
  id_RICaction_RefusedToBeRemoved_Item =  94,
  id_RICqueryHeader =  95,
  id_RICqueryDefinition =  96,
  id_RICqueryOutcome =  97
} ProtocolIE_ID_enum;

/* Initialize the protocol and registered fields */
static int proto_e2ap;
static int hf_e2ap_Cause_PDU;                     /* Cause */
static int hf_e2ap_CriticalityDiagnostics_PDU;    /* CriticalityDiagnostics */
static int hf_e2ap_GlobalE2node_ID_PDU;           /* GlobalE2node_ID */
static int hf_e2ap_GlobalRIC_ID_PDU;              /* GlobalRIC_ID */
static int hf_e2ap_RANfunctionID_PDU;             /* RANfunctionID */
static int hf_e2ap_RICactionID_PDU;               /* RICactionID */
static int hf_e2ap_RICcallProcessID_PDU;          /* RICcallProcessID */
static int hf_e2ap_RICcontrolAckRequest_PDU;      /* RICcontrolAckRequest */
static int hf_e2ap_RICcontrolHeader_PDU;          /* RICcontrolHeader */
static int hf_e2ap_RICcontrolMessage_PDU;         /* RICcontrolMessage */
static int hf_e2ap_RICcontrolOutcome_PDU;         /* RICcontrolOutcome */
static int hf_e2ap_RICeventTriggerDefinition_PDU;  /* RICeventTriggerDefinition */
static int hf_e2ap_RICindicationHeader_PDU;       /* RICindicationHeader */
static int hf_e2ap_RICindicationMessage_PDU;      /* RICindicationMessage */
static int hf_e2ap_RICindicationSN_PDU;           /* RICindicationSN */
static int hf_e2ap_RICindicationType_PDU;         /* RICindicationType */
static int hf_e2ap_RICrequestID_PDU;              /* RICrequestID */
static int hf_e2ap_RICsubscriptionTime_PDU;       /* RICsubscriptionTime */
static int hf_e2ap_RICqueryHeader_PDU;            /* RICqueryHeader */
static int hf_e2ap_RICqueryDefinition_PDU;        /* RICqueryDefinition */
static int hf_e2ap_RICqueryOutcome_PDU;           /* RICqueryOutcome */
static int hf_e2ap_TimeToWait_PDU;                /* TimeToWait */
static int hf_e2ap_TNLinformation_PDU;            /* TNLinformation */
static int hf_e2ap_TransactionID_PDU;             /* TransactionID */
static int hf_e2ap_RICsubscriptionRequest_PDU;    /* RICsubscriptionRequest */
static int hf_e2ap_RICsubscriptionDetails_PDU;    /* RICsubscriptionDetails */
static int hf_e2ap_RICaction_ToBeSetup_Item_PDU;  /* RICaction_ToBeSetup_Item */
static int hf_e2ap_RICsubscriptionResponse_PDU;   /* RICsubscriptionResponse */
static int hf_e2ap_RICaction_Admitted_List_PDU;   /* RICaction_Admitted_List */
static int hf_e2ap_RICaction_Admitted_Item_PDU;   /* RICaction_Admitted_Item */
static int hf_e2ap_RICaction_NotAdmitted_List_PDU;  /* RICaction_NotAdmitted_List */
static int hf_e2ap_RICaction_NotAdmitted_Item_PDU;  /* RICaction_NotAdmitted_Item */
static int hf_e2ap_RICsubscriptionFailure_PDU;    /* RICsubscriptionFailure */
static int hf_e2ap_RICsubscriptionDeleteRequest_PDU;  /* RICsubscriptionDeleteRequest */
static int hf_e2ap_RICsubscriptionDeleteResponse_PDU;  /* RICsubscriptionDeleteResponse */
static int hf_e2ap_RICsubscriptionDeleteFailure_PDU;  /* RICsubscriptionDeleteFailure */
static int hf_e2ap_RICsubscriptionDeleteRequired_PDU;  /* RICsubscriptionDeleteRequired */
static int hf_e2ap_RICsubscription_List_withCause_PDU;  /* RICsubscription_List_withCause */
static int hf_e2ap_RICsubscription_withCause_Item_PDU;  /* RICsubscription_withCause_Item */
static int hf_e2ap_RICsubscriptionModificationRequest_PDU;  /* RICsubscriptionModificationRequest */
static int hf_e2ap_RICactions_ToBeRemovedForModification_List_PDU;  /* RICactions_ToBeRemovedForModification_List */
static int hf_e2ap_RICaction_ToBeRemovedForModification_Item_PDU;  /* RICaction_ToBeRemovedForModification_Item */
static int hf_e2ap_RICactions_ToBeModifiedForModification_List_PDU;  /* RICactions_ToBeModifiedForModification_List */
static int hf_e2ap_RICaction_ToBeModifiedForModification_Item_PDU;  /* RICaction_ToBeModifiedForModification_Item */
static int hf_e2ap_RICactions_ToBeAddedForModification_List_PDU;  /* RICactions_ToBeAddedForModification_List */
static int hf_e2ap_RICaction_ToBeAddedForModification_Item_PDU;  /* RICaction_ToBeAddedForModification_Item */
static int hf_e2ap_RICsubscriptionModificationResponse_PDU;  /* RICsubscriptionModificationResponse */
static int hf_e2ap_RICactions_RemovedForModification_List_PDU;  /* RICactions_RemovedForModification_List */
static int hf_e2ap_RICaction_RemovedForModification_Item_PDU;  /* RICaction_RemovedForModification_Item */
static int hf_e2ap_RICactions_FailedToBeRemovedForModification_List_PDU;  /* RICactions_FailedToBeRemovedForModification_List */
static int hf_e2ap_RICaction_FailedToBeRemovedForModification_Item_PDU;  /* RICaction_FailedToBeRemovedForModification_Item */
static int hf_e2ap_RICactions_ModifiedForModification_List_PDU;  /* RICactions_ModifiedForModification_List */
static int hf_e2ap_RICaction_ModifiedForModification_Item_PDU;  /* RICaction_ModifiedForModification_Item */
static int hf_e2ap_RICactions_FailedToBeModifiedForModification_List_PDU;  /* RICactions_FailedToBeModifiedForModification_List */
static int hf_e2ap_RICaction_FailedToBeModifiedForModification_Item_PDU;  /* RICaction_FailedToBeModifiedForModification_Item */
static int hf_e2ap_RICactions_AddedForModification_List_PDU;  /* RICactions_AddedForModification_List */
static int hf_e2ap_RICaction_AddedForModification_Item_PDU;  /* RICaction_AddedForModification_Item */
static int hf_e2ap_RICactions_FailedToBeAddedForModification_List_PDU;  /* RICactions_FailedToBeAddedForModification_List */
static int hf_e2ap_RICaction_FailedToBeAddedForModification_Item_PDU;  /* RICaction_FailedToBeAddedForModification_Item */
static int hf_e2ap_RICsubscriptionModificationFailure_PDU;  /* RICsubscriptionModificationFailure */
static int hf_e2ap_RICsubscriptionModificationRequired_PDU;  /* RICsubscriptionModificationRequired */
static int hf_e2ap_RICactions_RequiredToBeModified_List_PDU;  /* RICactions_RequiredToBeModified_List */
static int hf_e2ap_RICaction_RequiredToBeModified_Item_PDU;  /* RICaction_RequiredToBeModified_Item */
static int hf_e2ap_RICactions_RequiredToBeRemoved_List_PDU;  /* RICactions_RequiredToBeRemoved_List */
static int hf_e2ap_RICaction_RequiredToBeRemoved_Item_PDU;  /* RICaction_RequiredToBeRemoved_Item */
static int hf_e2ap_RICsubscriptionModificationConfirm_PDU;  /* RICsubscriptionModificationConfirm */
static int hf_e2ap_RICactions_ConfirmedForModification_List_PDU;  /* RICactions_ConfirmedForModification_List */
static int hf_e2ap_RICaction_ConfirmedForModification_Item_PDU;  /* RICaction_ConfirmedForModification_Item */
static int hf_e2ap_RICactions_RefusedToBeModified_List_PDU;  /* RICactions_RefusedToBeModified_List */
static int hf_e2ap_RICaction_RefusedToBeModified_Item_PDU;  /* RICaction_RefusedToBeModified_Item */
static int hf_e2ap_RICactions_ConfirmedForRemoval_List_PDU;  /* RICactions_ConfirmedForRemoval_List */
static int hf_e2ap_RICaction_ConfirmedForRemoval_Item_PDU;  /* RICaction_ConfirmedForRemoval_Item */
static int hf_e2ap_RICactions_RefusedToBeRemoved_List_PDU;  /* RICactions_RefusedToBeRemoved_List */
static int hf_e2ap_RICaction_RefusedToBeRemoved_Item_PDU;  /* RICaction_RefusedToBeRemoved_Item */
static int hf_e2ap_RICsubscriptionModificationRefuse_PDU;  /* RICsubscriptionModificationRefuse */
static int hf_e2ap_RICindication_PDU;             /* RICindication */
static int hf_e2ap_RICcontrolRequest_PDU;         /* RICcontrolRequest */
static int hf_e2ap_RICcontrolAcknowledge_PDU;     /* RICcontrolAcknowledge */
static int hf_e2ap_RICcontrolFailure_PDU;         /* RICcontrolFailure */
static int hf_e2ap_RICQueryRequest_PDU;           /* RICQueryRequest */
static int hf_e2ap_RICQueryResponse_PDU;          /* RICQueryResponse */
static int hf_e2ap_RICQueryFailure_PDU;           /* RICQueryFailure */
static int hf_e2ap_ErrorIndication_PDU;           /* ErrorIndication */
static int hf_e2ap_E2setupRequest_PDU;            /* E2setupRequest */
static int hf_e2ap_E2setupResponse_PDU;           /* E2setupResponse */
static int hf_e2ap_E2setupFailure_PDU;            /* E2setupFailure */
static int hf_e2ap_E2connectionUpdate_PDU;        /* E2connectionUpdate */
static int hf_e2ap_E2connectionUpdate_List_PDU;   /* E2connectionUpdate_List */
static int hf_e2ap_E2connectionUpdate_Item_PDU;   /* E2connectionUpdate_Item */
static int hf_e2ap_E2connectionUpdateRemove_List_PDU;  /* E2connectionUpdateRemove_List */
static int hf_e2ap_E2connectionUpdateRemove_Item_PDU;  /* E2connectionUpdateRemove_Item */
static int hf_e2ap_E2connectionUpdateAcknowledge_PDU;  /* E2connectionUpdateAcknowledge */
static int hf_e2ap_E2connectionSetupFailed_List_PDU;  /* E2connectionSetupFailed_List */
static int hf_e2ap_E2connectionSetupFailed_Item_PDU;  /* E2connectionSetupFailed_Item */
static int hf_e2ap_E2connectionUpdateFailure_PDU;  /* E2connectionUpdateFailure */
static int hf_e2ap_E2nodeConfigurationUpdate_PDU;  /* E2nodeConfigurationUpdate */
static int hf_e2ap_E2nodeComponentConfigAddition_List_PDU;  /* E2nodeComponentConfigAddition_List */
static int hf_e2ap_E2nodeComponentConfigAddition_Item_PDU;  /* E2nodeComponentConfigAddition_Item */
static int hf_e2ap_E2nodeComponentConfigUpdate_List_PDU;  /* E2nodeComponentConfigUpdate_List */
static int hf_e2ap_E2nodeComponentConfigUpdate_Item_PDU;  /* E2nodeComponentConfigUpdate_Item */
static int hf_e2ap_E2nodeComponentConfigRemoval_List_PDU;  /* E2nodeComponentConfigRemoval_List */
static int hf_e2ap_E2nodeComponentConfigRemoval_Item_PDU;  /* E2nodeComponentConfigRemoval_Item */
static int hf_e2ap_E2nodeTNLassociationRemoval_List_PDU;  /* E2nodeTNLassociationRemoval_List */
static int hf_e2ap_E2nodeTNLassociationRemoval_Item_PDU;  /* E2nodeTNLassociationRemoval_Item */
static int hf_e2ap_E2nodeConfigurationUpdateAcknowledge_PDU;  /* E2nodeConfigurationUpdateAcknowledge */
static int hf_e2ap_E2nodeComponentConfigAdditionAck_List_PDU;  /* E2nodeComponentConfigAdditionAck_List */
static int hf_e2ap_E2nodeComponentConfigAdditionAck_Item_PDU;  /* E2nodeComponentConfigAdditionAck_Item */
static int hf_e2ap_E2nodeComponentConfigUpdateAck_List_PDU;  /* E2nodeComponentConfigUpdateAck_List */
static int hf_e2ap_E2nodeComponentConfigUpdateAck_Item_PDU;  /* E2nodeComponentConfigUpdateAck_Item */
static int hf_e2ap_E2nodeComponentConfigRemovalAck_List_PDU;  /* E2nodeComponentConfigRemovalAck_List */
static int hf_e2ap_E2nodeComponentConfigRemovalAck_Item_PDU;  /* E2nodeComponentConfigRemovalAck_Item */
static int hf_e2ap_E2nodeConfigurationUpdateFailure_PDU;  /* E2nodeConfigurationUpdateFailure */
static int hf_e2ap_ResetRequest_PDU;              /* ResetRequest */
static int hf_e2ap_ResetResponse_PDU;             /* ResetResponse */
static int hf_e2ap_RICserviceUpdate_PDU;          /* RICserviceUpdate */
static int hf_e2ap_RANfunctions_List_PDU;         /* RANfunctions_List */
static int hf_e2ap_RANfunction_Item_PDU;          /* RANfunction_Item */
static int hf_e2ap_RANfunctionsID_List_PDU;       /* RANfunctionsID_List */
static int hf_e2ap_RANfunctionID_Item_PDU;        /* RANfunctionID_Item */
static int hf_e2ap_RICserviceUpdateAcknowledge_PDU;  /* RICserviceUpdateAcknowledge */
static int hf_e2ap_RANfunctionsIDcause_List_PDU;  /* RANfunctionsIDcause_List */
static int hf_e2ap_RANfunctionIDcause_Item_PDU;   /* RANfunctionIDcause_Item */
static int hf_e2ap_RICserviceUpdateFailure_PDU;   /* RICserviceUpdateFailure */
static int hf_e2ap_RICserviceQuery_PDU;           /* RICserviceQuery */
static int hf_e2ap_E2RemovalRequest_PDU;          /* E2RemovalRequest */
static int hf_e2ap_E2RemovalResponse_PDU;         /* E2RemovalResponse */
static int hf_e2ap_E2RemovalFailure_PDU;          /* E2RemovalFailure */
static int hf_e2ap_E2AP_PDU_PDU;                  /* E2AP_PDU */
static int hf_e2ap_E2SM_RC_EventTrigger_PDU;      /* E2SM_RC_EventTrigger */
static int hf_e2ap_E2SM_RC_ActionDefinition_PDU;  /* E2SM_RC_ActionDefinition */
static int hf_e2ap_E2SM_RC_IndicationHeader_PDU;  /* E2SM_RC_IndicationHeader */
static int hf_e2ap_E2SM_RC_IndicationMessage_PDU;  /* E2SM_RC_IndicationMessage */
static int hf_e2ap_E2SM_RC_CallProcessID_PDU;     /* E2SM_RC_CallProcessID */
static int hf_e2ap_E2SM_RC_ControlHeader_PDU;     /* E2SM_RC_ControlHeader */
static int hf_e2ap_E2SM_RC_ControlMessage_PDU;    /* E2SM_RC_ControlMessage */
static int hf_e2ap_E2SM_RC_ControlOutcome_PDU;    /* E2SM_RC_ControlOutcome */
static int hf_e2ap_E2SM_RC_RANFunctionDefinition_PDU;  /* E2SM_RC_RANFunctionDefinition */
static int hf_e2ap_E2SM_KPM_EventTriggerDefinition_PDU;  /* E2SM_KPM_EventTriggerDefinition */
static int hf_e2ap_E2SM_KPM_ActionDefinition_PDU;  /* E2SM_KPM_ActionDefinition */
static int hf_e2ap_E2SM_KPM_IndicationHeader_PDU;  /* E2SM_KPM_IndicationHeader */
static int hf_e2ap_E2SM_KPM_IndicationMessage_PDU;  /* E2SM_KPM_IndicationMessage */
static int hf_e2ap_E2SM_KPM_RANfunction_Description_PDU;  /* E2SM_KPM_RANfunction_Description */
static int hf_e2ap_E2SM_NI_EventTriggerDefinition_PDU;  /* E2SM_NI_EventTriggerDefinition */
static int hf_e2ap_E2SM_NI_ActionDefinition_PDU;  /* E2SM_NI_ActionDefinition */
static int hf_e2ap_E2SM_NI_IndicationHeader_PDU;  /* E2SM_NI_IndicationHeader */
static int hf_e2ap_E2SM_NI_IndicationMessage_PDU;  /* E2SM_NI_IndicationMessage */
static int hf_e2ap_E2SM_NI_CallProcessID_PDU;     /* E2SM_NI_CallProcessID */
static int hf_e2ap_E2SM_NI_ControlHeader_PDU;     /* E2SM_NI_ControlHeader */
static int hf_e2ap_E2SM_NI_ControlMessage_PDU;    /* E2SM_NI_ControlMessage */
static int hf_e2ap_E2SM_NI_ControlOutcome_PDU;    /* E2SM_NI_ControlOutcome */
static int hf_e2ap_E2SM_NI_RANfunction_Description_PDU;  /* E2SM_NI_RANfunction_Description */
static int hf_e2ap_ProtocolIE_Container_item;     /* ProtocolIE_Field */
static int hf_e2ap_id;                            /* ProtocolIE_ID */
static int hf_e2ap_criticality;                   /* Criticality */
static int hf_e2ap_value;                         /* T_value */
static int hf_e2ap_ricRequest;                    /* CauseRICrequest */
static int hf_e2ap_ricService;                    /* CauseRICservice */
static int hf_e2ap_e2Node;                        /* CauseE2node */
static int hf_e2ap_transport;                     /* CauseTransport */
static int hf_e2ap_protocol;                      /* CauseProtocol */
static int hf_e2ap_misc;                          /* CauseMisc */
static int hf_e2ap_procedureCode;                 /* ProcedureCode */
static int hf_e2ap_triggeringMessage;             /* TriggeringMessage */
static int hf_e2ap_procedureCriticality;          /* Criticality */
static int hf_e2ap_ricRequestorID;                /* RICrequestID */
static int hf_e2ap_iEsCriticalityDiagnostics;     /* CriticalityDiagnostics_IE_List */
static int hf_e2ap_CriticalityDiagnostics_IE_List_item;  /* CriticalityDiagnostics_IE_Item */
static int hf_e2ap_iECriticality;                 /* Criticality */
static int hf_e2ap_iE_ID;                         /* ProtocolIE_ID */
static int hf_e2ap_typeOfError;                   /* TypeOfError */
static int hf_e2ap_e2nodeComponentRequestPart;    /* T_e2nodeComponentRequestPart */
static int hf_e2ap_e2nodeComponentResponsePart;   /* T_e2nodeComponentResponsePart */
static int hf_e2ap_updateOutcome;                 /* T_updateOutcome */
static int hf_e2ap_failureCause;                  /* Cause */
static int hf_e2ap_e2nodeComponentInterfaceTypeNG;  /* T_e2nodeComponentInterfaceTypeNG */
static int hf_e2ap_e2nodeComponentInterfaceTypeXn;  /* T_e2nodeComponentInterfaceTypeXn */
static int hf_e2ap_e2nodeComponentInterfaceTypeE1;  /* T_e2nodeComponentInterfaceTypeE1 */
static int hf_e2ap_e2nodeComponentInterfaceTypeF1;  /* T_e2nodeComponentInterfaceTypeF1 */
static int hf_e2ap_e2nodeComponentInterfaceTypeW1;  /* E2nodeComponentInterfaceW1 */
static int hf_e2ap_e2nodeComponentInterfaceTypeS1;  /* T_e2nodeComponentInterfaceTypeS1 */
static int hf_e2ap_e2nodeComponentInterfaceTypeX2;  /* T_e2nodeComponentInterfaceTypeX2 */
static int hf_e2ap_gNB_CU_UP_ID;                  /* GNB_CU_UP_ID */
static int hf_e2ap_gNB_DU_ID;                     /* GNB_DU_ID */
static int hf_e2ap_amf_name;                      /* AMFName */
static int hf_e2ap_mme_name;                      /* MMEname */
static int hf_e2ap_global_eNB_ID;                 /* GlobalENB_ID */
static int hf_e2ap_global_en_gNB_ID;              /* GlobalenGNB_ID */
static int hf_e2ap_global_NG_RAN_Node_ID;         /* GlobalNG_RANNode_ID */
static int hf_e2ap_ng_eNB_DU_ID;                  /* NGENB_DU_ID */
static int hf_e2ap_macro_eNB_ID;                  /* BIT_STRING_SIZE_20 */
static int hf_e2ap_home_eNB_ID;                   /* BIT_STRING_SIZE_28 */
static int hf_e2ap_short_Macro_eNB_ID;            /* BIT_STRING_SIZE_18 */
static int hf_e2ap_long_Macro_eNB_ID;             /* BIT_STRING_SIZE_21 */
static int hf_e2ap_enb_ID_macro;                  /* BIT_STRING_SIZE_20 */
static int hf_e2ap_enb_ID_shortmacro;             /* BIT_STRING_SIZE_18 */
static int hf_e2ap_enb_ID_longmacro;              /* BIT_STRING_SIZE_21 */
static int hf_e2ap_gNB_ID;                        /* BIT_STRING_SIZE_22_32 */
static int hf_e2ap_gNB;                           /* GlobalE2node_gNB_ID */
static int hf_e2ap_en_gNB;                        /* GlobalE2node_en_gNB_ID */
static int hf_e2ap_ng_eNB;                        /* GlobalE2node_ng_eNB_ID */
static int hf_e2ap_eNB;                           /* GlobalE2node_eNB_ID */
static int hf_e2ap_en_gNB_CU_UP_ID;               /* GNB_CU_UP_ID */
static int hf_e2ap_en_gNB_DU_ID;                  /* GNB_DU_ID */
static int hf_e2ap_global_gNB_ID;                 /* GlobalgNB_ID */
static int hf_e2ap_global_ng_eNB_ID;              /* GlobalngeNB_ID */
static int hf_e2ap_ngENB_DU_ID;                   /* NGENB_DU_ID */
static int hf_e2ap_pLMN_Identity;                 /* PLMN_Identity */
static int hf_e2ap_eNB_ID;                        /* ENB_ID */
static int hf_e2ap_gNB_ID_01;                     /* ENGNB_ID */
static int hf_e2ap_plmn_id;                       /* PLMN_Identity */
static int hf_e2ap_gnb_id;                        /* T_gnb_id */
static int hf_e2ap_enb_id;                        /* ENB_ID_Choice */
static int hf_e2ap_gNB_01;                        /* GlobalgNB_ID */
static int hf_e2ap_ng_eNB_01;                     /* GlobalngeNB_ID */
static int hf_e2ap_ric_ID;                        /* BIT_STRING_SIZE_20 */
static int hf_e2ap_gnb_ID;                        /* BIT_STRING_SIZE_22_32 */
static int hf_e2ap_ricRequestorID_01;             /* INTEGER_0_65535 */
static int hf_e2ap_ricInstanceID;                 /* INTEGER_0_65535 */
static int hf_e2ap_ricSubsequentActionType;       /* RICsubsequentActionType */
static int hf_e2ap_ricTimeToWait;                 /* RICtimeToWait */
static int hf_e2ap_tnlAddress;                    /* T_tnlAddress */
static int hf_e2ap_tnlPort;                       /* T_tnlPort */
static int hf_e2ap_protocolIEs;                   /* ProtocolIE_Container */
static int hf_e2ap_ricEventTriggerDefinition;     /* RICeventTriggerDefinition */
static int hf_e2ap_ricAction_ToBeSetup_List;      /* RICactions_ToBeSetup_List */
static int hf_e2ap_RICactions_ToBeSetup_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_ricActionID;                   /* RICactionID */
static int hf_e2ap_ricActionType;                 /* RICactionType */
static int hf_e2ap_ricActionDefinition;           /* RICactionDefinition */
static int hf_e2ap_ricSubsequentAction;           /* RICsubsequentAction */
static int hf_e2ap_ricActionExecutionOrder;       /* RICactionExecutionOrder */
static int hf_e2ap_RICaction_Admitted_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICaction_NotAdmitted_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_cause;                         /* Cause */
static int hf_e2ap_RICsubscription_List_withCause_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_ricRequestID;                  /* RICrequestID */
static int hf_e2ap_ranFunctionID;                 /* RANfunctionID */
static int hf_e2ap_RICactions_ToBeRemovedForModification_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_ToBeModifiedForModification_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_ToBeAddedForModification_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_RemovedForModification_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_FailedToBeRemovedForModification_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_ModifiedForModification_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_FailedToBeModifiedForModification_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_AddedForModification_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_FailedToBeAddedForModification_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_RequiredToBeModified_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_RequiredToBeRemoved_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_ConfirmedForModification_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_RefusedToBeModified_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_ConfirmedForRemoval_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICactions_RefusedToBeRemoved_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_E2connectionUpdate_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_tnlInformation;                /* TNLinformation */
static int hf_e2ap_tnlUsage;                      /* TNLusage */
static int hf_e2ap_E2connectionUpdateRemove_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_E2connectionSetupFailed_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_E2nodeComponentConfigAddition_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_e2nodeComponentInterfaceType;  /* E2nodeComponentInterfaceType */
static int hf_e2ap_e2nodeComponentID;             /* E2nodeComponentID */
static int hf_e2ap_e2nodeComponentConfiguration;  /* E2nodeComponentConfiguration */
static int hf_e2ap_E2nodeComponentConfigUpdate_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_E2nodeComponentConfigRemoval_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_E2nodeTNLassociationRemoval_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_tnlInformationRIC;             /* TNLinformation */
static int hf_e2ap_E2nodeComponentConfigAdditionAck_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_e2nodeComponentConfigurationAck;  /* E2nodeComponentConfigurationAck */
static int hf_e2ap_E2nodeComponentConfigUpdateAck_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_E2nodeComponentConfigRemovalAck_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RANfunctions_List_item;        /* ProtocolIE_SingleContainer */
static int hf_e2ap_ranFunctionDefinition;         /* RANfunctionDefinition */
static int hf_e2ap_ranFunctionRevision;           /* RANfunctionRevision */
static int hf_e2ap_ranFunctionOID;                /* RANfunctionOID */
static int hf_e2ap_RANfunctionsID_List_item;      /* ProtocolIE_SingleContainer */
static int hf_e2ap_RANfunctionsIDcause_List_item;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_initiatingMessage;             /* InitiatingMessage */
static int hf_e2ap_successfulOutcome;             /* SuccessfulOutcome */
static int hf_e2ap_unsuccessfulOutcome;           /* UnsuccessfulOutcome */
static int hf_e2ap_initiatingMessagevalue;        /* InitiatingMessage_value */
static int hf_e2ap_successfulOutcome_value;       /* SuccessfulOutcome_value */
static int hf_e2ap_unsuccessfulOutcome_value;     /* UnsuccessfulOutcome_value */
static int hf_e2ap_nR_CGI;                        /* NR_CGI */
static int hf_e2ap_eUTRA_CGI;                     /* EUTRA_CGI */
static int hf_e2ap_nG;                            /* InterfaceID_NG */
static int hf_e2ap_xN;                            /* InterfaceID_Xn */
static int hf_e2ap_f1;                            /* InterfaceID_F1 */
static int hf_e2ap_e1;                            /* InterfaceID_E1 */
static int hf_e2ap_s1;                            /* InterfaceID_S1 */
static int hf_e2ap_x2;                            /* InterfaceID_X2 */
static int hf_e2ap_w1;                            /* InterfaceID_W1 */
static int hf_e2ap_guami;                         /* GUAMI */
static int hf_e2ap_global_NG_RAN_ID;              /* GlobalNGRANNodeID */
static int hf_e2ap_globalGNB_ID;                  /* GlobalGNB_ID */
static int hf_e2ap_gUMMEI;                        /* GUMMEI */
static int hf_e2ap_nodeType;                      /* T_nodeType */
static int hf_e2ap_global_ng_eNB_ID_01;           /* GlobalNgENB_ID */
static int hf_e2ap_interfaceProcedureID;          /* INTEGER */
static int hf_e2ap_messageType;                   /* T_messageType */
static int hf_e2ap_ranFunction_ShortName;         /* T_ranFunction_ShortName */
static int hf_e2ap_ranFunction_E2SM_OID;          /* PrintableString_SIZE_1_1000_ */
static int hf_e2ap_ranFunction_Description;       /* PrintableString_SIZE_1_150_ */
static int hf_e2ap_ranFunction_Instance;          /* INTEGER */
static int hf_e2ap_rrcType;                       /* T_rrcType */
static int hf_e2ap_lTE;                           /* RRCclass_LTE */
static int hf_e2ap_nR;                            /* RRCclass_NR */
static int hf_e2ap_messageID;                     /* INTEGER */
static int hf_e2ap_nR_01;                         /* NR_ARFCN */
static int hf_e2ap_eUTRA;                         /* E_UTRA_ARFCN */
static int hf_e2ap_nR_02;                         /* NR_PCI */
static int hf_e2ap_eUTRA_01;                      /* E_UTRA_PCI */
static int hf_e2ap_gNB_UEID;                      /* UEID_GNB */
static int hf_e2ap_gNB_DU_UEID;                   /* UEID_GNB_DU */
static int hf_e2ap_gNB_CU_UP_UEID;                /* UEID_GNB_CU_UP */
static int hf_e2ap_ng_eNB_UEID;                   /* UEID_NG_ENB */
static int hf_e2ap_ng_eNB_DU_UEID;                /* UEID_NG_ENB_DU */
static int hf_e2ap_en_gNB_UEID;                   /* UEID_EN_GNB */
static int hf_e2ap_eNB_UEID;                      /* UEID_ENB */
static int hf_e2ap_amf_UE_NGAP_ID;                /* AMF_UE_NGAP_ID */
static int hf_e2ap_gNB_CU_UE_F1AP_ID_List;        /* UEID_GNB_CU_F1AP_ID_List */
static int hf_e2ap_gNB_CU_CP_UE_E1AP_ID_List;     /* UEID_GNB_CU_CP_E1AP_ID_List */
static int hf_e2ap_ran_UEID;                      /* RANUEID */
static int hf_e2ap_m_NG_RAN_UE_XnAP_ID;           /* NG_RANnodeUEXnAPID */
static int hf_e2ap_globalNG_RANNode_ID;           /* GlobalNGRANNodeID */
static int hf_e2ap_UEID_GNB_CU_CP_E1AP_ID_List_item;  /* UEID_GNB_CU_CP_E1AP_ID_Item */
static int hf_e2ap_gNB_CU_CP_UE_E1AP_ID;          /* GNB_CU_CP_UE_E1AP_ID */
static int hf_e2ap_UEID_GNB_CU_F1AP_ID_List_item;  /* UEID_GNB_CU_CP_F1AP_ID_Item */
static int hf_e2ap_gNB_CU_UE_F1AP_ID;             /* GNB_CU_UE_F1AP_ID */
static int hf_e2ap_ng_eNB_CU_UE_W1AP_ID;          /* NGENB_CU_UE_W1AP_ID */
static int hf_e2ap_globalNgENB_ID;                /* GlobalNgENB_ID */
static int hf_e2ap_m_eNB_UE_X2AP_ID;              /* ENB_UE_X2AP_ID */
static int hf_e2ap_m_eNB_UE_X2AP_ID_Extension;    /* ENB_UE_X2AP_ID_Extension */
static int hf_e2ap_globalENB_ID;                  /* GlobalENB_ID */
static int hf_e2ap_mME_UE_S1AP_ID;                /* MME_UE_S1AP_ID */
static int hf_e2ap_pLMN_Identity_01;              /* PLMNIdentity */
static int hf_e2ap_mME_Group_ID;                  /* MME_Group_ID */
static int hf_e2ap_mME_Code;                      /* MME_Code */
static int hf_e2ap_pLMNIdentity;                  /* PLMNIdentity */
static int hf_e2ap_eUTRACellIdentity;             /* EUTRACellIdentity */
static int hf_e2ap_gNB_ID_02;                     /* GNB_ID */
static int hf_e2ap_ngENB_ID;                      /* NgENB_ID */
static int hf_e2ap_aMFRegionID;                   /* AMFRegionID */
static int hf_e2ap_aMFSetID;                      /* AMFSetID */
static int hf_e2ap_aMFPointer;                    /* AMFPointer */
static int hf_e2ap_macroNgENB_ID;                 /* BIT_STRING_SIZE_20 */
static int hf_e2ap_shortMacroNgENB_ID;            /* BIT_STRING_SIZE_18 */
static int hf_e2ap_longMacroNgENB_ID;             /* BIT_STRING_SIZE_21 */
static int hf_e2ap_nRCellIdentity;                /* NRCellIdentity */
static int hf_e2ap_sST;                           /* SST */
static int hf_e2ap_sD;                            /* SD */
static int hf_e2ap_gNB_02;                        /* GlobalGNB_ID */
static int hf_e2ap_ng_eNB_02;                     /* GlobalNgENB_ID */
static int hf_e2ap_nRARFCN;                       /* INTEGER_0_maxNRARFCN */
static int hf_e2ap_NRFrequencyBand_List_item;     /* NRFrequencyBandItem */
static int hf_e2ap_freqBandIndicatorNr;           /* INTEGER_1_1024_ */
static int hf_e2ap_supportedSULBandList;          /* SupportedSULBandList */
static int hf_e2ap_nrARFCN;                       /* NR_ARFCN */
static int hf_e2ap_frequencyBand_List;            /* NRFrequencyBand_List */
static int hf_e2ap_frequencyShift7p5khz;          /* NRFrequencyShift7p5khz */
static int hf_e2ap_SupportedSULBandList_item;     /* SupportedSULFreqBandItem */
static int hf_e2ap_NeighborCell_List_item;        /* NeighborCell_Item */
static int hf_e2ap_ranType_Choice_NR;             /* NeighborCell_Item_Choice_NR */
static int hf_e2ap_ranType_Choice_EUTRA;          /* NeighborCell_Item_Choice_E_UTRA */
static int hf_e2ap_nR_PCI;                        /* NR_PCI */
static int hf_e2ap_fiveGS_TAC;                    /* FiveGS_TAC */
static int hf_e2ap_nR_mode_info;                  /* T_nR_mode_info */
static int hf_e2ap_nR_FreqInfo;                   /* NRFrequencyInfo */
static int hf_e2ap_x2_Xn_established;             /* T_x2_Xn_established */
static int hf_e2ap_hO_validated;                  /* T_hO_validated */
static int hf_e2ap_version;                       /* INTEGER_1_65535_ */
static int hf_e2ap_eUTRA_PCI;                     /* E_UTRA_PCI */
static int hf_e2ap_eUTRA_ARFCN;                   /* E_UTRA_ARFCN */
static int hf_e2ap_eUTRA_TAC;                     /* E_UTRA_TAC */
static int hf_e2ap_x2_Xn_established_01;          /* T_x2_Xn_established_01 */
static int hf_e2ap_hO_validated_01;               /* T_hO_validated_01 */
static int hf_e2ap_servingCellPCI;                /* ServingCell_PCI */
static int hf_e2ap_servingCellARFCN;              /* ServingCell_ARFCN */
static int hf_e2ap_neighborCell_List;             /* NeighborCell_List */
static int hf_e2ap_cellInfo_List;                 /* SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item */
static int hf_e2ap_cellInfo_List_item;            /* EventTrigger_Cell_Info_Item */
static int hf_e2ap_eventTriggerCellID;            /* RIC_EventTrigger_Cell_ID */
static int hf_e2ap_cellType;                      /* T_cellType */
static int hf_e2ap_cellType_Choice_Individual;    /* EventTrigger_Cell_Info_Item_Choice_Individual */
static int hf_e2ap_cellType_Choice_Group;         /* EventTrigger_Cell_Info_Item_Choice_Group */
static int hf_e2ap_logicalOR;                     /* LogicalOR */
static int hf_e2ap_cellGlobalID;                  /* CGI */
static int hf_e2ap_ranParameterTesting;           /* RANParameter_Testing */
static int hf_e2ap_ueInfo_List;                   /* SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item */
static int hf_e2ap_ueInfo_List_item;              /* EventTrigger_UE_Info_Item */
static int hf_e2ap_eventTriggerUEID;              /* RIC_EventTrigger_UE_ID */
static int hf_e2ap_ueType;                        /* T_ueType */
static int hf_e2ap_ueType_Choice_Individual;      /* EventTrigger_UE_Info_Item_Choice_Individual */
static int hf_e2ap_ueType_Choice_Group;           /* EventTrigger_UE_Info_Item_Choice_Group */
static int hf_e2ap_ueID;                          /* UEID */
static int hf_e2ap_ueEvent_List;                  /* SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item */
static int hf_e2ap_ueEvent_List_item;             /* EventTrigger_UEevent_Info_Item */
static int hf_e2ap_ueEventID;                     /* RIC_EventTrigger_UEevent_ID */
static int hf_e2ap_ranParameter_Definition_Choice;  /* RANParameter_Definition_Choice */
static int hf_e2ap_choiceLIST;                    /* RANParameter_Definition_Choice_LIST */
static int hf_e2ap_choiceSTRUCTURE;               /* RANParameter_Definition_Choice_STRUCTURE */
static int hf_e2ap_ranParameter_List;             /* SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item */
static int hf_e2ap_ranParameter_List_item;        /* RANParameter_Definition_Choice_LIST_Item */
static int hf_e2ap_ranParameter_ID;               /* RANParameter_ID */
static int hf_e2ap_ranParameter_name;             /* RANParameter_Name */
static int hf_e2ap_ranParameter_Definition;       /* RANParameter_Definition */
static int hf_e2ap_ranParameter_STRUCTURE;        /* SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item */
static int hf_e2ap_ranParameter_STRUCTURE_item;   /* RANParameter_Definition_Choice_STRUCTURE_Item */
static int hf_e2ap_valueBoolean;                  /* BOOLEAN */
static int hf_e2ap_valueInt;                      /* INTEGER */
static int hf_e2ap_valueReal;                     /* REAL */
static int hf_e2ap_valueBitS;                     /* BIT_STRING */
static int hf_e2ap_valueOctS;                     /* OCTET_STRING */
static int hf_e2ap_valuePrintableString;          /* PrintableString */
static int hf_e2ap_ranP_Choice_ElementTrue;       /* RANParameter_ValueType_Choice_ElementTrue */
static int hf_e2ap_ranP_Choice_ElementFalse;      /* RANParameter_ValueType_Choice_ElementFalse */
static int hf_e2ap_ranP_Choice_Structure;         /* RANParameter_ValueType_Choice_Structure */
static int hf_e2ap_ranP_Choice_List;              /* RANParameter_ValueType_Choice_List */
static int hf_e2ap_ranParameter_value;            /* RANParameter_Value */
static int hf_e2ap_ranParameter_Structure;        /* RANParameter_STRUCTURE */
static int hf_e2ap_ranParameter_List_01;          /* RANParameter_LIST */
static int hf_e2ap_sequence_of_ranParameters;     /* SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item */
static int hf_e2ap_sequence_of_ranParameters_item;  /* RANParameter_STRUCTURE_Item */
static int hf_e2ap_ranParameter_valueType;        /* RANParameter_ValueType */
static int hf_e2ap_list_of_ranParameter;          /* SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE */
static int hf_e2ap_list_of_ranParameter_item;     /* RANParameter_STRUCTURE */
static int hf_e2ap_RANParameter_Testing_item;     /* RANParameter_Testing_Item */
static int hf_e2ap_ranP_Choice_comparison;        /* T_ranP_Choice_comparison */
static int hf_e2ap_ranP_Choice_presence;          /* T_ranP_Choice_presence */
static int hf_e2ap_ranParameter_Type;             /* T_ranParameter_Type */
static int hf_e2ap_ranP_Choice_List_01;           /* RANParameter_Testing_Item_Choice_List */
static int hf_e2ap_ranP_Choice_Structure_01;      /* RANParameter_Testing_Item_Choice_Structure */
static int hf_e2ap_ranP_Choice_ElementTrue_01;    /* RANParameter_Testing_Item_Choice_ElementTrue */
static int hf_e2ap_ranP_Choice_ElementFalse_01;   /* RANParameter_Testing_Item_Choice_ElementFalse */
static int hf_e2ap_ranParameter_List_02;          /* RANParameter_Testing_LIST */
static int hf_e2ap_ranParameter_Structure_01;     /* RANParameter_Testing_STRUCTURE */
static int hf_e2ap_ranParameter_TestCondition;    /* RANParameter_TestingCondition */
static int hf_e2ap_ranParameter_Value;            /* RANParameter_Value */
static int hf_e2ap_RANParameter_Testing_LIST_item;  /* RANParameter_Testing_Item */
static int hf_e2ap_RANParameter_Testing_STRUCTURE_item;  /* RANParameter_Testing_Item */
static int hf_e2ap_ric_PolicyAction_ID;           /* RIC_ControlAction_ID */
static int hf_e2ap_ranParameters_List;            /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item */
static int hf_e2ap_ranParameters_List_item;       /* RIC_PolicyAction_RANParameter_Item */
static int hf_e2ap_ric_PolicyDecision;            /* T_ric_PolicyDecision */
static int hf_e2ap_ric_eventTrigger_formats;      /* T_ric_eventTrigger_formats */
static int hf_e2ap_eventTrigger_Format1;          /* E2SM_RC_EventTrigger_Format1 */
static int hf_e2ap_eventTrigger_Format2;          /* E2SM_RC_EventTrigger_Format2 */
static int hf_e2ap_eventTrigger_Format3;          /* E2SM_RC_EventTrigger_Format3 */
static int hf_e2ap_eventTrigger_Format4;          /* E2SM_RC_EventTrigger_Format4 */
static int hf_e2ap_eventTrigger_Format5;          /* E2SM_RC_EventTrigger_Format5 */
static int hf_e2ap_message_List;                  /* SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item */
static int hf_e2ap_message_List_item;             /* E2SM_RC_EventTrigger_Format1_Item */
static int hf_e2ap_globalAssociatedUEInfo;        /* EventTrigger_UE_Info */
static int hf_e2ap_ric_eventTriggerCondition_ID;  /* RIC_EventTriggerCondition_ID */
static int hf_e2ap_messageType_01;                /* MessageType_Choice */
static int hf_e2ap_messageDirection;              /* T_messageDirection */
static int hf_e2ap_associatedUEInfo;              /* EventTrigger_UE_Info */
static int hf_e2ap_associatedUEEvent;             /* EventTrigger_UEevent_Info */
static int hf_e2ap_messageType_Choice_NI;         /* MessageType_Choice_NI */
static int hf_e2ap_messageType_Choice_RRC;        /* MessageType_Choice_RRC */
static int hf_e2ap_nI_Type;                       /* InterfaceType */
static int hf_e2ap_nI_Identifier;                 /* InterfaceIdentifier */
static int hf_e2ap_nI_Message;                    /* Interface_MessageID */
static int hf_e2ap_rRC_Message;                   /* RRC_MessageID */
static int hf_e2ap_ric_callProcessType_ID;        /* RIC_CallProcessType_ID */
static int hf_e2ap_ric_callProcessBreakpoint_ID;  /* RIC_CallProcessBreakpoint_ID */
static int hf_e2ap_associatedE2NodeInfo;          /* RANParameter_Testing */
static int hf_e2ap_e2NodeInfoChange_List;         /* SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item */
static int hf_e2ap_e2NodeInfoChange_List_item;    /* E2SM_RC_EventTrigger_Format3_Item */
static int hf_e2ap_e2NodeInfoChange_ID;           /* INTEGER_1_512_ */
static int hf_e2ap_associatedCellInfo;            /* EventTrigger_Cell_Info */
static int hf_e2ap_uEInfoChange_List;             /* SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item */
static int hf_e2ap_uEInfoChange_List_item;        /* E2SM_RC_EventTrigger_Format4_Item */
static int hf_e2ap_triggerType;                   /* TriggerType_Choice */
static int hf_e2ap_triggerType_Choice_RRCstate;   /* TriggerType_Choice_RRCstate */
static int hf_e2ap_triggerType_Choice_UEID;       /* TriggerType_Choice_UEID */
static int hf_e2ap_triggerType_Choice_L2state;    /* TriggerType_Choice_L2state */
static int hf_e2ap_rrcState_List;                 /* SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item */
static int hf_e2ap_rrcState_List_item;            /* TriggerType_Choice_RRCstate_Item */
static int hf_e2ap_stateChangedTo;                /* RRC_State */
static int hf_e2ap_ueIDchange_ID;                 /* INTEGER_1_512_ */
static int hf_e2ap_associatedL2variables;         /* RANParameter_Testing */
static int hf_e2ap_onDemand;                      /* T_onDemand */
static int hf_e2ap_ric_Style_Type;                /* RIC_Style_Type */
static int hf_e2ap_ric_actionDefinition_formats;  /* T_ric_actionDefinition_formats */
static int hf_e2ap_actionDefinition_Format1;      /* E2SM_RC_ActionDefinition_Format1 */
static int hf_e2ap_actionDefinition_Format2;      /* E2SM_RC_ActionDefinition_Format2 */
static int hf_e2ap_actionDefinition_Format3;      /* E2SM_RC_ActionDefinition_Format3 */
static int hf_e2ap_actionDefinition_Format4;      /* E2SM_RC_ActionDefinition_Format4 */
static int hf_e2ap_ranP_ToBeReported_List;        /* SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item */
static int hf_e2ap_ranP_ToBeReported_List_item;   /* E2SM_RC_ActionDefinition_Format1_Item */
static int hf_e2ap_ric_PolicyConditions_List;     /* SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item */
static int hf_e2ap_ric_PolicyConditions_List_item;  /* E2SM_RC_ActionDefinition_Format2_Item */
static int hf_e2ap_ric_PolicyAction;              /* RIC_PolicyAction */
static int hf_e2ap_ric_PolicyConditionDefinition;  /* RANParameter_Testing */
static int hf_e2ap_ric_InsertIndication_ID;       /* RIC_InsertIndication_ID */
static int hf_e2ap_ranP_InsertIndication_List;    /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item */
static int hf_e2ap_ranP_InsertIndication_List_item;  /* E2SM_RC_ActionDefinition_Format3_Item */
static int hf_e2ap_ric_InsertStyle_List;          /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item */
static int hf_e2ap_ric_InsertStyle_List_item;     /* E2SM_RC_ActionDefinition_Format4_Style_Item */
static int hf_e2ap_requested_Insert_Style_Type;   /* RIC_Style_Type */
static int hf_e2ap_ric_InsertIndication_List;     /* SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item */
static int hf_e2ap_ric_InsertIndication_List_item;  /* E2SM_RC_ActionDefinition_Format4_Indication_Item */
static int hf_e2ap_ranP_InsertIndication_List_01;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item */
static int hf_e2ap_ranP_InsertIndication_List_item_01;  /* E2SM_RC_ActionDefinition_Format4_RANP_Item */
static int hf_e2ap_ric_indicationHeader_formats;  /* T_ric_indicationHeader_formats */
static int hf_e2ap_indicationHeader_Format1;      /* E2SM_RC_IndicationHeader_Format1 */
static int hf_e2ap_indicationHeader_Format2;      /* E2SM_RC_IndicationHeader_Format2 */
static int hf_e2ap_indicationHeader_Format3;      /* E2SM_RC_IndicationHeader_Format3 */
static int hf_e2ap_ric_InsertStyle_Type;          /* RIC_Style_Type */
static int hf_e2ap_ric_indicationMessage_formats;  /* T_ric_indicationMessage_formats */
static int hf_e2ap_indicationMessage_Format1;     /* E2SM_RC_IndicationMessage_Format1 */
static int hf_e2ap_indicationMessage_Format2;     /* E2SM_RC_IndicationMessage_Format2 */
static int hf_e2ap_indicationMessage_Format3;     /* E2SM_RC_IndicationMessage_Format3 */
static int hf_e2ap_indicationMessage_Format4;     /* E2SM_RC_IndicationMessage_Format4 */
static int hf_e2ap_indicationMessage_Format5;     /* E2SM_RC_IndicationMessage_Format5 */
static int hf_e2ap_indicationMessage_Format6;     /* E2SM_RC_IndicationMessage_Format6 */
static int hf_e2ap_ranP_Reported_List;            /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item */
static int hf_e2ap_ranP_Reported_List_item;       /* E2SM_RC_IndicationMessage_Format1_Item */
static int hf_e2ap_ueParameter_List;              /* SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item */
static int hf_e2ap_ueParameter_List_item;         /* E2SM_RC_IndicationMessage_Format2_Item */
static int hf_e2ap_ranP_List;                     /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item */
static int hf_e2ap_ranP_List_item;                /* E2SM_RC_IndicationMessage_Format2_RANParameter_Item */
static int hf_e2ap_cellInfo_List_01;              /* SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item */
static int hf_e2ap_cellInfo_List_item_01;         /* E2SM_RC_IndicationMessage_Format3_Item */
static int hf_e2ap_cellGlobal_ID;                 /* CGI */
static int hf_e2ap_cellContextInfo;               /* OCTET_STRING */
static int hf_e2ap_cellDeleted;                   /* BOOLEAN */
static int hf_e2ap_neighborRelation_Table;        /* NeighborRelation_Info */
static int hf_e2ap_ueInfo_List_01;                /* SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format4_ItemUE */
static int hf_e2ap_ueInfo_List_item_01;           /* E2SM_RC_IndicationMessage_Format4_ItemUE */
static int hf_e2ap_cellInfo_List_02;              /* SEQUENCE_SIZE_0_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format4_ItemCell */
static int hf_e2ap_cellInfo_List_item_02;         /* E2SM_RC_IndicationMessage_Format4_ItemCell */
static int hf_e2ap_ueContextInfo;                 /* OCTET_STRING */
static int hf_e2ap_ranP_Requested_List;           /* SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item */
static int hf_e2ap_ranP_Requested_List_item;      /* E2SM_RC_IndicationMessage_Format5_Item */
static int hf_e2ap_ric_InsertStyle_List_01;       /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item */
static int hf_e2ap_ric_InsertStyle_List_item_01;  /* E2SM_RC_IndicationMessage_Format6_Style_Item */
static int hf_e2ap_indicated_Insert_Style_Type;   /* RIC_Style_Type */
static int hf_e2ap_ric_InsertIndication_List_01;  /* SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item */
static int hf_e2ap_ric_InsertIndication_List_item_01;  /* E2SM_RC_IndicationMessage_Format6_Indication_Item */
static int hf_e2ap_ranP_InsertIndication_List_02;  /* SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item */
static int hf_e2ap_ranP_InsertIndication_List_item_02;  /* E2SM_RC_IndicationMessage_Format6_RANP_Item */
static int hf_e2ap_ric_callProcessID_formats;     /* T_ric_callProcessID_formats */
static int hf_e2ap_callProcessID_Format1;         /* E2SM_RC_CallProcessID_Format1 */
static int hf_e2ap_ric_callProcess_ID;            /* RAN_CallProcess_ID */
static int hf_e2ap_ric_controlHeader_formats;     /* T_ric_controlHeader_formats */
static int hf_e2ap_controlHeader_Format1;         /* E2SM_RC_ControlHeader_Format1 */
static int hf_e2ap_controlHeader_Format2;         /* E2SM_RC_ControlHeader_Format2 */
static int hf_e2ap_ric_ControlAction_ID;          /* RIC_ControlAction_ID */
static int hf_e2ap_ric_ControlDecision;           /* T_ric_ControlDecision */
static int hf_e2ap_ric_ControlDecision_01;        /* T_ric_ControlDecision_01 */
static int hf_e2ap_ric_controlMessage_formats;    /* T_ric_controlMessage_formats */
static int hf_e2ap_controlMessage_Format1;        /* E2SM_RC_ControlMessage_Format1 */
static int hf_e2ap_controlMessage_Format2;        /* E2SM_RC_ControlMessage_Format2 */
static int hf_e2ap_ranP_List_01;                  /* SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item */
static int hf_e2ap_ranP_List_item_01;             /* E2SM_RC_ControlMessage_Format1_Item */
static int hf_e2ap_ric_ControlStyle_List;         /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item */
static int hf_e2ap_ric_ControlStyle_List_item;    /* E2SM_RC_ControlMessage_Format2_Style_Item */
static int hf_e2ap_indicated_Control_Style_Type;  /* RIC_Style_Type */
static int hf_e2ap_ric_ControlAction_List;        /* SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item */
static int hf_e2ap_ric_ControlAction_List_item;   /* E2SM_RC_ControlMessage_Format2_ControlAction_Item */
static int hf_e2ap_ranP_List_02;                  /* E2SM_RC_ControlMessage_Format1 */
static int hf_e2ap_ric_controlOutcome_formats;    /* T_ric_controlOutcome_formats */
static int hf_e2ap_controlOutcome_Format1;        /* E2SM_RC_ControlOutcome_Format1 */
static int hf_e2ap_controlOutcome_Format2;        /* E2SM_RC_ControlOutcome_Format2 */
static int hf_e2ap_controlOutcome_Format3;        /* E2SM_RC_ControlOutcome_Format3 */
static int hf_e2ap_ranP_List_03;                  /* SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item */
static int hf_e2ap_ranP_List_item_02;             /* E2SM_RC_ControlOutcome_Format1_Item */
static int hf_e2ap_ric_ControlStyle_List_01;      /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item */
static int hf_e2ap_ric_ControlStyle_List_item_01;  /* E2SM_RC_ControlOutcome_Format2_Style_Item */
static int hf_e2ap_ric_ControlOutcome_List;       /* SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item */
static int hf_e2ap_ric_ControlOutcome_List_item;  /* E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item */
static int hf_e2ap_ranP_List_04;                  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item */
static int hf_e2ap_ranP_List_item_03;             /* E2SM_RC_ControlOutcome_Format2_RANP_Item */
static int hf_e2ap_ranP_List_05;                  /* SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item */
static int hf_e2ap_ranP_List_item_04;             /* E2SM_RC_ControlOutcome_Format3_Item */
static int hf_e2ap_ranFunction_Name;              /* RANfunction_Name */
static int hf_e2ap_ranFunctionDefinition_EventTrigger;  /* RANFunctionDefinition_EventTrigger */
static int hf_e2ap_ranFunctionDefinition_Report;  /* RANFunctionDefinition_Report */
static int hf_e2ap_ranFunctionDefinition_Insert;  /* RANFunctionDefinition_Insert */
static int hf_e2ap_ranFunctionDefinition_Control;  /* RANFunctionDefinition_Control */
static int hf_e2ap_ranFunctionDefinition_Policy;  /* RANFunctionDefinition_Policy */
static int hf_e2ap_ric_EventTriggerStyle_List;    /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item */
static int hf_e2ap_ric_EventTriggerStyle_List_item;  /* RANFunctionDefinition_EventTrigger_Style_Item */
static int hf_e2ap_ran_L2Parameters_List;         /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item */
static int hf_e2ap_ran_L2Parameters_List_item;    /* L2Parameters_RANParameter_Item */
static int hf_e2ap_ran_CallProcessTypes_List;     /* SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item */
static int hf_e2ap_ran_CallProcessTypes_List_item;  /* RANFunctionDefinition_EventTrigger_CallProcess_Item */
static int hf_e2ap_ran_UEIdentificationParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item */
static int hf_e2ap_ran_UEIdentificationParameters_List_item;  /* UEIdentification_RANParameter_Item */
static int hf_e2ap_ran_CellIdentificationParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item */
static int hf_e2ap_ran_CellIdentificationParameters_List_item;  /* CellIdentification_RANParameter_Item */
static int hf_e2ap_ric_EventTriggerStyle_Type;    /* RIC_Style_Type */
static int hf_e2ap_ric_EventTriggerStyle_Name;    /* RIC_Style_Name */
static int hf_e2ap_ric_EventTriggerFormat_Type;   /* RIC_Format_Type */
static int hf_e2ap_callProcessType_ID;            /* RIC_CallProcessType_ID */
static int hf_e2ap_callProcessType_Name;          /* RIC_CallProcessType_Name */
static int hf_e2ap_callProcessBreakpoints_List;   /* SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item */
static int hf_e2ap_callProcessBreakpoints_List_item;  /* RANFunctionDefinition_EventTrigger_Breakpoint_Item */
static int hf_e2ap_callProcessBreakpoint_ID;      /* RIC_CallProcessBreakpoint_ID */
static int hf_e2ap_callProcessBreakpoint_Name;    /* RIC_CallProcessBreakpoint_Name */
static int hf_e2ap_ran_CallProcessBreakpointParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item */
static int hf_e2ap_ran_CallProcessBreakpointParameters_List_item;  /* CallProcessBreakpoint_RANParameter_Item */
static int hf_e2ap_ric_ReportStyle_List;          /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item */
static int hf_e2ap_ric_ReportStyle_List_item;     /* RANFunctionDefinition_Report_Item */
static int hf_e2ap_ric_ReportStyle_Type;          /* RIC_Style_Type */
static int hf_e2ap_ric_ReportStyle_Name;          /* RIC_Style_Name */
static int hf_e2ap_ric_SupportedEventTriggerStyle_Type;  /* RIC_Style_Type */
static int hf_e2ap_ric_ReportActionFormat_Type;   /* RIC_Format_Type */
static int hf_e2ap_ric_IndicationHeaderFormat_Type;  /* RIC_Format_Type */
static int hf_e2ap_ric_IndicationMessageFormat_Type;  /* RIC_Format_Type */
static int hf_e2ap_ran_ReportParameters_List;     /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item */
static int hf_e2ap_ran_ReportParameters_List_item;  /* Report_RANParameter_Item */
static int hf_e2ap_ric_InsertStyle_List_02;       /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item */
static int hf_e2ap_ric_InsertStyle_List_item_02;  /* RANFunctionDefinition_Insert_Item */
static int hf_e2ap_ric_InsertStyle_Name;          /* RIC_Style_Name */
static int hf_e2ap_ric_ActionDefinitionFormat_Type;  /* RIC_Format_Type */
static int hf_e2ap_ric_InsertIndication_List_02;  /* SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item */
static int hf_e2ap_ric_InsertIndication_List_item_02;  /* RANFunctionDefinition_Insert_Indication_Item */
static int hf_e2ap_ric_CallProcessIDFormat_Type;  /* RIC_Format_Type */
static int hf_e2ap_ric_InsertIndication_Name;     /* RIC_InsertIndication_Name */
static int hf_e2ap_ran_InsertIndicationParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item */
static int hf_e2ap_ran_InsertIndicationParameters_List_item;  /* InsertIndication_RANParameter_Item */
static int hf_e2ap_ric_ControlStyle_List_02;      /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item */
static int hf_e2ap_ric_ControlStyle_List_item_02;  /* RANFunctionDefinition_Control_Item */
static int hf_e2ap_ric_ControlStyle_Type;         /* RIC_Style_Type */
static int hf_e2ap_ric_ControlStyle_Name;         /* RIC_Style_Name */
static int hf_e2ap_ric_ControlAction_List_01;     /* SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item */
static int hf_e2ap_ric_ControlAction_List_item_01;  /* RANFunctionDefinition_Control_Action_Item */
static int hf_e2ap_ric_ControlHeaderFormat_Type;  /* RIC_Format_Type */
static int hf_e2ap_ric_ControlMessageFormat_Type;  /* RIC_Format_Type */
static int hf_e2ap_ric_ControlOutcomeFormat_Type;  /* RIC_Format_Type */
static int hf_e2ap_ran_ControlOutcomeParameters_List;  /* SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item */
static int hf_e2ap_ran_ControlOutcomeParameters_List_item;  /* ControlOutcome_RANParameter_Item */
static int hf_e2ap_ric_ControlAction_Name;        /* RIC_ControlAction_Name */
static int hf_e2ap_ran_ControlActionParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item */
static int hf_e2ap_ran_ControlActionParameters_List_item;  /* ControlAction_RANParameter_Item */
static int hf_e2ap_ric_PolicyStyle_List;          /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item */
static int hf_e2ap_ric_PolicyStyle_List_item;     /* RANFunctionDefinition_Policy_Item */
static int hf_e2ap_ric_PolicyStyle_Type;          /* RIC_Style_Type */
static int hf_e2ap_ric_PolicyStyle_Name;          /* RIC_Style_Name */
static int hf_e2ap_ric_PolicyAction_List;         /* SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item */
static int hf_e2ap_ric_PolicyAction_List_item;    /* RANFunctionDefinition_Policy_Action_Item */
static int hf_e2ap_ric_PolicyAction_Name;         /* RIC_ControlAction_Name */
static int hf_e2ap_ran_PolicyActionParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item */
static int hf_e2ap_ran_PolicyActionParameters_List_item;  /* PolicyAction_RANParameter_Item */
static int hf_e2ap_ran_PolicyConditionParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item */
static int hf_e2ap_ran_PolicyConditionParameters_List_item;  /* PolicyCondition_RANParameter_Item */
static int hf_e2ap_measName;                      /* MeasurementTypeName */
static int hf_e2ap_measID;                        /* MeasurementTypeID */
static int hf_e2ap_noLabel;                       /* T_noLabel */
static int hf_e2ap_plmnID;                        /* PLMNIdentity */
static int hf_e2ap_sliceID;                       /* S_NSSAI */
static int hf_e2ap_fiveQI;                        /* FiveQI */
static int hf_e2ap_qFI;                           /* QosFlowIdentifier */
static int hf_e2ap_qCI;                           /* QCI */
static int hf_e2ap_qCImax;                        /* QCI */
static int hf_e2ap_qCImin;                        /* QCI */
static int hf_e2ap_aRPmax;                        /* INTEGER_1_15_ */
static int hf_e2ap_aRPmin;                        /* INTEGER_1_15_ */
static int hf_e2ap_bitrateRange;                  /* INTEGER_1_65535_ */
static int hf_e2ap_layerMU_MIMO;                  /* INTEGER_1_65535_ */
static int hf_e2ap_sUM;                           /* T_sUM */
static int hf_e2ap_distBinX;                      /* INTEGER_1_65535_ */
static int hf_e2ap_distBinY;                      /* INTEGER_1_65535_ */
static int hf_e2ap_distBinZ;                      /* INTEGER_1_65535_ */
static int hf_e2ap_preLabelOverride;              /* T_preLabelOverride */
static int hf_e2ap_startEndInd;                   /* T_startEndInd */
static int hf_e2ap_min;                           /* T_min */
static int hf_e2ap_max;                           /* T_max */
static int hf_e2ap_avg;                           /* T_avg */
static int hf_e2ap_ssbIndex;                      /* INTEGER_1_65535_ */
static int hf_e2ap_nonGoB_BFmode_Index;           /* INTEGER_1_65535_ */
static int hf_e2ap_mIMO_mode_Index;               /* INTEGER_1_2_ */
static int hf_e2ap_testType;                      /* TestCond_Type */
static int hf_e2ap_testExpr;                      /* TestCond_Expression */
static int hf_e2ap_testValue;                     /* TestCond_Value */
static int hf_e2ap_gBR;                           /* T_gBR */
static int hf_e2ap_aMBR;                          /* T_aMBR */
static int hf_e2ap_isStat;                        /* T_isStat */
static int hf_e2ap_isCatM;                        /* T_isCatM */
static int hf_e2ap_rSRP;                          /* T_rSRP */
static int hf_e2ap_rSRQ;                          /* T_rSRQ */
static int hf_e2ap_ul_rSRP;                       /* T_ul_rSRP */
static int hf_e2ap_cQI;                           /* T_cQI */
static int hf_e2ap_fiveQI_01;                     /* T_fiveQI */
static int hf_e2ap_qCI_01;                        /* T_qCI */
static int hf_e2ap_sNSSAI;                        /* T_sNSSAI */
static int hf_e2ap_valueEnum;                     /* INTEGER */
static int hf_e2ap_valueBool;                     /* BOOLEAN */
static int hf_e2ap_valuePrtS;                     /* PrintableString */
static int hf_e2ap_binRangeListX;                 /* BinRangeList */
static int hf_e2ap_binRangeListY;                 /* BinRangeList */
static int hf_e2ap_binRangeListZ;                 /* BinRangeList */
static int hf_e2ap_BinRangeList_item;             /* BinRangeItem */
static int hf_e2ap_binIndex;                      /* BinIndex */
static int hf_e2ap_startValue;                    /* BinRangeValue */
static int hf_e2ap_endValue;                      /* BinRangeValue */
static int hf_e2ap_DistMeasurementBinRangeList_item;  /* DistMeasurementBinRangeItem */
static int hf_e2ap_measType;                      /* MeasurementType */
static int hf_e2ap_binRangeDef;                   /* BinRangeDefinition */
static int hf_e2ap_MeasurementInfoList_item;      /* MeasurementInfoItem */
static int hf_e2ap_labelInfoList;                 /* LabelInfoList */
static int hf_e2ap_LabelInfoList_item;            /* LabelInfoItem */
static int hf_e2ap_measLabel;                     /* MeasurementLabel */
static int hf_e2ap_MeasurementData_item;          /* MeasurementDataItem */
static int hf_e2ap_measRecord;                    /* MeasurementRecord */
static int hf_e2ap_incompleteFlag;                /* T_incompleteFlag */
static int hf_e2ap_MeasurementRecord_item;        /* MeasurementRecordItem */
static int hf_e2ap_integer;                       /* INTEGER_0_4294967295 */
static int hf_e2ap_real;                          /* REAL */
static int hf_e2ap_noValue;                       /* NULL */
static int hf_e2ap_MeasurementInfo_Action_List_item;  /* MeasurementInfo_Action_Item */
static int hf_e2ap_MeasurementCondList_item;      /* MeasurementCondItem */
static int hf_e2ap_matchingCond;                  /* MatchingCondList */
static int hf_e2ap_MeasurementCondUEidList_item;  /* MeasurementCondUEidItem */
static int hf_e2ap_matchingUEidList;              /* MatchingUEidList */
static int hf_e2ap_matchingUEidPerGP;             /* MatchingUEidPerGP */
static int hf_e2ap_MatchingCondList_item;         /* MatchingCondItem */
static int hf_e2ap_matchingCondChoice;            /* MatchingCondItem_Choice */
static int hf_e2ap_testCondInfo;                  /* TestCondInfo */
static int hf_e2ap_MatchingUEidList_item;         /* MatchingUEidItem */
static int hf_e2ap_MatchingUEidPerGP_item;        /* MatchingUEidPerGP_Item */
static int hf_e2ap_matchedPerGP;                  /* T_matchedPerGP */
static int hf_e2ap_noUEmatched;                   /* T_noUEmatched */
static int hf_e2ap_oneOrMoreUEmatched;            /* MatchingUEidList_PerGP */
static int hf_e2ap_MatchingUEidList_PerGP_item;   /* MatchingUEidItem_PerGP */
static int hf_e2ap_MatchingUeCondPerSubList_item;  /* MatchingUeCondPerSubItem */
static int hf_e2ap_MatchingUEidPerSubList_item;   /* MatchingUEidPerSubItem */
static int hf_e2ap_UEMeasurementReportList_item;  /* UEMeasurementReportItem */
static int hf_e2ap_measReport;                    /* E2SM_KPM_IndicationMessage_Format1 */
static int hf_e2ap_eventDefinition_formats;       /* T_eventDefinition_formats */
static int hf_e2ap_eventDefinition_Format1;       /* E2SM_KPM_EventTriggerDefinition_Format1 */
static int hf_e2ap_reportingPeriod;               /* INTEGER_1_4294967295 */
static int hf_e2ap_actionDefinition_formats;      /* T_actionDefinition_formats */
static int hf_e2ap_actionDefinition_Format1_01;   /* E2SM_KPM_ActionDefinition_Format1 */
static int hf_e2ap_actionDefinition_Format2_01;   /* E2SM_KPM_ActionDefinition_Format2 */
static int hf_e2ap_actionDefinition_Format3_01;   /* E2SM_KPM_ActionDefinition_Format3 */
static int hf_e2ap_actionDefinition_Format4_01;   /* E2SM_KPM_ActionDefinition_Format4 */
static int hf_e2ap_actionDefinition_Format5;      /* E2SM_KPM_ActionDefinition_Format5 */
static int hf_e2ap_measInfoList;                  /* MeasurementInfoList */
static int hf_e2ap_granulPeriod;                  /* GranularityPeriod */
static int hf_e2ap_distMeasBinRangeInfo;          /* DistMeasurementBinRangeList */
static int hf_e2ap_subscriptInfo;                 /* E2SM_KPM_ActionDefinition_Format1 */
static int hf_e2ap_measCondList;                  /* MeasurementCondList */
static int hf_e2ap_matchingUeCondList;            /* MatchingUeCondPerSubList */
static int hf_e2ap_subscriptionInfo;              /* E2SM_KPM_ActionDefinition_Format1 */
static int hf_e2ap_matchingUEidList_01;           /* MatchingUEidPerSubList */
static int hf_e2ap_indicationHeader_formats;      /* T_indicationHeader_formats */
static int hf_e2ap_indicationHeader_Format1_01;   /* E2SM_KPM_IndicationHeader_Format1 */
static int hf_e2ap_colletStartTime;               /* T_colletStartTime */
static int hf_e2ap_fileFormatversion;             /* PrintableString_SIZE_0_15_ */
static int hf_e2ap_senderName;                    /* PrintableString_SIZE_0_400_ */
static int hf_e2ap_senderType;                    /* PrintableString_SIZE_0_8_ */
static int hf_e2ap_vendorName;                    /* PrintableString_SIZE_0_32_ */
static int hf_e2ap_indicationMessage_formats;     /* T_indicationMessage_formats */
static int hf_e2ap_indicationMessage_Format1_01;  /* E2SM_KPM_IndicationMessage_Format1 */
static int hf_e2ap_indicationMessage_Format2_01;  /* E2SM_KPM_IndicationMessage_Format2 */
static int hf_e2ap_indicationMessage_Format3_01;  /* E2SM_KPM_IndicationMessage_Format3 */
static int hf_e2ap_measData;                      /* MeasurementData */
static int hf_e2ap_measCondUEidList;              /* MeasurementCondUEidList */
static int hf_e2ap_ueMeasReportList;              /* UEMeasurementReportList */
static int hf_e2ap_ric_EventTriggerStyle_List_01;  /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item */
static int hf_e2ap_ric_EventTriggerStyle_List_item_01;  /* RIC_EventTriggerStyle_Item */
static int hf_e2ap_ric_ReportStyle_List_01;       /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item */
static int hf_e2ap_ric_ReportStyle_List_item_01;  /* RIC_ReportStyle_Item */
static int hf_e2ap_ric_ActionFormat_Type;         /* RIC_Format_Type */
static int hf_e2ap_measInfo_Action_List;          /* MeasurementInfo_Action_List */
static int hf_e2ap_eventDefinition_Format1_01;    /* E2SM_NI_EventTriggerDefinition_Format1 */
static int hf_e2ap_interface_type;                /* NI_Type */
static int hf_e2ap_interface_ID;                  /* NI_Identifier */
static int hf_e2ap_interfaceDirection;            /* NI_Direction */
static int hf_e2ap_interfaceMessageType;          /* NI_MessageType */
static int hf_e2ap_interfaceProtocolIE_List;      /* SEQUENCE_SIZE_1_maxofInterfaceProtocolTests_OF_NI_ProtocolIE_Item */
static int hf_e2ap_interfaceProtocolIE_List_item;  /* NI_ProtocolIE_Item */
static int hf_e2ap_action_Definition_Format;      /* E2SM_NI_ActionDefinitionFormat */
static int hf_e2ap_actionDefinition_Format1_02;   /* E2SM_NI_ActionDefinition_Format1 */
static int hf_e2ap_actionDefinition_Format2_02;   /* E2SM_NI_ActionDefinition_Format2 */
static int hf_e2ap_actionParameter_List;          /* SEQUENCE_SIZE_1_maxofActionParameters_OF_RANparameter_Item */
static int hf_e2ap_actionParameter_List_item;     /* RANparameter_Item */
static int hf_e2ap_ranUEgroup_List;               /* SEQUENCE_SIZE_1_maxofRANueGroups_OF_RANueGroup_Item */
static int hf_e2ap_ranUEgroup_List_item;          /* RANueGroup_Item */
static int hf_e2ap_indicationHeader_Format1_02;   /* E2SM_NI_IndicationHeader_Format1 */
static int hf_e2ap_timestamp;                     /* NI_TimeStamp */
static int hf_e2ap_indicationMessage_Format1_02;  /* E2SM_NI_IndicationMessage_Format1 */
static int hf_e2ap_interfaceMessage;              /* NI_Message */
static int hf_e2ap_callProcessID_Format1_01;      /* E2SM_NI_CallProcessID_Format1 */
static int hf_e2ap_callProcessID_Format2;         /* E2SM_NI_CallProcessID_Format2 */
static int hf_e2ap_callProcess_ID;                /* RANcallProcess_ID_number */
static int hf_e2ap_callProcess_ID_01;             /* RANcallProcess_ID_string */
static int hf_e2ap_controlHeader_Format1_01;      /* E2SM_NI_ControlHeader_Format1 */
static int hf_e2ap_interface_Direction;           /* NI_Direction */
static int hf_e2ap_ric_Control_Message_Priority;  /* RIC_Control_Message_Priority */
static int hf_e2ap_controlMessage_Format1_01;     /* E2SM_NI_ControlMessage_Format1 */
static int hf_e2ap_controlOutcome_Format1_01;     /* E2SM_NI_ControlOutcome_Format1 */
static int hf_e2ap_outcomeElement_List;           /* SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameter_Item */
static int hf_e2ap_outcomeElement_List_item;      /* RANparameter_Item */
static int hf_e2ap_ni_Type_List;                  /* SEQUENCE_SIZE_1_maxofNItypes_OF_E2SM_NI_RANfunction_Item */
static int hf_e2ap_ni_Type_List_item;             /* E2SM_NI_RANfunction_Item */
static int hf_e2ap_ric_EventTriggerStyle_List_02;  /* SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List */
static int hf_e2ap_ric_EventTriggerStyle_List_item_02;  /* RIC_EventTriggerStyle_List */
static int hf_e2ap_ric_ReportStyle_List_02;       /* SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List */
static int hf_e2ap_ric_ReportStyle_List_item_02;  /* RIC_ReportStyle_List */
static int hf_e2ap_ric_InsertStyle_List_03;       /* SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_InsertStyle_List */
static int hf_e2ap_ric_InsertStyle_List_item_03;  /* RIC_InsertStyle_List */
static int hf_e2ap_ric_ControlStyle_List_03;      /* SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ControlStyle_List */
static int hf_e2ap_ric_ControlStyle_List_item_03;  /* RIC_ControlStyle_List */
static int hf_e2ap_ric_PolicyStyle_List_01;       /* SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_PolicyStyle_List */
static int hf_e2ap_ric_PolicyStyle_List_item_01;  /* RIC_PolicyStyle_List */
static int hf_e2ap_global_ng_RAN_ID;              /* Global_ng_RAN_ID */
static int hf_e2ap_global_eNB_ID_01;              /* Global_eNB_ID */
static int hf_e2ap_global_en_gNB_ID_01;           /* Global_en_gNB_ID */
static int hf_e2ap_global_gNB_DU_ID;              /* Global_gNB_DU_ID */
static int hf_e2ap_global_gNB_CU_UP_ID;           /* Global_gNB_CU_UP_ID */
static int hf_e2ap_s1MessageType;                 /* NI_MessageTypeS1 */
static int hf_e2ap_x2MessageType;                 /* NI_MessageTypeX2 */
static int hf_e2ap_ngMessageType;                 /* NI_MessageTypeNG */
static int hf_e2ap_xnMessageType;                 /* NI_MessageTypeXn */
static int hf_e2ap_f1MessageType;                 /* NI_MessageTypeF1 */
static int hf_e2ap_e1MessageType;                 /* NI_MessageTypeE1 */
static int hf_e2ap_typeOfMessage;                 /* TypeOfMessage */
static int hf_e2ap_interfaceProtocolIE_ID;        /* NI_ProtocolIE_ID */
static int hf_e2ap_interfaceProtocolIE_Test;      /* NI_ProtocolIE_Test */
static int hf_e2ap_interfaceProtocolIE_Value;     /* NI_ProtocolIE_Value */
static int hf_e2ap_ranImperativePolicy_List;      /* SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameter_Item */
static int hf_e2ap_ranImperativePolicy_List_item;  /* RANparameter_Item */
static int hf_e2ap_ranParameter_ID_01;            /* RANparameter_ID */
static int hf_e2ap_ranParameter_Value_01;         /* RANparameter_Value */
static int hf_e2ap_ranParameter_Name;             /* RANparameter_Name */
static int hf_e2ap_ranParameter_Type_01;          /* RANparameter_Type */
static int hf_e2ap_ranUEgroupID;                  /* RANueGroupID */
static int hf_e2ap_ranUEgroupDefinition;          /* RANueGroupDefinition */
static int hf_e2ap_ranPolicy;                     /* RANimperativePolicy */
static int hf_e2ap_ranUEgroupDef_List;            /* SEQUENCE_SIZE_1_maxofRANparameters_OF_RANueGroupDef_Item */
static int hf_e2ap_ranUEgroupDef_List_item;       /* RANueGroupDef_Item */
static int hf_e2ap_ranParameter_Test;             /* RANparameter_Test_Condition */
static int hf_e2ap_ric_ControlFormat_Type;        /* RIC_Format_Type */
static int hf_e2ap_ric_ControlOutcomeRanParaDef_List;  /* SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item */
static int hf_e2ap_ric_ControlOutcomeRanParaDef_List_item;  /* RANparameterDef_Item */
static int hf_e2ap_ric_InsertActionFormat_Type;   /* RIC_Format_Type */
static int hf_e2ap_ric_InsertRanParameterDef_List;  /* SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item */
static int hf_e2ap_ric_InsertRanParameterDef_List_item;  /* RANparameterDef_Item */
static int hf_e2ap_ric_PolicyActionFormat_Type;   /* RIC_Format_Type */
static int hf_e2ap_ric_PolicyRanParameterDef_List;  /* SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item */
static int hf_e2ap_ric_PolicyRanParameterDef_List_item;  /* RANparameterDef_Item */
static int hf_e2ap_ric_ReportRanParameterDef_List;  /* SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item */
static int hf_e2ap_ric_ReportRanParameterDef_List_item;  /* RANparameterDef_Item */

static int hf_e2ap_unmapped_ran_function_id;
static int hf_e2ap_ran_function_name_not_recognised;
static int hf_e2ap_ran_function_setup_frame;
/* TODO: for each RAN Function, also link forward to where setup is referenced (if at all?).  Maybe just first usage? */

static int hf_e2ap_dissector_version;
static int hf_e2ap_frame_version;

static int hf_e2ap_timestamp_string;


/* Initialize the subtree pointers */
static int ett_e2ap;

static expert_field ei_e2ap_ran_function_names_no_match;
static expert_field ei_e2ap_ran_function_id_not_mapped;
static expert_field ei_e2ap_ran_function_dissector_mismatch;
static expert_field ei_e2ap_ran_function_max_dissectors_registered;

static int ett_e2ap_ProtocolIE_Container;
static int ett_e2ap_ProtocolIE_Field;
static int ett_e2ap_Cause;
static int ett_e2ap_CriticalityDiagnostics;
static int ett_e2ap_CriticalityDiagnostics_IE_List;
static int ett_e2ap_CriticalityDiagnostics_IE_Item;
static int ett_e2ap_E2nodeComponentConfiguration;
static int ett_e2ap_E2nodeComponentConfigurationAck;
static int ett_e2ap_E2nodeComponentID;
static int ett_e2ap_E2nodeComponentInterfaceE1;
static int ett_e2ap_E2nodeComponentInterfaceF1;
static int ett_e2ap_E2nodeComponentInterfaceNG;
static int ett_e2ap_E2nodeComponentInterfaceS1;
static int ett_e2ap_E2nodeComponentInterfaceX2;
static int ett_e2ap_E2nodeComponentInterfaceXn;
static int ett_e2ap_E2nodeComponentInterfaceW1;
static int ett_e2ap_ENB_ID;
static int ett_e2ap_ENB_ID_Choice;
static int ett_e2ap_ENGNB_ID;
static int ett_e2ap_GlobalE2node_ID;
static int ett_e2ap_GlobalE2node_en_gNB_ID;
static int ett_e2ap_GlobalE2node_eNB_ID;
static int ett_e2ap_GlobalE2node_gNB_ID;
static int ett_e2ap_GlobalE2node_ng_eNB_ID;
static int ett_e2ap_GlobalENB_ID;
static int ett_e2ap_GlobalenGNB_ID;
static int ett_e2ap_GlobalgNB_ID;
static int ett_e2ap_GlobalngeNB_ID;
static int ett_e2ap_GlobalNG_RANNode_ID;
static int ett_e2ap_GlobalRIC_ID;
static int ett_e2ap_GNB_ID_Choice;
static int ett_e2ap_RICrequestID;
static int ett_e2ap_RICsubsequentAction;
static int ett_e2ap_TNLinformation;
static int ett_e2ap_RICsubscriptionRequest;
static int ett_e2ap_RICsubscriptionDetails;
static int ett_e2ap_RICactions_ToBeSetup_List;
static int ett_e2ap_RICaction_ToBeSetup_Item;
static int ett_e2ap_RICsubscriptionResponse;
static int ett_e2ap_RICaction_Admitted_List;
static int ett_e2ap_RICaction_Admitted_Item;
static int ett_e2ap_RICaction_NotAdmitted_List;
static int ett_e2ap_RICaction_NotAdmitted_Item;
static int ett_e2ap_RICsubscriptionFailure;
static int ett_e2ap_RICsubscriptionDeleteRequest;
static int ett_e2ap_RICsubscriptionDeleteResponse;
static int ett_e2ap_RICsubscriptionDeleteFailure;
static int ett_e2ap_RICsubscriptionDeleteRequired;
static int ett_e2ap_RICsubscription_List_withCause;
static int ett_e2ap_RICsubscription_withCause_Item;
static int ett_e2ap_RICsubscriptionModificationRequest;
static int ett_e2ap_RICactions_ToBeRemovedForModification_List;
static int ett_e2ap_RICaction_ToBeRemovedForModification_Item;
static int ett_e2ap_RICactions_ToBeModifiedForModification_List;
static int ett_e2ap_RICaction_ToBeModifiedForModification_Item;
static int ett_e2ap_RICactions_ToBeAddedForModification_List;
static int ett_e2ap_RICaction_ToBeAddedForModification_Item;
static int ett_e2ap_RICsubscriptionModificationResponse;
static int ett_e2ap_RICactions_RemovedForModification_List;
static int ett_e2ap_RICaction_RemovedForModification_Item;
static int ett_e2ap_RICactions_FailedToBeRemovedForModification_List;
static int ett_e2ap_RICaction_FailedToBeRemovedForModification_Item;
static int ett_e2ap_RICactions_ModifiedForModification_List;
static int ett_e2ap_RICaction_ModifiedForModification_Item;
static int ett_e2ap_RICactions_FailedToBeModifiedForModification_List;
static int ett_e2ap_RICaction_FailedToBeModifiedForModification_Item;
static int ett_e2ap_RICactions_AddedForModification_List;
static int ett_e2ap_RICaction_AddedForModification_Item;
static int ett_e2ap_RICactions_FailedToBeAddedForModification_List;
static int ett_e2ap_RICaction_FailedToBeAddedForModification_Item;
static int ett_e2ap_RICsubscriptionModificationFailure;
static int ett_e2ap_RICsubscriptionModificationRequired;
static int ett_e2ap_RICactions_RequiredToBeModified_List;
static int ett_e2ap_RICaction_RequiredToBeModified_Item;
static int ett_e2ap_RICactions_RequiredToBeRemoved_List;
static int ett_e2ap_RICaction_RequiredToBeRemoved_Item;
static int ett_e2ap_RICsubscriptionModificationConfirm;
static int ett_e2ap_RICactions_ConfirmedForModification_List;
static int ett_e2ap_RICaction_ConfirmedForModification_Item;
static int ett_e2ap_RICactions_RefusedToBeModified_List;
static int ett_e2ap_RICaction_RefusedToBeModified_Item;
static int ett_e2ap_RICactions_ConfirmedForRemoval_List;
static int ett_e2ap_RICaction_ConfirmedForRemoval_Item;
static int ett_e2ap_RICactions_RefusedToBeRemoved_List;
static int ett_e2ap_RICaction_RefusedToBeRemoved_Item;
static int ett_e2ap_RICsubscriptionModificationRefuse;
static int ett_e2ap_RICindication;
static int ett_e2ap_RICcontrolRequest;
static int ett_e2ap_RICcontrolAcknowledge;
static int ett_e2ap_RICcontrolFailure;
static int ett_e2ap_RICQueryRequest;
static int ett_e2ap_RICQueryResponse;
static int ett_e2ap_RICQueryFailure;
static int ett_e2ap_ErrorIndication;
static int ett_e2ap_E2setupRequest;
static int ett_e2ap_E2setupResponse;
static int ett_e2ap_E2setupFailure;
static int ett_e2ap_E2connectionUpdate;
static int ett_e2ap_E2connectionUpdate_List;
static int ett_e2ap_E2connectionUpdate_Item;
static int ett_e2ap_E2connectionUpdateRemove_List;
static int ett_e2ap_E2connectionUpdateRemove_Item;
static int ett_e2ap_E2connectionUpdateAcknowledge;
static int ett_e2ap_E2connectionSetupFailed_List;
static int ett_e2ap_E2connectionSetupFailed_Item;
static int ett_e2ap_E2connectionUpdateFailure;
static int ett_e2ap_E2nodeConfigurationUpdate;
static int ett_e2ap_E2nodeComponentConfigAddition_List;
static int ett_e2ap_E2nodeComponentConfigAddition_Item;
static int ett_e2ap_E2nodeComponentConfigUpdate_List;
static int ett_e2ap_E2nodeComponentConfigUpdate_Item;
static int ett_e2ap_E2nodeComponentConfigRemoval_List;
static int ett_e2ap_E2nodeComponentConfigRemoval_Item;
static int ett_e2ap_E2nodeTNLassociationRemoval_List;
static int ett_e2ap_E2nodeTNLassociationRemoval_Item;
static int ett_e2ap_E2nodeConfigurationUpdateAcknowledge;
static int ett_e2ap_E2nodeComponentConfigAdditionAck_List;
static int ett_e2ap_E2nodeComponentConfigAdditionAck_Item;
static int ett_e2ap_E2nodeComponentConfigUpdateAck_List;
static int ett_e2ap_E2nodeComponentConfigUpdateAck_Item;
static int ett_e2ap_E2nodeComponentConfigRemovalAck_List;
static int ett_e2ap_E2nodeComponentConfigRemovalAck_Item;
static int ett_e2ap_E2nodeConfigurationUpdateFailure;
static int ett_e2ap_ResetRequest;
static int ett_e2ap_ResetResponse;
static int ett_e2ap_RICserviceUpdate;
static int ett_e2ap_RANfunctions_List;
static int ett_e2ap_RANfunction_Item;
static int ett_e2ap_RANfunctionsID_List;
static int ett_e2ap_RANfunctionID_Item;
static int ett_e2ap_RICserviceUpdateAcknowledge;
static int ett_e2ap_RANfunctionsIDcause_List;
static int ett_e2ap_RANfunctionIDcause_Item;
static int ett_e2ap_RICserviceUpdateFailure;
static int ett_e2ap_RICserviceQuery;
static int ett_e2ap_E2RemovalRequest;
static int ett_e2ap_E2RemovalResponse;
static int ett_e2ap_E2RemovalFailure;
static int ett_e2ap_E2AP_PDU;
static int ett_e2ap_InitiatingMessage;
static int ett_e2ap_SuccessfulOutcome;
static int ett_e2ap_UnsuccessfulOutcome;
static int ett_e2ap_CGI;
static int ett_e2ap_InterfaceIdentifier;
static int ett_e2ap_InterfaceID_NG;
static int ett_e2ap_InterfaceID_Xn;
static int ett_e2ap_InterfaceID_F1;
static int ett_e2ap_InterfaceID_E1;
static int ett_e2ap_InterfaceID_S1;
static int ett_e2ap_InterfaceID_X2;
static int ett_e2ap_T_nodeType;
static int ett_e2ap_InterfaceID_W1;
static int ett_e2ap_Interface_MessageID;
static int ett_e2ap_RANfunction_Name;
static int ett_e2ap_RRC_MessageID;
static int ett_e2ap_T_rrcType;
static int ett_e2ap_ServingCell_ARFCN;
static int ett_e2ap_ServingCell_PCI;
static int ett_e2ap_UEID;
static int ett_e2ap_UEID_GNB;
static int ett_e2ap_UEID_GNB_CU_CP_E1AP_ID_List;
static int ett_e2ap_UEID_GNB_CU_CP_E1AP_ID_Item;
static int ett_e2ap_UEID_GNB_CU_F1AP_ID_List;
static int ett_e2ap_UEID_GNB_CU_CP_F1AP_ID_Item;
static int ett_e2ap_UEID_GNB_DU;
static int ett_e2ap_UEID_GNB_CU_UP;
static int ett_e2ap_UEID_NG_ENB;
static int ett_e2ap_UEID_NG_ENB_DU;
static int ett_e2ap_UEID_EN_GNB;
static int ett_e2ap_UEID_ENB;
static int ett_e2ap_GUMMEI;
static int ett_e2ap_EUTRA_CGI;
static int ett_e2ap_GlobalGNB_ID;
static int ett_e2ap_GlobalNgENB_ID;
static int ett_e2ap_GNB_ID;
static int ett_e2ap_GUAMI;
static int ett_e2ap_NgENB_ID;
static int ett_e2ap_NR_CGI;
static int ett_e2ap_S_NSSAI;
static int ett_e2ap_GlobalNGRANNodeID;
static int ett_e2ap_NR_ARFCN;
static int ett_e2ap_NRFrequencyBand_List;
static int ett_e2ap_NRFrequencyBandItem;
static int ett_e2ap_NRFrequencyInfo;
static int ett_e2ap_SupportedSULBandList;
static int ett_e2ap_SupportedSULFreqBandItem;
static int ett_e2ap_NeighborCell_List;
static int ett_e2ap_NeighborCell_Item;
static int ett_e2ap_NeighborCell_Item_Choice_NR;
static int ett_e2ap_NeighborCell_Item_Choice_E_UTRA;
static int ett_e2ap_NeighborRelation_Info;
static int ett_e2ap_EventTrigger_Cell_Info;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item;
static int ett_e2ap_EventTrigger_Cell_Info_Item;
static int ett_e2ap_T_cellType;
static int ett_e2ap_EventTrigger_Cell_Info_Item_Choice_Individual;
static int ett_e2ap_EventTrigger_Cell_Info_Item_Choice_Group;
static int ett_e2ap_EventTrigger_UE_Info;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item;
static int ett_e2ap_EventTrigger_UE_Info_Item;
static int ett_e2ap_T_ueType;
static int ett_e2ap_EventTrigger_UE_Info_Item_Choice_Individual;
static int ett_e2ap_EventTrigger_UE_Info_Item_Choice_Group;
static int ett_e2ap_EventTrigger_UEevent_Info;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item;
static int ett_e2ap_EventTrigger_UEevent_Info_Item;
static int ett_e2ap_RANParameter_Definition;
static int ett_e2ap_RANParameter_Definition_Choice;
static int ett_e2ap_RANParameter_Definition_Choice_LIST;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item;
static int ett_e2ap_RANParameter_Definition_Choice_LIST_Item;
static int ett_e2ap_RANParameter_Definition_Choice_STRUCTURE;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item;
static int ett_e2ap_RANParameter_Definition_Choice_STRUCTURE_Item;
static int ett_e2ap_RANParameter_Value;
static int ett_e2ap_RANParameter_ValueType;
static int ett_e2ap_RANParameter_ValueType_Choice_ElementTrue;
static int ett_e2ap_RANParameter_ValueType_Choice_ElementFalse;
static int ett_e2ap_RANParameter_ValueType_Choice_Structure;
static int ett_e2ap_RANParameter_ValueType_Choice_List;
static int ett_e2ap_RANParameter_STRUCTURE;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item;
static int ett_e2ap_RANParameter_STRUCTURE_Item;
static int ett_e2ap_RANParameter_LIST;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE;
static int ett_e2ap_RANParameter_Testing;
static int ett_e2ap_RANParameter_TestingCondition;
static int ett_e2ap_RANParameter_Testing_Item;
static int ett_e2ap_T_ranParameter_Type;
static int ett_e2ap_RANParameter_Testing_Item_Choice_List;
static int ett_e2ap_RANParameter_Testing_Item_Choice_Structure;
static int ett_e2ap_RANParameter_Testing_Item_Choice_ElementTrue;
static int ett_e2ap_RANParameter_Testing_Item_Choice_ElementFalse;
static int ett_e2ap_RANParameter_Testing_LIST;
static int ett_e2ap_RANParameter_Testing_STRUCTURE;
static int ett_e2ap_RIC_PolicyAction;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item;
static int ett_e2ap_RIC_PolicyAction_RANParameter_Item;
static int ett_e2ap_E2SM_RC_EventTrigger;
static int ett_e2ap_T_ric_eventTrigger_formats;
static int ett_e2ap_E2SM_RC_EventTrigger_Format1;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item;
static int ett_e2ap_E2SM_RC_EventTrigger_Format1_Item;
static int ett_e2ap_MessageType_Choice;
static int ett_e2ap_MessageType_Choice_NI;
static int ett_e2ap_MessageType_Choice_RRC;
static int ett_e2ap_E2SM_RC_EventTrigger_Format2;
static int ett_e2ap_E2SM_RC_EventTrigger_Format3;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item;
static int ett_e2ap_E2SM_RC_EventTrigger_Format3_Item;
static int ett_e2ap_E2SM_RC_EventTrigger_Format4;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item;
static int ett_e2ap_E2SM_RC_EventTrigger_Format4_Item;
static int ett_e2ap_TriggerType_Choice;
static int ett_e2ap_TriggerType_Choice_RRCstate;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item;
static int ett_e2ap_TriggerType_Choice_RRCstate_Item;
static int ett_e2ap_TriggerType_Choice_UEID;
static int ett_e2ap_TriggerType_Choice_L2state;
static int ett_e2ap_E2SM_RC_EventTrigger_Format5;
static int ett_e2ap_E2SM_RC_ActionDefinition;
static int ett_e2ap_T_ric_actionDefinition_formats;
static int ett_e2ap_E2SM_RC_ActionDefinition_Format1;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item;
static int ett_e2ap_E2SM_RC_ActionDefinition_Format1_Item;
static int ett_e2ap_E2SM_RC_ActionDefinition_Format2;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item;
static int ett_e2ap_E2SM_RC_ActionDefinition_Format2_Item;
static int ett_e2ap_E2SM_RC_ActionDefinition_Format3;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item;
static int ett_e2ap_E2SM_RC_ActionDefinition_Format3_Item;
static int ett_e2ap_E2SM_RC_ActionDefinition_Format4;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item;
static int ett_e2ap_E2SM_RC_ActionDefinition_Format4_Style_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item;
static int ett_e2ap_E2SM_RC_ActionDefinition_Format4_Indication_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item;
static int ett_e2ap_E2SM_RC_ActionDefinition_Format4_RANP_Item;
static int ett_e2ap_E2SM_RC_IndicationHeader;
static int ett_e2ap_T_ric_indicationHeader_formats;
static int ett_e2ap_E2SM_RC_IndicationHeader_Format1;
static int ett_e2ap_E2SM_RC_IndicationHeader_Format2;
static int ett_e2ap_E2SM_RC_IndicationHeader_Format3;
static int ett_e2ap_E2SM_RC_IndicationMessage;
static int ett_e2ap_T_ric_indicationMessage_formats;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format1;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format1_Item;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format2;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format2_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format2_RANParameter_Item;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format3;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format3_Item;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format4;
static int ett_e2ap_SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format4_ItemUE;
static int ett_e2ap_SEQUENCE_SIZE_0_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format4_ItemCell;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format4_ItemUE;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format4_ItemCell;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format5;
static int ett_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format5_Item;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format6;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format6_Style_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format6_Indication_Item;
static int ett_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item;
static int ett_e2ap_E2SM_RC_IndicationMessage_Format6_RANP_Item;
static int ett_e2ap_E2SM_RC_CallProcessID;
static int ett_e2ap_T_ric_callProcessID_formats;
static int ett_e2ap_E2SM_RC_CallProcessID_Format1;
static int ett_e2ap_E2SM_RC_ControlHeader;
static int ett_e2ap_T_ric_controlHeader_formats;
static int ett_e2ap_E2SM_RC_ControlHeader_Format1;
static int ett_e2ap_E2SM_RC_ControlHeader_Format2;
static int ett_e2ap_E2SM_RC_ControlMessage;
static int ett_e2ap_T_ric_controlMessage_formats;
static int ett_e2ap_E2SM_RC_ControlMessage_Format1;
static int ett_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item;
static int ett_e2ap_E2SM_RC_ControlMessage_Format1_Item;
static int ett_e2ap_E2SM_RC_ControlMessage_Format2;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item;
static int ett_e2ap_E2SM_RC_ControlMessage_Format2_Style_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item;
static int ett_e2ap_E2SM_RC_ControlMessage_Format2_ControlAction_Item;
static int ett_e2ap_E2SM_RC_ControlOutcome;
static int ett_e2ap_T_ric_controlOutcome_formats;
static int ett_e2ap_E2SM_RC_ControlOutcome_Format1;
static int ett_e2ap_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item;
static int ett_e2ap_E2SM_RC_ControlOutcome_Format1_Item;
static int ett_e2ap_E2SM_RC_ControlOutcome_Format2;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item;
static int ett_e2ap_E2SM_RC_ControlOutcome_Format2_Style_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item;
static int ett_e2ap_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item;
static int ett_e2ap_E2SM_RC_ControlOutcome_Format2_RANP_Item;
static int ett_e2ap_E2SM_RC_ControlOutcome_Format3;
static int ett_e2ap_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item;
static int ett_e2ap_E2SM_RC_ControlOutcome_Format3_Item;
static int ett_e2ap_E2SM_RC_RANFunctionDefinition;
static int ett_e2ap_RANFunctionDefinition_EventTrigger;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item;
static int ett_e2ap_RANFunctionDefinition_EventTrigger_Style_Item;
static int ett_e2ap_L2Parameters_RANParameter_Item;
static int ett_e2ap_UEIdentification_RANParameter_Item;
static int ett_e2ap_CellIdentification_RANParameter_Item;
static int ett_e2ap_RANFunctionDefinition_EventTrigger_CallProcess_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item;
static int ett_e2ap_RANFunctionDefinition_EventTrigger_Breakpoint_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item;
static int ett_e2ap_CallProcessBreakpoint_RANParameter_Item;
static int ett_e2ap_RANFunctionDefinition_Report;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item;
static int ett_e2ap_RANFunctionDefinition_Report_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item;
static int ett_e2ap_Report_RANParameter_Item;
static int ett_e2ap_RANFunctionDefinition_Insert;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item;
static int ett_e2ap_RANFunctionDefinition_Insert_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item;
static int ett_e2ap_RANFunctionDefinition_Insert_Indication_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item;
static int ett_e2ap_InsertIndication_RANParameter_Item;
static int ett_e2ap_RANFunctionDefinition_Control;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item;
static int ett_e2ap_RANFunctionDefinition_Control_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item;
static int ett_e2ap_ControlOutcome_RANParameter_Item;
static int ett_e2ap_RANFunctionDefinition_Control_Action_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item;
static int ett_e2ap_ControlAction_RANParameter_Item;
static int ett_e2ap_RANFunctionDefinition_Policy;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item;
static int ett_e2ap_RANFunctionDefinition_Policy_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item;
static int ett_e2ap_RANFunctionDefinition_Policy_Action_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item;
static int ett_e2ap_PolicyAction_RANParameter_Item;
static int ett_e2ap_PolicyCondition_RANParameter_Item;
static int ett_e2ap_BinRangeValue;
static int ett_e2ap_MeasurementType;
static int ett_e2ap_MeasurementLabel;
static int ett_e2ap_TestCondInfo;
static int ett_e2ap_TestCond_Type;
static int ett_e2ap_TestCond_Value;
static int ett_e2ap_BinRangeDefinition;
static int ett_e2ap_BinRangeList;
static int ett_e2ap_BinRangeItem;
static int ett_e2ap_DistMeasurementBinRangeList;
static int ett_e2ap_DistMeasurementBinRangeItem;
static int ett_e2ap_MeasurementInfoList;
static int ett_e2ap_MeasurementInfoItem;
static int ett_e2ap_LabelInfoList;
static int ett_e2ap_LabelInfoItem;
static int ett_e2ap_MeasurementData;
static int ett_e2ap_MeasurementDataItem;
static int ett_e2ap_MeasurementRecord;
static int ett_e2ap_MeasurementRecordItem;
static int ett_e2ap_MeasurementInfo_Action_List;
static int ett_e2ap_MeasurementInfo_Action_Item;
static int ett_e2ap_MeasurementCondList;
static int ett_e2ap_MeasurementCondItem;
static int ett_e2ap_MeasurementCondUEidList;
static int ett_e2ap_MeasurementCondUEidItem;
static int ett_e2ap_MatchingCondList;
static int ett_e2ap_MatchingCondItem;
static int ett_e2ap_MatchingCondItem_Choice;
static int ett_e2ap_MatchingUEidList;
static int ett_e2ap_MatchingUEidItem;
static int ett_e2ap_MatchingUEidPerGP;
static int ett_e2ap_MatchingUEidPerGP_Item;
static int ett_e2ap_T_matchedPerGP;
static int ett_e2ap_MatchingUEidList_PerGP;
static int ett_e2ap_MatchingUEidItem_PerGP;
static int ett_e2ap_MatchingUeCondPerSubList;
static int ett_e2ap_MatchingUeCondPerSubItem;
static int ett_e2ap_MatchingUEidPerSubList;
static int ett_e2ap_MatchingUEidPerSubItem;
static int ett_e2ap_UEMeasurementReportList;
static int ett_e2ap_UEMeasurementReportItem;
static int ett_e2ap_E2SM_KPM_EventTriggerDefinition;
static int ett_e2ap_T_eventDefinition_formats;
static int ett_e2ap_E2SM_KPM_EventTriggerDefinition_Format1;
static int ett_e2ap_E2SM_KPM_ActionDefinition;
static int ett_e2ap_T_actionDefinition_formats;
static int ett_e2ap_E2SM_KPM_ActionDefinition_Format1;
static int ett_e2ap_E2SM_KPM_ActionDefinition_Format2;
static int ett_e2ap_E2SM_KPM_ActionDefinition_Format3;
static int ett_e2ap_E2SM_KPM_ActionDefinition_Format4;
static int ett_e2ap_E2SM_KPM_ActionDefinition_Format5;
static int ett_e2ap_E2SM_KPM_IndicationHeader;
static int ett_e2ap_T_indicationHeader_formats;
static int ett_e2ap_E2SM_KPM_IndicationHeader_Format1;
static int ett_e2ap_E2SM_KPM_IndicationMessage;
static int ett_e2ap_T_indicationMessage_formats;
static int ett_e2ap_E2SM_KPM_IndicationMessage_Format1;
static int ett_e2ap_E2SM_KPM_IndicationMessage_Format2;
static int ett_e2ap_E2SM_KPM_IndicationMessage_Format3;
static int ett_e2ap_E2SM_KPM_RANfunction_Description;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item;
static int ett_e2ap_RIC_EventTriggerStyle_Item;
static int ett_e2ap_RIC_ReportStyle_Item;
static int ett_e2ap_E2SM_NI_EventTriggerDefinition;
static int ett_e2ap_E2SM_NI_EventTriggerDefinition_Format1;
static int ett_e2ap_SEQUENCE_SIZE_1_maxofInterfaceProtocolTests_OF_NI_ProtocolIE_Item;
static int ett_e2ap_E2SM_NI_ActionDefinition;
static int ett_e2ap_E2SM_NI_ActionDefinitionFormat;
static int ett_e2ap_E2SM_NI_ActionDefinition_Format1;
static int ett_e2ap_SEQUENCE_SIZE_1_maxofActionParameters_OF_RANparameter_Item;
static int ett_e2ap_E2SM_NI_ActionDefinition_Format2;
static int ett_e2ap_SEQUENCE_SIZE_1_maxofRANueGroups_OF_RANueGroup_Item;
static int ett_e2ap_E2SM_NI_IndicationHeader;
static int ett_e2ap_E2SM_NI_IndicationHeader_Format1;
static int ett_e2ap_E2SM_NI_IndicationMessage;
static int ett_e2ap_E2SM_NI_IndicationMessage_Format1;
static int ett_e2ap_E2SM_NI_CallProcessID;
static int ett_e2ap_E2SM_NI_CallProcessID_Format1;
static int ett_e2ap_E2SM_NI_CallProcessID_Format2;
static int ett_e2ap_E2SM_NI_ControlHeader;
static int ett_e2ap_E2SM_NI_ControlHeader_Format1;
static int ett_e2ap_E2SM_NI_ControlMessage;
static int ett_e2ap_E2SM_NI_ControlMessage_Format1;
static int ett_e2ap_E2SM_NI_ControlOutcome;
static int ett_e2ap_E2SM_NI_ControlOutcome_Format1;
static int ett_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameter_Item;
static int ett_e2ap_E2SM_NI_RANfunction_Description;
static int ett_e2ap_SEQUENCE_SIZE_1_maxofNItypes_OF_E2SM_NI_RANfunction_Item;
static int ett_e2ap_E2SM_NI_RANfunction_Item;
static int ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List;
static int ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List;
static int ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_InsertStyle_List;
static int ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ControlStyle_List;
static int ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_PolicyStyle_List;
static int ett_e2ap_Global_gNB_DU_ID;
static int ett_e2ap_Global_gNB_CU_UP_ID;
static int ett_e2ap_NI_Identifier;
static int ett_e2ap_NI_MessageType;
static int ett_e2ap_NI_MessageTypeApproach1;
static int ett_e2ap_NI_ProtocolIE_Item;
static int ett_e2ap_NI_ProtocolIE_Value;
static int ett_e2ap_RANimperativePolicy;
static int ett_e2ap_RANparameter_Item;
static int ett_e2ap_RANparameterDef_Item;
static int ett_e2ap_RANparameter_Value;
static int ett_e2ap_RANueGroup_Item;
static int ett_e2ap_RANueGroupDefinition;
static int ett_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANueGroupDef_Item;
static int ett_e2ap_RANueGroupDef_Item;
static int ett_e2ap_RIC_ControlStyle_List;
static int ett_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item;
static int ett_e2ap_RIC_EventTriggerStyle_List;
static int ett_e2ap_RIC_InsertStyle_List;
static int ett_e2ap_RIC_PolicyStyle_List;
static int ett_e2ap_RIC_ReportStyle_List;


/* Forward declarations */
static int dissect_e2ap_RANfunction_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);


static int dissect_E2SM_KPM_EventTriggerDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_RANfunction_Description_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static int dissect_E2SM_RC_EventTrigger_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_RANFunctionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_CallProcessID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ControlHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ControlMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ControlOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static int dissect_E2SM_NI_EventTriggerDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_RANfunction_Description_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_CallProcessID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_ControlHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_ControlMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_NI_ControlOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

enum {
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};


/* E2AP stats - Tap interface */

static void set_stats_message_type(packet_info *pinfo, int type);

static const uint8_t *st_str_packets        = "Total Packets";
static const uint8_t *st_str_packet_types   = "E2AP Packet Types";

static int st_node_packets = -1;
static int st_node_packet_types = -1;
static int e2ap_tap;

struct e2ap_tap_t {
    int e2ap_mtype;
};

#define MTYPE_E2_CONNECTION_UPDATE             1
#define MTYPE_E2_CONNECTION_UPDATE_ACK         2
#define MTYPE_E2_CONNECTION_UPDATE_FAIL        3
#define MTYPE_E2_CONFIGURATION_UPDATE          4
#define MTYPE_E2_CONFIGURATION_UPDATE_ACK      5
#define MTYPE_E2_CONFIGURATION_UPDATE_FAIL     6
#define MTYPE_E2_SETUP_FAIL                    7
#define MTYPE_E2_SETUP_REQUEST                 8
#define MTYPE_E2_SETUP_RESPONSE                9
#define MTYPE_ERROR_INDICATION                 10
#define MTYPE_RESET_REQUEST                    11
#define MTYPE_RESET_RESPONSE                   12
#define MTYPE_RIC_CONTROL_ACK                  13
#define MTYPE_RIC_CONTROL_FAIL                 14
#define MTYPE_RIC_CONTROL_REQUEST              15
#define MTYPE_RIC_IND                          16
#define MTYPE_RIC_SERVICE_QUERY                17
#define MTYPE_RIC_SERVICE_UPDATE               18
#define MTYPE_RIC_SERVICE_UPDATE_ACK           19
#define MTYPE_RIC_SERVICE_UPDATE_FAIL          20
#define MTYPE_RIC_SUBSCRIPTION_FAIL            21
#define MTYPE_RIC_SUBSCRIPTION_REQUEST         22
#define MTYPE_RIC_SUBSCRIPTION_RESPONSE        23
#define MTYPE_RIC_SUBSCRIPTION_DELETE_FAIL     24
#define MTYPE_RIC_SUBSCRIPTION_DELETE_REQUEST  25
#define MTYPE_RIC_SUBSCRIPTION_DELETE_RESPONSE 26
#define MTYPE_RIC_SUBSCRIPTION_DELETE_REQUIRED 27

/* Value Strings. TODO: ext? */
static const value_string mtype_names[] = {
    { MTYPE_E2_CONNECTION_UPDATE,                "E2connectionUpdate"},
    { MTYPE_E2_CONNECTION_UPDATE_ACK,            "E2connectionUpdateAcknowledge"},
    { MTYPE_E2_CONNECTION_UPDATE_FAIL,           "E2connectionUpdateFailure"},
    { MTYPE_E2_CONFIGURATION_UPDATE,             "E2nodeConfigurationUpdate"},
    { MTYPE_E2_CONFIGURATION_UPDATE_ACK,         "E2nodeConfigurationUpdateAcknowledge"},
    { MTYPE_E2_CONFIGURATION_UPDATE_FAIL,        "E2nodeConfigurationUpdateFailure"},
    { MTYPE_E2_SETUP_FAIL,                       "E2setupFailure"},
    { MTYPE_E2_SETUP_REQUEST,                    "E2setupRequest"},
    { MTYPE_E2_SETUP_RESPONSE,                   "E2setupResponse"},
    { MTYPE_ERROR_INDICATION,                    "ErrorIndication"},
    { MTYPE_RESET_REQUEST,                       "ResetRequest"},
    { MTYPE_RESET_RESPONSE,                      "ResetResponse"},
    { MTYPE_RIC_CONTROL_ACK,                     "RICcontrolAcknowledge"},
    { MTYPE_RIC_CONTROL_FAIL,                    "RICcontrolFailure"},
    { MTYPE_RIC_CONTROL_REQUEST,                 "RICcontrolRequest"},
    { MTYPE_RIC_IND,                             "RICindication"},
    { MTYPE_RIC_SERVICE_QUERY,                   "RICserviceQuery"},
    { MTYPE_RIC_SERVICE_UPDATE,                  "RICserviceUpdate"},
    { MTYPE_RIC_SERVICE_UPDATE_ACK,              "RICserviceUpdateAcknowledge"},
    { MTYPE_RIC_SERVICE_UPDATE_FAIL,             "RICserviceUpdateFailure"},
    { MTYPE_RIC_SUBSCRIPTION_FAIL,               "RICsubscriptionFailure"},
    { MTYPE_RIC_SUBSCRIPTION_REQUEST,            "RICsubscriptionRequest"},
    { MTYPE_RIC_SUBSCRIPTION_RESPONSE,           "RICsubscriptionResponse"},
    { MTYPE_RIC_SUBSCRIPTION_DELETE_FAIL,        "RICsubscriptionDeleteFailure"},
    { MTYPE_RIC_SUBSCRIPTION_DELETE_REQUEST,     "RICsubscriptionDeleteRequest"},
    { MTYPE_RIC_SUBSCRIPTION_DELETE_RESPONSE,    "RICsubscriptionDeleteResponse"},
    { MTYPE_RIC_SUBSCRIPTION_DELETE_REQUIRED,    "RICsubscriptionDeleteRequired"},
    { 0,  NULL }
};

static proto_tree *top_tree;

static void set_message_label(asn1_ctx_t *actx, int type)
{
  const char *label = val_to_str_const(type, mtype_names, "Unknown");
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, label);
  proto_item_append_text(top_tree, " (%s)", label);
}




/* Temporary private info to remember while dissecting frame */
struct e2ap_private_data {
  uint32_t procedure_code;
  uint32_t protocol_ie_id;
  uint32_t message_type;

  uint32_t ran_function_id;
  uint32_t gnb_id_len;
#define MAX_GNB_ID_BYTES 6
  uint8_t gnb_id_bytes[MAX_GNB_ID_BYTES];
  dissector_handle_t component_configuration_dissector;
  struct e2ap_tap_t *stats_tap;
};

/* Lookup temporary private info */
static struct e2ap_private_data*
e2ap_get_private_data(packet_info *pinfo)
{
  struct e2ap_private_data *e2ap_data = (struct e2ap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_e2ap, 0);
  if (!e2ap_data) {
    e2ap_data = wmem_new0(pinfo->pool, struct e2ap_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_e2ap, 0, e2ap_data);
  }
  return e2ap_data;
}

/****************************************************************************************************************/
/* These are the strings that we look for at the beginning of RAN Function Description to identify RAN Function */
/* Static table mapping from string -> ran_function */
static const char* g_ran_function_name_table[MAX_RANFUNCTIONS] =
{
    "ORAN-E2SM-KPM",
    "ORAN-E2SM-RC",
    "ORAN-E2SM-NI",
    "{"               /* For now, CCC is the only JSON-based RAN Function, so just match opening */
};



/* Per-conversation mapping: ranFunctionId -> ran_function+dissector */
typedef struct {
    uint32_t                 setup_frame;
    uint32_t                 ran_function_id;
    ran_function_t           ran_function;
    char                     oid[MAX_OID_LEN];       // i.e., OID from setupRequest
    ran_function_dissector_t *dissector;
} ran_function_id_mapping_t;

typedef struct  {
#define MAX_RANFUNCTION_ENTRIES 8
    uint32_t                  num_entries;
    ran_function_id_mapping_t entries[MAX_RANFUNCTION_ENTRIES];
} ran_functionid_table_t;

static const char *ran_function_to_str(ran_function_t ran_function)
{
    switch (ran_function) {
        case KPM_RANFUNCTIONS:
            return "KPM";
        case RC_RANFUNCTIONS:
            return "RC";
        case NI_RANFUNCTIONS:
            return "NI";
        case CCC_RANFUNCTIONS:
            return "CCC";

        default:
            return "Unknown";
    }
}

/* Table of RAN Function tables, indexed by gnbId (bytes) */
typedef struct {
#define MAX_GNBS 6
    uint32_t num_gnbs;
    struct {
        uint8_t id_value[MAX_GNB_ID_BYTES];
        uint32_t id_len;
        ran_functionid_table_t *ran_function_table;
    } gnb[MAX_GNBS];
} gnb_ran_functions_t;

static gnb_ran_functions_t s_gnb_ran_functions_table;


/* Table of available dissectors for each RAN function */
typedef struct {
    uint32_t                 num_available_dissectors;
#define MAX_DISSECTORS_PER_RAN_FUNCTION 8
    ran_function_dissector_t* ran_function_dissectors[MAX_DISSECTORS_PER_RAN_FUNCTION];
} ran_function_available_dissectors_t;

/* Available dissectors should be set here */
static ran_function_available_dissectors_t g_ran_functions_available_dissectors[MAX_RANFUNCTIONS];

/* Will be called from outside this file by separate dissectors */
void register_e2ap_ran_function_dissector(ran_function_t ran_function, ran_function_dissector_t *dissector)
{
    if ((ran_function >= MIN_RANFUNCTIONS) && (ran_function < MAX_RANFUNCTIONS)) {
        ran_function_available_dissectors_t *available_dissectors = &g_ran_functions_available_dissectors[ran_function];
        if (available_dissectors->num_available_dissectors < MAX_DISSECTORS_PER_RAN_FUNCTION) {
            available_dissectors->ran_function_dissectors[available_dissectors->num_available_dissectors++] = dissector;
        }
    }
}


/* Get RANfunctionID table from conversation data - create new if necessary */
static ran_functionid_table_t* get_ran_functionid_table(packet_info *pinfo)
{
    conversation_t *p_conv;
    ran_functionid_table_t *p_conv_data = NULL;

    /* Lookup conversation */
    p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                               conversation_pt_to_endpoint_type(pinfo->ptype),
                               pinfo->destport, pinfo->srcport, 0);
    if (!p_conv) {
        /* None, so create new data and set */
        p_conv = conversation_new(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                                  conversation_pt_to_endpoint_type(pinfo->ptype),
                                  pinfo->destport, pinfo->srcport, 0);
        p_conv_data = (ran_functionid_table_t*)wmem_new0(wmem_file_scope(), ran_functionid_table_t);
        conversation_add_proto_data(p_conv, proto_e2ap, p_conv_data);
    }
    else {
        /* Will return existing conversation data */
        p_conv_data = (ran_functionid_table_t*)conversation_get_proto_data(p_conv, proto_e2ap);
    }

    return p_conv_data;
}


/* Store new RANfunctionID -> Service Model mapping in table */
void e2ap_store_ran_function_mapping(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, const char *name)
{
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
    ran_functionid_table_t *table = get_ran_functionid_table(pinfo);

    /* Need these pointers not to be NULL */
    if (!name || !table) {
      return;
    }

    /* Stop if already reached table limit */
    if (table->num_entries == MAX_RANFUNCTION_ENTRIES) {
        proto_tree_add_expert_format(tree, pinfo, &ei_e2ap_ran_function_max_dissectors_registered,
                                     tvb, 0, 0,
                                     "Dissector wants to register for %s, but max (%u) already reached",
                                     name, MAX_RANFUNCTION_ENTRIES);
        return;
    }

    uint32_t ran_function_id = e2ap_data->ran_function_id;

    ran_function_t           ran_function = MAX_RANFUNCTIONS;  /* i.e. invalid */
    ran_function_dissector_t *ran_function_dissector = NULL;

    /* Check known RAN function names */
    for (int n=MIN_RANFUNCTIONS; n < MAX_RANFUNCTIONS; n++) {
        if (strcmp(name, g_ran_function_name_table[n]) == 0) {
            ran_function = n;

            /* Don't know OID yet, so for now, just choose first/only one */
            /* TODO: is latest one likely to be more compatible? First fields (at least) come from E2SM.. */
            if (g_ran_functions_available_dissectors[table->entries[n].ran_function].num_available_dissectors) {
                ran_function_dissector = g_ran_functions_available_dissectors[table->entries[n].ran_function].ran_function_dissectors[0];
            }
            break;
        }
    }

    /* Nothing to do if no matches */
    if (ran_function == MAX_RANFUNCTIONS) {
        return;
    }

    /* If ID already mapped, can stop here */
    for (unsigned n=0; n < table->num_entries; n++) {
        if (table->entries[n].ran_function_id == ran_function_id) {
            return;
        }
    }

    /* OK, store this new entry */
    unsigned idx = table->num_entries++;
    table->entries[idx].setup_frame = pinfo->num;
    table->entries[idx].ran_function_id = ran_function_id;
    table->entries[idx].ran_function = ran_function;
    table->entries[idx].dissector = ran_function_dissector;

    /* When add first entry, also want to set up table from gnbId -> table */
    if (idx == 0) {
        unsigned id_len = e2ap_data->gnb_id_len;
        uint8_t *id_value = &e2ap_data->gnb_id_bytes[0];

        bool found = false;
        for (unsigned n=0; n<s_gnb_ran_functions_table.num_gnbs; n++) {
            if ((s_gnb_ran_functions_table.gnb[n].id_len = id_len) &&
                (memcmp(s_gnb_ran_functions_table.gnb[n].id_value, id_value, id_len) == 0)) {
                /* Already have an entry for this gnb. */
                found = true;
                break;
            }
        }

        if (!found) {
            /* Add entry (if room for 1 more) */
            uint32_t new_idx = s_gnb_ran_functions_table.num_gnbs;
            if (new_idx < MAX_GNBS-1) {
                s_gnb_ran_functions_table.gnb[new_idx].id_len = id_len;
                memcpy(s_gnb_ran_functions_table.gnb[new_idx].id_value, id_value, id_len);
                s_gnb_ran_functions_table.gnb[new_idx].ran_function_table = table;

                s_gnb_ran_functions_table.num_gnbs++;
            }
        }
    }
}

/* Look for Service Model function pointers, based on current RANFunctionID from frame */
static ran_function_dissector_t* lookup_ranfunction_dissector(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
    /* Get ranFunctionID from this frame */
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
    unsigned ran_function_id = e2ap_data->ran_function_id;

    /* Get ranFunction table corresponding to this frame's conversation */
    ran_functionid_table_t *table = get_ran_functionid_table(pinfo);
    if (!table) {
        /* There is no ran function table associated with this frame's conversation info */
        return NULL;
    }

    /* Find the entry in this table corresponding to ran_function_id */
    for (unsigned n=0; n < table->num_entries; n++) {
        if (ran_function_id == table->entries[n].ran_function_id) {
            if (tree) {
                /* Point back at the setup frame where this ranfunction was mapped */
                proto_item *ti = proto_tree_add_uint(tree, hf_e2ap_ran_function_setup_frame,
                                                     tvb, 0, 0, table->entries[n].setup_frame);
                /* Show that mapping */
                proto_item_append_text(ti, " (%u -> %s)", table->entries[n].ran_function_id, ran_function_to_str(table->entries[n].ran_function));
                proto_item_set_generated(ti);

                /* Also take the chance to compare signalled and available dissector */
                char *frame_version = oid_resolved_from_string(pinfo->pool, table->entries[n].oid);
                ti = proto_tree_add_string(tree, hf_e2ap_frame_version, tvb, 0, 0, frame_version);
                proto_item_set_generated(ti);

                char *dissector_version = oid_resolved_from_string(pinfo->pool, table->entries[n].dissector->oid);
                ti = proto_tree_add_string(tree, hf_e2ap_dissector_version, tvb, 0, 0, dissector_version);
                proto_item_set_generated(ti);

                if (strcmp(frame_version, dissector_version) != 0) {
                    /* Expert info for version mismatch! */
                    expert_add_info_format(pinfo, ti, &ei_e2ap_ran_function_dissector_mismatch,
                                           "Dissector version mismatch - frame is %s but dissector is %s",
                                           frame_version, dissector_version);
                }
            }

            /* Return the dissector */
            return table->entries[n].dissector;
        }
    }

    if (tree) {
        /* No match found.. */
        proto_item *ti = proto_tree_add_item(tree, hf_e2ap_unmapped_ran_function_id, tvb, 0, 0, ENC_NA);
        expert_add_info_format(pinfo, ti, &ei_e2ap_ran_function_id_not_mapped,
                               "Service Model not mapped for FunctionID %u", ran_function_id);
    }

    return NULL;
}

/* Return the oid associated with this frame's conversation */
static char* lookup_ranfunction_oid(packet_info *pinfo)
{
    /* Get ranFunctionID from this frame */
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
    unsigned ran_function_id = e2ap_data->ran_function_id;

    /* Get ranFunction table corresponding to this frame's conversation */
    ran_functionid_table_t *table = get_ran_functionid_table(pinfo);
    if (!table) {
        /* There is no ran function table associated with this frame's conversation info */
        return NULL;
    }

    /* Find the entry in this table corresponding to ran_function_id */
    for (unsigned n=0; n < table->num_entries; n++) {
        if (ran_function_id == table->entries[n].ran_function_id) {
            return (char*)(table->entries[n].oid);
        }
    }

    /* Not found */
    return NULL;
}


/* We now know the OID - can we set a dissector that is an exact match from what has been signalled? */
static void update_dissector_using_oid(packet_info *pinfo, ran_function_t ran_function)
{
    char *frame_oid = lookup_ranfunction_oid(pinfo);
    if (frame_oid == NULL) {
        /* TODO: error? */
        return;
    }

    bool found = false;

    /* Look at available dissectors for this RAN function */
    ran_function_available_dissectors_t *available = &g_ran_functions_available_dissectors[ran_function];
    if (!available->num_available_dissectors) {
        /* Oops - none available at all! */
        return;
    }

    // Get mapping in use
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
    unsigned ran_function_id = e2ap_data->ran_function_id;
    ran_function_id_mapping_t *mapping = NULL;
    ran_functionid_table_t *table = get_ran_functionid_table(pinfo);
    if (!table) {
        return;
    }

    /* Find the entry in this table corresponding to ran_function_id */
    for (unsigned n=0; n < table->num_entries; n++) {
        if (ran_function_id == table->entries[n].ran_function_id) {
            mapping = &(table->entries[n]);
        }
    }

    if (!mapping) {
        return;
    }

    /* Set dissector pointer in ran_function_id_mapping_t */
    for (uint32_t n=0; n < available->num_available_dissectors; n++) {
        /* If exact match, set it */
        if (strcmp(frame_oid, available->ran_function_dissectors[n]->oid) == 0) {
            mapping->dissector = available->ran_function_dissectors[n];
            found = true;
            break;
        }
    }

    /* If not exact match, just set to first one available (TODO: closest above better?) */
    if (!found) {
        mapping->dissector = available->ran_function_dissectors[0];
    }
}


/* Update RANfunctionID -> Service Model mapping in table (now that we know OID) */
void e2ap_update_ran_function_mapping(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, const char *oid)
{
    /* Copy OID into table entry (so may be used to choose and be compared with chosen available dissector */
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
    ran_functionid_table_t *table = get_ran_functionid_table(pinfo);
    /* Make sure we have private and table data to compare */
    if (!e2ap_data || !table) {
        return;
    }
    ran_function_t ran_function = MAX_RANFUNCTIONS;
    for (unsigned n=0; n < table->num_entries; n++) {
        if (e2ap_data->ran_function_id == table->entries[n].ran_function_id) {
            ran_function = table->entries[n].ran_function;
            g_strlcpy(table->entries[n].oid, oid, MAX_OID_LEN);
        }
    }

    /* Look up version from oid and show as generated field */
    char *version = oid_resolved_from_string(pinfo->pool, oid);
    proto_item *ti = proto_tree_add_string(tree, hf_e2ap_frame_version, tvb, 0, 0, version);
    proto_item_set_generated(ti);

    /* Can now pick most appropriate dissector for this RAN Function name, based upon this OID and the available dissectors */
    if (ran_function < MAX_RANFUNCTIONS) {
        if (pinfo->fd->visited) {
            update_dissector_using_oid(pinfo, ran_function);
        }
    }
}

/* This will get used for E2nodeConfigurationUpdate, where we have a gnb-id but haven't seen E2setupRequest */
static void update_conversation_from_gnb_id(asn1_ctx_t *actx)
{
    packet_info *pinfo = actx->pinfo;
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

    /* Look for conversation data */
    conversation_t *p_conv;
    ran_functionid_table_t *p_conv_data = NULL;

    /* Lookup conversation */
    p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                               conversation_pt_to_endpoint_type(pinfo->ptype),
                               pinfo->destport, pinfo->srcport, 0);

    if (!p_conv) {
        /* None, so create new data and set */
        p_conv = conversation_new(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                                  conversation_pt_to_endpoint_type(pinfo->ptype),
                                  pinfo->destport, pinfo->srcport, 0);
        p_conv_data = (ran_functionid_table_t*)wmem_new0(wmem_file_scope(), ran_functionid_table_t);
        conversation_add_proto_data(p_conv, proto_e2ap, p_conv_data);

        /* Look to see if we already know about the mappings in effect on this gNB */
        unsigned id_len = e2ap_data->gnb_id_len;
        uint8_t *id_value = &e2ap_data->gnb_id_bytes[0];

        for (unsigned n=0; n<s_gnb_ran_functions_table.num_gnbs; n++) {
            if ((s_gnb_ran_functions_table.gnb[n].id_len = id_len) &&
                (memcmp(s_gnb_ran_functions_table.gnb[n].id_value, id_value, id_len) == 0)) {

                /* Have an entry for this gnb.  Set direct pointer to existing data (used by original conversation). */
                /* N.B. This means that no further updates for the gNB are expected on different conversations.. */
                p_conv_data = s_gnb_ran_functions_table.gnb[n].ran_function_table;
                conversation_add_proto_data(p_conv, proto_e2ap, p_conv_data);

                /* TODO: may want to try to add a generated field to pass back to E2setupRequest where RAN function mappings were first seen? */
                break;
            }
        }
    }
}

static dissector_handle_t json_handle;

static int dissect_E2SM_NI_JSON_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Send to JSON dissector */
    return call_dissector_only(json_handle, tvb, pinfo, tree, NULL);
}


/* Dissector tables */
static dissector_table_t e2ap_ies_dissector_table;

//static dissector_table_t e2ap_ies_p1_dissector_table;
//static dissector_table_t e2ap_ies_p2_dissector_table;
static dissector_table_t e2ap_extension_dissector_table;
static dissector_table_t e2ap_proc_imsg_dissector_table;
static dissector_table_t e2ap_proc_sout_dissector_table;
static dissector_table_t e2ap_proc_uout_dissector_table;
static dissector_table_t e2ap_n2_ie_type_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
*/


static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);


/*--- Cyclic dependencies ---*/

/* RANParameter-Testing-Item -> RANParameter-Testing-Item/ranParameter-Type -> RANParameter-Testing-Item-Choice-List -> RANParameter-Testing-LIST -> RANParameter-Testing-Item */
/* RANParameter-Testing-Item -> RANParameter-Testing-Item/ranParameter-Type -> RANParameter-Testing-Item-Choice-Structure -> RANParameter-Testing-STRUCTURE -> RANParameter-Testing-Item */
static int dissect_e2ap_RANParameter_Testing_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* RANParameter-Definition -> RANParameter-Definition-Choice -> RANParameter-Definition-Choice-LIST -> RANParameter-Definition-Choice-LIST/ranParameter-List -> RANParameter-Definition-Choice-LIST-Item -> RANParameter-Definition */
/* RANParameter-Definition -> RANParameter-Definition-Choice -> RANParameter-Definition-Choice-STRUCTURE -> RANParameter-Definition-Choice-STRUCTURE/ranParameter-STRUCTURE -> RANParameter-Definition-Choice-STRUCTURE-Item -> RANParameter-Definition */
static int dissect_e2ap_RANParameter_Definition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* RANParameter-ValueType -> RANParameter-ValueType-Choice-Structure -> RANParameter-STRUCTURE -> RANParameter-STRUCTURE/sequence-of-ranParameters -> RANParameter-STRUCTURE-Item -> RANParameter-ValueType */
static int dissect_e2ap_RANParameter_ValueType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);



static const value_string e2ap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_e2ap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}


static const value_string e2ap_ProcedureCode_vals[] = {
  { id_E2setup, "id-E2setup" },
  { id_ErrorIndication, "id-ErrorIndication" },
  { id_Reset, "id-Reset" },
  { id_RICcontrol, "id-RICcontrol" },
  { id_RICindication, "id-RICindication" },
  { id_RICserviceQuery, "id-RICserviceQuery" },
  { id_RICserviceUpdate, "id-RICserviceUpdate" },
  { id_RICsubscription, "id-RICsubscription" },
  { id_RICsubscriptionDelete, "id-RICsubscriptionDelete" },
  { id_E2nodeConfigurationUpdate, "id-E2nodeConfigurationUpdate" },
  { id_E2connectionUpdate, "id-E2connectionUpdate" },
  { id_RICsubscriptionDeleteRequired, "id-RICsubscriptionDeleteRequired" },
  { id_E2removal, "id-E2removal" },
  { id_RICsubscriptionModification, "id-RICsubscriptionModification" },
  { id_RICsubscriptionModificationRequired, "id-RICsubscriptionModificationRequired" },
  { id_RICquery, "id-RICquery" },
  { 0, NULL }
};

static value_string_ext e2ap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(e2ap_ProcedureCode_vals);


static int
dissect_e2ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &e2ap_data->procedure_code, false);

  //col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s", val_to_str(e2ap_data->procedure_code, e2ap_ProcedureCode_vals, "Unknown"));

  return offset;
}


static const value_string e2ap_ProtocolIE_ID_vals[] = {
  { id_Cause, "id-Cause" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_GlobalE2node_ID, "id-GlobalE2node-ID" },
  { id_GlobalRIC_ID, "id-GlobalRIC-ID" },
  { id_RANfunctionID, "id-RANfunctionID" },
  { id_RANfunctionID_Item, "id-RANfunctionID-Item" },
  { id_RANfunctionIEcause_Item, "id-RANfunctionIEcause-Item" },
  { id_RANfunction_Item, "id-RANfunction-Item" },
  { id_RANfunctionsAccepted, "id-RANfunctionsAccepted" },
  { id_RANfunctionsAdded, "id-RANfunctionsAdded" },
  { id_RANfunctionsDeleted, "id-RANfunctionsDeleted" },
  { id_RANfunctionsModified, "id-RANfunctionsModified" },
  { id_RANfunctionsRejected, "id-RANfunctionsRejected" },
  { id_RICaction_Admitted_Item, "id-RICaction-Admitted-Item" },
  { id_RICactionID, "id-RICactionID" },
  { id_RICaction_NotAdmitted_Item, "id-RICaction-NotAdmitted-Item" },
  { id_RICactions_Admitted, "id-RICactions-Admitted" },
  { id_RICactions_NotAdmitted, "id-RICactions-NotAdmitted" },
  { id_RICaction_ToBeSetup_Item, "id-RICaction-ToBeSetup-Item" },
  { id_RICcallProcessID, "id-RICcallProcessID" },
  { id_RICcontrolAckRequest, "id-RICcontrolAckRequest" },
  { id_RICcontrolHeader, "id-RICcontrolHeader" },
  { id_RICcontrolMessage, "id-RICcontrolMessage" },
  { id_RICcontrolStatus, "id-RICcontrolStatus" },
  { id_RICindicationHeader, "id-RICindicationHeader" },
  { id_RICindicationMessage, "id-RICindicationMessage" },
  { id_RICindicationSN, "id-RICindicationSN" },
  { id_RICindicationType, "id-RICindicationType" },
  { id_RICrequestID, "id-RICrequestID" },
  { id_RICsubscriptionDetails, "id-RICsubscriptionDetails" },
  { id_TimeToWait, "id-TimeToWait" },
  { id_RICcontrolOutcome, "id-RICcontrolOutcome" },
  { id_E2nodeComponentConfigUpdate, "id-E2nodeComponentConfigUpdate" },
  { id_E2nodeComponentConfigUpdate_Item, "id-E2nodeComponentConfigUpdate-Item" },
  { id_E2nodeComponentConfigUpdateAck, "id-E2nodeComponentConfigUpdateAck" },
  { id_E2nodeComponentConfigUpdateAck_Item, "id-E2nodeComponentConfigUpdateAck-Item" },
  { id_E2connectionSetup, "id-E2connectionSetup" },
  { id_E2connectionSetupFailed, "id-E2connectionSetupFailed" },
  { id_E2connectionSetupFailed_Item, "id-E2connectionSetupFailed-Item" },
  { id_E2connectionFailed_Item, "id-E2connectionFailed-Item" },
  { id_E2connectionUpdate_Item, "id-E2connectionUpdate-Item" },
  { id_E2connectionUpdateAdd, "id-E2connectionUpdateAdd" },
  { id_E2connectionUpdateModify, "id-E2connectionUpdateModify" },
  { id_E2connectionUpdateRemove, "id-E2connectionUpdateRemove" },
  { id_E2connectionUpdateRemove_Item, "id-E2connectionUpdateRemove-Item" },
  { id_TNLinformation, "id-TNLinformation" },
  { id_TransactionID, "id-TransactionID" },
  { id_E2nodeComponentConfigAddition, "id-E2nodeComponentConfigAddition" },
  { id_E2nodeComponentConfigAddition_Item, "id-E2nodeComponentConfigAddition-Item" },
  { id_E2nodeComponentConfigAdditionAck, "id-E2nodeComponentConfigAdditionAck" },
  { id_E2nodeComponentConfigAdditionAck_Item, "id-E2nodeComponentConfigAdditionAck-Item" },
  { id_E2nodeComponentConfigRemoval, "id-E2nodeComponentConfigRemoval" },
  { id_E2nodeComponentConfigRemoval_Item, "id-E2nodeComponentConfigRemoval-Item" },
  { id_E2nodeComponentConfigRemovalAck, "id-E2nodeComponentConfigRemovalAck" },
  { id_E2nodeComponentConfigRemovalAck_Item, "id-E2nodeComponentConfigRemovalAck-Item" },
  { id_E2nodeTNLassociationRemoval, "id-E2nodeTNLassociationRemoval" },
  { id_E2nodeTNLassociationRemoval_Item, "id-E2nodeTNLassociationRemoval-Item" },
  { id_RICsubscriptionToBeRemoved, "id-RICsubscriptionToBeRemoved" },
  { id_RICsubscription_withCause_Item, "id-RICsubscription-withCause-Item" },
  { id_RICsubscriptionStartTime, "id-RICsubscriptionStartTime" },
  { id_RICsubscriptionEndTime, "id-RICsubscriptionEndTime" },
  { id_RICeventTriggerDefinitionToBeModified, "id-RICeventTriggerDefinitionToBeModified" },
  { id_RICactionsToBeRemovedForModification_List, "id-RICactionsToBeRemovedForModification-List" },
  { id_RICaction_ToBeRemovedForModification_Item, "id-RICaction-ToBeRemovedForModification-Item" },
  { id_RICactionsToBeModifiedForModification_List, "id-RICactionsToBeModifiedForModification-List" },
  { id_RICaction_ToBeModifiedForModification_Item, "id-RICaction-ToBeModifiedForModification-Item" },
  { id_RICactionsToBeAddedForModification_List, "id-RICactionsToBeAddedForModification-List" },
  { id_RICaction_ToBeAddedForModification_Item, "id-RICaction-ToBeAddedForModification-Item" },
  { id_RICactionsRemovedForModification_List, "id-RICactionsRemovedForModification-List" },
  { id_RICaction_RemovedForModification_Item, "id-RICaction-RemovedForModification-Item" },
  { id_RICactionsFailedToBeRemovedForModification_List, "id-RICactionsFailedToBeRemovedForModification-List" },
  { id_RICaction_FailedToBeRemovedForModification_Item, "id-RICaction-FailedToBeRemovedForModification-Item" },
  { id_RICactionsModifiedForModification_List, "id-RICactionsModifiedForModification-List" },
  { id_RICaction_ModifiedForModification_Item, "id-RICaction-ModifiedForModification-Item" },
  { id_RICactionsFailedToBeModifiedForModification_List, "id-RICactionsFailedToBeModifiedForModification-List" },
  { id_RICaction_FailedToBeModifiedForModification_Item, "id-RICaction-FailedToBeModifiedForModification-Item" },
  { id_RICactionsAddedForModification_List, "id-RICactionsAddedForModification-List" },
  { id_RICaction_AddedForModification_Item, "id-RICaction-AddedForModification-Item" },
  { id_RICactionsFailedToBeAddedForModification_List, "id-RICactionsFailedToBeAddedForModification-List" },
  { id_RICaction_FailedToBeAddedForModification_Item, "id-RICaction-FailedToBeAddedForModification-Item" },
  { id_RICactionsRequiredToBeModified_List, "id-RICactionsRequiredToBeModified-List" },
  { id_RICaction_RequiredToBeModified_Item, "id-RICaction-RequiredToBeModified-Item" },
  { id_RICactionsRequiredToBeRemoved_List, "id-RICactionsRequiredToBeRemoved-List" },
  { id_RICaction_RequiredToBeRemoved_Item, "id-RICaction-RequiredToBeRemoved-Item" },
  { id_RICactionsConfirmedForModification_List, "id-RICactionsConfirmedForModification-List" },
  { id_RICaction_ConfirmedForModification_Item, "id-RICaction-ConfirmedForModification-Item" },
  { id_RICactionsRefusedToBeModified_List, "id-RICactionsRefusedToBeModified-List" },
  { id_RICaction_RefusedToBeModified_Item, "id-RICaction-RefusedToBeModified-Item" },
  { id_RICactionsConfirmedForRemoval_List, "id-RICactionsConfirmedForRemoval-List" },
  { id_RICaction_ConfirmedForRemoval_Item, "id-RICaction-ConfirmedForRemoval-Item" },
  { id_RICactionsRefusedToBeRemoved_List, "id-RICactionsRefusedToBeRemoved-List" },
  { id_RICaction_RefusedToBeRemoved_Item, "id-RICaction-RefusedToBeRemoved-Item" },
  { id_RICqueryHeader, "id-RICqueryHeader" },
  { id_RICqueryDefinition, "id-RICqueryDefinition" },
  { id_RICqueryOutcome, "id-RICqueryOutcome" },
  { 0, NULL }
};

static value_string_ext e2ap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(e2ap_ProtocolIE_ID_vals);


static int
dissect_e2ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &e2ap_data->protocol_ie_id, false);



  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s",
                           val_to_str_ext(e2ap_data->protocol_ie_id, &e2ap_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }
  return offset;
}


static const value_string e2ap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessfull-outcome" },
  { 0, NULL }
};


static int
dissect_e2ap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_e2ap_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_e2ap_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_ID },
  { &hf_e2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_Criticality },
  { &hf_e2ap_value          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_e2ap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Field },
};

static int
dissect_e2ap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, false);

  return offset;
}



static int
dissect_e2ap_ProtocolIE_SingleContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_e2ap_AMFName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}


static const value_string e2ap_CauseRICrequest_vals[] = {
  {   0, "ran-function-id-invalid" },
  {   1, "action-not-supported" },
  {   2, "excessive-actions" },
  {   3, "duplicate-action" },
  {   4, "duplicate-event-trigger" },
  {   5, "function-resource-limit" },
  {   6, "request-id-unknown" },
  {   7, "inconsistent-action-subsequent-action-sequence" },
  {   8, "control-message-invalid" },
  {   9, "ric-call-process-id-invalid" },
  {  10, "control-timer-expired" },
  {  11, "control-failed-to-execute" },
  {  12, "system-not-ready" },
  {  13, "unspecified" },
  {  14, "ric-subscription-end-time-expired" },
  {  15, "ric-subscription-end-time-invalid" },
  {  16, "duplicate-ric-request-id" },
  {  17, "eventTriggerNotSupported" },
  {  18, "requested-information-unavailable" },
  {  19, "invalid-information-request" },
  { 0, NULL }
};


static int
dissect_e2ap_CauseRICrequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, true, 6, NULL);

  return offset;
}


static const value_string e2ap_CauseRICservice_vals[] = {
  {   0, "ran-function-not-supported" },
  {   1, "excessive-functions" },
  {   2, "ric-resource-limit" },
  { 0, NULL }
};


static int
dissect_e2ap_CauseRICservice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_CauseE2node_vals[] = {
  {   0, "e2node-component-unknown" },
  { 0, NULL }
};


static int
dissect_e2ap_CauseE2node(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_CauseTransport_vals[] = {
  {   0, "unspecified" },
  {   1, "transport-resource-unavailable" },
  { 0, NULL }
};


static int
dissect_e2ap_CauseTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_CauseProtocol_vals[] = {
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
dissect_e2ap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_CauseMisc_vals[] = {
  {   0, "control-processing-overload" },
  {   1, "hardware-failure" },
  {   2, "om-intervention" },
  {   3, "unspecified" },
  { 0, NULL }
};


static int
dissect_e2ap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_Cause_vals[] = {
  {   0, "ricRequest" },
  {   1, "ricService" },
  {   2, "e2Node" },
  {   3, "transport" },
  {   4, "protocol" },
  {   5, "misc" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_e2ap_ricRequest     , ASN1_EXTENSION_ROOT    , dissect_e2ap_CauseRICrequest },
  {   1, &hf_e2ap_ricService     , ASN1_EXTENSION_ROOT    , dissect_e2ap_CauseRICservice },
  {   2, &hf_e2ap_e2Node         , ASN1_EXTENSION_ROOT    , dissect_e2ap_CauseE2node },
  {   3, &hf_e2ap_transport      , ASN1_EXTENSION_ROOT    , dissect_e2ap_CauseTransport },
  {   4, &hf_e2ap_protocol       , ASN1_EXTENSION_ROOT    , dissect_e2ap_CauseProtocol },
  {   5, &hf_e2ap_misc           , ASN1_EXTENSION_ROOT    , dissect_e2ap_CauseMisc },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_Cause, Cause_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const per_sequence_t RICrequestID_sequence[] = {
  { &hf_e2ap_ricRequestorID_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_0_65535 },
  { &hf_e2ap_ricInstanceID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICrequestID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICrequestID, RICrequestID_sequence);

  return offset;
}


static const value_string e2ap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_e2ap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_Item_sequence[] = {
  { &hf_e2ap_iECriticality  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_Criticality },
  { &hf_e2ap_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_ID },
  { &hf_e2ap_typeOfError    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_TypeOfError },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_CriticalityDiagnostics_IE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_CriticalityDiagnostics_IE_Item, CriticalityDiagnostics_IE_Item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_e2ap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_CriticalityDiagnostics_IE_Item },
};

static int
dissect_e2ap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxnoofErrors, false);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_e2ap_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_ProcedureCode },
  { &hf_e2ap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_TriggeringMessage },
  { &hf_e2ap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_Criticality },
  { &hf_e2ap_ricRequestorID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RICrequestID },
  { &hf_e2ap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_CriticalityDiagnostics_IE_List },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_e2ap_T_e2nodeComponentRequestPart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *value_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &value_tvb);

  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  if (e2ap_data->component_configuration_dissector) {
    col_append_str(actx->pinfo->cinfo, COL_PROTOCOL, "|");
    col_set_fence(actx->pinfo->cinfo, COL_PROTOCOL);
    col_set_writable(actx->pinfo->cinfo, COL_INFO, false);
    call_dissector(e2ap_data->component_configuration_dissector, value_tvb, actx->pinfo, tree);
    col_set_writable(actx->pinfo->cinfo, COL_INFO, true);
  }


  return offset;
}



static int
dissect_e2ap_T_e2nodeComponentResponsePart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *value_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &value_tvb);

  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  if (e2ap_data->component_configuration_dissector) {
    col_set_writable(actx->pinfo->cinfo, COL_INFO, false);
    call_dissector(e2ap_data->component_configuration_dissector, value_tvb, actx->pinfo, tree);
    col_set_writable(actx->pinfo->cinfo, COL_INFO, true);
  }



  return offset;
}


static const per_sequence_t E2nodeComponentConfiguration_sequence[] = {
  { &hf_e2ap_e2nodeComponentRequestPart, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_e2nodeComponentRequestPart },
  { &hf_e2ap_e2nodeComponentResponsePart, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_e2nodeComponentResponsePart },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentConfiguration, E2nodeComponentConfiguration_sequence);

  return offset;
}


static const value_string e2ap_T_updateOutcome_vals[] = {
  {   0, "success" },
  {   1, "failure" },
  { 0, NULL }
};


static int
dissect_e2ap_T_updateOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t E2nodeComponentConfigurationAck_sequence[] = {
  { &hf_e2ap_updateOutcome  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_updateOutcome },
  { &hf_e2ap_failureCause   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_Cause },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentConfigurationAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentConfigurationAck, E2nodeComponentConfigurationAck_sequence);

  return offset;
}


static const value_string e2ap_E2nodeComponentInterfaceType_vals[] = {
  {   0, "ng" },
  {   1, "xn" },
  {   2, "e1" },
  {   3, "f1" },
  {   4, "w1" },
  {   5, "s1" },
  {   6, "x2" },
  { 0, NULL }
};


static int
dissect_e2ap_E2nodeComponentInterfaceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t E2nodeComponentInterfaceNG_sequence[] = {
  { &hf_e2ap_amf_name       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_AMFName },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentInterfaceNG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentInterfaceNG, E2nodeComponentInterfaceNG_sequence);

  return offset;
}



static int
dissect_e2ap_T_e2nodeComponentInterfaceTypeNG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_E2nodeComponentInterfaceNG(tvb, offset, actx, tree, hf_index);

  /* Store value in packet-private data */
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  e2ap_data->component_configuration_dissector = find_dissector("ngap");


  return offset;
}



static int
dissect_e2ap_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}



static int
dissect_e2ap_BIT_STRING_SIZE_22_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     22, 32, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string e2ap_GNB_ID_Choice_vals[] = {
  {   0, "gnb-ID" },
  { 0, NULL }
};

static const per_choice_t GNB_ID_Choice_choice[] = {
  {   0, &hf_e2ap_gnb_ID         , ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING_SIZE_22_32 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_GNB_ID_Choice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_GNB_ID_Choice, GNB_ID_Choice_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_T_gnb_id(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int start_offset = offset;
  offset = dissect_e2ap_GNB_ID_Choice(tvb, offset, actx, tree, hf_index);

  /* Store value in packet-private data */
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  /* Limit length, but really can't be > 5 bytes.. */
  e2ap_data->gnb_id_len = MIN((offset-start_offset)/8, MAX_GNB_ID_BYTES);
  tvb_memcpy(tvb, &e2ap_data->gnb_id_bytes, start_offset/8, e2ap_data->gnb_id_len);
  update_conversation_from_gnb_id(actx);




  return offset;
}


static const per_sequence_t GlobalgNB_ID_sequence[] = {
  { &hf_e2ap_plmn_id        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMN_Identity },
  { &hf_e2ap_gnb_id         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_gnb_id },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalgNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalgNB_ID, GlobalgNB_ID_sequence);

  return offset;
}



static int
dissect_e2ap_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e2ap_BIT_STRING_SIZE_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     18, 18, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e2ap_BIT_STRING_SIZE_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     21, 21, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string e2ap_ENB_ID_Choice_vals[] = {
  {   0, "enb-ID-macro" },
  {   1, "enb-ID-shortmacro" },
  {   2, "enb-ID-longmacro" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_Choice_choice[] = {
  {   0, &hf_e2ap_enb_ID_macro   , ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING_SIZE_20 },
  {   1, &hf_e2ap_enb_ID_shortmacro, ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING_SIZE_18 },
  {   2, &hf_e2ap_enb_ID_longmacro, ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING_SIZE_21 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_ENB_ID_Choice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_ENB_ID_Choice, ENB_ID_Choice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalngeNB_ID_sequence[] = {
  { &hf_e2ap_plmn_id        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMN_Identity },
  { &hf_e2ap_enb_id         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ENB_ID_Choice },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalngeNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalngeNB_ID, GlobalngeNB_ID_sequence);

  return offset;
}


static const value_string e2ap_GlobalNG_RANNode_ID_vals[] = {
  {   0, "gNB" },
  {   1, "ng-eNB" },
  { 0, NULL }
};

static const per_choice_t GlobalNG_RANNode_ID_choice[] = {
  {   0, &hf_e2ap_gNB_01         , ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalgNB_ID },
  {   1, &hf_e2ap_ng_eNB_01      , ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalngeNB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_GlobalNG_RANNode_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_GlobalNG_RANNode_ID, GlobalNG_RANNode_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2nodeComponentInterfaceXn_sequence[] = {
  { &hf_e2ap_global_NG_RAN_Node_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalNG_RANNode_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentInterfaceXn(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentInterfaceXn, E2nodeComponentInterfaceXn_sequence);

  return offset;
}



static int
dissect_e2ap_T_e2nodeComponentInterfaceTypeXn(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_E2nodeComponentInterfaceXn(tvb, offset, actx, tree, hf_index);

  /* Store value in packet-private data */
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  e2ap_data->component_configuration_dissector = find_dissector("xnap");


  return offset;
}



static int
dissect_e2ap_GNB_CU_UP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(68719476735), NULL, false);

  return offset;
}


static const per_sequence_t E2nodeComponentInterfaceE1_sequence[] = {
  { &hf_e2ap_gNB_CU_UP_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GNB_CU_UP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentInterfaceE1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentInterfaceE1, E2nodeComponentInterfaceE1_sequence);

  return offset;
}



static int
dissect_e2ap_T_e2nodeComponentInterfaceTypeE1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_E2nodeComponentInterfaceE1(tvb, offset, actx, tree, hf_index);

  /* Store value in packet-private data */
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  e2ap_data->component_configuration_dissector = find_dissector("e1ap");


  return offset;
}



static int
dissect_e2ap_GNB_DU_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(68719476735), NULL, false);

  return offset;
}


static const per_sequence_t E2nodeComponentInterfaceF1_sequence[] = {
  { &hf_e2ap_gNB_DU_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GNB_DU_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentInterfaceF1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentInterfaceF1, E2nodeComponentInterfaceF1_sequence);

  return offset;
}



static int
dissect_e2ap_T_e2nodeComponentInterfaceTypeF1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_E2nodeComponentInterfaceF1(tvb, offset, actx, tree, hf_index);

  /* Store value in packet-private data */
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  e2ap_data->component_configuration_dissector = find_dissector("f1ap");



  return offset;
}



static int
dissect_e2ap_NGENB_DU_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(68719476735), NULL, false);

  return offset;
}


static const per_sequence_t E2nodeComponentInterfaceW1_sequence[] = {
  { &hf_e2ap_ng_eNB_DU_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NGENB_DU_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentInterfaceW1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentInterfaceW1, E2nodeComponentInterfaceW1_sequence);

  return offset;
}



static int
dissect_e2ap_MMEname(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}


static const per_sequence_t E2nodeComponentInterfaceS1_sequence[] = {
  { &hf_e2ap_mme_name       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MMEname },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentInterfaceS1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentInterfaceS1, E2nodeComponentInterfaceS1_sequence);

  return offset;
}



static int
dissect_e2ap_T_e2nodeComponentInterfaceTypeS1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_E2nodeComponentInterfaceS1(tvb, offset, actx, tree, hf_index);

  /* Store value in packet-private data */
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  e2ap_data->component_configuration_dissector = find_dissector("s1ap");


  return offset;
}



static int
dissect_e2ap_BIT_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string e2ap_ENB_ID_vals[] = {
  {   0, "macro-eNB-ID" },
  {   1, "home-eNB-ID" },
  {   2, "short-Macro-eNB-ID" },
  {   3, "long-Macro-eNB-ID" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_choice[] = {
  {   0, &hf_e2ap_macro_eNB_ID   , ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING_SIZE_20 },
  {   1, &hf_e2ap_home_eNB_ID    , ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING_SIZE_28 },
  {   2, &hf_e2ap_short_Macro_eNB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_BIT_STRING_SIZE_18 },
  {   3, &hf_e2ap_long_Macro_eNB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_BIT_STRING_SIZE_21 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_ENB_ID, ENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalENB_ID_sequence[] = {
  { &hf_e2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMN_Identity },
  { &hf_e2ap_eNB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ENB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalENB_ID, GlobalENB_ID_sequence);

  return offset;
}


static const value_string e2ap_ENGNB_ID_vals[] = {
  {   0, "gNB-ID" },
  { 0, NULL }
};

static const per_choice_t ENGNB_ID_choice[] = {
  {   0, &hf_e2ap_gNB_ID         , ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING_SIZE_22_32 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_ENGNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_ENGNB_ID, ENGNB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalenGNB_ID_sequence[] = {
  { &hf_e2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMN_Identity },
  { &hf_e2ap_gNB_ID_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ENGNB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalenGNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalenGNB_ID, GlobalenGNB_ID_sequence);

  return offset;
}


static const per_sequence_t E2nodeComponentInterfaceX2_sequence[] = {
  { &hf_e2ap_global_eNB_ID  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GlobalENB_ID },
  { &hf_e2ap_global_en_gNB_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GlobalenGNB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentInterfaceX2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentInterfaceX2, E2nodeComponentInterfaceX2_sequence);

  return offset;
}



static int
dissect_e2ap_T_e2nodeComponentInterfaceTypeX2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_E2nodeComponentInterfaceX2(tvb, offset, actx, tree, hf_index);

  /* Store value in packet-private data */
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  e2ap_data->component_configuration_dissector = find_dissector("x2ap");





  return offset;
}


static const value_string e2ap_E2nodeComponentID_vals[] = {
  {   0, "e2nodeComponentInterfaceTypeNG" },
  {   1, "e2nodeComponentInterfaceTypeXn" },
  {   2, "e2nodeComponentInterfaceTypeE1" },
  {   3, "e2nodeComponentInterfaceTypeF1" },
  {   4, "e2nodeComponentInterfaceTypeW1" },
  {   5, "e2nodeComponentInterfaceTypeS1" },
  {   6, "e2nodeComponentInterfaceTypeX2" },
  { 0, NULL }
};

static const per_choice_t E2nodeComponentID_choice[] = {
  {   0, &hf_e2ap_e2nodeComponentInterfaceTypeNG, ASN1_EXTENSION_ROOT    , dissect_e2ap_T_e2nodeComponentInterfaceTypeNG },
  {   1, &hf_e2ap_e2nodeComponentInterfaceTypeXn, ASN1_EXTENSION_ROOT    , dissect_e2ap_T_e2nodeComponentInterfaceTypeXn },
  {   2, &hf_e2ap_e2nodeComponentInterfaceTypeE1, ASN1_EXTENSION_ROOT    , dissect_e2ap_T_e2nodeComponentInterfaceTypeE1 },
  {   3, &hf_e2ap_e2nodeComponentInterfaceTypeF1, ASN1_EXTENSION_ROOT    , dissect_e2ap_T_e2nodeComponentInterfaceTypeF1 },
  {   4, &hf_e2ap_e2nodeComponentInterfaceTypeW1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2nodeComponentInterfaceW1 },
  {   5, &hf_e2ap_e2nodeComponentInterfaceTypeS1, ASN1_EXTENSION_ROOT    , dissect_e2ap_T_e2nodeComponentInterfaceTypeS1 },
  {   6, &hf_e2ap_e2nodeComponentInterfaceTypeX2, ASN1_EXTENSION_ROOT    , dissect_e2ap_T_e2nodeComponentInterfaceTypeX2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_E2nodeComponentID, E2nodeComponentID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalE2node_gNB_ID_sequence[] = {
  { &hf_e2ap_global_gNB_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalgNB_ID },
  { &hf_e2ap_global_en_gNB_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GlobalenGNB_ID },
  { &hf_e2ap_gNB_CU_UP_ID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GNB_CU_UP_ID },
  { &hf_e2ap_gNB_DU_ID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GNB_DU_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalE2node_gNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalE2node_gNB_ID, GlobalE2node_gNB_ID_sequence);

  return offset;
}


static const per_sequence_t GlobalE2node_en_gNB_ID_sequence[] = {
  { &hf_e2ap_global_en_gNB_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalenGNB_ID },
  { &hf_e2ap_en_gNB_CU_UP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GNB_CU_UP_ID },
  { &hf_e2ap_en_gNB_DU_ID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GNB_DU_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalE2node_en_gNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalE2node_en_gNB_ID, GlobalE2node_en_gNB_ID_sequence);

  return offset;
}


static const per_sequence_t GlobalE2node_ng_eNB_ID_sequence[] = {
  { &hf_e2ap_global_ng_eNB_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalngeNB_ID },
  { &hf_e2ap_global_eNB_ID  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GlobalENB_ID },
  { &hf_e2ap_ngENB_DU_ID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_NGENB_DU_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalE2node_ng_eNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalE2node_ng_eNB_ID, GlobalE2node_ng_eNB_ID_sequence);

  return offset;
}


static const per_sequence_t GlobalE2node_eNB_ID_sequence[] = {
  { &hf_e2ap_global_eNB_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalENB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalE2node_eNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalE2node_eNB_ID, GlobalE2node_eNB_ID_sequence);

  return offset;
}


static const value_string e2ap_GlobalE2node_ID_vals[] = {
  {   0, "gNB" },
  {   1, "en-gNB" },
  {   2, "ng-eNB" },
  {   3, "eNB" },
  { 0, NULL }
};

static const per_choice_t GlobalE2node_ID_choice[] = {
  {   0, &hf_e2ap_gNB            , ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalE2node_gNB_ID },
  {   1, &hf_e2ap_en_gNB         , ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalE2node_en_gNB_ID },
  {   2, &hf_e2ap_ng_eNB         , ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalE2node_ng_eNB_ID },
  {   3, &hf_e2ap_eNB            , ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalE2node_eNB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_GlobalE2node_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_GlobalE2node_ID, GlobalE2node_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalRIC_ID_sequence[] = {
  { &hf_e2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMN_Identity },
  { &hf_e2ap_ric_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_BIT_STRING_SIZE_20 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalRIC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalRIC_ID, GlobalRIC_ID_sequence);

  return offset;
}



static int
dissect_e2ap_RANfunctionDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;

  /* We know that the next thing is a RANFunction-Name, but it's wrapped up in a sequence,
     so can't silently/hiddenly call ranFunctionName here... */

    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);


  /* Looking for shortName string near beginning of tvb */
  bool found = false;
  /* For each RAN function name.. */
  int n, found_index;
  for (n=KPM_RANFUNCTIONS; n<MAX_RANFUNCTIONS && !found; n++) {
    uint32_t tvb_len = tvb_captured_length(parameter_tvb);
    unsigned name_len = (int)strlen(g_ran_function_name_table[n]);
    /* For each of several byte positions.. */
    for (int m=0; (m<30) && ((m+name_len+1))<tvb_len; m++) {
      /* Have we found a match on the name? */
      if (tvb_strneql(parameter_tvb, m, g_ran_function_name_table[n], name_len) == 0) {
        /* We don't yet know the OID (should be OK),
           so for now just call with the first/only available dissector for this RAN Function name */
        if (g_ran_functions_available_dissectors[n].num_available_dissectors) {
          g_ran_functions_available_dissectors[n].ran_function_dissectors[0]->functions.ran_function_definition_dissector(parameter_tvb, actx->pinfo, tree, NULL);
          found = true;
          found_index = n;
          break;
        }
      }
    }
  }

  if (found && (found_index==CCC_RANFUNCTIONS)) {
    // ranFunctionName, for this ranFunction, is inside the JSON.  Rather than try to retrive it,
    // just use this proxy that ought to appear at the start...  OID should get set in the normal way.
    if (!actx->pinfo->fd->visited) {
      e2ap_store_ran_function_mapping(actx->pinfo, tree, parameter_tvb, "{" /*"ORAN-E2SM-CCC"*/);
    }
  }

  if (!found) {
    proto_item *ti = proto_tree_add_item(tree, hf_e2ap_ran_function_name_not_recognised, tvb, 0, 0, ENC_NA);
    expert_add_info_format(actx->pinfo, ti, &ei_e2ap_ran_function_names_no_match,
                           "ShortName does not match any known Service Model");
  }


  return offset;
}



static int
dissect_e2ap_RANfunctionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t value;
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, &value, false);

  /* Store value in packet-private data */
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  e2ap_data->ran_function_id = value;



  return offset;
}



static int
dissect_e2ap_RANfunctionOID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 1000, true,
                                          &parameter_tvb);

  /* Now complete mapping with OID string */
  e2ap_update_ran_function_mapping(actx->pinfo, tree, parameter_tvb,
                                   tvb_get_string_enc(actx->pinfo->pool, parameter_tvb, 0,
                                   tvb_captured_length(parameter_tvb), ENC_ASCII));





  return offset;
}



static int
dissect_e2ap_RANfunctionRevision(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}



static int
dissect_e2ap_RICactionDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);

  ran_function_dissector_t* dissector = lookup_ranfunction_dissector(actx->pinfo, tree, parameter_tvb);
  if (dissector) {
    if (dissector->functions.ran_action_definition_dissector) {
      dissector->functions.ran_action_definition_dissector(parameter_tvb, actx->pinfo, tree, NULL);
    }
  }


  return offset;
}



static int
dissect_e2ap_RICactionExecutionOrder(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, true);

  return offset;
}



static int
dissect_e2ap_RICactionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const value_string e2ap_RICactionType_vals[] = {
  {   0, "report" },
  {   1, "insert" },
  {   2, "policy" },
  { 0, NULL }
};


static int
dissect_e2ap_RICactionType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e2ap_RICcallProcessID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);

  ran_function_dissector_t* dissector = lookup_ranfunction_dissector(actx->pinfo, tree, parameter_tvb);
  if (dissector) {
    if (dissector->functions.ran_callprocessid_dissector) {
      dissector->functions.ran_callprocessid_dissector(parameter_tvb, actx->pinfo, tree, NULL);
    }
  }




  return offset;
}


static const value_string e2ap_RICcontrolAckRequest_vals[] = {
  {   0, "noAck" },
  {   1, "ack" },
  { 0, NULL }
};


static int
dissect_e2ap_RICcontrolAckRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e2ap_RICcontrolHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);

  ran_function_dissector_t* dissector = lookup_ranfunction_dissector(actx->pinfo, tree, parameter_tvb);
  if (dissector) {
    if (dissector->functions.ric_control_header_dissector) {
      dissector->functions.ric_control_header_dissector(parameter_tvb, actx->pinfo, tree, NULL);
    }
  }


  return offset;
}



static int
dissect_e2ap_RICcontrolMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);

  ran_function_dissector_t* dissector = lookup_ranfunction_dissector(actx->pinfo, tree, parameter_tvb);
  if (dissector) {
    if (dissector->functions.ric_control_message_dissector) {
      dissector->functions.ric_control_message_dissector(parameter_tvb, actx->pinfo, tree, NULL);
    }
  }


  return offset;
}



static int
dissect_e2ap_RICcontrolOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);

  ran_function_dissector_t* dissector = lookup_ranfunction_dissector(actx->pinfo, tree, parameter_tvb);
  if (dissector) {
    if (dissector->functions.ric_control_outcome_dissector) {
        dissector->functions.ric_control_outcome_dissector(parameter_tvb, actx->pinfo, tree, NULL);
    }
  }


  return offset;
}



static int
dissect_e2ap_RICeventTriggerDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);

  ran_function_dissector_t* dissector = lookup_ranfunction_dissector(actx->pinfo, tree, parameter_tvb);
  if (dissector) {
    if (dissector->functions.ran_event_trigger_dissector) {
      dissector->functions.ran_event_trigger_dissector(parameter_tvb, actx->pinfo, tree, NULL);
    }
  }


  return offset;
}



static int
dissect_e2ap_RICindicationHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);

  ran_function_dissector_t* dissector = lookup_ranfunction_dissector(actx->pinfo, tree, parameter_tvb);
  if (dissector) {
    if (dissector->functions.ran_indication_header_dissector) {
      dissector->functions.ran_indication_header_dissector(parameter_tvb, actx->pinfo, tree, NULL);
    }
  }


  return offset;
}



static int
dissect_e2ap_RICindicationMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);

  ran_function_dissector_t* dissector = lookup_ranfunction_dissector(actx->pinfo, tree, parameter_tvb);
  if (dissector) {
    if (dissector->functions.ran_indication_message_dissector) {
      dissector->functions.ran_indication_message_dissector(parameter_tvb, actx->pinfo, tree, NULL);
    }
  }


  return offset;
}



static int
dissect_e2ap_RICindicationSN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const value_string e2ap_RICindicationType_vals[] = {
  {   0, "report" },
  {   1, "insert" },
  { 0, NULL }
};


static int
dissect_e2ap_RICindicationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e2ap_RICsubscriptionTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}


static const value_string e2ap_RICsubsequentActionType_vals[] = {
  {   0, "continue" },
  {   1, "wait" },
  { 0, NULL }
};


static int
dissect_e2ap_RICsubsequentActionType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_RICtimeToWait_vals[] = {
  {   0, "w1ms" },
  {   1, "w2ms" },
  {   2, "w5ms" },
  {   3, "w10ms" },
  {   4, "w20ms" },
  {   5, "w30ms" },
  {   6, "w40ms" },
  {   7, "w50ms" },
  {   8, "w100ms" },
  {   9, "w200ms" },
  {  10, "w500ms" },
  {  11, "w1s" },
  {  12, "w2s" },
  {  13, "w5s" },
  {  14, "w10s" },
  {  15, "w20s" },
  {  16, "w60s" },
  { 0, NULL }
};


static int
dissect_e2ap_RICtimeToWait(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     17, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t RICsubsequentAction_sequence[] = {
  { &hf_e2ap_ricSubsequentActionType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICsubsequentActionType },
  { &hf_e2ap_ricTimeToWait  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICtimeToWait },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubsequentAction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubsequentAction, RICsubsequentAction_sequence);

  return offset;
}



static int
dissect_e2ap_RICqueryHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);

  ran_function_dissector_t* dissector = lookup_ranfunction_dissector(actx->pinfo, tree, parameter_tvb);
  if (dissector) {
    if (dissector->functions.ric_query_header_dissector) {
      dissector->functions.ric_query_header_dissector(parameter_tvb, actx->pinfo, tree, NULL);
    }
  }




  return offset;
}



static int
dissect_e2ap_RICqueryDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);

  ran_function_dissector_t* dissector = lookup_ranfunction_dissector(actx->pinfo, tree, parameter_tvb);
  if (dissector) {
    if (dissector->functions.ric_query_definition_dissector) {
      dissector->functions.ric_query_definition_dissector(parameter_tvb, actx->pinfo, tree, NULL);
    }
  }


  return offset;
}



static int
dissect_e2ap_RICqueryOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);

  ran_function_dissector_t* dissector = lookup_ranfunction_dissector(actx->pinfo, tree, parameter_tvb);
  if (dissector) {
    if (dissector->functions.ric_query_outcome_dissector) {
      dissector->functions.ric_query_outcome_dissector(parameter_tvb, actx->pinfo, tree, NULL);
    }
  }


  return offset;
}


static const value_string e2ap_TimeToWait_vals[] = {
  {   0, "v1s" },
  {   1, "v2s" },
  {   2, "v5s" },
  {   3, "v10s" },
  {   4, "v20s" },
  {   5, "v60s" },
  { 0, NULL }
};


static int
dissect_e2ap_TimeToWait(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e2ap_T_tnlAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *value_tvb;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, true, NULL, 0, &value_tvb, NULL);

  if (tvb_captured_length(value_tvb)==4) {
    proto_item_append_text(tree, " (%s", tvb_ip_to_str(actx->pinfo->pool, value_tvb, 0));
  }
  else {
    proto_item_append_text(tree, " (%s", tvb_ip6_to_str(actx->pinfo->pool, value_tvb, 0));
  }


  return offset;
}



static int
dissect_e2ap_T_tnlPort(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  proto_item_append_text(tree, ":%u)", tvb_get_ntohs(tvb, offset/8));
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, NULL, NULL);




  return offset;
}


static const per_sequence_t TNLinformation_sequence[] = {
  { &hf_e2ap_tnlAddress     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_tnlAddress },
  { &hf_e2ap_tnlPort        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_T_tnlPort },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_TNLinformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_TNLinformation, TNLinformation_sequence);

  return offset;
}


static const value_string e2ap_TNLusage_vals[] = {
  {   0, "ric-service" },
  {   1, "support-function" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_e2ap_TNLusage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e2ap_TransactionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, true);

  return offset;
}


static const per_sequence_t RICsubscriptionRequest_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_SUBSCRIPTION_REQUEST);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_SUBSCRIPTION_REQUEST);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionRequest, RICsubscriptionRequest_sequence);

  return offset;
}


static const per_sequence_t RICactions_ToBeSetup_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_ToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_ToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_ToBeSetup_List, RICactions_ToBeSetup_List_sequence_of,
                                                  1, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICsubscriptionDetails_sequence[] = {
  { &hf_e2ap_ricEventTriggerDefinition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICeventTriggerDefinition },
  { &hf_e2ap_ricAction_ToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactions_ToBeSetup_List },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionDetails(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionDetails, RICsubscriptionDetails_sequence);

  return offset;
}


static const per_sequence_t RICaction_ToBeSetup_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { &hf_e2ap_ricActionType  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionType },
  { &hf_e2ap_ricActionDefinition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RICactionDefinition },
  { &hf_e2ap_ricSubsequentAction, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RICsubsequentAction },
  { &hf_e2ap_ricActionExecutionOrder, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RICactionExecutionOrder },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_ToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_ToBeSetup_Item, RICaction_ToBeSetup_Item_sequence);

  return offset;
}


static const per_sequence_t RICsubscriptionResponse_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_SUBSCRIPTION_RESPONSE);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_SUBSCRIPTION_RESPONSE);



  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionResponse, RICsubscriptionResponse_sequence);

  return offset;
}


static const per_sequence_t RICaction_Admitted_List_sequence_of[1] = {
  { &hf_e2ap_RICaction_Admitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICaction_Admitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICaction_Admitted_List, RICaction_Admitted_List_sequence_of,
                                                  1, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_Admitted_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_Admitted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_Admitted_Item, RICaction_Admitted_Item_sequence);

  return offset;
}


static const per_sequence_t RICaction_NotAdmitted_List_sequence_of[1] = {
  { &hf_e2ap_RICaction_NotAdmitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICaction_NotAdmitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICaction_NotAdmitted_List, RICaction_NotAdmitted_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_NotAdmitted_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { &hf_e2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_Cause },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_NotAdmitted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_NotAdmitted_Item, RICaction_NotAdmitted_Item_sequence);

  return offset;
}


static const per_sequence_t RICsubscriptionFailure_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_SUBSCRIPTION_FAIL);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_SUBSCRIPTION_FAIL);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionFailure, RICsubscriptionFailure_sequence);

  return offset;
}


static const per_sequence_t RICsubscriptionDeleteRequest_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionDeleteRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_SUBSCRIPTION_DELETE_REQUEST);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_SUBSCRIPTION_DELETE_REQUEST);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionDeleteRequest, RICsubscriptionDeleteRequest_sequence);

  return offset;
}


static const per_sequence_t RICsubscriptionDeleteResponse_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionDeleteResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_SUBSCRIPTION_DELETE_RESPONSE);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_SUBSCRIPTION_DELETE_RESPONSE);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionDeleteResponse, RICsubscriptionDeleteResponse_sequence);

  return offset;
}


static const per_sequence_t RICsubscriptionDeleteFailure_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionDeleteFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_SUBSCRIPTION_DELETE_FAIL);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_SUBSCRIPTION_DELETE_FAIL);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionDeleteFailure, RICsubscriptionDeleteFailure_sequence);

  return offset;
}


static const per_sequence_t RICsubscriptionDeleteRequired_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionDeleteRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_SUBSCRIPTION_DELETE_REQUIRED);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_SUBSCRIPTION_DELETE_REQUIRED);


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionDeleteRequired, RICsubscriptionDeleteRequired_sequence);

  return offset;
}


static const per_sequence_t RICsubscription_List_withCause_sequence_of[1] = {
  { &hf_e2ap_RICsubscription_List_withCause_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICsubscription_List_withCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICsubscription_List_withCause, RICsubscription_List_withCause_sequence_of,
                                                  1, maxofRICrequestID, false);

  return offset;
}


static const per_sequence_t RICsubscription_withCause_Item_sequence[] = {
  { &hf_e2ap_ricRequestID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICrequestID },
  { &hf_e2ap_ranFunctionID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunctionID },
  { &hf_e2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_Cause },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscription_withCause_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscription_withCause_Item, RICsubscription_withCause_Item_sequence);

  return offset;
}


static const per_sequence_t RICsubscriptionModificationRequest_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionModificationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionModificationRequest, RICsubscriptionModificationRequest_sequence);

  return offset;
}


static const per_sequence_t RICactions_ToBeRemovedForModification_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_ToBeRemovedForModification_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_ToBeRemovedForModification_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_ToBeRemovedForModification_List, RICactions_ToBeRemovedForModification_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_ToBeRemovedForModification_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_ToBeRemovedForModification_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_ToBeRemovedForModification_Item, RICaction_ToBeRemovedForModification_Item_sequence);

  return offset;
}


static const per_sequence_t RICactions_ToBeModifiedForModification_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_ToBeModifiedForModification_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_ToBeModifiedForModification_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_ToBeModifiedForModification_List, RICactions_ToBeModifiedForModification_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_ToBeModifiedForModification_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { &hf_e2ap_ricActionDefinition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RICactionDefinition },
  { &hf_e2ap_ricActionExecutionOrder, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RICactionExecutionOrder },
  { &hf_e2ap_ricSubsequentAction, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RICsubsequentAction },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_ToBeModifiedForModification_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_ToBeModifiedForModification_Item, RICaction_ToBeModifiedForModification_Item_sequence);

  return offset;
}


static const per_sequence_t RICactions_ToBeAddedForModification_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_ToBeAddedForModification_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_ToBeAddedForModification_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_ToBeAddedForModification_List, RICactions_ToBeAddedForModification_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_ToBeAddedForModification_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { &hf_e2ap_ricActionType  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionType },
  { &hf_e2ap_ricActionDefinition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionDefinition },
  { &hf_e2ap_ricActionExecutionOrder, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionExecutionOrder },
  { &hf_e2ap_ricSubsequentAction, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RICsubsequentAction },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_ToBeAddedForModification_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_ToBeAddedForModification_Item, RICaction_ToBeAddedForModification_Item_sequence);

  return offset;
}


static const per_sequence_t RICsubscriptionModificationResponse_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionModificationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionModificationResponse, RICsubscriptionModificationResponse_sequence);

  return offset;
}


static const per_sequence_t RICactions_RemovedForModification_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_RemovedForModification_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_RemovedForModification_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_RemovedForModification_List, RICactions_RemovedForModification_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_RemovedForModification_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_RemovedForModification_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_RemovedForModification_Item, RICaction_RemovedForModification_Item_sequence);

  return offset;
}


static const per_sequence_t RICactions_FailedToBeRemovedForModification_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_FailedToBeRemovedForModification_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_FailedToBeRemovedForModification_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_FailedToBeRemovedForModification_List, RICactions_FailedToBeRemovedForModification_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_FailedToBeRemovedForModification_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { &hf_e2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_Cause },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_FailedToBeRemovedForModification_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_FailedToBeRemovedForModification_Item, RICaction_FailedToBeRemovedForModification_Item_sequence);

  return offset;
}


static const per_sequence_t RICactions_ModifiedForModification_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_ModifiedForModification_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_ModifiedForModification_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_ModifiedForModification_List, RICactions_ModifiedForModification_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_ModifiedForModification_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_ModifiedForModification_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_ModifiedForModification_Item, RICaction_ModifiedForModification_Item_sequence);

  return offset;
}


static const per_sequence_t RICactions_FailedToBeModifiedForModification_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_FailedToBeModifiedForModification_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_FailedToBeModifiedForModification_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_FailedToBeModifiedForModification_List, RICactions_FailedToBeModifiedForModification_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_FailedToBeModifiedForModification_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { &hf_e2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_Cause },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_FailedToBeModifiedForModification_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_FailedToBeModifiedForModification_Item, RICaction_FailedToBeModifiedForModification_Item_sequence);

  return offset;
}


static const per_sequence_t RICactions_AddedForModification_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_AddedForModification_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_AddedForModification_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_AddedForModification_List, RICactions_AddedForModification_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_AddedForModification_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_AddedForModification_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_AddedForModification_Item, RICaction_AddedForModification_Item_sequence);

  return offset;
}


static const per_sequence_t RICactions_FailedToBeAddedForModification_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_FailedToBeAddedForModification_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_FailedToBeAddedForModification_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_FailedToBeAddedForModification_List, RICactions_FailedToBeAddedForModification_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_FailedToBeAddedForModification_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { &hf_e2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_Cause },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_FailedToBeAddedForModification_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_FailedToBeAddedForModification_Item, RICaction_FailedToBeAddedForModification_Item_sequence);

  return offset;
}


static const per_sequence_t RICsubscriptionModificationFailure_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionModificationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionModificationFailure, RICsubscriptionModificationFailure_sequence);

  return offset;
}


static const per_sequence_t RICsubscriptionModificationRequired_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionModificationRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionModificationRequired, RICsubscriptionModificationRequired_sequence);

  return offset;
}


static const per_sequence_t RICactions_RequiredToBeModified_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_RequiredToBeModified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_RequiredToBeModified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_RequiredToBeModified_List, RICactions_RequiredToBeModified_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_RequiredToBeModified_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { &hf_e2ap_ricTimeToWait  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICtimeToWait },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_RequiredToBeModified_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_RequiredToBeModified_Item, RICaction_RequiredToBeModified_Item_sequence);

  return offset;
}


static const per_sequence_t RICactions_RequiredToBeRemoved_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_RequiredToBeRemoved_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_RequiredToBeRemoved_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_RequiredToBeRemoved_List, RICactions_RequiredToBeRemoved_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_RequiredToBeRemoved_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { &hf_e2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_Cause },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_RequiredToBeRemoved_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_RequiredToBeRemoved_Item, RICaction_RequiredToBeRemoved_Item_sequence);

  return offset;
}


static const per_sequence_t RICsubscriptionModificationConfirm_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionModificationConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionModificationConfirm, RICsubscriptionModificationConfirm_sequence);

  return offset;
}


static const per_sequence_t RICactions_ConfirmedForModification_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_ConfirmedForModification_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_ConfirmedForModification_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_ConfirmedForModification_List, RICactions_ConfirmedForModification_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_ConfirmedForModification_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_ConfirmedForModification_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_ConfirmedForModification_Item, RICaction_ConfirmedForModification_Item_sequence);

  return offset;
}


static const per_sequence_t RICactions_RefusedToBeModified_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_RefusedToBeModified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_RefusedToBeModified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_RefusedToBeModified_List, RICactions_RefusedToBeModified_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_RefusedToBeModified_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { &hf_e2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_Cause },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_RefusedToBeModified_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_RefusedToBeModified_Item, RICaction_RefusedToBeModified_Item_sequence);

  return offset;
}


static const per_sequence_t RICactions_ConfirmedForRemoval_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_ConfirmedForRemoval_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_ConfirmedForRemoval_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_ConfirmedForRemoval_List, RICactions_ConfirmedForRemoval_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_ConfirmedForRemoval_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_ConfirmedForRemoval_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_ConfirmedForRemoval_Item, RICaction_ConfirmedForRemoval_Item_sequence);

  return offset;
}


static const per_sequence_t RICactions_RefusedToBeRemoved_List_sequence_of[1] = {
  { &hf_e2ap_RICactions_RefusedToBeRemoved_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RICactions_RefusedToBeRemoved_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RICactions_RefusedToBeRemoved_List, RICactions_RefusedToBeRemoved_List_sequence_of,
                                                  0, maxofRICactionID, false);

  return offset;
}


static const per_sequence_t RICaction_RefusedToBeRemoved_Item_sequence[] = {
  { &hf_e2ap_ricActionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RICactionID },
  { &hf_e2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_Cause },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICaction_RefusedToBeRemoved_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICaction_RefusedToBeRemoved_Item, RICaction_RefusedToBeRemoved_Item_sequence);

  return offset;
}


static const per_sequence_t RICsubscriptionModificationRefuse_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionModificationRefuse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionModificationRefuse, RICsubscriptionModificationRefuse_sequence);

  return offset;
}


static const per_sequence_t RICindication_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICindication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_IND);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_IND);


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICindication, RICindication_sequence);

  return offset;
}


static const per_sequence_t RICcontrolRequest_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICcontrolRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_CONTROL_REQUEST);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_CONTROL_REQUEST);


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICcontrolRequest, RICcontrolRequest_sequence);

  return offset;
}


static const per_sequence_t RICcontrolAcknowledge_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICcontrolAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_CONTROL_ACK);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_CONTROL_ACK);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICcontrolAcknowledge, RICcontrolAcknowledge_sequence);

  return offset;
}


static const per_sequence_t RICcontrolFailure_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICcontrolFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_CONTROL_FAIL);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_CONTROL_FAIL);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICcontrolFailure, RICcontrolFailure_sequence);

  return offset;
}


static const per_sequence_t RICQueryRequest_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICQueryRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICQueryRequest, RICQueryRequest_sequence);

  return offset;
}


static const per_sequence_t RICQueryResponse_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICQueryResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICQueryResponse, RICQueryResponse_sequence);

  return offset;
}


static const per_sequence_t RICQueryFailure_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICQueryFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICQueryFailure, RICQueryFailure_sequence);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_ERROR_INDICATION);
  set_stats_message_type(actx->pinfo, MTYPE_ERROR_INDICATION);


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t E2setupRequest_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2setupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_E2_SETUP_REQUEST);
  set_stats_message_type(actx->pinfo, MTYPE_E2_SETUP_REQUEST);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2setupRequest, E2setupRequest_sequence);

  return offset;
}


static const per_sequence_t E2setupResponse_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2setupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_E2_SETUP_RESPONSE);
  set_stats_message_type(actx->pinfo, MTYPE_E2_SETUP_RESPONSE);



  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2setupResponse, E2setupResponse_sequence);

  return offset;
}


static const per_sequence_t E2setupFailure_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2setupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_E2_SETUP_FAIL);
  set_stats_message_type(actx->pinfo, MTYPE_E2_SETUP_FAIL);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2setupFailure, E2setupFailure_sequence);

  return offset;
}


static const per_sequence_t E2connectionUpdate_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2connectionUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_E2_CONNECTION_UPDATE);
  set_stats_message_type(actx->pinfo, MTYPE_E2_CONNECTION_UPDATE);


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2connectionUpdate, E2connectionUpdate_sequence);

  return offset;
}


static const per_sequence_t E2connectionUpdate_List_sequence_of[1] = {
  { &hf_e2ap_E2connectionUpdate_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_E2connectionUpdate_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_E2connectionUpdate_List, E2connectionUpdate_List_sequence_of,
                                                  1, maxofTNLA, false);

  return offset;
}


static const per_sequence_t E2connectionUpdate_Item_sequence[] = {
  { &hf_e2ap_tnlInformation , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_TNLinformation },
  { &hf_e2ap_tnlUsage       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_TNLusage },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2connectionUpdate_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2connectionUpdate_Item, E2connectionUpdate_Item_sequence);

  return offset;
}


static const per_sequence_t E2connectionUpdateRemove_List_sequence_of[1] = {
  { &hf_e2ap_E2connectionUpdateRemove_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_E2connectionUpdateRemove_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_E2connectionUpdateRemove_List, E2connectionUpdateRemove_List_sequence_of,
                                                  1, maxofTNLA, false);

  return offset;
}


static const per_sequence_t E2connectionUpdateRemove_Item_sequence[] = {
  { &hf_e2ap_tnlInformation , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_TNLinformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2connectionUpdateRemove_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2connectionUpdateRemove_Item, E2connectionUpdateRemove_Item_sequence);

  return offset;
}


static const per_sequence_t E2connectionUpdateAcknowledge_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2connectionUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_E2_CONNECTION_UPDATE_ACK);
  set_stats_message_type(actx->pinfo, MTYPE_E2_CONNECTION_UPDATE_ACK);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2connectionUpdateAcknowledge, E2connectionUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t E2connectionSetupFailed_List_sequence_of[1] = {
  { &hf_e2ap_E2connectionSetupFailed_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_E2connectionSetupFailed_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_E2connectionSetupFailed_List, E2connectionSetupFailed_List_sequence_of,
                                                  1, maxofTNLA, false);

  return offset;
}


static const per_sequence_t E2connectionSetupFailed_Item_sequence[] = {
  { &hf_e2ap_tnlInformation , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_TNLinformation },
  { &hf_e2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_Cause },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2connectionSetupFailed_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2connectionSetupFailed_Item, E2connectionSetupFailed_Item_sequence);

  return offset;
}


static const per_sequence_t E2connectionUpdateFailure_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2connectionUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_E2_CONNECTION_UPDATE_FAIL);
  set_stats_message_type(actx->pinfo, MTYPE_E2_CONNECTION_UPDATE_FAIL);


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2connectionUpdateFailure, E2connectionUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t E2nodeConfigurationUpdate_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_E2_CONFIGURATION_UPDATE_FAIL);
  set_stats_message_type(actx->pinfo, MTYPE_E2_CONFIGURATION_UPDATE_FAIL);


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeConfigurationUpdate, E2nodeConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t E2nodeComponentConfigAddition_List_sequence_of[1] = {
  { &hf_e2ap_E2nodeComponentConfigAddition_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_E2nodeComponentConfigAddition_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_E2nodeComponentConfigAddition_List, E2nodeComponentConfigAddition_List_sequence_of,
                                                  1, maxofE2nodeComponents, false);

  return offset;
}


static const per_sequence_t E2nodeComponentConfigAddition_Item_sequence[] = {
  { &hf_e2ap_e2nodeComponentInterfaceType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentInterfaceType },
  { &hf_e2ap_e2nodeComponentID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentID },
  { &hf_e2ap_e2nodeComponentConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentConfiguration },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentConfigAddition_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentConfigAddition_Item, E2nodeComponentConfigAddition_Item_sequence);

  return offset;
}


static const per_sequence_t E2nodeComponentConfigUpdate_List_sequence_of[1] = {
  { &hf_e2ap_E2nodeComponentConfigUpdate_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_E2nodeComponentConfigUpdate_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_E2nodeComponentConfigUpdate_List, E2nodeComponentConfigUpdate_List_sequence_of,
                                                  1, maxofE2nodeComponents, false);

  return offset;
}


static const per_sequence_t E2nodeComponentConfigUpdate_Item_sequence[] = {
  { &hf_e2ap_e2nodeComponentInterfaceType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentInterfaceType },
  { &hf_e2ap_e2nodeComponentID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentID },
  { &hf_e2ap_e2nodeComponentConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentConfiguration },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentConfigUpdate_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentConfigUpdate_Item, E2nodeComponentConfigUpdate_Item_sequence);

  return offset;
}


static const per_sequence_t E2nodeComponentConfigRemoval_List_sequence_of[1] = {
  { &hf_e2ap_E2nodeComponentConfigRemoval_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_E2nodeComponentConfigRemoval_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_E2nodeComponentConfigRemoval_List, E2nodeComponentConfigRemoval_List_sequence_of,
                                                  1, maxofE2nodeComponents, false);

  return offset;
}


static const per_sequence_t E2nodeComponentConfigRemoval_Item_sequence[] = {
  { &hf_e2ap_e2nodeComponentInterfaceType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentInterfaceType },
  { &hf_e2ap_e2nodeComponentID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentConfigRemoval_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentConfigRemoval_Item, E2nodeComponentConfigRemoval_Item_sequence);

  return offset;
}


static const per_sequence_t E2nodeTNLassociationRemoval_List_sequence_of[1] = {
  { &hf_e2ap_E2nodeTNLassociationRemoval_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_E2nodeTNLassociationRemoval_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_E2nodeTNLassociationRemoval_List, E2nodeTNLassociationRemoval_List_sequence_of,
                                                  1, maxofTNLA, false);

  return offset;
}


static const per_sequence_t E2nodeTNLassociationRemoval_Item_sequence[] = {
  { &hf_e2ap_tnlInformation , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_TNLinformation },
  { &hf_e2ap_tnlInformationRIC, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_TNLinformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeTNLassociationRemoval_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeTNLassociationRemoval_Item, E2nodeTNLassociationRemoval_Item_sequence);

  return offset;
}


static const per_sequence_t E2nodeConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_E2_CONFIGURATION_UPDATE_ACK);
  set_stats_message_type(actx->pinfo, MTYPE_E2_CONFIGURATION_UPDATE_ACK);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeConfigurationUpdateAcknowledge, E2nodeConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t E2nodeComponentConfigAdditionAck_List_sequence_of[1] = {
  { &hf_e2ap_E2nodeComponentConfigAdditionAck_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_E2nodeComponentConfigAdditionAck_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_E2nodeComponentConfigAdditionAck_List, E2nodeComponentConfigAdditionAck_List_sequence_of,
                                                  1, maxofE2nodeComponents, false);

  return offset;
}


static const per_sequence_t E2nodeComponentConfigAdditionAck_Item_sequence[] = {
  { &hf_e2ap_e2nodeComponentInterfaceType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentInterfaceType },
  { &hf_e2ap_e2nodeComponentID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentID },
  { &hf_e2ap_e2nodeComponentConfigurationAck, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentConfigurationAck },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentConfigAdditionAck_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentConfigAdditionAck_Item, E2nodeComponentConfigAdditionAck_Item_sequence);

  return offset;
}


static const per_sequence_t E2nodeComponentConfigUpdateAck_List_sequence_of[1] = {
  { &hf_e2ap_E2nodeComponentConfigUpdateAck_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_E2nodeComponentConfigUpdateAck_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_E2nodeComponentConfigUpdateAck_List, E2nodeComponentConfigUpdateAck_List_sequence_of,
                                                  1, maxofE2nodeComponents, false);

  return offset;
}


static const per_sequence_t E2nodeComponentConfigUpdateAck_Item_sequence[] = {
  { &hf_e2ap_e2nodeComponentInterfaceType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentInterfaceType },
  { &hf_e2ap_e2nodeComponentID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentID },
  { &hf_e2ap_e2nodeComponentConfigurationAck, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentConfigurationAck },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentConfigUpdateAck_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentConfigUpdateAck_Item, E2nodeComponentConfigUpdateAck_Item_sequence);

  return offset;
}


static const per_sequence_t E2nodeComponentConfigRemovalAck_List_sequence_of[1] = {
  { &hf_e2ap_E2nodeComponentConfigRemovalAck_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_E2nodeComponentConfigRemovalAck_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_E2nodeComponentConfigRemovalAck_List, E2nodeComponentConfigRemovalAck_List_sequence_of,
                                                  1, maxofE2nodeComponents, false);

  return offset;
}


static const per_sequence_t E2nodeComponentConfigRemovalAck_Item_sequence[] = {
  { &hf_e2ap_e2nodeComponentInterfaceType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentInterfaceType },
  { &hf_e2ap_e2nodeComponentID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentID },
  { &hf_e2ap_e2nodeComponentConfigurationAck, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2nodeComponentConfigurationAck },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentConfigRemovalAck_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentConfigRemovalAck_Item, E2nodeComponentConfigRemovalAck_Item_sequence);

  return offset;
}


static const per_sequence_t E2nodeConfigurationUpdateFailure_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_E2_CONFIGURATION_UPDATE_FAIL);
  set_stats_message_type(actx->pinfo, MTYPE_E2_CONFIGURATION_UPDATE_FAIL);


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeConfigurationUpdateFailure, E2nodeConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t ResetRequest_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_ResetRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RESET_REQUEST);
  set_stats_message_type(actx->pinfo, MTYPE_RESET_REQUEST);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_ResetRequest, ResetRequest_sequence);

  return offset;
}


static const per_sequence_t ResetResponse_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_ResetResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RESET_RESPONSE);
  set_stats_message_type(actx->pinfo, MTYPE_RESET_RESPONSE);


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_ResetResponse, ResetResponse_sequence);

  return offset;
}


static const per_sequence_t RICserviceUpdate_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICserviceUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_SERVICE_UPDATE);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_SERVICE_UPDATE);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICserviceUpdate, RICserviceUpdate_sequence);

  return offset;
}


static const per_sequence_t RANfunctions_List_sequence_of[1] = {
  { &hf_e2ap_RANfunctions_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RANfunctions_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RANfunctions_List, RANfunctions_List_sequence_of,
                                                  1, maxofRANfunctionID, false);

  return offset;
}


static const per_sequence_t RANfunction_Item_sequence[] = {
  { &hf_e2ap_ranFunctionID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunctionID },
  { &hf_e2ap_ranFunctionDefinition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunctionDefinition },
  { &hf_e2ap_ranFunctionRevision, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunctionRevision },
  { &hf_e2ap_ranFunctionOID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunctionOID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANfunction_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANfunction_Item, RANfunction_Item_sequence);

  return offset;
}


static const per_sequence_t RANfunctionsID_List_sequence_of[1] = {
  { &hf_e2ap_RANfunctionsID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RANfunctionsID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RANfunctionsID_List, RANfunctionsID_List_sequence_of,
                                                  1, maxofRANfunctionID, false);

  return offset;
}


static const per_sequence_t RANfunctionID_Item_sequence[] = {
  { &hf_e2ap_ranFunctionID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunctionID },
  { &hf_e2ap_ranFunctionRevision, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunctionRevision },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANfunctionID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANfunctionID_Item, RANfunctionID_Item_sequence);

  return offset;
}


static const per_sequence_t RICserviceUpdateAcknowledge_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICserviceUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_SERVICE_UPDATE_ACK);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_SERVICE_UPDATE_ACK);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICserviceUpdateAcknowledge, RICserviceUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t RANfunctionsIDcause_List_sequence_of[1] = {
  { &hf_e2ap_RANfunctionsIDcause_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_SingleContainer },
};

static int
dissect_e2ap_RANfunctionsIDcause_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RANfunctionsIDcause_List, RANfunctionsIDcause_List_sequence_of,
                                                  1, maxofRANfunctionID, false);

  return offset;
}


static const per_sequence_t RANfunctionIDcause_Item_sequence[] = {
  { &hf_e2ap_ranFunctionID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunctionID },
  { &hf_e2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_Cause },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANfunctionIDcause_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANfunctionIDcause_Item, RANfunctionIDcause_Item_sequence);

  return offset;
}


static const per_sequence_t RICserviceUpdateFailure_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICserviceUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_SERVICE_UPDATE_FAIL);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_SERVICE_UPDATE_FAIL);



  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICserviceUpdateFailure, RICserviceUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t RICserviceQuery_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICserviceQuery(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  set_message_label(actx, MTYPE_RIC_SERVICE_QUERY);
  set_stats_message_type(actx->pinfo, MTYPE_RIC_SERVICE_QUERY);


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICserviceQuery, RICserviceQuery_sequence);

  return offset;
}


static const per_sequence_t E2RemovalRequest_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2RemovalRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2RemovalRequest, E2RemovalRequest_sequence);

  return offset;
}


static const per_sequence_t E2RemovalResponse_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2RemovalResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2RemovalResponse, E2RemovalResponse_sequence);

  return offset;
}


static const per_sequence_t E2RemovalFailure_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2RemovalFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2RemovalFailure, E2RemovalFailure_sequence);

  return offset;
}



static int
dissect_e2ap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  e2ap_data->message_type = INITIATING_MESSAGE;
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_e2ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProcedureCode },
  { &hf_e2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_Criticality },
  { &hf_e2ap_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_e2ap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  e2ap_data->message_type = SUCCESSFUL_OUTCOME;
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_e2ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProcedureCode },
  { &hf_e2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_Criticality },
  { &hf_e2ap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_e2ap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  e2ap_data->message_type = UNSUCCESSFUL_OUTCOME;

















  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_e2ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ProcedureCode },
  { &hf_e2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_Criticality },
  { &hf_e2ap_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string e2ap_E2AP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t E2AP_PDU_choice[] = {
  {   0, &hf_e2ap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_e2ap_InitiatingMessage },
  {   1, &hf_e2ap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_e2ap_SuccessfulOutcome },
  {   2, &hf_e2ap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_e2ap_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_E2AP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_E2AP_PDU, E2AP_PDU_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_PLMNIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}



static int
dissect_e2ap_NRCellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NR_CGI_sequence[] = {
  { &hf_e2ap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMNIdentity },
  { &hf_e2ap_nRCellIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NRCellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_NR_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_NR_CGI, NR_CGI_sequence);

  return offset;
}



static int
dissect_e2ap_EUTRACellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t EUTRA_CGI_sequence[] = {
  { &hf_e2ap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMNIdentity },
  { &hf_e2ap_eUTRACellIdentity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_EUTRACellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_EUTRA_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_EUTRA_CGI, EUTRA_CGI_sequence);

  return offset;
}


static const value_string e2ap_CGI_vals[] = {
  {   0, "nR-CGI" },
  {   1, "eUTRA-CGI" },
  { 0, NULL }
};

static const per_choice_t CGI_choice[] = {
  {   0, &hf_e2ap_nR_CGI         , ASN1_EXTENSION_ROOT    , dissect_e2ap_NR_CGI },
  {   1, &hf_e2ap_eUTRA_CGI      , ASN1_EXTENSION_ROOT    , dissect_e2ap_EUTRA_CGI },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_CGI, CGI_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_AMFRegionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e2ap_AMFSetID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e2ap_AMFPointer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GUAMI_sequence[] = {
  { &hf_e2ap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMNIdentity },
  { &hf_e2ap_aMFRegionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_AMFRegionID },
  { &hf_e2ap_aMFSetID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_AMFSetID },
  { &hf_e2ap_aMFPointer     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_AMFPointer },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GUAMI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GUAMI, GUAMI_sequence);

  return offset;
}


static const per_sequence_t InterfaceID_NG_sequence[] = {
  { &hf_e2ap_guami          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GUAMI },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_InterfaceID_NG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_InterfaceID_NG, InterfaceID_NG_sequence);

  return offset;
}


static const value_string e2ap_GNB_ID_vals[] = {
  {   0, "gNB-ID" },
  { 0, NULL }
};

static const per_choice_t GNB_ID_choice[] = {
  {   0, &hf_e2ap_gNB_ID         , ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING_SIZE_22_32 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_GNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_GNB_ID, GNB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalGNB_ID_sequence[] = {
  { &hf_e2ap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMNIdentity },
  { &hf_e2ap_gNB_ID_02      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GNB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalGNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalGNB_ID, GlobalGNB_ID_sequence);

  return offset;
}


static const value_string e2ap_NgENB_ID_vals[] = {
  {   0, "macroNgENB-ID" },
  {   1, "shortMacroNgENB-ID" },
  {   2, "longMacroNgENB-ID" },
  { 0, NULL }
};

static const per_choice_t NgENB_ID_choice[] = {
  {   0, &hf_e2ap_macroNgENB_ID  , ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING_SIZE_20 },
  {   1, &hf_e2ap_shortMacroNgENB_ID, ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING_SIZE_18 },
  {   2, &hf_e2ap_longMacroNgENB_ID, ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING_SIZE_21 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_NgENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_NgENB_ID, NgENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalNgENB_ID_sequence[] = {
  { &hf_e2ap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMNIdentity },
  { &hf_e2ap_ngENB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NgENB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalNgENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalNgENB_ID, GlobalNgENB_ID_sequence);

  return offset;
}


static const value_string e2ap_GlobalNGRANNodeID_vals[] = {
  {   0, "gNB" },
  {   1, "ng-eNB" },
  { 0, NULL }
};

static const per_choice_t GlobalNGRANNodeID_choice[] = {
  {   0, &hf_e2ap_gNB_02         , ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalGNB_ID },
  {   1, &hf_e2ap_ng_eNB_02      , ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalNgENB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_GlobalNGRANNodeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_GlobalNGRANNodeID, GlobalNGRANNodeID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t InterfaceID_Xn_sequence[] = {
  { &hf_e2ap_global_NG_RAN_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalNGRANNodeID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_InterfaceID_Xn(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_InterfaceID_Xn, InterfaceID_Xn_sequence);

  return offset;
}


static const per_sequence_t InterfaceID_F1_sequence[] = {
  { &hf_e2ap_globalGNB_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalGNB_ID },
  { &hf_e2ap_gNB_DU_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GNB_DU_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_InterfaceID_F1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_InterfaceID_F1, InterfaceID_F1_sequence);

  return offset;
}


static const per_sequence_t InterfaceID_E1_sequence[] = {
  { &hf_e2ap_globalGNB_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalGNB_ID },
  { &hf_e2ap_gNB_CU_UP_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GNB_CU_UP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_InterfaceID_E1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_InterfaceID_E1, InterfaceID_E1_sequence);

  return offset;
}



static int
dissect_e2ap_MME_Group_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, NULL);

  return offset;
}



static int
dissect_e2ap_MME_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const per_sequence_t GUMMEI_sequence[] = {
  { &hf_e2ap_pLMN_Identity_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMNIdentity },
  { &hf_e2ap_mME_Group_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MME_Group_ID },
  { &hf_e2ap_mME_Code       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MME_Code },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GUMMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GUMMEI, GUMMEI_sequence);

  return offset;
}


static const per_sequence_t InterfaceID_S1_sequence[] = {
  { &hf_e2ap_gUMMEI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GUMMEI },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_InterfaceID_S1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_InterfaceID_S1, InterfaceID_S1_sequence);

  return offset;
}


static const value_string e2ap_T_nodeType_vals[] = {
  {   0, "global-eNB-ID" },
  {   1, "global-en-gNB-ID" },
  { 0, NULL }
};

static const per_choice_t T_nodeType_choice[] = {
  {   0, &hf_e2ap_global_eNB_ID  , ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalENB_ID },
  {   1, &hf_e2ap_global_en_gNB_ID, ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalenGNB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_nodeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_nodeType, T_nodeType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t InterfaceID_X2_sequence[] = {
  { &hf_e2ap_nodeType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_nodeType },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_InterfaceID_X2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_InterfaceID_X2, InterfaceID_X2_sequence);

  return offset;
}


static const per_sequence_t InterfaceID_W1_sequence[] = {
  { &hf_e2ap_global_ng_eNB_ID_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalNgENB_ID },
  { &hf_e2ap_ng_eNB_DU_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NGENB_DU_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_InterfaceID_W1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_InterfaceID_W1, InterfaceID_W1_sequence);

  return offset;
}


static const value_string e2ap_InterfaceIdentifier_vals[] = {
  {   0, "nG" },
  {   1, "xN" },
  {   2, "f1" },
  {   3, "e1" },
  {   4, "s1" },
  {   5, "x2" },
  {   6, "w1" },
  { 0, NULL }
};

static const per_choice_t InterfaceIdentifier_choice[] = {
  {   0, &hf_e2ap_nG             , ASN1_EXTENSION_ROOT    , dissect_e2ap_InterfaceID_NG },
  {   1, &hf_e2ap_xN             , ASN1_EXTENSION_ROOT    , dissect_e2ap_InterfaceID_Xn },
  {   2, &hf_e2ap_f1             , ASN1_EXTENSION_ROOT    , dissect_e2ap_InterfaceID_F1 },
  {   3, &hf_e2ap_e1             , ASN1_EXTENSION_ROOT    , dissect_e2ap_InterfaceID_E1 },
  {   4, &hf_e2ap_s1             , ASN1_EXTENSION_ROOT    , dissect_e2ap_InterfaceID_S1 },
  {   5, &hf_e2ap_x2             , ASN1_EXTENSION_ROOT    , dissect_e2ap_InterfaceID_X2 },
  {   6, &hf_e2ap_w1             , ASN1_EXTENSION_ROOT    , dissect_e2ap_InterfaceID_W1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_InterfaceIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_InterfaceIdentifier, InterfaceIdentifier_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_INTEGER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string e2ap_T_messageType_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};


static int
dissect_e2ap_T_messageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t Interface_MessageID_sequence[] = {
  { &hf_e2ap_interfaceProcedureID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER },
  { &hf_e2ap_messageType    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_messageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_Interface_MessageID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_Interface_MessageID, Interface_MessageID_sequence);

  return offset;
}


static const value_string e2ap_InterfaceType_vals[] = {
  {   0, "nG" },
  {   1, "xn" },
  {   2, "f1" },
  {   3, "e1" },
  {   4, "s1" },
  {   5, "x2" },
  {   6, "w1" },
  { 0, NULL }
};


static int
dissect_e2ap_InterfaceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e2ap_T_ranFunction_ShortName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *value_tvb;
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          &value_tvb);

  if (!actx->pinfo->fd->visited) {
    /* N.B. too early to work out exact dissector, as don't have OID yet */
    e2ap_store_ran_function_mapping(actx->pinfo, tree, value_tvb,
                                    tvb_get_string_enc(actx->pinfo->pool, value_tvb, 0, tvb_captured_length(value_tvb), ENC_ASCII));
  }


  return offset;
}



static int
dissect_e2ap_PrintableString_SIZE_1_1000_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 1000, true,
                                          NULL);

  return offset;
}



static int
dissect_e2ap_PrintableString_SIZE_1_150_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}


static const per_sequence_t RANfunction_Name_sequence[] = {
  { &hf_e2ap_ranFunction_ShortName, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_ranFunction_ShortName },
  { &hf_e2ap_ranFunction_E2SM_OID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PrintableString_SIZE_1_1000_ },
  { &hf_e2ap_ranFunction_Description, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PrintableString_SIZE_1_150_ },
  { &hf_e2ap_ranFunction_Instance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANfunction_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANfunction_Name, RANfunction_Name_sequence);

  return offset;
}



static int
dissect_e2ap_RIC_Format_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_e2ap_RIC_Style_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_e2ap_RIC_Style_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}


static const value_string e2ap_RRCclass_LTE_vals[] = {
  {   0, "bCCH-BCH" },
  {   1, "bCCH-BCH-MBMS" },
  {   2, "bCCH-DL-SCH" },
  {   3, "bCCH-DL-SCH-BR" },
  {   4, "bCCH-DL-SCH-MBMS" },
  {   5, "mCCH" },
  {   6, "pCCH" },
  {   7, "dL-CCCH" },
  {   8, "dL-DCCH" },
  {   9, "uL-CCCH" },
  {  10, "uL-DCCH" },
  {  11, "sC-MCCH" },
  { 0, NULL }
};


static int
dissect_e2ap_RRCclass_LTE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     12, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_RRCclass_NR_vals[] = {
  {   0, "bCCH-BCH" },
  {   1, "bCCH-DL-SCH" },
  {   2, "dL-CCCH" },
  {   3, "dL-DCCH" },
  {   4, "pCCH" },
  {   5, "uL-CCCH" },
  {   6, "uL-CCCH1" },
  {   7, "uL-DCCH" },
  { 0, NULL }
};


static int
dissect_e2ap_RRCclass_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_rrcType_vals[] = {
  {   0, "lTE" },
  {   1, "nR" },
  { 0, NULL }
};

static const per_choice_t T_rrcType_choice[] = {
  {   0, &hf_e2ap_lTE            , ASN1_EXTENSION_ROOT    , dissect_e2ap_RRCclass_LTE },
  {   1, &hf_e2ap_nR             , ASN1_EXTENSION_ROOT    , dissect_e2ap_RRCclass_NR },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_rrcType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_rrcType, T_rrcType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRC_MessageID_sequence[] = {
  { &hf_e2ap_rrcType        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_rrcType },
  { &hf_e2ap_messageID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RRC_MessageID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RRC_MessageID, RRC_MessageID_sequence);

  return offset;
}



static int
dissect_e2ap_INTEGER_0_maxNRARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNRARFCN, NULL, false);

  return offset;
}


static const per_sequence_t NR_ARFCN_sequence[] = {
  { &hf_e2ap_nRARFCN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_0_maxNRARFCN },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_NR_ARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_NR_ARFCN, NR_ARFCN_sequence);

  return offset;
}



static int
dissect_e2ap_E_UTRA_ARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxEARFCN, NULL, false);

  return offset;
}


static const value_string e2ap_ServingCell_ARFCN_vals[] = {
  {   0, "nR" },
  {   1, "eUTRA" },
  { 0, NULL }
};

static const per_choice_t ServingCell_ARFCN_choice[] = {
  {   0, &hf_e2ap_nR_01          , ASN1_EXTENSION_ROOT    , dissect_e2ap_NR_ARFCN },
  {   1, &hf_e2ap_eUTRA          , ASN1_EXTENSION_ROOT    , dissect_e2ap_E_UTRA_ARFCN },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_ServingCell_ARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_ServingCell_ARFCN, ServingCell_ARFCN_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_NR_PCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1007U, NULL, false);

  return offset;
}



static int
dissect_e2ap_E_UTRA_PCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 503U, NULL, true);

  return offset;
}


static const value_string e2ap_ServingCell_PCI_vals[] = {
  {   0, "nR" },
  {   1, "eUTRA" },
  { 0, NULL }
};

static const per_choice_t ServingCell_PCI_choice[] = {
  {   0, &hf_e2ap_nR_02          , ASN1_EXTENSION_ROOT    , dissect_e2ap_NR_PCI },
  {   1, &hf_e2ap_eUTRA_01       , ASN1_EXTENSION_ROOT    , dissect_e2ap_E_UTRA_PCI },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_ServingCell_PCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_ServingCell_PCI, ServingCell_PCI_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_AMF_UE_NGAP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(1099511627775), NULL, false);

  return offset;
}



static int
dissect_e2ap_GNB_CU_UE_F1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_CP_F1AP_ID_Item_sequence[] = {
  { &hf_e2ap_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GNB_CU_UE_F1AP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_UEID_GNB_CU_CP_F1AP_ID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_UEID_GNB_CU_CP_F1AP_ID_Item, UEID_GNB_CU_CP_F1AP_ID_Item_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_F1AP_ID_List_sequence_of[1] = {
  { &hf_e2ap_UEID_GNB_CU_F1AP_ID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_UEID_GNB_CU_CP_F1AP_ID_Item },
};

static int
dissect_e2ap_UEID_GNB_CU_F1AP_ID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_UEID_GNB_CU_F1AP_ID_List, UEID_GNB_CU_F1AP_ID_List_sequence_of,
                                                  1, maxF1APid, false);

  return offset;
}



static int
dissect_e2ap_GNB_CU_CP_UE_E1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_CP_E1AP_ID_Item_sequence[] = {
  { &hf_e2ap_gNB_CU_CP_UE_E1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GNB_CU_CP_UE_E1AP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_UEID_GNB_CU_CP_E1AP_ID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_UEID_GNB_CU_CP_E1AP_ID_Item, UEID_GNB_CU_CP_E1AP_ID_Item_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_CP_E1AP_ID_List_sequence_of[1] = {
  { &hf_e2ap_UEID_GNB_CU_CP_E1AP_ID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_UEID_GNB_CU_CP_E1AP_ID_Item },
};

static int
dissect_e2ap_UEID_GNB_CU_CP_E1AP_ID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_UEID_GNB_CU_CP_E1AP_ID_List, UEID_GNB_CU_CP_E1AP_ID_List_sequence_of,
                                                  1, maxE1APid, false);

  return offset;
}



static int
dissect_e2ap_RANUEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}



static int
dissect_e2ap_NG_RANnodeUEXnAPID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_GNB_sequence[] = {
  { &hf_e2ap_amf_UE_NGAP_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_AMF_UE_NGAP_ID },
  { &hf_e2ap_guami          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GUAMI },
  { &hf_e2ap_gNB_CU_UE_F1AP_ID_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_UEID_GNB_CU_F1AP_ID_List },
  { &hf_e2ap_gNB_CU_CP_UE_E1AP_ID_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_UEID_GNB_CU_CP_E1AP_ID_List },
  { &hf_e2ap_ran_UEID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANUEID },
  { &hf_e2ap_m_NG_RAN_UE_XnAP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_NG_RANnodeUEXnAPID },
  { &hf_e2ap_globalGNB_ID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GlobalGNB_ID },
  { &hf_e2ap_globalNG_RANNode_ID, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_GlobalNGRANNodeID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_UEID_GNB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_UEID_GNB, UEID_GNB_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_DU_sequence[] = {
  { &hf_e2ap_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GNB_CU_UE_F1AP_ID },
  { &hf_e2ap_ran_UEID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANUEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_UEID_GNB_DU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_UEID_GNB_DU, UEID_GNB_DU_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_UP_sequence[] = {
  { &hf_e2ap_gNB_CU_CP_UE_E1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GNB_CU_CP_UE_E1AP_ID },
  { &hf_e2ap_ran_UEID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANUEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_UEID_GNB_CU_UP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_UEID_GNB_CU_UP, UEID_GNB_CU_UP_sequence);

  return offset;
}



static int
dissect_e2ap_NGENB_CU_UE_W1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_NG_ENB_sequence[] = {
  { &hf_e2ap_amf_UE_NGAP_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_AMF_UE_NGAP_ID },
  { &hf_e2ap_guami          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GUAMI },
  { &hf_e2ap_ng_eNB_CU_UE_W1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_NGENB_CU_UE_W1AP_ID },
  { &hf_e2ap_m_NG_RAN_UE_XnAP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_NG_RANnodeUEXnAPID },
  { &hf_e2ap_globalNgENB_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GlobalNgENB_ID },
  { &hf_e2ap_globalNG_RANNode_ID, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_GlobalNGRANNodeID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_UEID_NG_ENB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_UEID_NG_ENB, UEID_NG_ENB_sequence);

  return offset;
}


static const per_sequence_t UEID_NG_ENB_DU_sequence[] = {
  { &hf_e2ap_ng_eNB_CU_UE_W1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NGENB_CU_UE_W1AP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_UEID_NG_ENB_DU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_UEID_NG_ENB_DU, UEID_NG_ENB_DU_sequence);

  return offset;
}



static int
dissect_e2ap_ENB_UE_X2AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}



static int
dissect_e2ap_ENB_UE_X2AP_ID_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, true);

  return offset;
}


static const per_sequence_t UEID_EN_GNB_sequence[] = {
  { &hf_e2ap_m_eNB_UE_X2AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ENB_UE_X2AP_ID },
  { &hf_e2ap_m_eNB_UE_X2AP_ID_Extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_ENB_UE_X2AP_ID_Extension },
  { &hf_e2ap_globalENB_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalENB_ID },
  { &hf_e2ap_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GNB_CU_UE_F1AP_ID },
  { &hf_e2ap_gNB_CU_CP_UE_E1AP_ID_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_UEID_GNB_CU_CP_E1AP_ID_List },
  { &hf_e2ap_ran_UEID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANUEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_UEID_EN_GNB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_UEID_EN_GNB, UEID_EN_GNB_sequence);

  return offset;
}



static int
dissect_e2ap_MME_UE_S1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_ENB_sequence[] = {
  { &hf_e2ap_mME_UE_S1AP_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MME_UE_S1AP_ID },
  { &hf_e2ap_gUMMEI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GUMMEI },
  { &hf_e2ap_m_eNB_UE_X2AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_ENB_UE_X2AP_ID },
  { &hf_e2ap_m_eNB_UE_X2AP_ID_Extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_ENB_UE_X2AP_ID_Extension },
  { &hf_e2ap_globalENB_ID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GlobalENB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_UEID_ENB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_UEID_ENB, UEID_ENB_sequence);

  return offset;
}


static const value_string e2ap_UEID_vals[] = {
  {   0, "gNB-UEID" },
  {   1, "gNB-DU-UEID" },
  {   2, "gNB-CU-UP-UEID" },
  {   3, "ng-eNB-UEID" },
  {   4, "ng-eNB-DU-UEID" },
  {   5, "en-gNB-UEID" },
  {   6, "eNB-UEID" },
  { 0, NULL }
};

static const per_choice_t UEID_choice[] = {
  {   0, &hf_e2ap_gNB_UEID       , ASN1_EXTENSION_ROOT    , dissect_e2ap_UEID_GNB },
  {   1, &hf_e2ap_gNB_DU_UEID    , ASN1_EXTENSION_ROOT    , dissect_e2ap_UEID_GNB_DU },
  {   2, &hf_e2ap_gNB_CU_UP_UEID , ASN1_EXTENSION_ROOT    , dissect_e2ap_UEID_GNB_CU_UP },
  {   3, &hf_e2ap_ng_eNB_UEID    , ASN1_EXTENSION_ROOT    , dissect_e2ap_UEID_NG_ENB },
  {   4, &hf_e2ap_ng_eNB_DU_UEID , ASN1_EXTENSION_ROOT    , dissect_e2ap_UEID_NG_ENB_DU },
  {   5, &hf_e2ap_en_gNB_UEID    , ASN1_EXTENSION_ROOT    , dissect_e2ap_UEID_EN_GNB },
  {   6, &hf_e2ap_eNB_UEID       , ASN1_EXTENSION_ROOT    , dissect_e2ap_UEID_ENB },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_UEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_UEID, UEID_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_QCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_e2ap_E_UTRA_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, NULL);

  return offset;
}



static int
dissect_e2ap_FiveQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, true);

  return offset;
}



static int
dissect_e2ap_QosFlowIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, true);

  return offset;
}



static int
dissect_e2ap_SD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}



static int
dissect_e2ap_SST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const per_sequence_t S_NSSAI_sequence[] = {
  { &hf_e2ap_sST            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SST },
  { &hf_e2ap_sD             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SD },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_S_NSSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_S_NSSAI, S_NSSAI_sequence);

  return offset;
}



static int
dissect_e2ap_FiveGS_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}



static int
dissect_e2ap_INTEGER_1_1024_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, true);

  return offset;
}


static const per_sequence_t SupportedSULFreqBandItem_sequence[] = {
  { &hf_e2ap_freqBandIndicatorNr, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_1_1024_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_SupportedSULFreqBandItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_SupportedSULFreqBandItem, SupportedSULFreqBandItem_sequence);

  return offset;
}


static const per_sequence_t SupportedSULBandList_sequence_of[1] = {
  { &hf_e2ap_SupportedSULBandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_SupportedSULFreqBandItem },
};

static int
dissect_e2ap_SupportedSULBandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SupportedSULBandList, SupportedSULBandList_sequence_of,
                                                  0, maxnoofNrCellBands, false);

  return offset;
}


static const per_sequence_t NRFrequencyBandItem_sequence[] = {
  { &hf_e2ap_freqBandIndicatorNr, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_1_1024_ },
  { &hf_e2ap_supportedSULBandList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SupportedSULBandList },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_NRFrequencyBandItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_NRFrequencyBandItem, NRFrequencyBandItem_sequence);

  return offset;
}


static const per_sequence_t NRFrequencyBand_List_sequence_of[1] = {
  { &hf_e2ap_NRFrequencyBand_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_NRFrequencyBandItem },
};

static int
dissect_e2ap_NRFrequencyBand_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_NRFrequencyBand_List, NRFrequencyBand_List_sequence_of,
                                                  1, maxnoofNrCellBands, false);

  return offset;
}


static const value_string e2ap_NRFrequencyShift7p5khz_vals[] = {
  {   0, "false" },
  {   1, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_NRFrequencyShift7p5khz(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t NRFrequencyInfo_sequence[] = {
  { &hf_e2ap_nrARFCN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NR_ARFCN },
  { &hf_e2ap_frequencyBand_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NRFrequencyBand_List },
  { &hf_e2ap_frequencyShift7p5khz, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_NRFrequencyShift7p5khz },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_NRFrequencyInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_NRFrequencyInfo, NRFrequencyInfo_sequence);

  return offset;
}


static const value_string e2ap_LogicalOR_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_e2ap_LogicalOR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_nR_mode_info_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};


static int
dissect_e2ap_T_nR_mode_info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_x2_Xn_established_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_e2ap_T_x2_Xn_established(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_hO_validated_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_e2ap_T_hO_validated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e2ap_INTEGER_1_65535_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}


static const per_sequence_t NeighborCell_Item_Choice_NR_sequence[] = {
  { &hf_e2ap_nR_CGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NR_CGI },
  { &hf_e2ap_nR_PCI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NR_PCI },
  { &hf_e2ap_fiveGS_TAC     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_FiveGS_TAC },
  { &hf_e2ap_nR_mode_info   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_nR_mode_info },
  { &hf_e2ap_nR_FreqInfo    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NRFrequencyInfo },
  { &hf_e2ap_x2_Xn_established, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_x2_Xn_established },
  { &hf_e2ap_hO_validated   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_hO_validated },
  { &hf_e2ap_version        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_1_65535_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_NeighborCell_Item_Choice_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_NeighborCell_Item_Choice_NR, NeighborCell_Item_Choice_NR_sequence);

  return offset;
}


static const value_string e2ap_T_x2_Xn_established_01_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_e2ap_T_x2_Xn_established_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_hO_validated_01_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_e2ap_T_hO_validated_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t NeighborCell_Item_Choice_E_UTRA_sequence[] = {
  { &hf_e2ap_eUTRA_CGI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_EUTRA_CGI },
  { &hf_e2ap_eUTRA_PCI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E_UTRA_PCI },
  { &hf_e2ap_eUTRA_ARFCN    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E_UTRA_ARFCN },
  { &hf_e2ap_eUTRA_TAC      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E_UTRA_TAC },
  { &hf_e2ap_x2_Xn_established_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_x2_Xn_established_01 },
  { &hf_e2ap_hO_validated_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_hO_validated_01 },
  { &hf_e2ap_version        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_1_65535_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_NeighborCell_Item_Choice_E_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_NeighborCell_Item_Choice_E_UTRA, NeighborCell_Item_Choice_E_UTRA_sequence);

  return offset;
}


static const value_string e2ap_NeighborCell_Item_vals[] = {
  {   0, "ranType-Choice-NR" },
  {   1, "ranType-Choice-EUTRA" },
  { 0, NULL }
};

static const per_choice_t NeighborCell_Item_choice[] = {
  {   0, &hf_e2ap_ranType_Choice_NR, ASN1_EXTENSION_ROOT    , dissect_e2ap_NeighborCell_Item_Choice_NR },
  {   1, &hf_e2ap_ranType_Choice_EUTRA, ASN1_EXTENSION_ROOT    , dissect_e2ap_NeighborCell_Item_Choice_E_UTRA },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_NeighborCell_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_NeighborCell_Item, NeighborCell_Item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NeighborCell_List_sequence_of[1] = {
  { &hf_e2ap_NeighborCell_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_NeighborCell_Item },
};

static int
dissect_e2ap_NeighborCell_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_NeighborCell_List, NeighborCell_List_sequence_of,
                                                  1, maxnoofNeighbourCell, false);

  return offset;
}


static const per_sequence_t NeighborRelation_Info_sequence[] = {
  { &hf_e2ap_servingCellPCI , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ServingCell_PCI },
  { &hf_e2ap_servingCellARFCN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ServingCell_ARFCN },
  { &hf_e2ap_neighborCell_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NeighborCell_List },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_NeighborRelation_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_NeighborRelation_Info, NeighborRelation_Info_sequence);

  return offset;
}


static const value_string e2ap_RRC_State_vals[] = {
  {   0, "rrc-connected" },
  {   1, "rrc-inactive" },
  {   2, "rrc-idle" },
  {   3, "any" },
  { 0, NULL }
};


static int
dissect_e2ap_RRC_State(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e2ap_RIC_EventTrigger_Cell_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}


static const per_sequence_t EventTrigger_Cell_Info_Item_Choice_Individual_sequence[] = {
  { &hf_e2ap_cellGlobalID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_CGI },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_EventTrigger_Cell_Info_Item_Choice_Individual(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_EventTrigger_Cell_Info_Item_Choice_Individual, EventTrigger_Cell_Info_Item_Choice_Individual_sequence);

  return offset;
}



static int
dissect_e2ap_RANParameter_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            1U, UINT64_C(4294967296), NULL, true);

  return offset;
}


static const per_sequence_t RANParameter_Testing_LIST_sequence_of[1] = {
  { &hf_e2ap_RANParameter_Testing_LIST_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Testing_Item },
};

static int
dissect_e2ap_RANParameter_Testing_LIST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RANParameter_Testing_LIST, RANParameter_Testing_LIST_sequence_of,
                                                  1, maxnoofItemsinList, false);

  return offset;
}


static const per_sequence_t RANParameter_Testing_Item_Choice_List_sequence[] = {
  { &hf_e2ap_ranParameter_List_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Testing_LIST },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_Testing_Item_Choice_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_Testing_Item_Choice_List, RANParameter_Testing_Item_Choice_List_sequence);

  return offset;
}


static const per_sequence_t RANParameter_Testing_STRUCTURE_sequence_of[1] = {
  { &hf_e2ap_RANParameter_Testing_STRUCTURE_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Testing_Item },
};

static int
dissect_e2ap_RANParameter_Testing_STRUCTURE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RANParameter_Testing_STRUCTURE, RANParameter_Testing_STRUCTURE_sequence_of,
                                                  1, maxnoofParametersinStructure, false);

  return offset;
}


static const per_sequence_t RANParameter_Testing_Item_Choice_Structure_sequence[] = {
  { &hf_e2ap_ranParameter_Structure_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Testing_STRUCTURE },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_Testing_Item_Choice_Structure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_Testing_Item_Choice_Structure, RANParameter_Testing_Item_Choice_Structure_sequence);

  return offset;
}



static int
dissect_e2ap_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_e2ap_REAL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_real(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_e2ap_BIT_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e2ap_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}



static int
dissect_e2ap_PrintableString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND, false,
                                          NULL);

  return offset;
}


static const value_string e2ap_RANParameter_Value_vals[] = {
  {   0, "valueBoolean" },
  {   1, "valueInt" },
  {   2, "valueReal" },
  {   3, "valueBitS" },
  {   4, "valueOctS" },
  {   5, "valuePrintableString" },
  { 0, NULL }
};

static const per_choice_t RANParameter_Value_choice[] = {
  {   0, &hf_e2ap_valueBoolean   , ASN1_EXTENSION_ROOT    , dissect_e2ap_BOOLEAN },
  {   1, &hf_e2ap_valueInt       , ASN1_EXTENSION_ROOT    , dissect_e2ap_INTEGER },
  {   2, &hf_e2ap_valueReal      , ASN1_EXTENSION_ROOT    , dissect_e2ap_REAL },
  {   3, &hf_e2ap_valueBitS      , ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING },
  {   4, &hf_e2ap_valueOctS      , ASN1_EXTENSION_ROOT    , dissect_e2ap_OCTET_STRING },
  {   5, &hf_e2ap_valuePrintableString, ASN1_EXTENSION_ROOT    , dissect_e2ap_PrintableString },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_RANParameter_Value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_RANParameter_Value, RANParameter_Value_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RANParameter_Testing_Item_Choice_ElementTrue_sequence[] = {
  { &hf_e2ap_ranParameter_value, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_Testing_Item_Choice_ElementTrue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_Testing_Item_Choice_ElementTrue, RANParameter_Testing_Item_Choice_ElementTrue_sequence);

  return offset;
}


static const value_string e2ap_T_ranP_Choice_comparison_vals[] = {
  {   0, "equal" },
  {   1, "difference" },
  {   2, "greaterthan" },
  {   3, "lessthan" },
  {   4, "contains" },
  {   5, "starts-with" },
  { 0, NULL }
};


static int
dissect_e2ap_T_ranP_Choice_comparison(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_ranP_Choice_presence_vals[] = {
  {   0, "present" },
  {   1, "configured" },
  {   2, "rollover" },
  {   3, "non-zero" },
  { 0, NULL }
};


static int
dissect_e2ap_T_ranP_Choice_presence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_RANParameter_TestingCondition_vals[] = {
  {   0, "ranP-Choice-comparison" },
  {   1, "ranP-Choice-presence" },
  { 0, NULL }
};

static const per_choice_t RANParameter_TestingCondition_choice[] = {
  {   0, &hf_e2ap_ranP_Choice_comparison, ASN1_EXTENSION_ROOT    , dissect_e2ap_T_ranP_Choice_comparison },
  {   1, &hf_e2ap_ranP_Choice_presence, ASN1_EXTENSION_ROOT    , dissect_e2ap_T_ranP_Choice_presence },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_RANParameter_TestingCondition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_RANParameter_TestingCondition, RANParameter_TestingCondition_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RANParameter_Testing_Item_Choice_ElementFalse_sequence[] = {
  { &hf_e2ap_ranParameter_TestCondition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_TestingCondition },
  { &hf_e2ap_ranParameter_Value, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Value },
  { &hf_e2ap_logicalOR      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_Testing_Item_Choice_ElementFalse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_Testing_Item_Choice_ElementFalse, RANParameter_Testing_Item_Choice_ElementFalse_sequence);

  return offset;
}


static const value_string e2ap_T_ranParameter_Type_vals[] = {
  {   0, "ranP-Choice-List" },
  {   1, "ranP-Choice-Structure" },
  {   2, "ranP-Choice-ElementTrue" },
  {   3, "ranP-Choice-ElementFalse" },
  { 0, NULL }
};

static const per_choice_t T_ranParameter_Type_choice[] = {
  {   0, &hf_e2ap_ranP_Choice_List_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_RANParameter_Testing_Item_Choice_List },
  {   1, &hf_e2ap_ranP_Choice_Structure_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_RANParameter_Testing_Item_Choice_Structure },
  {   2, &hf_e2ap_ranP_Choice_ElementTrue_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_RANParameter_Testing_Item_Choice_ElementTrue },
  {   3, &hf_e2ap_ranP_Choice_ElementFalse_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_RANParameter_Testing_Item_Choice_ElementFalse },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_ranParameter_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_ranParameter_Type, T_ranParameter_Type_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RANParameter_Testing_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_ranParameter_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_Testing_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // RANParameter-Testing-Item -> RANParameter-Testing-Item/ranParameter-Type -> RANParameter-Testing-Item-Choice-List -> RANParameter-Testing-LIST -> RANParameter-Testing-Item
  actx->pinfo->dissection_depth += 4;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_Testing_Item, RANParameter_Testing_Item_sequence);

  actx->pinfo->dissection_depth -= 4;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const per_sequence_t RANParameter_Testing_sequence_of[1] = {
  { &hf_e2ap_RANParameter_Testing_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Testing_Item },
};

static int
dissect_e2ap_RANParameter_Testing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RANParameter_Testing, RANParameter_Testing_sequence_of,
                                                  1, maxnoofRANparamTest, false);

  return offset;
}


static const per_sequence_t EventTrigger_Cell_Info_Item_Choice_Group_sequence[] = {
  { &hf_e2ap_ranParameterTesting, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Testing },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_EventTrigger_Cell_Info_Item_Choice_Group(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_EventTrigger_Cell_Info_Item_Choice_Group, EventTrigger_Cell_Info_Item_Choice_Group_sequence);

  return offset;
}


static const value_string e2ap_T_cellType_vals[] = {
  {   0, "cellType-Choice-Individual" },
  {   1, "cellType-Choice-Group" },
  { 0, NULL }
};

static const per_choice_t T_cellType_choice[] = {
  {   0, &hf_e2ap_cellType_Choice_Individual, ASN1_EXTENSION_ROOT    , dissect_e2ap_EventTrigger_Cell_Info_Item_Choice_Individual },
  {   1, &hf_e2ap_cellType_Choice_Group, ASN1_EXTENSION_ROOT    , dissect_e2ap_EventTrigger_Cell_Info_Item_Choice_Group },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_cellType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_cellType, T_cellType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t EventTrigger_Cell_Info_Item_sequence[] = {
  { &hf_e2ap_eventTriggerCellID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_EventTrigger_Cell_ID },
  { &hf_e2ap_cellType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_cellType },
  { &hf_e2ap_logicalOR      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_EventTrigger_Cell_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_EventTrigger_Cell_Info_Item, EventTrigger_Cell_Info_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item_sequence_of[1] = {
  { &hf_e2ap_cellInfo_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_EventTrigger_Cell_Info_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item, SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item_sequence_of,
                                                  1, maxnoofCellInfo, false);

  return offset;
}


static const per_sequence_t EventTrigger_Cell_Info_sequence[] = {
  { &hf_e2ap_cellInfo_List  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_EventTrigger_Cell_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_EventTrigger_Cell_Info, EventTrigger_Cell_Info_sequence);

  return offset;
}



static int
dissect_e2ap_RIC_EventTrigger_UE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}


static const per_sequence_t EventTrigger_UE_Info_Item_Choice_Individual_sequence[] = {
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_UEID },
  { &hf_e2ap_ranParameterTesting, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Testing },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_EventTrigger_UE_Info_Item_Choice_Individual(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_EventTrigger_UE_Info_Item_Choice_Individual, EventTrigger_UE_Info_Item_Choice_Individual_sequence);

  return offset;
}


static const per_sequence_t EventTrigger_UE_Info_Item_Choice_Group_sequence[] = {
  { &hf_e2ap_ranParameterTesting, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Testing },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_EventTrigger_UE_Info_Item_Choice_Group(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_EventTrigger_UE_Info_Item_Choice_Group, EventTrigger_UE_Info_Item_Choice_Group_sequence);

  return offset;
}


static const value_string e2ap_T_ueType_vals[] = {
  {   0, "ueType-Choice-Individual" },
  {   1, "ueType-Choice-Group" },
  { 0, NULL }
};

static const per_choice_t T_ueType_choice[] = {
  {   0, &hf_e2ap_ueType_Choice_Individual, ASN1_EXTENSION_ROOT    , dissect_e2ap_EventTrigger_UE_Info_Item_Choice_Individual },
  {   1, &hf_e2ap_ueType_Choice_Group, ASN1_EXTENSION_ROOT    , dissect_e2ap_EventTrigger_UE_Info_Item_Choice_Group },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_ueType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_ueType, T_ueType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t EventTrigger_UE_Info_Item_sequence[] = {
  { &hf_e2ap_eventTriggerUEID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_EventTrigger_UE_ID },
  { &hf_e2ap_ueType         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_ueType },
  { &hf_e2ap_logicalOR      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_EventTrigger_UE_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_EventTrigger_UE_Info_Item, EventTrigger_UE_Info_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item_sequence_of[1] = {
  { &hf_e2ap_ueInfo_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_EventTrigger_UE_Info_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item, SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item_sequence_of,
                                                  1, maxnoofUEInfo, false);

  return offset;
}


static const per_sequence_t EventTrigger_UE_Info_sequence[] = {
  { &hf_e2ap_ueInfo_List    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_EventTrigger_UE_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_EventTrigger_UE_Info, EventTrigger_UE_Info_sequence);

  return offset;
}



static int
dissect_e2ap_RIC_EventTrigger_UEevent_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}


static const per_sequence_t EventTrigger_UEevent_Info_Item_sequence[] = {
  { &hf_e2ap_ueEventID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_EventTrigger_UEevent_ID },
  { &hf_e2ap_logicalOR      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_EventTrigger_UEevent_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_EventTrigger_UEevent_Info_Item, EventTrigger_UEevent_Info_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item_sequence_of[1] = {
  { &hf_e2ap_ueEvent_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_EventTrigger_UEevent_Info_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item, SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item_sequence_of,
                                                  1, maxnoofUEeventInfo, false);

  return offset;
}


static const per_sequence_t EventTrigger_UEevent_Info_sequence[] = {
  { &hf_e2ap_ueEvent_List   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_EventTrigger_UEevent_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_EventTrigger_UEevent_Info, EventTrigger_UEevent_Info_sequence);

  return offset;
}



static int
dissect_e2ap_RANParameter_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}


static const per_sequence_t RANParameter_Definition_Choice_LIST_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Name },
  { &hf_e2ap_ranParameter_Definition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_Definition_Choice_LIST_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_Definition_Choice_LIST_Item, RANParameter_Definition_Choice_LIST_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item_sequence_of[1] = {
  { &hf_e2ap_ranParameter_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Definition_Choice_LIST_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item, SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item_sequence_of,
                                                  1, maxnoofItemsinList, false);

  return offset;
}


static const per_sequence_t RANParameter_Definition_Choice_LIST_sequence[] = {
  { &hf_e2ap_ranParameter_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_Definition_Choice_LIST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_Definition_Choice_LIST, RANParameter_Definition_Choice_LIST_sequence);

  return offset;
}


static const per_sequence_t RANParameter_Definition_Choice_STRUCTURE_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Name },
  { &hf_e2ap_ranParameter_Definition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_Definition_Choice_STRUCTURE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_Definition_Choice_STRUCTURE_Item, RANParameter_Definition_Choice_STRUCTURE_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item_sequence_of[1] = {
  { &hf_e2ap_ranParameter_STRUCTURE_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Definition_Choice_STRUCTURE_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item, SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item_sequence_of,
                                                  1, maxnoofParametersinStructure, false);

  return offset;
}


static const per_sequence_t RANParameter_Definition_Choice_STRUCTURE_sequence[] = {
  { &hf_e2ap_ranParameter_STRUCTURE, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_Definition_Choice_STRUCTURE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_Definition_Choice_STRUCTURE, RANParameter_Definition_Choice_STRUCTURE_sequence);

  return offset;
}


static const value_string e2ap_RANParameter_Definition_Choice_vals[] = {
  {   0, "choiceLIST" },
  {   1, "choiceSTRUCTURE" },
  { 0, NULL }
};

static const per_choice_t RANParameter_Definition_Choice_choice[] = {
  {   0, &hf_e2ap_choiceLIST     , ASN1_EXTENSION_ROOT    , dissect_e2ap_RANParameter_Definition_Choice_LIST },
  {   1, &hf_e2ap_choiceSTRUCTURE, ASN1_EXTENSION_ROOT    , dissect_e2ap_RANParameter_Definition_Choice_STRUCTURE },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_RANParameter_Definition_Choice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_RANParameter_Definition_Choice, RANParameter_Definition_Choice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RANParameter_Definition_sequence[] = {
  { &hf_e2ap_ranParameter_Definition_Choice, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Definition_Choice },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_Definition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // RANParameter-Definition -> RANParameter-Definition-Choice -> RANParameter-Definition-Choice-LIST -> RANParameter-Definition-Choice-LIST/ranParameter-List -> RANParameter-Definition-Choice-LIST-Item -> RANParameter-Definition
  actx->pinfo->dissection_depth += 5;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_Definition, RANParameter_Definition_sequence);

  actx->pinfo->dissection_depth -= 5;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const per_sequence_t RANParameter_ValueType_Choice_ElementTrue_sequence[] = {
  { &hf_e2ap_ranParameter_value, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_ValueType_Choice_ElementTrue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_ValueType_Choice_ElementTrue, RANParameter_ValueType_Choice_ElementTrue_sequence);

  return offset;
}


static const per_sequence_t RANParameter_ValueType_Choice_ElementFalse_sequence[] = {
  { &hf_e2ap_ranParameter_value, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_ValueType_Choice_ElementFalse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_ValueType_Choice_ElementFalse, RANParameter_ValueType_Choice_ElementFalse_sequence);

  return offset;
}


static const per_sequence_t RANParameter_STRUCTURE_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_STRUCTURE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_STRUCTURE_Item, RANParameter_STRUCTURE_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item_sequence_of[1] = {
  { &hf_e2ap_sequence_of_ranParameters_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_STRUCTURE_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item, SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item_sequence_of,
                                                  1, maxnoofParametersinStructure, false);

  return offset;
}


static const per_sequence_t RANParameter_STRUCTURE_sequence[] = {
  { &hf_e2ap_sequence_of_ranParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_STRUCTURE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_STRUCTURE, RANParameter_STRUCTURE_sequence);

  return offset;
}


static const per_sequence_t RANParameter_ValueType_Choice_Structure_sequence[] = {
  { &hf_e2ap_ranParameter_Structure, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_STRUCTURE },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_ValueType_Choice_Structure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_ValueType_Choice_Structure, RANParameter_ValueType_Choice_Structure_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE_sequence_of[1] = {
  { &hf_e2ap_list_of_ranParameter_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_STRUCTURE },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE, SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE_sequence_of,
                                                  1, maxnoofItemsinList, false);

  return offset;
}


static const per_sequence_t RANParameter_LIST_sequence[] = {
  { &hf_e2ap_list_of_ranParameter, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_LIST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_LIST, RANParameter_LIST_sequence);

  return offset;
}


static const per_sequence_t RANParameter_ValueType_Choice_List_sequence[] = {
  { &hf_e2ap_ranParameter_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_LIST },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANParameter_ValueType_Choice_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_ValueType_Choice_List, RANParameter_ValueType_Choice_List_sequence);

  return offset;
}


static const value_string e2ap_RANParameter_ValueType_vals[] = {
  {   0, "ranP-Choice-ElementTrue" },
  {   1, "ranP-Choice-ElementFalse" },
  {   2, "ranP-Choice-Structure" },
  {   3, "ranP-Choice-List" },
  { 0, NULL }
};

static const per_choice_t RANParameter_ValueType_choice[] = {
  {   0, &hf_e2ap_ranP_Choice_ElementTrue, ASN1_EXTENSION_ROOT    , dissect_e2ap_RANParameter_ValueType_Choice_ElementTrue },
  {   1, &hf_e2ap_ranP_Choice_ElementFalse, ASN1_EXTENSION_ROOT    , dissect_e2ap_RANParameter_ValueType_Choice_ElementFalse },
  {   2, &hf_e2ap_ranP_Choice_Structure, ASN1_EXTENSION_ROOT    , dissect_e2ap_RANParameter_ValueType_Choice_Structure },
  {   3, &hf_e2ap_ranP_Choice_List, ASN1_EXTENSION_ROOT    , dissect_e2ap_RANParameter_ValueType_Choice_List },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_RANParameter_ValueType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // RANParameter-ValueType -> RANParameter-ValueType-Choice-Structure -> RANParameter-STRUCTURE -> RANParameter-STRUCTURE/sequence-of-ranParameters -> RANParameter-STRUCTURE-Item -> RANParameter-ValueType
  actx->pinfo->dissection_depth += 5;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_RANParameter_ValueType, RANParameter_ValueType_choice,
                                 NULL);

  actx->pinfo->dissection_depth -= 5;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}



static int
dissect_e2ap_RAN_CallProcess_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 232U, NULL, true);

  return offset;
}



static int
dissect_e2ap_RIC_CallProcessType_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_e2ap_RIC_CallProcessType_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_e2ap_RIC_CallProcessBreakpoint_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_e2ap_RIC_CallProcessBreakpoint_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_e2ap_RIC_ControlAction_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_e2ap_RIC_ControlAction_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_e2ap_RIC_EventTriggerCondition_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_e2ap_RIC_InsertIndication_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_e2ap_RIC_InsertIndication_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}


static const per_sequence_t RIC_PolicyAction_RANParameter_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RIC_PolicyAction_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RIC_PolicyAction_RANParameter_Item, RIC_PolicyAction_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item_sequence_of[1] = {
  { &hf_e2ap_ranParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_PolicyAction_RANParameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const value_string e2ap_T_ric_PolicyDecision_vals[] = {
  {   0, "accept" },
  {   1, "reject" },
  { 0, NULL }
};


static int
dissect_e2ap_T_ric_PolicyDecision(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t RIC_PolicyAction_sequence[] = {
  { &hf_e2ap_ric_PolicyAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_ControlAction_ID },
  { &hf_e2ap_ranParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item },
  { &hf_e2ap_ric_PolicyDecision, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_T_ric_PolicyDecision },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RIC_PolicyAction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RIC_PolicyAction, RIC_PolicyAction_sequence);

  return offset;
}


static const per_sequence_t MessageType_Choice_NI_sequence[] = {
  { &hf_e2ap_nI_Type        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_InterfaceType },
  { &hf_e2ap_nI_Identifier  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_InterfaceIdentifier },
  { &hf_e2ap_nI_Message     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_Interface_MessageID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MessageType_Choice_NI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MessageType_Choice_NI, MessageType_Choice_NI_sequence);

  return offset;
}


static const per_sequence_t MessageType_Choice_RRC_sequence[] = {
  { &hf_e2ap_rRC_Message    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RRC_MessageID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MessageType_Choice_RRC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MessageType_Choice_RRC, MessageType_Choice_RRC_sequence);

  return offset;
}


static const value_string e2ap_MessageType_Choice_vals[] = {
  {   0, "messageType-Choice-NI" },
  {   1, "messageType-Choice-RRC" },
  { 0, NULL }
};

static const per_choice_t MessageType_Choice_choice[] = {
  {   0, &hf_e2ap_messageType_Choice_NI, ASN1_EXTENSION_ROOT    , dissect_e2ap_MessageType_Choice_NI },
  {   1, &hf_e2ap_messageType_Choice_RRC, ASN1_EXTENSION_ROOT    , dissect_e2ap_MessageType_Choice_RRC },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_MessageType_Choice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_MessageType_Choice, MessageType_Choice_choice,
                                 NULL);

  return offset;
}


static const value_string e2ap_T_messageDirection_vals[] = {
  {   0, "incoming" },
  {   1, "outgoing" },
  { 0, NULL }
};


static int
dissect_e2ap_T_messageDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format1_Item_sequence[] = {
  { &hf_e2ap_ric_eventTriggerCondition_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_EventTriggerCondition_ID },
  { &hf_e2ap_messageType_01 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MessageType_Choice },
  { &hf_e2ap_messageDirection, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_T_messageDirection },
  { &hf_e2ap_associatedUEInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_EventTrigger_UE_Info },
  { &hf_e2ap_associatedUEEvent, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_EventTrigger_UEevent_Info },
  { &hf_e2ap_logicalOR      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_EventTrigger_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_EventTrigger_Format1_Item, E2SM_RC_EventTrigger_Format1_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item_sequence_of[1] = {
  { &hf_e2ap_message_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_EventTrigger_Format1_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item, SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item_sequence_of,
                                                  1, maxnoofMessages, false);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format1_sequence[] = {
  { &hf_e2ap_message_List   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item },
  { &hf_e2ap_globalAssociatedUEInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_EventTrigger_UE_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_EventTrigger_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_EventTrigger_Format1, E2SM_RC_EventTrigger_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format2_sequence[] = {
  { &hf_e2ap_ric_callProcessType_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_CallProcessType_ID },
  { &hf_e2ap_ric_callProcessBreakpoint_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_CallProcessBreakpoint_ID },
  { &hf_e2ap_associatedE2NodeInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Testing },
  { &hf_e2ap_associatedUEInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_EventTrigger_UE_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_EventTrigger_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_EventTrigger_Format2, E2SM_RC_EventTrigger_Format2_sequence);

  return offset;
}



static int
dissect_e2ap_INTEGER_1_512_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 512U, NULL, true);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format3_Item_sequence[] = {
  { &hf_e2ap_ric_eventTriggerCondition_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_EventTriggerCondition_ID },
  { &hf_e2ap_e2NodeInfoChange_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_1_512_ },
  { &hf_e2ap_associatedCellInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_EventTrigger_Cell_Info },
  { &hf_e2ap_logicalOR      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_EventTrigger_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_EventTrigger_Format3_Item, E2SM_RC_EventTrigger_Format3_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item_sequence_of[1] = {
  { &hf_e2ap_e2NodeInfoChange_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_EventTrigger_Format3_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item, SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item_sequence_of,
                                                  1, maxnoofE2InfoChanges, false);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format3_sequence[] = {
  { &hf_e2ap_e2NodeInfoChange_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_EventTrigger_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_EventTrigger_Format3, E2SM_RC_EventTrigger_Format3_sequence);

  return offset;
}


static const per_sequence_t TriggerType_Choice_RRCstate_Item_sequence[] = {
  { &hf_e2ap_stateChangedTo , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RRC_State },
  { &hf_e2ap_logicalOR      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_TriggerType_Choice_RRCstate_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_TriggerType_Choice_RRCstate_Item, TriggerType_Choice_RRCstate_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item_sequence_of[1] = {
  { &hf_e2ap_rrcState_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_TriggerType_Choice_RRCstate_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item, SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item_sequence_of,
                                                  1, maxnoofRRCstate, false);

  return offset;
}


static const per_sequence_t TriggerType_Choice_RRCstate_sequence[] = {
  { &hf_e2ap_rrcState_List  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_TriggerType_Choice_RRCstate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_TriggerType_Choice_RRCstate, TriggerType_Choice_RRCstate_sequence);

  return offset;
}


static const per_sequence_t TriggerType_Choice_UEID_sequence[] = {
  { &hf_e2ap_ueIDchange_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_1_512_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_TriggerType_Choice_UEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_TriggerType_Choice_UEID, TriggerType_Choice_UEID_sequence);

  return offset;
}


static const per_sequence_t TriggerType_Choice_L2state_sequence[] = {
  { &hf_e2ap_associatedL2variables, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Testing },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_TriggerType_Choice_L2state(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_TriggerType_Choice_L2state, TriggerType_Choice_L2state_sequence);

  return offset;
}


static const value_string e2ap_TriggerType_Choice_vals[] = {
  {   0, "triggerType-Choice-RRCstate" },
  {   1, "triggerType-Choice-UEID" },
  {   2, "triggerType-Choice-L2state" },
  { 0, NULL }
};

static const per_choice_t TriggerType_Choice_choice[] = {
  {   0, &hf_e2ap_triggerType_Choice_RRCstate, ASN1_EXTENSION_ROOT    , dissect_e2ap_TriggerType_Choice_RRCstate },
  {   1, &hf_e2ap_triggerType_Choice_UEID, ASN1_EXTENSION_ROOT    , dissect_e2ap_TriggerType_Choice_UEID },
  {   2, &hf_e2ap_triggerType_Choice_L2state, ASN1_EXTENSION_ROOT    , dissect_e2ap_TriggerType_Choice_L2state },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_TriggerType_Choice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_TriggerType_Choice, TriggerType_Choice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format4_Item_sequence[] = {
  { &hf_e2ap_ric_eventTriggerCondition_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_EventTriggerCondition_ID },
  { &hf_e2ap_triggerType    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_TriggerType_Choice },
  { &hf_e2ap_associatedUEInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_EventTrigger_UE_Info },
  { &hf_e2ap_logicalOR      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_EventTrigger_Format4_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_EventTrigger_Format4_Item, E2SM_RC_EventTrigger_Format4_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item_sequence_of[1] = {
  { &hf_e2ap_uEInfoChange_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_EventTrigger_Format4_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item, SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item_sequence_of,
                                                  1, maxnoofUEInfoChanges, false);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format4_sequence[] = {
  { &hf_e2ap_uEInfoChange_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_EventTrigger_Format4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_EventTrigger_Format4, E2SM_RC_EventTrigger_Format4_sequence);

  return offset;
}


static const value_string e2ap_T_onDemand_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_onDemand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format5_sequence[] = {
  { &hf_e2ap_onDemand       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_onDemand },
  { &hf_e2ap_associatedUEInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_EventTrigger_UE_Info },
  { &hf_e2ap_associatedCellInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_EventTrigger_Cell_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_EventTrigger_Format5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_EventTrigger_Format5, E2SM_RC_EventTrigger_Format5_sequence);

  return offset;
}


static const value_string e2ap_T_ric_eventTrigger_formats_vals[] = {
  {   0, "eventTrigger-Format1" },
  {   1, "eventTrigger-Format2" },
  {   2, "eventTrigger-Format3" },
  {   3, "eventTrigger-Format4" },
  {   4, "eventTrigger-Format5" },
  { 0, NULL }
};

static const per_choice_t T_ric_eventTrigger_formats_choice[] = {
  {   0, &hf_e2ap_eventTrigger_Format1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_EventTrigger_Format1 },
  {   1, &hf_e2ap_eventTrigger_Format2, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_EventTrigger_Format2 },
  {   2, &hf_e2ap_eventTrigger_Format3, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_EventTrigger_Format3 },
  {   3, &hf_e2ap_eventTrigger_Format4, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_EventTrigger_Format4 },
  {   4, &hf_e2ap_eventTrigger_Format5, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_EventTrigger_Format5 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_ric_eventTrigger_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_ric_eventTrigger_formats, T_ric_eventTrigger_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_sequence[] = {
  { &hf_e2ap_ric_eventTrigger_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_ric_eventTrigger_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_EventTrigger(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_EventTrigger, E2SM_RC_EventTrigger_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format1_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ActionDefinition_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ActionDefinition_Format1_Item, E2SM_RC_ActionDefinition_Format1_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item_sequence_of[1] = {
  { &hf_e2ap_ranP_ToBeReported_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ActionDefinition_Format1_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item, SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item_sequence_of,
                                                  1, maxnoofParametersToReport, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format1_sequence[] = {
  { &hf_e2ap_ranP_ToBeReported_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ActionDefinition_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ActionDefinition_Format1, E2SM_RC_ActionDefinition_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format2_Item_sequence[] = {
  { &hf_e2ap_ric_PolicyAction, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_PolicyAction },
  { &hf_e2ap_ric_PolicyConditionDefinition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Testing },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ActionDefinition_Format2_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ActionDefinition_Format2_Item, E2SM_RC_ActionDefinition_Format2_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item_sequence_of[1] = {
  { &hf_e2ap_ric_PolicyConditions_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ActionDefinition_Format2_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item, SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item_sequence_of,
                                                  1, maxnoofPolicyConditions, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format2_sequence[] = {
  { &hf_e2ap_ric_PolicyConditions_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ActionDefinition_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ActionDefinition_Format2, E2SM_RC_ActionDefinition_Format2_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format3_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ActionDefinition_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ActionDefinition_Format3_Item, E2SM_RC_ActionDefinition_Format3_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item_sequence_of[1] = {
  { &hf_e2ap_ranP_InsertIndication_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ActionDefinition_Format3_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format3_sequence[] = {
  { &hf_e2ap_ric_InsertIndication_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_InsertIndication_ID },
  { &hf_e2ap_ranP_InsertIndication_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item },
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_UEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ActionDefinition_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ActionDefinition_Format3, E2SM_RC_ActionDefinition_Format3_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format4_RANP_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ActionDefinition_Format4_RANP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ActionDefinition_Format4_RANP_Item, E2SM_RC_ActionDefinition_Format4_RANP_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item_sequence_of[1] = {
  { &hf_e2ap_ranP_InsertIndication_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ActionDefinition_Format4_RANP_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format4_Indication_Item_sequence[] = {
  { &hf_e2ap_ric_InsertIndication_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_InsertIndication_ID },
  { &hf_e2ap_ranP_InsertIndication_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ActionDefinition_Format4_Indication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ActionDefinition_Format4_Indication_Item, E2SM_RC_ActionDefinition_Format4_Indication_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item_sequence_of[1] = {
  { &hf_e2ap_ric_InsertIndication_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ActionDefinition_Format4_Indication_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item, SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item_sequence_of,
                                                  1, maxnoofInsertIndicationActions, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format4_Style_Item_sequence[] = {
  { &hf_e2ap_requested_Insert_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_InsertIndication_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ActionDefinition_Format4_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ActionDefinition_Format4_Style_Item, E2SM_RC_ActionDefinition_Format4_Style_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item_sequence_of[1] = {
  { &hf_e2ap_ric_InsertStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ActionDefinition_Format4_Style_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format4_sequence[] = {
  { &hf_e2ap_ric_InsertStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item },
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_UEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ActionDefinition_Format4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ActionDefinition_Format4, E2SM_RC_ActionDefinition_Format4_sequence);

  return offset;
}


static const value_string e2ap_T_ric_actionDefinition_formats_vals[] = {
  {   0, "actionDefinition-Format1" },
  {   1, "actionDefinition-Format2" },
  {   2, "actionDefinition-Format3" },
  {   3, "actionDefinition-Format4" },
  { 0, NULL }
};

static const per_choice_t T_ric_actionDefinition_formats_choice[] = {
  {   0, &hf_e2ap_actionDefinition_Format1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_ActionDefinition_Format1 },
  {   1, &hf_e2ap_actionDefinition_Format2, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_ActionDefinition_Format2 },
  {   2, &hf_e2ap_actionDefinition_Format3, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_ActionDefinition_Format3 },
  {   3, &hf_e2ap_actionDefinition_Format4, ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_E2SM_RC_ActionDefinition_Format4 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_ric_actionDefinition_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_ric_actionDefinition_formats, T_ric_actionDefinition_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_sequence[] = {
  { &hf_e2ap_ric_Style_Type , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_actionDefinition_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_ric_actionDefinition_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ActionDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ActionDefinition, E2SM_RC_ActionDefinition_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationHeader_Format1_sequence[] = {
  { &hf_e2ap_ric_eventTriggerCondition_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RIC_EventTriggerCondition_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationHeader_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationHeader_Format1, E2SM_RC_IndicationHeader_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationHeader_Format2_sequence[] = {
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_UEID },
  { &hf_e2ap_ric_InsertStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_InsertIndication_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_InsertIndication_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationHeader_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationHeader_Format2, E2SM_RC_IndicationHeader_Format2_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationHeader_Format3_sequence[] = {
  { &hf_e2ap_ric_eventTriggerCondition_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RIC_EventTriggerCondition_ID },
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_UEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationHeader_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationHeader_Format3, E2SM_RC_IndicationHeader_Format3_sequence);

  return offset;
}


static const value_string e2ap_T_ric_indicationHeader_formats_vals[] = {
  {   0, "indicationHeader-Format1" },
  {   1, "indicationHeader-Format2" },
  {   2, "indicationHeader-Format3" },
  { 0, NULL }
};

static const per_choice_t T_ric_indicationHeader_formats_choice[] = {
  {   0, &hf_e2ap_indicationHeader_Format1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_IndicationHeader_Format1 },
  {   1, &hf_e2ap_indicationHeader_Format2, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_IndicationHeader_Format2 },
  {   2, &hf_e2ap_indicationHeader_Format3, ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_E2SM_RC_IndicationHeader_Format3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_ric_indicationHeader_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_ric_indicationHeader_formats, T_ric_indicationHeader_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationHeader_sequence[] = {
  { &hf_e2ap_ric_indicationHeader_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_ric_indicationHeader_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationHeader, E2SM_RC_IndicationHeader_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format1_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format1_Item, E2SM_RC_IndicationMessage_Format1_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item_sequence_of[1] = {
  { &hf_e2ap_ranP_Reported_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_IndicationMessage_Format1_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format1_sequence[] = {
  { &hf_e2ap_ranP_Reported_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format1, E2SM_RC_IndicationMessage_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format2_RANParameter_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format2_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format2_RANParameter_Item, E2SM_RC_IndicationMessage_Format2_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item_sequence_of[1] = {
  { &hf_e2ap_ranP_List_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_IndicationMessage_Format2_RANParameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format2_Item_sequence[] = {
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_UEID },
  { &hf_e2ap_ranP_List      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format2_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format2_Item, E2SM_RC_IndicationMessage_Format2_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item_sequence_of[1] = {
  { &hf_e2ap_ueParameter_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_IndicationMessage_Format2_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item, SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item_sequence_of,
                                                  1, maxnoofUEID, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format2_sequence[] = {
  { &hf_e2ap_ueParameter_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format2, E2SM_RC_IndicationMessage_Format2_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format3_Item_sequence[] = {
  { &hf_e2ap_cellGlobal_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_CGI },
  { &hf_e2ap_cellContextInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_OCTET_STRING },
  { &hf_e2ap_cellDeleted    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_BOOLEAN },
  { &hf_e2ap_neighborRelation_Table, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_NeighborRelation_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format3_Item, E2SM_RC_IndicationMessage_Format3_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item_sequence_of[1] = {
  { &hf_e2ap_cellInfo_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_IndicationMessage_Format3_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item, SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item_sequence_of,
                                                  1, maxnoofCellID, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format3_sequence[] = {
  { &hf_e2ap_cellInfo_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format3, E2SM_RC_IndicationMessage_Format3_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format4_ItemUE_sequence[] = {
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_UEID },
  { &hf_e2ap_ueContextInfo  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_OCTET_STRING },
  { &hf_e2ap_cellGlobal_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_CGI },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format4_ItemUE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format4_ItemUE, E2SM_RC_IndicationMessage_Format4_ItemUE_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format4_ItemUE_sequence_of[1] = {
  { &hf_e2ap_ueInfo_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_IndicationMessage_Format4_ItemUE },
};

static int
dissect_e2ap_SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format4_ItemUE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format4_ItemUE, SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format4_ItemUE_sequence_of,
                                                  0, maxnoofUEID, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format4_ItemCell_sequence[] = {
  { &hf_e2ap_cellGlobal_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_CGI },
  { &hf_e2ap_cellContextInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_OCTET_STRING },
  { &hf_e2ap_neighborRelation_Table, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_NeighborRelation_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format4_ItemCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format4_ItemCell, E2SM_RC_IndicationMessage_Format4_ItemCell_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format4_ItemCell_sequence_of[1] = {
  { &hf_e2ap_cellInfo_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_IndicationMessage_Format4_ItemCell },
};

static int
dissect_e2ap_SEQUENCE_SIZE_0_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format4_ItemCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_0_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format4_ItemCell, SEQUENCE_SIZE_0_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format4_ItemCell_sequence_of,
                                                  0, maxnoofCellID, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format4_sequence[] = {
  { &hf_e2ap_ueInfo_List_01 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format4_ItemUE },
  { &hf_e2ap_cellInfo_List_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_0_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format4_ItemCell },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format4, E2SM_RC_IndicationMessage_Format4_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format5_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format5_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format5_Item, E2SM_RC_IndicationMessage_Format5_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item_sequence_of[1] = {
  { &hf_e2ap_ranP_Requested_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_IndicationMessage_Format5_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item, SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item_sequence_of,
                                                  0, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format5_sequence[] = {
  { &hf_e2ap_ranP_Requested_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format5, E2SM_RC_IndicationMessage_Format5_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format6_RANP_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format6_RANP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format6_RANP_Item, E2SM_RC_IndicationMessage_Format6_RANP_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item_sequence_of[1] = {
  { &hf_e2ap_ranP_InsertIndication_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_IndicationMessage_Format6_RANP_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item, SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item_sequence_of,
                                                  0, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format6_Indication_Item_sequence[] = {
  { &hf_e2ap_ric_InsertIndication_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_InsertIndication_ID },
  { &hf_e2ap_ranP_InsertIndication_List_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format6_Indication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format6_Indication_Item, E2SM_RC_IndicationMessage_Format6_Indication_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item_sequence_of[1] = {
  { &hf_e2ap_ric_InsertIndication_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_IndicationMessage_Format6_Indication_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item, SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item_sequence_of,
                                                  1, maxnoofInsertIndicationActions, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format6_Style_Item_sequence[] = {
  { &hf_e2ap_indicated_Insert_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_InsertIndication_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format6_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format6_Style_Item, E2SM_RC_IndicationMessage_Format6_Style_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item_sequence_of[1] = {
  { &hf_e2ap_ric_InsertStyle_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_IndicationMessage_Format6_Style_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format6_sequence[] = {
  { &hf_e2ap_ric_InsertStyle_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage_Format6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage_Format6, E2SM_RC_IndicationMessage_Format6_sequence);

  return offset;
}


static const value_string e2ap_T_ric_indicationMessage_formats_vals[] = {
  {   0, "indicationMessage-Format1" },
  {   1, "indicationMessage-Format2" },
  {   2, "indicationMessage-Format3" },
  {   3, "indicationMessage-Format4" },
  {   4, "indicationMessage-Format5" },
  {   5, "indicationMessage-Format6" },
  { 0, NULL }
};

static const per_choice_t T_ric_indicationMessage_formats_choice[] = {
  {   0, &hf_e2ap_indicationMessage_Format1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_IndicationMessage_Format1 },
  {   1, &hf_e2ap_indicationMessage_Format2, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_IndicationMessage_Format2 },
  {   2, &hf_e2ap_indicationMessage_Format3, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_IndicationMessage_Format3 },
  {   3, &hf_e2ap_indicationMessage_Format4, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_IndicationMessage_Format4 },
  {   4, &hf_e2ap_indicationMessage_Format5, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_IndicationMessage_Format5 },
  {   5, &hf_e2ap_indicationMessage_Format6, ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_E2SM_RC_IndicationMessage_Format6 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_ric_indicationMessage_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_ric_indicationMessage_formats, T_ric_indicationMessage_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_sequence[] = {
  { &hf_e2ap_ric_indicationMessage_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_ric_indicationMessage_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_IndicationMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_IndicationMessage, E2SM_RC_IndicationMessage_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_CallProcessID_Format1_sequence[] = {
  { &hf_e2ap_ric_callProcess_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RAN_CallProcess_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_CallProcessID_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_CallProcessID_Format1, E2SM_RC_CallProcessID_Format1_sequence);

  return offset;
}


static const value_string e2ap_T_ric_callProcessID_formats_vals[] = {
  {   0, "callProcessID-Format1" },
  { 0, NULL }
};

static const per_choice_t T_ric_callProcessID_formats_choice[] = {
  {   0, &hf_e2ap_callProcessID_Format1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_CallProcessID_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_ric_callProcessID_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_ric_callProcessID_formats, T_ric_callProcessID_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_CallProcessID_sequence[] = {
  { &hf_e2ap_ric_callProcessID_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_ric_callProcessID_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_CallProcessID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_CallProcessID, E2SM_RC_CallProcessID_sequence);

  return offset;
}


static const value_string e2ap_T_ric_ControlDecision_vals[] = {
  {   0, "accept" },
  {   1, "reject" },
  { 0, NULL }
};


static int
dissect_e2ap_T_ric_ControlDecision(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlHeader_Format1_sequence[] = {
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_UEID },
  { &hf_e2ap_ric_Style_Type , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_ControlAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_ControlAction_ID },
  { &hf_e2ap_ric_ControlDecision, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_T_ric_ControlDecision },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlHeader_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlHeader_Format1, E2SM_RC_ControlHeader_Format1_sequence);

  return offset;
}


static const value_string e2ap_T_ric_ControlDecision_01_vals[] = {
  {   0, "accept" },
  {   1, "reject" },
  { 0, NULL }
};


static int
dissect_e2ap_T_ric_ControlDecision_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlHeader_Format2_sequence[] = {
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_UEID },
  { &hf_e2ap_ric_ControlDecision_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_T_ric_ControlDecision_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlHeader_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlHeader_Format2, E2SM_RC_ControlHeader_Format2_sequence);

  return offset;
}


static const value_string e2ap_T_ric_controlHeader_formats_vals[] = {
  {   0, "controlHeader-Format1" },
  {   1, "controlHeader-Format2" },
  { 0, NULL }
};

static const per_choice_t T_ric_controlHeader_formats_choice[] = {
  {   0, &hf_e2ap_controlHeader_Format1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_ControlHeader_Format1 },
  {   1, &hf_e2ap_controlHeader_Format2, ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_E2SM_RC_ControlHeader_Format2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_ric_controlHeader_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_ric_controlHeader_formats, T_ric_controlHeader_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlHeader_sequence[] = {
  { &hf_e2ap_ric_controlHeader_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_ric_controlHeader_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlHeader, E2SM_RC_ControlHeader_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_Format1_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlMessage_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlMessage_Format1_Item, E2SM_RC_ControlMessage_Format1_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item_sequence_of[1] = {
  { &hf_e2ap_ranP_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ControlMessage_Format1_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item, SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item_sequence_of,
                                                  0, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_Format1_sequence[] = {
  { &hf_e2ap_ranP_List_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlMessage_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlMessage_Format1, E2SM_RC_ControlMessage_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_Format2_ControlAction_Item_sequence[] = {
  { &hf_e2ap_ric_ControlAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_ControlAction_ID },
  { &hf_e2ap_ranP_List_02   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ControlMessage_Format1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlMessage_Format2_ControlAction_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlMessage_Format2_ControlAction_Item, E2SM_RC_ControlMessage_Format2_ControlAction_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item_sequence_of[1] = {
  { &hf_e2ap_ric_ControlAction_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ControlMessage_Format2_ControlAction_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item, SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item_sequence_of,
                                                  1, maxnoofMulCtrlActions, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_Format2_Style_Item_sequence[] = {
  { &hf_e2ap_indicated_Control_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_ControlAction_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlMessage_Format2_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlMessage_Format2_Style_Item, E2SM_RC_ControlMessage_Format2_Style_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item_sequence_of[1] = {
  { &hf_e2ap_ric_ControlStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ControlMessage_Format2_Style_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_Format2_sequence[] = {
  { &hf_e2ap_ric_ControlStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlMessage_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlMessage_Format2, E2SM_RC_ControlMessage_Format2_sequence);

  return offset;
}


static const value_string e2ap_T_ric_controlMessage_formats_vals[] = {
  {   0, "controlMessage-Format1" },
  {   1, "controlMessage-Format2" },
  { 0, NULL }
};

static const per_choice_t T_ric_controlMessage_formats_choice[] = {
  {   0, &hf_e2ap_controlMessage_Format1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_ControlMessage_Format1 },
  {   1, &hf_e2ap_controlMessage_Format2, ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_E2SM_RC_ControlMessage_Format2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_ric_controlMessage_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_ric_controlMessage_formats, T_ric_controlMessage_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_sequence[] = {
  { &hf_e2ap_ric_controlMessage_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_ric_controlMessage_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlMessage, E2SM_RC_ControlMessage_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format1_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_value, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlOutcome_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlOutcome_Format1_Item, E2SM_RC_ControlOutcome_Format1_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item_sequence_of[1] = {
  { &hf_e2ap_ranP_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ControlOutcome_Format1_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item, SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item_sequence_of,
                                                  0, maxnoofRANOutcomeParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format1_sequence[] = {
  { &hf_e2ap_ranP_List_03   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlOutcome_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlOutcome_Format1, E2SM_RC_ControlOutcome_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format2_RANP_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_value, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlOutcome_Format2_RANP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlOutcome_Format2_RANP_Item, E2SM_RC_ControlOutcome_Format2_RANP_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item_sequence_of[1] = {
  { &hf_e2ap_ranP_List_item_03, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ControlOutcome_Format2_RANP_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item_sequence[] = {
  { &hf_e2ap_ric_ControlAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_ControlAction_ID },
  { &hf_e2ap_ranP_List_04   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item, E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item_sequence_of[1] = {
  { &hf_e2ap_ric_ControlOutcome_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item, SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item_sequence_of,
                                                  1, maxnoofMulCtrlActions, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format2_Style_Item_sequence[] = {
  { &hf_e2ap_indicated_Control_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_ControlOutcome_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlOutcome_Format2_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlOutcome_Format2_Style_Item, E2SM_RC_ControlOutcome_Format2_Style_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item_sequence_of[1] = {
  { &hf_e2ap_ric_ControlStyle_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ControlOutcome_Format2_Style_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format2_sequence[] = {
  { &hf_e2ap_ric_ControlStyle_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlOutcome_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlOutcome_Format2, E2SM_RC_ControlOutcome_Format2_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format3_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlOutcome_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlOutcome_Format3_Item, E2SM_RC_ControlOutcome_Format3_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item_sequence_of[1] = {
  { &hf_e2ap_ranP_List_item_04, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_RC_ControlOutcome_Format3_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item, SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item_sequence_of,
                                                  0, maxnoofRANOutcomeParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format3_sequence[] = {
  { &hf_e2ap_ranP_List_05   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlOutcome_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlOutcome_Format3, E2SM_RC_ControlOutcome_Format3_sequence);

  return offset;
}


static const value_string e2ap_T_ric_controlOutcome_formats_vals[] = {
  {   0, "controlOutcome-Format1" },
  {   1, "controlOutcome-Format2" },
  {   2, "controlOutcome-Format3" },
  { 0, NULL }
};

static const per_choice_t T_ric_controlOutcome_formats_choice[] = {
  {   0, &hf_e2ap_controlOutcome_Format1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_RC_ControlOutcome_Format1 },
  {   1, &hf_e2ap_controlOutcome_Format2, ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_E2SM_RC_ControlOutcome_Format2 },
  {   2, &hf_e2ap_controlOutcome_Format3, ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_E2SM_RC_ControlOutcome_Format3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_ric_controlOutcome_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_ric_controlOutcome_formats, T_ric_controlOutcome_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_sequence[] = {
  { &hf_e2ap_ric_controlOutcome_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_ric_controlOutcome_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_ControlOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_ControlOutcome, E2SM_RC_ControlOutcome_sequence);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_EventTrigger_Style_Item_sequence[] = {
  { &hf_e2ap_ric_EventTriggerStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_EventTriggerStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Name },
  { &hf_e2ap_ric_EventTriggerFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_EventTrigger_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_EventTrigger_Style_Item, RANFunctionDefinition_EventTrigger_Style_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item_sequence_of[1] = {
  { &hf_e2ap_ric_EventTriggerStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANFunctionDefinition_EventTrigger_Style_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t L2Parameters_RANParameter_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Name },
  { &hf_e2ap_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_L2Parameters_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_L2Parameters_RANParameter_Item, L2Parameters_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item_sequence_of[1] = {
  { &hf_e2ap_ran_L2Parameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_L2Parameters_RANParameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t CallProcessBreakpoint_RANParameter_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Name },
  { &hf_e2ap_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_CallProcessBreakpoint_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_CallProcessBreakpoint_RANParameter_Item, CallProcessBreakpoint_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item_sequence_of[1] = {
  { &hf_e2ap_ran_CallProcessBreakpointParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_CallProcessBreakpoint_RANParameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_EventTrigger_Breakpoint_Item_sequence[] = {
  { &hf_e2ap_callProcessBreakpoint_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_CallProcessBreakpoint_ID },
  { &hf_e2ap_callProcessBreakpoint_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_CallProcessBreakpoint_Name },
  { &hf_e2ap_ran_CallProcessBreakpointParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_EventTrigger_Breakpoint_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_EventTrigger_Breakpoint_Item, RANFunctionDefinition_EventTrigger_Breakpoint_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item_sequence_of[1] = {
  { &hf_e2ap_callProcessBreakpoints_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANFunctionDefinition_EventTrigger_Breakpoint_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item, SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item_sequence_of,
                                                  1, maxnoofCallProcessBreakpoints, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_EventTrigger_CallProcess_Item_sequence[] = {
  { &hf_e2ap_callProcessType_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_CallProcessType_ID },
  { &hf_e2ap_callProcessType_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_CallProcessType_Name },
  { &hf_e2ap_callProcessBreakpoints_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_EventTrigger_CallProcess_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_EventTrigger_CallProcess_Item, RANFunctionDefinition_EventTrigger_CallProcess_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item_sequence_of[1] = {
  { &hf_e2ap_ran_CallProcessTypes_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANFunctionDefinition_EventTrigger_CallProcess_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item, SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item_sequence_of,
                                                  1, maxnoofCallProcessTypes, false);

  return offset;
}


static const per_sequence_t UEIdentification_RANParameter_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Name },
  { &hf_e2ap_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_UEIdentification_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_UEIdentification_RANParameter_Item, UEIdentification_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item_sequence_of[1] = {
  { &hf_e2ap_ran_UEIdentificationParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_UEIdentification_RANParameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t CellIdentification_RANParameter_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Name },
  { &hf_e2ap_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_CellIdentification_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_CellIdentification_RANParameter_Item, CellIdentification_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item_sequence_of[1] = {
  { &hf_e2ap_ran_CellIdentificationParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_CellIdentification_RANParameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_EventTrigger_sequence[] = {
  { &hf_e2ap_ric_EventTriggerStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item },
  { &hf_e2ap_ran_L2Parameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item },
  { &hf_e2ap_ran_CallProcessTypes_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item },
  { &hf_e2ap_ran_UEIdentificationParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item },
  { &hf_e2ap_ran_CellIdentificationParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_EventTrigger(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_EventTrigger, RANFunctionDefinition_EventTrigger_sequence);

  return offset;
}


static const per_sequence_t Report_RANParameter_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Name },
  { &hf_e2ap_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_Report_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_Report_RANParameter_Item, Report_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item_sequence_of[1] = {
  { &hf_e2ap_ran_ReportParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_Report_RANParameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Report_Item_sequence[] = {
  { &hf_e2ap_ric_ReportStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_ReportStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Name },
  { &hf_e2ap_ric_SupportedEventTriggerStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_ReportActionFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_IndicationHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_IndicationMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ran_ReportParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_Report_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_Report_Item, RANFunctionDefinition_Report_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item_sequence_of[1] = {
  { &hf_e2ap_ric_ReportStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANFunctionDefinition_Report_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Report_sequence[] = {
  { &hf_e2ap_ric_ReportStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_Report(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_Report, RANFunctionDefinition_Report_sequence);

  return offset;
}


static const per_sequence_t InsertIndication_RANParameter_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Name },
  { &hf_e2ap_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_InsertIndication_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_InsertIndication_RANParameter_Item, InsertIndication_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item_sequence_of[1] = {
  { &hf_e2ap_ran_InsertIndicationParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_InsertIndication_RANParameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Insert_Indication_Item_sequence[] = {
  { &hf_e2ap_ric_InsertIndication_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_InsertIndication_ID },
  { &hf_e2ap_ric_InsertIndication_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_InsertIndication_Name },
  { &hf_e2ap_ran_InsertIndicationParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_Insert_Indication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_Insert_Indication_Item, RANFunctionDefinition_Insert_Indication_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item_sequence_of[1] = {
  { &hf_e2ap_ric_InsertIndication_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANFunctionDefinition_Insert_Indication_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item, SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item_sequence_of,
                                                  1, maxnoofInsertIndication, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Insert_Item_sequence[] = {
  { &hf_e2ap_ric_InsertStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_InsertStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Name },
  { &hf_e2ap_ric_SupportedEventTriggerStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_ActionDefinitionFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_InsertIndication_List_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item },
  { &hf_e2ap_ric_IndicationHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_IndicationMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_CallProcessIDFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_Insert_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_Insert_Item, RANFunctionDefinition_Insert_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item_sequence_of[1] = {
  { &hf_e2ap_ric_InsertStyle_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANFunctionDefinition_Insert_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Insert_sequence[] = {
  { &hf_e2ap_ric_InsertStyle_List_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_Insert(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_Insert, RANFunctionDefinition_Insert_sequence);

  return offset;
}


static const per_sequence_t ControlAction_RANParameter_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Name },
  { &hf_e2ap_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_ControlAction_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_ControlAction_RANParameter_Item, ControlAction_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item_sequence_of[1] = {
  { &hf_e2ap_ran_ControlActionParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ControlAction_RANParameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Control_Action_Item_sequence[] = {
  { &hf_e2ap_ric_ControlAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_ControlAction_ID },
  { &hf_e2ap_ric_ControlAction_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_ControlAction_Name },
  { &hf_e2ap_ran_ControlActionParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_Control_Action_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_Control_Action_Item, RANFunctionDefinition_Control_Action_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item_sequence_of[1] = {
  { &hf_e2ap_ric_ControlAction_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANFunctionDefinition_Control_Action_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item, SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item_sequence_of,
                                                  1, maxnoofControlAction, false);

  return offset;
}


static const per_sequence_t ControlOutcome_RANParameter_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Name },
  { &hf_e2ap_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_ControlOutcome_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_ControlOutcome_RANParameter_Item, ControlOutcome_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item_sequence_of[1] = {
  { &hf_e2ap_ran_ControlOutcomeParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ControlOutcome_RANParameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item_sequence_of,
                                                  1, maxnoofRANOutcomeParameters, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Control_Item_sequence[] = {
  { &hf_e2ap_ric_ControlStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_ControlStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Name },
  { &hf_e2ap_ric_ControlAction_List_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item },
  { &hf_e2ap_ric_ControlHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_ControlMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_CallProcessIDFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_ControlOutcomeFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ran_ControlOutcomeParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_Control_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_Control_Item, RANFunctionDefinition_Control_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item_sequence_of[1] = {
  { &hf_e2ap_ric_ControlStyle_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANFunctionDefinition_Control_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Control_sequence[] = {
  { &hf_e2ap_ric_ControlStyle_List_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_Control(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_Control, RANFunctionDefinition_Control_sequence);

  return offset;
}


static const per_sequence_t PolicyAction_RANParameter_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Name },
  { &hf_e2ap_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_PolicyAction_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_PolicyAction_RANParameter_Item, PolicyAction_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item_sequence_of[1] = {
  { &hf_e2ap_ran_PolicyActionParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_PolicyAction_RANParameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t PolicyCondition_RANParameter_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_ID },
  { &hf_e2ap_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Name },
  { &hf_e2ap_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_PolicyCondition_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_PolicyCondition_RANParameter_Item, PolicyCondition_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item_sequence_of[1] = {
  { &hf_e2ap_ran_PolicyConditionParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_PolicyCondition_RANParameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Policy_Action_Item_sequence[] = {
  { &hf_e2ap_ric_PolicyAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_ControlAction_ID },
  { &hf_e2ap_ric_PolicyAction_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_ControlAction_Name },
  { &hf_e2ap_ric_ActionDefinitionFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ran_PolicyActionParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item },
  { &hf_e2ap_ran_PolicyConditionParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_Policy_Action_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_Policy_Action_Item, RANFunctionDefinition_Policy_Action_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item_sequence_of[1] = {
  { &hf_e2ap_ric_PolicyAction_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANFunctionDefinition_Policy_Action_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item, SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item_sequence_of,
                                                  1, maxnoofPolicyAction, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Policy_Item_sequence[] = {
  { &hf_e2ap_ric_PolicyStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_PolicyStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Name },
  { &hf_e2ap_ric_SupportedEventTriggerStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_PolicyAction_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_Policy_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_Policy_Item, RANFunctionDefinition_Policy_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item_sequence_of[1] = {
  { &hf_e2ap_ric_PolicyStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANFunctionDefinition_Policy_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Policy_sequence[] = {
  { &hf_e2ap_ric_PolicyStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANFunctionDefinition_Policy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANFunctionDefinition_Policy, RANFunctionDefinition_Policy_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_RANFunctionDefinition_sequence[] = {
  { &hf_e2ap_ranFunction_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunction_Name },
  { &hf_e2ap_ranFunctionDefinition_EventTrigger, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANFunctionDefinition_EventTrigger },
  { &hf_e2ap_ranFunctionDefinition_Report, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANFunctionDefinition_Report },
  { &hf_e2ap_ranFunctionDefinition_Insert, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANFunctionDefinition_Insert },
  { &hf_e2ap_ranFunctionDefinition_Control, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANFunctionDefinition_Control },
  { &hf_e2ap_ranFunctionDefinition_Policy, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RANFunctionDefinition_Policy },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_RC_RANFunctionDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_RC_RANFunctionDefinition, E2SM_RC_RANFunctionDefinition_sequence);

  return offset;
}



static int
dissect_e2ap_TimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}



static int
dissect_e2ap_BinIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}


static const value_string e2ap_BinRangeValue_vals[] = {
  {   0, "valueInt" },
  {   1, "valueReal" },
  { 0, NULL }
};

static const per_choice_t BinRangeValue_choice[] = {
  {   0, &hf_e2ap_valueInt       , ASN1_EXTENSION_ROOT    , dissect_e2ap_INTEGER },
  {   1, &hf_e2ap_valueReal      , ASN1_EXTENSION_ROOT    , dissect_e2ap_REAL },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_BinRangeValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_BinRangeValue, BinRangeValue_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_GranularityPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_e2ap_MeasurementTypeName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_e2ap_MeasurementTypeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65536U, NULL, true);

  return offset;
}


static const value_string e2ap_MeasurementType_vals[] = {
  {   0, "measName" },
  {   1, "measID" },
  { 0, NULL }
};

static const per_choice_t MeasurementType_choice[] = {
  {   0, &hf_e2ap_measName       , ASN1_EXTENSION_ROOT    , dissect_e2ap_MeasurementTypeName },
  {   1, &hf_e2ap_measID         , ASN1_EXTENSION_ROOT    , dissect_e2ap_MeasurementTypeID },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_MeasurementType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_MeasurementType, MeasurementType_choice,
                                 NULL);

  return offset;
}


static const value_string e2ap_T_noLabel_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_noLabel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e2ap_INTEGER_1_15_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 15U, NULL, true);

  return offset;
}


static const value_string e2ap_T_sUM_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_sUM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_preLabelOverride_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_preLabelOverride(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_startEndInd_vals[] = {
  {   0, "start" },
  {   1, "end" },
  { 0, NULL }
};


static int
dissect_e2ap_T_startEndInd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_min_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_min(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_max_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_max(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_avg_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_avg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e2ap_INTEGER_1_2_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 2U, NULL, true);

  return offset;
}


static const per_sequence_t MeasurementLabel_sequence[] = {
  { &hf_e2ap_noLabel        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_T_noLabel },
  { &hf_e2ap_plmnID         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_PLMNIdentity },
  { &hf_e2ap_sliceID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_S_NSSAI },
  { &hf_e2ap_fiveQI         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_FiveQI },
  { &hf_e2ap_qFI            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_QosFlowIdentifier },
  { &hf_e2ap_qCI            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_QCI },
  { &hf_e2ap_qCImax         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_QCI },
  { &hf_e2ap_qCImin         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_QCI },
  { &hf_e2ap_aRPmax         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_1_15_ },
  { &hf_e2ap_aRPmin         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_1_15_ },
  { &hf_e2ap_bitrateRange   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_1_65535_ },
  { &hf_e2ap_layerMU_MIMO   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_1_65535_ },
  { &hf_e2ap_sUM            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_T_sUM },
  { &hf_e2ap_distBinX       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_1_65535_ },
  { &hf_e2ap_distBinY       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_1_65535_ },
  { &hf_e2ap_distBinZ       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_1_65535_ },
  { &hf_e2ap_preLabelOverride, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_T_preLabelOverride },
  { &hf_e2ap_startEndInd    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_T_startEndInd },
  { &hf_e2ap_min            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_T_min },
  { &hf_e2ap_max            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_T_max },
  { &hf_e2ap_avg            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_T_avg },
  { &hf_e2ap_ssbIndex       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_INTEGER_1_65535_ },
  { &hf_e2ap_nonGoB_BFmode_Index, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_INTEGER_1_65535_ },
  { &hf_e2ap_mIMO_mode_Index, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_INTEGER_1_2_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MeasurementLabel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MeasurementLabel, MeasurementLabel_sequence);

  return offset;
}


static const value_string e2ap_T_gBR_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_gBR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_aMBR_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_aMBR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_isStat_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_isStat(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_isCatM_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_isCatM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_rSRP_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_rSRP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_rSRQ_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_rSRQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_ul_rSRP_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_ul_rSRP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_cQI_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_cQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_fiveQI_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_fiveQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_qCI_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_qCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_T_sNSSAI_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_sNSSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_TestCond_Type_vals[] = {
  {   0, "gBR" },
  {   1, "aMBR" },
  {   2, "isStat" },
  {   3, "isCatM" },
  {   4, "rSRP" },
  {   5, "rSRQ" },
  {   6, "ul-rSRP" },
  {   7, "cQI" },
  {   8, "fiveQI" },
  {   9, "qCI" },
  {  10, "sNSSAI" },
  { 0, NULL }
};

static const per_choice_t TestCond_Type_choice[] = {
  {   0, &hf_e2ap_gBR            , ASN1_EXTENSION_ROOT    , dissect_e2ap_T_gBR },
  {   1, &hf_e2ap_aMBR           , ASN1_EXTENSION_ROOT    , dissect_e2ap_T_aMBR },
  {   2, &hf_e2ap_isStat         , ASN1_EXTENSION_ROOT    , dissect_e2ap_T_isStat },
  {   3, &hf_e2ap_isCatM         , ASN1_EXTENSION_ROOT    , dissect_e2ap_T_isCatM },
  {   4, &hf_e2ap_rSRP           , ASN1_EXTENSION_ROOT    , dissect_e2ap_T_rSRP },
  {   5, &hf_e2ap_rSRQ           , ASN1_EXTENSION_ROOT    , dissect_e2ap_T_rSRQ },
  {   6, &hf_e2ap_ul_rSRP        , ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_T_ul_rSRP },
  {   7, &hf_e2ap_cQI            , ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_T_cQI },
  {   8, &hf_e2ap_fiveQI_01      , ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_T_fiveQI },
  {   9, &hf_e2ap_qCI_01         , ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_T_qCI },
  {  10, &hf_e2ap_sNSSAI         , ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_T_sNSSAI },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_TestCond_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_TestCond_Type, TestCond_Type_choice,
                                 NULL);

  return offset;
}


static const value_string e2ap_TestCond_Expression_vals[] = {
  {   0, "equal" },
  {   1, "greaterthan" },
  {   2, "lessthan" },
  {   3, "contains" },
  {   4, "present" },
  { 0, NULL }
};


static int
dissect_e2ap_TestCond_Expression(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_TestCond_Value_vals[] = {
  {   0, "valueInt" },
  {   1, "valueEnum" },
  {   2, "valueBool" },
  {   3, "valueBitS" },
  {   4, "valueOctS" },
  {   5, "valuePrtS" },
  {   6, "valueReal" },
  { 0, NULL }
};

static const per_choice_t TestCond_Value_choice[] = {
  {   0, &hf_e2ap_valueInt       , ASN1_EXTENSION_ROOT    , dissect_e2ap_INTEGER },
  {   1, &hf_e2ap_valueEnum      , ASN1_EXTENSION_ROOT    , dissect_e2ap_INTEGER },
  {   2, &hf_e2ap_valueBool      , ASN1_EXTENSION_ROOT    , dissect_e2ap_BOOLEAN },
  {   3, &hf_e2ap_valueBitS      , ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING },
  {   4, &hf_e2ap_valueOctS      , ASN1_EXTENSION_ROOT    , dissect_e2ap_OCTET_STRING },
  {   5, &hf_e2ap_valuePrtS      , ASN1_EXTENSION_ROOT    , dissect_e2ap_PrintableString },
  {   6, &hf_e2ap_valueReal      , ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_REAL },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_TestCond_Value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_TestCond_Value, TestCond_Value_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TestCondInfo_sequence[] = {
  { &hf_e2ap_testType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_TestCond_Type },
  { &hf_e2ap_testExpr       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_TestCond_Expression },
  { &hf_e2ap_testValue      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_TestCond_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_TestCondInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_TestCondInfo, TestCondInfo_sequence);

  return offset;
}


static const per_sequence_t BinRangeItem_sequence[] = {
  { &hf_e2ap_binIndex       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_BinIndex },
  { &hf_e2ap_startValue     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_BinRangeValue },
  { &hf_e2ap_endValue       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_BinRangeValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_BinRangeItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_BinRangeItem, BinRangeItem_sequence);

  return offset;
}


static const per_sequence_t BinRangeList_sequence_of[1] = {
  { &hf_e2ap_BinRangeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_BinRangeItem },
};

static int
dissect_e2ap_BinRangeList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_BinRangeList, BinRangeList_sequence_of,
                                                  1, maxnoofBin, false);

  return offset;
}


static const per_sequence_t BinRangeDefinition_sequence[] = {
  { &hf_e2ap_binRangeListX  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_BinRangeList },
  { &hf_e2ap_binRangeListY  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_BinRangeList },
  { &hf_e2ap_binRangeListZ  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_BinRangeList },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_BinRangeDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_BinRangeDefinition, BinRangeDefinition_sequence);

  return offset;
}


static const per_sequence_t DistMeasurementBinRangeItem_sequence[] = {
  { &hf_e2ap_measType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementType },
  { &hf_e2ap_binRangeDef    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_BinRangeDefinition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_DistMeasurementBinRangeItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_DistMeasurementBinRangeItem, DistMeasurementBinRangeItem_sequence);

  return offset;
}


static const per_sequence_t DistMeasurementBinRangeList_sequence_of[1] = {
  { &hf_e2ap_DistMeasurementBinRangeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_DistMeasurementBinRangeItem },
};

static int
dissect_e2ap_DistMeasurementBinRangeList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_DistMeasurementBinRangeList, DistMeasurementBinRangeList_sequence_of,
                                                  1, maxnoofMeasurementInfo, false);

  return offset;
}


static const per_sequence_t LabelInfoItem_sequence[] = {
  { &hf_e2ap_measLabel      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementLabel },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_LabelInfoItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_LabelInfoItem, LabelInfoItem_sequence);

  return offset;
}


static const per_sequence_t LabelInfoList_sequence_of[1] = {
  { &hf_e2ap_LabelInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_LabelInfoItem },
};

static int
dissect_e2ap_LabelInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_LabelInfoList, LabelInfoList_sequence_of,
                                                  1, maxnoofLabelInfo, false);

  return offset;
}


static const per_sequence_t MeasurementInfoItem_sequence[] = {
  { &hf_e2ap_measType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementType },
  { &hf_e2ap_labelInfoList  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_LabelInfoList },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MeasurementInfoItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MeasurementInfoItem, MeasurementInfoItem_sequence);

  return offset;
}


static const per_sequence_t MeasurementInfoList_sequence_of[1] = {
  { &hf_e2ap_MeasurementInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementInfoItem },
};

static int
dissect_e2ap_MeasurementInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_MeasurementInfoList, MeasurementInfoList_sequence_of,
                                                  1, maxnoofMeasurementInfo, false);

  return offset;
}



static int
dissect_e2ap_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_e2ap_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string e2ap_MeasurementRecordItem_vals[] = {
  {   0, "integer" },
  {   1, "real" },
  {   2, "noValue" },
  { 0, NULL }
};

static const per_choice_t MeasurementRecordItem_choice[] = {
  {   0, &hf_e2ap_integer        , ASN1_EXTENSION_ROOT    , dissect_e2ap_INTEGER_0_4294967295 },
  {   1, &hf_e2ap_real           , ASN1_EXTENSION_ROOT    , dissect_e2ap_REAL },
  {   2, &hf_e2ap_noValue        , ASN1_EXTENSION_ROOT    , dissect_e2ap_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_MeasurementRecordItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_MeasurementRecordItem, MeasurementRecordItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MeasurementRecord_sequence_of[1] = {
  { &hf_e2ap_MeasurementRecord_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementRecordItem },
};

static int
dissect_e2ap_MeasurementRecord(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_MeasurementRecord, MeasurementRecord_sequence_of,
                                                  1, maxnoofMeasurementValue, false);

  return offset;
}


static const value_string e2ap_T_incompleteFlag_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_incompleteFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MeasurementDataItem_sequence[] = {
  { &hf_e2ap_measRecord     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementRecord },
  { &hf_e2ap_incompleteFlag , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_T_incompleteFlag },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MeasurementDataItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MeasurementDataItem, MeasurementDataItem_sequence);

  return offset;
}


static const per_sequence_t MeasurementData_sequence_of[1] = {
  { &hf_e2ap_MeasurementData_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementDataItem },
};

static int
dissect_e2ap_MeasurementData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_MeasurementData, MeasurementData_sequence_of,
                                                  1, maxnoofMeasurementRecord, false);

  return offset;
}


static const per_sequence_t MeasurementInfo_Action_Item_sequence[] = {
  { &hf_e2ap_measName       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementTypeName },
  { &hf_e2ap_measID         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_MeasurementTypeID },
  { &hf_e2ap_binRangeDef    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_BinRangeDefinition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MeasurementInfo_Action_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MeasurementInfo_Action_Item, MeasurementInfo_Action_Item_sequence);

  return offset;
}


static const per_sequence_t MeasurementInfo_Action_List_sequence_of[1] = {
  { &hf_e2ap_MeasurementInfo_Action_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementInfo_Action_Item },
};

static int
dissect_e2ap_MeasurementInfo_Action_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_MeasurementInfo_Action_List, MeasurementInfo_Action_List_sequence_of,
                                                  1, maxnoofMeasurementInfo, false);

  return offset;
}


static const value_string e2ap_MatchingCondItem_Choice_vals[] = {
  {   0, "measLabel" },
  {   1, "testCondInfo" },
  { 0, NULL }
};

static const per_choice_t MatchingCondItem_Choice_choice[] = {
  {   0, &hf_e2ap_measLabel      , ASN1_EXTENSION_ROOT    , dissect_e2ap_MeasurementLabel },
  {   1, &hf_e2ap_testCondInfo   , ASN1_EXTENSION_ROOT    , dissect_e2ap_TestCondInfo },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_MatchingCondItem_Choice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_MatchingCondItem_Choice, MatchingCondItem_Choice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MatchingCondItem_sequence[] = {
  { &hf_e2ap_matchingCondChoice, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingCondItem_Choice },
  { &hf_e2ap_logicalOR      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MatchingCondItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MatchingCondItem, MatchingCondItem_sequence);

  return offset;
}


static const per_sequence_t MatchingCondList_sequence_of[1] = {
  { &hf_e2ap_MatchingCondList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingCondItem },
};

static int
dissect_e2ap_MatchingCondList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_MatchingCondList, MatchingCondList_sequence_of,
                                                  1, maxnoofConditionInfo, false);

  return offset;
}


static const per_sequence_t MeasurementCondItem_sequence[] = {
  { &hf_e2ap_measType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementType },
  { &hf_e2ap_matchingCond   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingCondList },
  { &hf_e2ap_binRangeDef    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_BinRangeDefinition },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MeasurementCondItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MeasurementCondItem, MeasurementCondItem_sequence);

  return offset;
}


static const per_sequence_t MeasurementCondList_sequence_of[1] = {
  { &hf_e2ap_MeasurementCondList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementCondItem },
};

static int
dissect_e2ap_MeasurementCondList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_MeasurementCondList, MeasurementCondList_sequence_of,
                                                  1, maxnoofMeasurementInfo, false);

  return offset;
}


static const per_sequence_t MatchingUEidItem_sequence[] = {
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_UEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MatchingUEidItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MatchingUEidItem, MatchingUEidItem_sequence);

  return offset;
}


static const per_sequence_t MatchingUEidList_sequence_of[1] = {
  { &hf_e2ap_MatchingUEidList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingUEidItem },
};

static int
dissect_e2ap_MatchingUEidList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_MatchingUEidList, MatchingUEidList_sequence_of,
                                                  1, maxnoofUEID, false);

  return offset;
}


static const value_string e2ap_T_noUEmatched_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_noUEmatched(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MatchingUEidItem_PerGP_sequence[] = {
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_UEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MatchingUEidItem_PerGP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MatchingUEidItem_PerGP, MatchingUEidItem_PerGP_sequence);

  return offset;
}


static const per_sequence_t MatchingUEidList_PerGP_sequence_of[1] = {
  { &hf_e2ap_MatchingUEidList_PerGP_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingUEidItem_PerGP },
};

static int
dissect_e2ap_MatchingUEidList_PerGP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_MatchingUEidList_PerGP, MatchingUEidList_PerGP_sequence_of,
                                                  1, maxnoofUEID, false);

  return offset;
}


static const value_string e2ap_T_matchedPerGP_vals[] = {
  {   0, "noUEmatched" },
  {   1, "oneOrMoreUEmatched" },
  { 0, NULL }
};

static const per_choice_t T_matchedPerGP_choice[] = {
  {   0, &hf_e2ap_noUEmatched    , ASN1_EXTENSION_ROOT    , dissect_e2ap_T_noUEmatched },
  {   1, &hf_e2ap_oneOrMoreUEmatched, ASN1_EXTENSION_ROOT    , dissect_e2ap_MatchingUEidList_PerGP },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_matchedPerGP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_matchedPerGP, T_matchedPerGP_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MatchingUEidPerGP_Item_sequence[] = {
  { &hf_e2ap_matchedPerGP   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_matchedPerGP },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MatchingUEidPerGP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MatchingUEidPerGP_Item, MatchingUEidPerGP_Item_sequence);

  return offset;
}


static const per_sequence_t MatchingUEidPerGP_sequence_of[1] = {
  { &hf_e2ap_MatchingUEidPerGP_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingUEidPerGP_Item },
};

static int
dissect_e2ap_MatchingUEidPerGP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_MatchingUEidPerGP, MatchingUEidPerGP_sequence_of,
                                                  1, maxnoofMeasurementRecord, false);

  return offset;
}


static const per_sequence_t MeasurementCondUEidItem_sequence[] = {
  { &hf_e2ap_measType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementType },
  { &hf_e2ap_matchingCond   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingCondList },
  { &hf_e2ap_matchingUEidList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_MatchingUEidList },
  { &hf_e2ap_matchingUEidPerGP, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_MatchingUEidPerGP },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MeasurementCondUEidItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MeasurementCondUEidItem, MeasurementCondUEidItem_sequence);

  return offset;
}


static const per_sequence_t MeasurementCondUEidList_sequence_of[1] = {
  { &hf_e2ap_MeasurementCondUEidList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementCondUEidItem },
};

static int
dissect_e2ap_MeasurementCondUEidList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_MeasurementCondUEidList, MeasurementCondUEidList_sequence_of,
                                                  1, maxnoofMeasurementInfo, false);

  return offset;
}


static const per_sequence_t MatchingUeCondPerSubItem_sequence[] = {
  { &hf_e2ap_testCondInfo   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_TestCondInfo },
  { &hf_e2ap_logicalOR      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MatchingUeCondPerSubItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MatchingUeCondPerSubItem, MatchingUeCondPerSubItem_sequence);

  return offset;
}


static const per_sequence_t MatchingUeCondPerSubList_sequence_of[1] = {
  { &hf_e2ap_MatchingUeCondPerSubList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingUeCondPerSubItem },
};

static int
dissect_e2ap_MatchingUeCondPerSubList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_MatchingUeCondPerSubList, MatchingUeCondPerSubList_sequence_of,
                                                  1, maxnoofConditionInfoPerSub, false);

  return offset;
}


static const per_sequence_t MatchingUEidPerSubItem_sequence[] = {
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_UEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_MatchingUEidPerSubItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_MatchingUEidPerSubItem, MatchingUEidPerSubItem_sequence);

  return offset;
}


static const per_sequence_t MatchingUEidPerSubList_sequence_of[1] = {
  { &hf_e2ap_MatchingUEidPerSubList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingUEidPerSubItem },
};

static int
dissect_e2ap_MatchingUEidPerSubList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_MatchingUEidPerSubList, MatchingUEidPerSubList_sequence_of,
                                                  2, maxnoofUEIDPerSub, false);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationMessage_Format1_sequence[] = {
  { &hf_e2ap_measData       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementData },
  { &hf_e2ap_measInfoList   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_MeasurementInfoList },
  { &hf_e2ap_granulPeriod   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GranularityPeriod },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_IndicationMessage_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_IndicationMessage_Format1, E2SM_KPM_IndicationMessage_Format1_sequence);

  return offset;
}


static const per_sequence_t UEMeasurementReportItem_sequence[] = {
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_UEID },
  { &hf_e2ap_measReport     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_KPM_IndicationMessage_Format1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_UEMeasurementReportItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_UEMeasurementReportItem, UEMeasurementReportItem_sequence);

  return offset;
}


static const per_sequence_t UEMeasurementReportList_sequence_of[1] = {
  { &hf_e2ap_UEMeasurementReportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_UEMeasurementReportItem },
};

static int
dissect_e2ap_UEMeasurementReportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_UEMeasurementReportList, UEMeasurementReportList_sequence_of,
                                                  1, maxnoofUEMeasReport, false);

  return offset;
}



static int
dissect_e2ap_INTEGER_1_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t E2SM_KPM_EventTriggerDefinition_Format1_sequence[] = {
  { &hf_e2ap_reportingPeriod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_1_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_EventTriggerDefinition_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_EventTriggerDefinition_Format1, E2SM_KPM_EventTriggerDefinition_Format1_sequence);

  return offset;
}


static const value_string e2ap_T_eventDefinition_formats_vals[] = {
  {   0, "eventDefinition-Format1" },
  { 0, NULL }
};

static const per_choice_t T_eventDefinition_formats_choice[] = {
  {   0, &hf_e2ap_eventDefinition_Format1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_KPM_EventTriggerDefinition_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_eventDefinition_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_eventDefinition_formats, T_eventDefinition_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_KPM_EventTriggerDefinition_sequence[] = {
  { &hf_e2ap_eventDefinition_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_eventDefinition_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_EventTriggerDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_EventTriggerDefinition, E2SM_KPM_EventTriggerDefinition_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_ActionDefinition_Format1_sequence[] = {
  { &hf_e2ap_measInfoList   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementInfoList },
  { &hf_e2ap_granulPeriod   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GranularityPeriod },
  { &hf_e2ap_cellGlobalID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_CGI },
  { &hf_e2ap_distMeasBinRangeInfo, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_e2ap_DistMeasurementBinRangeList },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_ActionDefinition_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_ActionDefinition_Format1, E2SM_KPM_ActionDefinition_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_ActionDefinition_Format2_sequence[] = {
  { &hf_e2ap_ueID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_UEID },
  { &hf_e2ap_subscriptInfo  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_KPM_ActionDefinition_Format1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_ActionDefinition_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_ActionDefinition_Format2, E2SM_KPM_ActionDefinition_Format2_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_ActionDefinition_Format3_sequence[] = {
  { &hf_e2ap_measCondList   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementCondList },
  { &hf_e2ap_granulPeriod   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GranularityPeriod },
  { &hf_e2ap_cellGlobalID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_CGI },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_ActionDefinition_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_ActionDefinition_Format3, E2SM_KPM_ActionDefinition_Format3_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_ActionDefinition_Format4_sequence[] = {
  { &hf_e2ap_matchingUeCondList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingUeCondPerSubList },
  { &hf_e2ap_subscriptionInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_KPM_ActionDefinition_Format1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_ActionDefinition_Format4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_ActionDefinition_Format4, E2SM_KPM_ActionDefinition_Format4_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_ActionDefinition_Format5_sequence[] = {
  { &hf_e2ap_matchingUEidList_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingUEidPerSubList },
  { &hf_e2ap_subscriptionInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_KPM_ActionDefinition_Format1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_ActionDefinition_Format5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_ActionDefinition_Format5, E2SM_KPM_ActionDefinition_Format5_sequence);

  return offset;
}


static const value_string e2ap_T_actionDefinition_formats_vals[] = {
  {   0, "actionDefinition-Format1" },
  {   1, "actionDefinition-Format2" },
  {   2, "actionDefinition-Format3" },
  {   3, "actionDefinition-Format4" },
  {   4, "actionDefinition-Format5" },
  { 0, NULL }
};

static const per_choice_t T_actionDefinition_formats_choice[] = {
  {   0, &hf_e2ap_actionDefinition_Format1_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_KPM_ActionDefinition_Format1 },
  {   1, &hf_e2ap_actionDefinition_Format2_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_KPM_ActionDefinition_Format2 },
  {   2, &hf_e2ap_actionDefinition_Format3_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_KPM_ActionDefinition_Format3 },
  {   3, &hf_e2ap_actionDefinition_Format4_01, ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_E2SM_KPM_ActionDefinition_Format4 },
  {   4, &hf_e2ap_actionDefinition_Format5, ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_E2SM_KPM_ActionDefinition_Format5 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_actionDefinition_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_actionDefinition_formats, T_actionDefinition_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_KPM_ActionDefinition_sequence[] = {
  { &hf_e2ap_ric_Style_Type , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_actionDefinition_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_actionDefinition_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_ActionDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_ActionDefinition, E2SM_KPM_ActionDefinition_sequence);

  return offset;
}



static int
dissect_e2ap_T_colletStartTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int ts_offset = offset;
    offset = dissect_e2ap_TimeStamp(tvb, offset, actx, tree, hf_index);

  /* Add as a generated field the timestamp decoded */
  const char *time_str = tvb_ntp_fmt_ts_sec(tvb, (ts_offset+7)/8);
  proto_item *ti = proto_tree_add_string(tree, hf_e2ap_timestamp_string, tvb, (ts_offset+7)/8, 4, time_str);
  proto_item_set_generated(ti);




  return offset;
}



static int
dissect_e2ap_PrintableString_SIZE_0_15_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          0, 15, true,
                                          NULL);

  return offset;
}



static int
dissect_e2ap_PrintableString_SIZE_0_400_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          0, 400, true,
                                          NULL);

  return offset;
}



static int
dissect_e2ap_PrintableString_SIZE_0_8_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          0, 8, true,
                                          NULL);

  return offset;
}



static int
dissect_e2ap_PrintableString_SIZE_0_32_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          0, 32, true,
                                          NULL);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationHeader_Format1_sequence[] = {
  { &hf_e2ap_colletStartTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_colletStartTime },
  { &hf_e2ap_fileFormatversion, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_PrintableString_SIZE_0_15_ },
  { &hf_e2ap_senderName     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_PrintableString_SIZE_0_400_ },
  { &hf_e2ap_senderType     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_PrintableString_SIZE_0_8_ },
  { &hf_e2ap_vendorName     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_PrintableString_SIZE_0_32_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_IndicationHeader_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_IndicationHeader_Format1, E2SM_KPM_IndicationHeader_Format1_sequence);

  return offset;
}


static const value_string e2ap_T_indicationHeader_formats_vals[] = {
  {   0, "indicationHeader-Format1" },
  { 0, NULL }
};

static const per_choice_t T_indicationHeader_formats_choice[] = {
  {   0, &hf_e2ap_indicationHeader_Format1_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_KPM_IndicationHeader_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_indicationHeader_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_indicationHeader_formats, T_indicationHeader_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationHeader_sequence[] = {
  { &hf_e2ap_indicationHeader_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_indicationHeader_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_IndicationHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_IndicationHeader, E2SM_KPM_IndicationHeader_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationMessage_Format2_sequence[] = {
  { &hf_e2ap_measData       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementData },
  { &hf_e2ap_measCondUEidList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementCondUEidList },
  { &hf_e2ap_granulPeriod   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GranularityPeriod },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_IndicationMessage_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_IndicationMessage_Format2, E2SM_KPM_IndicationMessage_Format2_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationMessage_Format3_sequence[] = {
  { &hf_e2ap_ueMeasReportList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_UEMeasurementReportList },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_IndicationMessage_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_IndicationMessage_Format3, E2SM_KPM_IndicationMessage_Format3_sequence);

  return offset;
}


static const value_string e2ap_T_indicationMessage_formats_vals[] = {
  {   0, "indicationMessage-Format1" },
  {   1, "indicationMessage-Format2" },
  {   2, "indicationMessage-Format3" },
  { 0, NULL }
};

static const per_choice_t T_indicationMessage_formats_choice[] = {
  {   0, &hf_e2ap_indicationMessage_Format1_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_KPM_IndicationMessage_Format1 },
  {   1, &hf_e2ap_indicationMessage_Format2_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_KPM_IndicationMessage_Format2 },
  {   2, &hf_e2ap_indicationMessage_Format3_01, ASN1_NOT_EXTENSION_ROOT, dissect_e2ap_E2SM_KPM_IndicationMessage_Format3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_T_indicationMessage_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_T_indicationMessage_formats, T_indicationMessage_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationMessage_sequence[] = {
  { &hf_e2ap_indicationMessage_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_indicationMessage_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_IndicationMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_IndicationMessage, E2SM_KPM_IndicationMessage_sequence);

  return offset;
}


static const per_sequence_t RIC_EventTriggerStyle_Item_sequence[] = {
  { &hf_e2ap_ric_EventTriggerStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_EventTriggerStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Name },
  { &hf_e2ap_ric_EventTriggerFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RIC_EventTriggerStyle_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RIC_EventTriggerStyle_Item, RIC_EventTriggerStyle_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item_sequence_of[1] = {
  { &hf_e2ap_ric_EventTriggerStyle_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_EventTriggerStyle_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RIC_ReportStyle_Item_sequence[] = {
  { &hf_e2ap_ric_ReportStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_ReportStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Name },
  { &hf_e2ap_ric_ActionFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_measInfo_Action_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementInfo_Action_List },
  { &hf_e2ap_ric_IndicationHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_IndicationMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RIC_ReportStyle_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RIC_ReportStyle_Item, RIC_ReportStyle_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item_sequence_of[1] = {
  { &hf_e2ap_ric_ReportStyle_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_ReportStyle_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t E2SM_KPM_RANfunction_Description_sequence[] = {
  { &hf_e2ap_ranFunction_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunction_Name },
  { &hf_e2ap_ric_EventTriggerStyle_List_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item },
  { &hf_e2ap_ric_ReportStyle_List_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_RANfunction_Description(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_RANfunction_Description, E2SM_KPM_RANfunction_Description_sequence);

  return offset;
}


static const value_string e2ap_NI_Type_vals[] = {
  {   0, "s1" },
  {   1, "x2" },
  {   2, "ng" },
  {   3, "xn" },
  {   4, "f1" },
  {   5, "e1" },
  { 0, NULL }
};


static int
dissect_e2ap_NI_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_e2ap_Global_eNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_GlobalENB_ID(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_e2ap_Global_en_gNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_GlobalenGNB_ID(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_e2ap_Global_ng_RAN_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_GlobalNG_RANNode_ID(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t Global_gNB_DU_ID_sequence[] = {
  { &hf_e2ap_global_ng_RAN_ID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_Global_ng_RAN_ID },
  { &hf_e2ap_gNB_DU_ID      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_GNB_DU_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_Global_gNB_DU_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_Global_gNB_DU_ID, Global_gNB_DU_ID_sequence);

  return offset;
}


static const per_sequence_t Global_gNB_CU_UP_ID_sequence[] = {
  { &hf_e2ap_global_ng_RAN_ID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_Global_ng_RAN_ID },
  { &hf_e2ap_gNB_CU_UP_ID   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_GNB_CU_UP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_Global_gNB_CU_UP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_Global_gNB_CU_UP_ID, Global_gNB_CU_UP_ID_sequence);

  return offset;
}


static const value_string e2ap_NI_Identifier_vals[] = {
  {   0, "global-eNB-ID" },
  {   1, "global-en-gNB-ID" },
  {   2, "global-ng-RAN-ID" },
  {   3, "global-gNB-DU-ID" },
  {   4, "global-gNB-CU-UP-ID" },
  { 0, NULL }
};

static const per_choice_t NI_Identifier_choice[] = {
  {   0, &hf_e2ap_global_eNB_ID_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_Global_eNB_ID },
  {   1, &hf_e2ap_global_en_gNB_ID_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_Global_en_gNB_ID },
  {   2, &hf_e2ap_global_ng_RAN_ID, ASN1_EXTENSION_ROOT    , dissect_e2ap_Global_ng_RAN_ID },
  {   3, &hf_e2ap_global_gNB_DU_ID, ASN1_EXTENSION_ROOT    , dissect_e2ap_Global_gNB_DU_ID },
  {   4, &hf_e2ap_global_gNB_CU_UP_ID, ASN1_EXTENSION_ROOT    , dissect_e2ap_Global_gNB_CU_UP_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_NI_Identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_NI_Identifier, NI_Identifier_choice,
                                 NULL);

  return offset;
}


static const value_string e2ap_NI_Direction_vals[] = {
  {   0, "incoming" },
  {   1, "outgoing" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_e2ap_NI_Direction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_TypeOfMessage_vals[] = {
  {   0, "nothing" },
  {   1, "initiating-message" },
  {   2, "successful-outcome" },
  {   3, "unsuccessful-outcome" },
  { 0, NULL }
};


static int
dissect_e2ap_TypeOfMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t NI_MessageTypeApproach1_sequence[] = {
  { &hf_e2ap_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProcedureCode },
  { &hf_e2ap_typeOfMessage  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_TypeOfMessage },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_NI_MessageTypeApproach1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_NI_MessageTypeApproach1, NI_MessageTypeApproach1_sequence);

  return offset;
}



static int
dissect_e2ap_NI_MessageTypeS1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_NI_MessageTypeApproach1(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_e2ap_NI_MessageTypeX2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_NI_MessageTypeApproach1(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_e2ap_NI_MessageTypeNG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_NI_MessageTypeApproach1(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_e2ap_NI_MessageTypeXn(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_NI_MessageTypeApproach1(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_e2ap_NI_MessageTypeF1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_NI_MessageTypeApproach1(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_e2ap_NI_MessageTypeE1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_NI_MessageTypeApproach1(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string e2ap_NI_MessageType_vals[] = {
  {   0, "s1MessageType" },
  {   1, "x2MessageType" },
  {   2, "ngMessageType" },
  {   3, "xnMessageType" },
  {   4, "f1MessageType" },
  {   5, "e1MessageType" },
  { 0, NULL }
};

static const per_choice_t NI_MessageType_choice[] = {
  {   0, &hf_e2ap_s1MessageType  , ASN1_EXTENSION_ROOT    , dissect_e2ap_NI_MessageTypeS1 },
  {   1, &hf_e2ap_x2MessageType  , ASN1_EXTENSION_ROOT    , dissect_e2ap_NI_MessageTypeX2 },
  {   2, &hf_e2ap_ngMessageType  , ASN1_EXTENSION_ROOT    , dissect_e2ap_NI_MessageTypeNG },
  {   3, &hf_e2ap_xnMessageType  , ASN1_EXTENSION_ROOT    , dissect_e2ap_NI_MessageTypeXn },
  {   4, &hf_e2ap_f1MessageType  , ASN1_EXTENSION_ROOT    , dissect_e2ap_NI_MessageTypeF1 },
  {   5, &hf_e2ap_e1MessageType  , ASN1_EXTENSION_ROOT    , dissect_e2ap_NI_MessageTypeE1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_NI_MessageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_NI_MessageType, NI_MessageType_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_NI_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_e2ap_ProtocolIE_ID(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string e2ap_NI_ProtocolIE_Test_vals[] = {
  {   0, "equal" },
  {   1, "greaterthan" },
  {   2, "lessthan" },
  {   3, "contains" },
  {   4, "present" },
  { 0, NULL }
};


static int
dissect_e2ap_NI_ProtocolIE_Test(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const value_string e2ap_NI_ProtocolIE_Value_vals[] = {
  {   0, "valueInt" },
  {   1, "valueEnum" },
  {   2, "valueBool" },
  {   3, "valueBitS" },
  {   4, "valueOctS" },
  {   5, "valuePrtS" },
  { 0, NULL }
};

static const per_choice_t NI_ProtocolIE_Value_choice[] = {
  {   0, &hf_e2ap_valueInt       , ASN1_EXTENSION_ROOT    , dissect_e2ap_INTEGER },
  {   1, &hf_e2ap_valueEnum      , ASN1_EXTENSION_ROOT    , dissect_e2ap_INTEGER },
  {   2, &hf_e2ap_valueBool      , ASN1_EXTENSION_ROOT    , dissect_e2ap_BOOLEAN },
  {   3, &hf_e2ap_valueBitS      , ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING },
  {   4, &hf_e2ap_valueOctS      , ASN1_EXTENSION_ROOT    , dissect_e2ap_OCTET_STRING },
  {   5, &hf_e2ap_valuePrtS      , ASN1_EXTENSION_ROOT    , dissect_e2ap_PrintableString },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_NI_ProtocolIE_Value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_NI_ProtocolIE_Value, NI_ProtocolIE_Value_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NI_ProtocolIE_Item_sequence[] = {
  { &hf_e2ap_interfaceProtocolIE_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_ProtocolIE_ID },
  { &hf_e2ap_interfaceProtocolIE_Test, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_ProtocolIE_Test },
  { &hf_e2ap_interfaceProtocolIE_Value, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_ProtocolIE_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_NI_ProtocolIE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_NI_ProtocolIE_Item, NI_ProtocolIE_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxofInterfaceProtocolTests_OF_NI_ProtocolIE_Item_sequence_of[1] = {
  { &hf_e2ap_interfaceProtocolIE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_ProtocolIE_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofInterfaceProtocolTests_OF_NI_ProtocolIE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofInterfaceProtocolTests_OF_NI_ProtocolIE_Item, SEQUENCE_SIZE_1_maxofInterfaceProtocolTests_OF_NI_ProtocolIE_Item_sequence_of,
                                                  1, maxofInterfaceProtocolTests, false);

  return offset;
}


static const per_sequence_t E2SM_NI_EventTriggerDefinition_Format1_sequence[] = {
  { &hf_e2ap_interface_type , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_Type },
  { &hf_e2ap_interface_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_Identifier },
  { &hf_e2ap_interfaceDirection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_Direction },
  { &hf_e2ap_interfaceMessageType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_MessageType },
  { &hf_e2ap_interfaceProtocolIE_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofInterfaceProtocolTests_OF_NI_ProtocolIE_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_EventTriggerDefinition_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_NI_EventTriggerDefinition_Format1, E2SM_NI_EventTriggerDefinition_Format1_sequence);

  return offset;
}


static const value_string e2ap_E2SM_NI_EventTriggerDefinition_vals[] = {
  {   0, "eventDefinition-Format1" },
  { 0, NULL }
};

static const per_choice_t E2SM_NI_EventTriggerDefinition_choice[] = {
  {   0, &hf_e2ap_eventDefinition_Format1_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_NI_EventTriggerDefinition_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_EventTriggerDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_E2SM_NI_EventTriggerDefinition, E2SM_NI_EventTriggerDefinition_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_RANparameter_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxofRANparameters, NULL, false);

  return offset;
}


static const value_string e2ap_RANparameter_Value_vals[] = {
  {   0, "valueInt" },
  {   1, "valueEnum" },
  {   2, "valueBool" },
  {   3, "valueBitS" },
  {   4, "valueOctS" },
  {   5, "valuePrtS" },
  { 0, NULL }
};

static const per_choice_t RANparameter_Value_choice[] = {
  {   0, &hf_e2ap_valueInt       , ASN1_EXTENSION_ROOT    , dissect_e2ap_INTEGER },
  {   1, &hf_e2ap_valueEnum      , ASN1_EXTENSION_ROOT    , dissect_e2ap_INTEGER },
  {   2, &hf_e2ap_valueBool      , ASN1_EXTENSION_ROOT    , dissect_e2ap_BOOLEAN },
  {   3, &hf_e2ap_valueBitS      , ASN1_EXTENSION_ROOT    , dissect_e2ap_BIT_STRING },
  {   4, &hf_e2ap_valueOctS      , ASN1_EXTENSION_ROOT    , dissect_e2ap_OCTET_STRING },
  {   5, &hf_e2ap_valuePrtS      , ASN1_EXTENSION_ROOT    , dissect_e2ap_PrintableString },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_RANparameter_Value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_RANparameter_Value, RANparameter_Value_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RANparameter_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANparameter_ID },
  { &hf_e2ap_ranParameter_Value_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANparameter_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANparameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANparameter_Item, RANparameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxofActionParameters_OF_RANparameter_Item_sequence_of[1] = {
  { &hf_e2ap_actionParameter_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANparameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofActionParameters_OF_RANparameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofActionParameters_OF_RANparameter_Item, SEQUENCE_SIZE_1_maxofActionParameters_OF_RANparameter_Item_sequence_of,
                                                  1, maxofActionParameters, false);

  return offset;
}


static const per_sequence_t E2SM_NI_ActionDefinition_Format1_sequence[] = {
  { &hf_e2ap_actionParameter_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofActionParameters_OF_RANparameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_ActionDefinition_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_NI_ActionDefinition_Format1, E2SM_NI_ActionDefinition_Format1_sequence);

  return offset;
}



static int
dissect_e2ap_RANueGroupID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxofRANueGroups, NULL, false);

  return offset;
}


static const value_string e2ap_RANparameter_Test_Condition_vals[] = {
  {   0, "equal" },
  {   1, "greaterthan" },
  {   2, "lessthan" },
  {   3, "contains" },
  {   4, "present" },
  { 0, NULL }
};


static int
dissect_e2ap_RANparameter_Test_Condition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t RANueGroupDef_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANparameter_ID },
  { &hf_e2ap_ranParameter_Test, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANparameter_Test_Condition },
  { &hf_e2ap_ranParameter_Value_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANparameter_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANueGroupDef_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANueGroupDef_Item, RANueGroupDef_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxofRANparameters_OF_RANueGroupDef_Item_sequence_of[1] = {
  { &hf_e2ap_ranUEgroupDef_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANueGroupDef_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANueGroupDef_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANueGroupDef_Item, SEQUENCE_SIZE_1_maxofRANparameters_OF_RANueGroupDef_Item_sequence_of,
                                                  1, maxofRANparameters, false);

  return offset;
}


static const per_sequence_t RANueGroupDefinition_sequence[] = {
  { &hf_e2ap_ranUEgroupDef_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANueGroupDef_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANueGroupDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANueGroupDefinition, RANueGroupDefinition_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameter_Item_sequence_of[1] = {
  { &hf_e2ap_outcomeElement_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANparameter_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameter_Item, SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameter_Item_sequence_of,
                                                  1, maxofRANparameters, false);

  return offset;
}


static const per_sequence_t RANimperativePolicy_sequence[] = {
  { &hf_e2ap_ranImperativePolicy_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANimperativePolicy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANimperativePolicy, RANimperativePolicy_sequence);

  return offset;
}


static const per_sequence_t RANueGroup_Item_sequence[] = {
  { &hf_e2ap_ranUEgroupID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANueGroupID },
  { &hf_e2ap_ranUEgroupDefinition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANueGroupDefinition },
  { &hf_e2ap_ranPolicy      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANimperativePolicy },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANueGroup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANueGroup_Item, RANueGroup_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxofRANueGroups_OF_RANueGroup_Item_sequence_of[1] = {
  { &hf_e2ap_ranUEgroup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANueGroup_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofRANueGroups_OF_RANueGroup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofRANueGroups_OF_RANueGroup_Item, SEQUENCE_SIZE_1_maxofRANueGroups_OF_RANueGroup_Item_sequence_of,
                                                  1, maxofRANueGroups, false);

  return offset;
}


static const per_sequence_t E2SM_NI_ActionDefinition_Format2_sequence[] = {
  { &hf_e2ap_ranUEgroup_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofRANueGroups_OF_RANueGroup_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_ActionDefinition_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_NI_ActionDefinition_Format2, E2SM_NI_ActionDefinition_Format2_sequence);

  return offset;
}


static const value_string e2ap_E2SM_NI_ActionDefinitionFormat_vals[] = {
  {   0, "actionDefinition-Format1" },
  {   1, "actionDefinition-Format2" },
  { 0, NULL }
};

static const per_choice_t E2SM_NI_ActionDefinitionFormat_choice[] = {
  {   0, &hf_e2ap_actionDefinition_Format1_02, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_NI_ActionDefinition_Format1 },
  {   1, &hf_e2ap_actionDefinition_Format2_02, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_NI_ActionDefinition_Format2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_ActionDefinitionFormat(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_E2SM_NI_ActionDefinitionFormat, E2SM_NI_ActionDefinitionFormat_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_NI_ActionDefinition_sequence[] = {
  { &hf_e2ap_ric_Style_Type , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_action_Definition_Format, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_NI_ActionDefinitionFormat },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_ActionDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_NI_ActionDefinition, E2SM_NI_ActionDefinition_sequence);

  return offset;
}



static int
dissect_e2ap_NI_TimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}


static const per_sequence_t E2SM_NI_IndicationHeader_Format1_sequence[] = {
  { &hf_e2ap_interface_type , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_Type },
  { &hf_e2ap_interface_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_Identifier },
  { &hf_e2ap_interfaceDirection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_Direction },
  { &hf_e2ap_timestamp      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_NI_TimeStamp },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_IndicationHeader_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_NI_IndicationHeader_Format1, E2SM_NI_IndicationHeader_Format1_sequence);

  return offset;
}


static const value_string e2ap_E2SM_NI_IndicationHeader_vals[] = {
  {   0, "indicationHeader-Format1" },
  { 0, NULL }
};

static const per_choice_t E2SM_NI_IndicationHeader_choice[] = {
  {   0, &hf_e2ap_indicationHeader_Format1_02, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_NI_IndicationHeader_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_IndicationHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_E2SM_NI_IndicationHeader, E2SM_NI_IndicationHeader_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_NI_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const per_sequence_t E2SM_NI_IndicationMessage_Format1_sequence[] = {
  { &hf_e2ap_interfaceMessage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_Message },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_IndicationMessage_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_NI_IndicationMessage_Format1, E2SM_NI_IndicationMessage_Format1_sequence);

  return offset;
}


static const value_string e2ap_E2SM_NI_IndicationMessage_vals[] = {
  {   0, "indicationMessage-Format1" },
  { 0, NULL }
};

static const per_choice_t E2SM_NI_IndicationMessage_choice[] = {
  {   0, &hf_e2ap_indicationMessage_Format1_02, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_NI_IndicationMessage_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_IndicationMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_E2SM_NI_IndicationMessage, E2SM_NI_IndicationMessage_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_RANcallProcess_ID_number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t E2SM_NI_CallProcessID_Format1_sequence[] = {
  { &hf_e2ap_callProcess_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANcallProcess_ID_number },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_CallProcessID_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_NI_CallProcessID_Format1, E2SM_NI_CallProcessID_Format1_sequence);

  return offset;
}



static int
dissect_e2ap_RANcallProcess_ID_string(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}


static const per_sequence_t E2SM_NI_CallProcessID_Format2_sequence[] = {
  { &hf_e2ap_callProcess_ID_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANcallProcess_ID_string },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_CallProcessID_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_NI_CallProcessID_Format2, E2SM_NI_CallProcessID_Format2_sequence);

  return offset;
}


static const value_string e2ap_E2SM_NI_CallProcessID_vals[] = {
  {   0, "callProcessID-Format1" },
  {   1, "callProcessID-Format2" },
  { 0, NULL }
};

static const per_choice_t E2SM_NI_CallProcessID_choice[] = {
  {   0, &hf_e2ap_callProcessID_Format1_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_NI_CallProcessID_Format1 },
  {   1, &hf_e2ap_callProcessID_Format2, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_NI_CallProcessID_Format2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_CallProcessID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_E2SM_NI_CallProcessID, E2SM_NI_CallProcessID_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_RIC_Control_Message_Priority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t E2SM_NI_ControlHeader_Format1_sequence[] = {
  { &hf_e2ap_interface_type , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_Type },
  { &hf_e2ap_interface_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_Identifier },
  { &hf_e2ap_interface_Direction, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_Direction },
  { &hf_e2ap_ric_Control_Message_Priority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RIC_Control_Message_Priority },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_ControlHeader_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_NI_ControlHeader_Format1, E2SM_NI_ControlHeader_Format1_sequence);

  return offset;
}


static const value_string e2ap_E2SM_NI_ControlHeader_vals[] = {
  {   0, "controlHeader-Format1" },
  { 0, NULL }
};

static const per_choice_t E2SM_NI_ControlHeader_choice[] = {
  {   0, &hf_e2ap_controlHeader_Format1_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_NI_ControlHeader_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_ControlHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_E2SM_NI_ControlHeader, E2SM_NI_ControlHeader_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_NI_ControlMessage_Format1_sequence[] = {
  { &hf_e2ap_interfaceMessage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_Message },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_ControlMessage_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_NI_ControlMessage_Format1, E2SM_NI_ControlMessage_Format1_sequence);

  return offset;
}


static const value_string e2ap_E2SM_NI_ControlMessage_vals[] = {
  {   0, "controlMessage-Format1" },
  { 0, NULL }
};

static const per_choice_t E2SM_NI_ControlMessage_choice[] = {
  {   0, &hf_e2ap_controlMessage_Format1_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_NI_ControlMessage_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_ControlMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_E2SM_NI_ControlMessage, E2SM_NI_ControlMessage_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_NI_ControlOutcome_Format1_sequence[] = {
  { &hf_e2ap_outcomeElement_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_ControlOutcome_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_NI_ControlOutcome_Format1, E2SM_NI_ControlOutcome_Format1_sequence);

  return offset;
}


static const value_string e2ap_E2SM_NI_ControlOutcome_vals[] = {
  {   0, "controlOutcome-Format1" },
  { 0, NULL }
};

static const per_choice_t E2SM_NI_ControlOutcome_choice[] = {
  {   0, &hf_e2ap_controlOutcome_Format1_01, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_NI_ControlOutcome_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_ControlOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_E2SM_NI_ControlOutcome, E2SM_NI_ControlOutcome_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RIC_EventTriggerStyle_List_sequence[] = {
  { &hf_e2ap_ric_EventTriggerStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_EventTriggerStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Name },
  { &hf_e2ap_ric_EventTriggerFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RIC_EventTriggerStyle_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RIC_EventTriggerStyle_List, RIC_EventTriggerStyle_List_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List_sequence_of[1] = {
  { &hf_e2ap_ric_EventTriggerStyle_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_EventTriggerStyle_List },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List, SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List_sequence_of,
                                                  1, maxofRICstyles, false);

  return offset;
}



static int
dissect_e2ap_RANparameter_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}


static const value_string e2ap_RANparameter_Type_vals[] = {
  {   0, "integer" },
  {   1, "enumerated" },
  {   2, "boolean" },
  {   3, "bit-string" },
  {   4, "octet-string" },
  {   5, "printable-string" },
  { 0, NULL }
};


static int
dissect_e2ap_RANparameter_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t RANparameterDef_Item_sequence[] = {
  { &hf_e2ap_ranParameter_ID_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANparameter_ID },
  { &hf_e2ap_ranParameter_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANparameter_Name },
  { &hf_e2ap_ranParameter_Type_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANparameter_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RANparameterDef_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANparameterDef_Item, RANparameterDef_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item_sequence_of[1] = {
  { &hf_e2ap_ric_ControlOutcomeRanParaDef_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANparameterDef_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item, SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item_sequence_of,
                                                  1, maxofRANparameters, false);

  return offset;
}


static const per_sequence_t RIC_ReportStyle_List_sequence[] = {
  { &hf_e2ap_ric_ReportStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_ReportStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Name },
  { &hf_e2ap_ric_ReportActionFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_ReportRanParameterDef_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item },
  { &hf_e2ap_ric_IndicationHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_IndicationMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RIC_ReportStyle_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RIC_ReportStyle_List, RIC_ReportStyle_List_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List_sequence_of[1] = {
  { &hf_e2ap_ric_ReportStyle_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_ReportStyle_List },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List, SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List_sequence_of,
                                                  1, maxofRICstyles, false);

  return offset;
}


static const per_sequence_t RIC_InsertStyle_List_sequence[] = {
  { &hf_e2ap_ric_InsertStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_InsertStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Name },
  { &hf_e2ap_ric_InsertActionFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_InsertRanParameterDef_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item },
  { &hf_e2ap_ric_IndicationHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_IndicationMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_CallProcessIDFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RIC_InsertStyle_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RIC_InsertStyle_List, RIC_InsertStyle_List_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_InsertStyle_List_sequence_of[1] = {
  { &hf_e2ap_ric_InsertStyle_List_item_03, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_InsertStyle_List },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_InsertStyle_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_InsertStyle_List, SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_InsertStyle_List_sequence_of,
                                                  1, maxofRICstyles, false);

  return offset;
}


static const per_sequence_t RIC_ControlStyle_List_sequence[] = {
  { &hf_e2ap_ric_ControlStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_ControlStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Name },
  { &hf_e2ap_ric_ControlFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_ControlHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_ControlMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_CallProcessIDFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_ControlOutcomeFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_ControlOutcomeRanParaDef_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RIC_ControlStyle_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RIC_ControlStyle_List, RIC_ControlStyle_List_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ControlStyle_List_sequence_of[1] = {
  { &hf_e2ap_ric_ControlStyle_List_item_03, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_ControlStyle_List },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ControlStyle_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ControlStyle_List, SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ControlStyle_List_sequence_of,
                                                  1, maxofRICstyles, false);

  return offset;
}


static const per_sequence_t RIC_PolicyStyle_List_sequence[] = {
  { &hf_e2ap_ric_PolicyStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_PolicyStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Name },
  { &hf_e2ap_ric_PolicyActionFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Format_Type },
  { &hf_e2ap_ric_PolicyRanParameterDef_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RIC_PolicyStyle_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RIC_PolicyStyle_List, RIC_PolicyStyle_List_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_PolicyStyle_List_sequence_of[1] = {
  { &hf_e2ap_ric_PolicyStyle_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_PolicyStyle_List },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_PolicyStyle_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_PolicyStyle_List, SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_PolicyStyle_List_sequence_of,
                                                  1, maxofRICstyles, false);

  return offset;
}


static const per_sequence_t E2SM_NI_RANfunction_Item_sequence[] = {
  { &hf_e2ap_interface_type , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_Type },
  { &hf_e2ap_ric_EventTriggerStyle_List_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List },
  { &hf_e2ap_ric_ReportStyle_List_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List },
  { &hf_e2ap_ric_InsertStyle_List_03, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_InsertStyle_List },
  { &hf_e2ap_ric_ControlStyle_List_03, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ControlStyle_List },
  { &hf_e2ap_ric_PolicyStyle_List_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_PolicyStyle_List },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_RANfunction_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_NI_RANfunction_Item, E2SM_NI_RANfunction_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxofNItypes_OF_E2SM_NI_RANfunction_Item_sequence_of[1] = {
  { &hf_e2ap_ni_Type_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_E2SM_NI_RANfunction_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofNItypes_OF_E2SM_NI_RANfunction_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofNItypes_OF_E2SM_NI_RANfunction_Item, SEQUENCE_SIZE_1_maxofNItypes_OF_E2SM_NI_RANfunction_Item_sequence_of,
                                                  1, maxofNItypes, false);

  return offset;
}


static const per_sequence_t E2SM_NI_RANfunction_Description_sequence[] = {
  { &hf_e2ap_ranFunction_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunction_Name },
  { &hf_e2ap_ni_Type_List   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofNItypes_OF_E2SM_NI_RANfunction_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_NI_RANfunction_Description(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_NI_RANfunction_Description, E2SM_NI_RANfunction_Description_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_Cause(tvb, offset, &asn1_ctx, tree, hf_e2ap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_e2ap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalE2node_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_GlobalE2node_ID(tvb, offset, &asn1_ctx, tree, hf_e2ap_GlobalE2node_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalRIC_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_GlobalRIC_ID(tvb, offset, &asn1_ctx, tree, hf_e2ap_GlobalRIC_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunctionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RANfunctionID(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunctionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactionID(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcallProcessID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICcallProcessID(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcallProcessID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolAckRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICcontrolAckRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolAckRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICcontrolHeader(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICcontrolMessage(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICcontrolOutcome(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolOutcome_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICeventTriggerDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICeventTriggerDefinition(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICeventTriggerDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICindicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICindicationHeader(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICindicationHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICindicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICindicationMessage(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICindicationMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICindicationSN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICindicationSN(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICindicationSN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICindicationType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICindicationType(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICindicationType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICrequestID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICrequestID(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICrequestID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionTime(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionTime_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICqueryHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICqueryHeader(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICqueryHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICqueryDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICqueryDefinition(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICqueryDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICqueryOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICqueryOutcome(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICqueryOutcome_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToWait_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_TimeToWait(tvb, offset, &asn1_ctx, tree, hf_e2ap_TimeToWait_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TNLinformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_TNLinformation(tvb, offset, &asn1_ctx, tree, hf_e2ap_TNLinformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransactionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_TransactionID(tvb, offset, &asn1_ctx, tree, hf_e2ap_TransactionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionDetails_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionDetails(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionDetails_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_ToBeSetup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_ToBeSetup_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_ToBeSetup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionResponse(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_Admitted_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_Admitted_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_Admitted_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_Admitted_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_Admitted_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_Admitted_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_NotAdmitted_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_NotAdmitted_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_NotAdmitted_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_NotAdmitted_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_NotAdmitted_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_NotAdmitted_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionDeleteRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionDeleteRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionDeleteRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionDeleteResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionDeleteResponse(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionDeleteResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionDeleteFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionDeleteFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionDeleteFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionDeleteRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionDeleteRequired(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionDeleteRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscription_List_withCause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscription_List_withCause(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscription_List_withCause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscription_withCause_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscription_withCause_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscription_withCause_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionModificationRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_ToBeRemovedForModification_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_ToBeRemovedForModification_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_ToBeRemovedForModification_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_ToBeRemovedForModification_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_ToBeRemovedForModification_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_ToBeRemovedForModification_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_ToBeModifiedForModification_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_ToBeModifiedForModification_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_ToBeModifiedForModification_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_ToBeModifiedForModification_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_ToBeModifiedForModification_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_ToBeModifiedForModification_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_ToBeAddedForModification_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_ToBeAddedForModification_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_ToBeAddedForModification_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_ToBeAddedForModification_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_ToBeAddedForModification_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_ToBeAddedForModification_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionModificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionModificationResponse(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionModificationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_RemovedForModification_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_RemovedForModification_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_RemovedForModification_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_RemovedForModification_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_RemovedForModification_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_RemovedForModification_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_FailedToBeRemovedForModification_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_FailedToBeRemovedForModification_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_FailedToBeRemovedForModification_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_FailedToBeRemovedForModification_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_FailedToBeRemovedForModification_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_FailedToBeRemovedForModification_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_ModifiedForModification_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_ModifiedForModification_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_ModifiedForModification_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_ModifiedForModification_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_ModifiedForModification_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_ModifiedForModification_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_FailedToBeModifiedForModification_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_FailedToBeModifiedForModification_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_FailedToBeModifiedForModification_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_FailedToBeModifiedForModification_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_FailedToBeModifiedForModification_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_FailedToBeModifiedForModification_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_AddedForModification_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_AddedForModification_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_AddedForModification_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_AddedForModification_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_AddedForModification_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_AddedForModification_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_FailedToBeAddedForModification_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_FailedToBeAddedForModification_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_FailedToBeAddedForModification_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_FailedToBeAddedForModification_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_FailedToBeAddedForModification_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_FailedToBeAddedForModification_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionModificationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionModificationFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionModificationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionModificationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionModificationRequired(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionModificationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_RequiredToBeModified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_RequiredToBeModified_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_RequiredToBeModified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_RequiredToBeModified_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_RequiredToBeModified_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_RequiredToBeModified_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_RequiredToBeRemoved_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_RequiredToBeRemoved_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_RequiredToBeRemoved_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_RequiredToBeRemoved_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_RequiredToBeRemoved_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_RequiredToBeRemoved_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionModificationConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionModificationConfirm(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionModificationConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_ConfirmedForModification_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_ConfirmedForModification_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_ConfirmedForModification_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_ConfirmedForModification_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_ConfirmedForModification_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_ConfirmedForModification_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_RefusedToBeModified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_RefusedToBeModified_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_RefusedToBeModified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_RefusedToBeModified_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_RefusedToBeModified_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_RefusedToBeModified_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_ConfirmedForRemoval_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_ConfirmedForRemoval_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_ConfirmedForRemoval_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_ConfirmedForRemoval_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_ConfirmedForRemoval_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_ConfirmedForRemoval_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactions_RefusedToBeRemoved_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICactions_RefusedToBeRemoved_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactions_RefusedToBeRemoved_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_RefusedToBeRemoved_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICaction_RefusedToBeRemoved_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_RefusedToBeRemoved_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionModificationRefuse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICsubscriptionModificationRefuse(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionModificationRefuse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICindication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICindication(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICindication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICcontrolRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICcontrolAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICcontrolFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICQueryRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICQueryRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICQueryRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICQueryResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICQueryResponse(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICQueryResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICQueryFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICQueryFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICQueryFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_e2ap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2setupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2setupRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2setupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2setupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2setupResponse(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2setupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2setupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2setupFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2setupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2connectionUpdate(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdate_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2connectionUpdate_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdate_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdate_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2connectionUpdate_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdate_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdateRemove_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2connectionUpdateRemove_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdateRemove_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdateRemove_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2connectionUpdateRemove_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdateRemove_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2connectionUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionSetupFailed_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2connectionSetupFailed_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionSetupFailed_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionSetupFailed_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2connectionSetupFailed_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionSetupFailed_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2connectionUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigAddition_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigAddition_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigAddition_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigAddition_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigAddition_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigAddition_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigUpdate_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigUpdate_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigUpdate_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigUpdate_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigUpdate_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigUpdate_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigRemoval_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigRemoval_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigRemoval_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigRemoval_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigRemoval_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigRemoval_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeTNLassociationRemoval_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeTNLassociationRemoval_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeTNLassociationRemoval_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeTNLassociationRemoval_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeTNLassociationRemoval_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeTNLassociationRemoval_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigAdditionAck_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigAdditionAck_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigAdditionAck_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigAdditionAck_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigAdditionAck_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigAdditionAck_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigUpdateAck_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigUpdateAck_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigUpdateAck_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigUpdateAck_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigUpdateAck_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigUpdateAck_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigRemovalAck_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigRemovalAck_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigRemovalAck_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigRemovalAck_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigRemovalAck_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigRemovalAck_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2nodeConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_ResetRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_ResetRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_ResetResponse(tvb, offset, &asn1_ctx, tree, hf_e2ap_ResetResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICserviceUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICserviceUpdate(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICserviceUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunctions_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RANfunctions_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunctions_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunction_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RANfunction_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunction_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunctionsID_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RANfunctionsID_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunctionsID_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunctionID_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RANfunctionID_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunctionID_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICserviceUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICserviceUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICserviceUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunctionsIDcause_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RANfunctionsIDcause_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunctionsIDcause_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunctionIDcause_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RANfunctionIDcause_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunctionIDcause_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICserviceUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICserviceUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICserviceUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICserviceQuery_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_RICserviceQuery(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICserviceQuery_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2RemovalRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2RemovalRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2RemovalRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2RemovalResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2RemovalResponse(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2RemovalResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2RemovalFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2RemovalFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2RemovalFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2AP_PDU(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2AP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_EventTrigger_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_RC_EventTrigger(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_EventTrigger_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_RC_ActionDefinition(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_ActionDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_RC_IndicationHeader(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_IndicationHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_RC_IndicationMessage(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_IndicationMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_CallProcessID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_RC_CallProcessID(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_CallProcessID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_ControlHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_RC_ControlHeader(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_ControlHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_ControlMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_RC_ControlMessage(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_ControlMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_ControlOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_RC_ControlOutcome(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_ControlOutcome_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_RANFunctionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_RC_RANFunctionDefinition(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_RANFunctionDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_EventTriggerDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_KPM_EventTriggerDefinition(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_KPM_EventTriggerDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_KPM_ActionDefinition(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_KPM_ActionDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_KPM_IndicationHeader(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_KPM_IndicationHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_KPM_IndicationMessage(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_KPM_IndicationMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_RANfunction_Description_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_KPM_RANfunction_Description(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_KPM_RANfunction_Description_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_NI_EventTriggerDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_NI_EventTriggerDefinition(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_NI_EventTriggerDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_NI_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_NI_ActionDefinition(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_NI_ActionDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_NI_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_NI_IndicationHeader(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_NI_IndicationHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_NI_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_NI_IndicationMessage(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_NI_IndicationMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_NI_CallProcessID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_NI_CallProcessID(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_NI_CallProcessID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_NI_ControlHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_NI_ControlHeader(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_NI_ControlHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_NI_ControlMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_NI_ControlMessage(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_NI_ControlMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_NI_ControlOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_NI_ControlOutcome(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_NI_ControlOutcome_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_NI_RANfunction_Description_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_e2ap_E2SM_NI_RANfunction_Description(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_NI_RANfunction_Description_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
  return (dissector_try_uint_new(e2ap_ies_dissector_table, e2ap_data->protocol_ie_id, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}



/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint(e2ap_ies_p1_dissector_table, e2ap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint(e2ap_ies_p2_dissector_table, e2ap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}
*/


static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e2ap_proc_imsg_dissector_table, e2ap_data->procedure_code, tvb, pinfo, tree, true, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e2ap_proc_sout_dissector_table, e2ap_data->procedure_code, tvb, pinfo, tree, true, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e2ap_proc_uout_dissector_table, e2ap_data->procedure_code, tvb, pinfo, tree, true, data)) ? tvb_captured_length(tvb) : 0;
}


static void set_stats_message_type(packet_info *pinfo, int type)
{
    struct e2ap_private_data* priv_data = e2ap_get_private_data(pinfo);
    priv_data->stats_tap->e2ap_mtype = type;
}

static void
e2ap_stats_tree_init(stats_tree *st)
{
    st_node_packets =      stats_tree_create_node(st, st_str_packets, 0, STAT_DT_INT, true);
    st_node_packet_types = stats_tree_create_pivot(st, st_str_packet_types, st_node_packets);
}

static tap_packet_status
e2ap_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
                       epan_dissect_t* edt _U_ , const void* p, tap_flags_t flags _U_)
{
    const struct e2ap_tap_t *pi = (const struct e2ap_tap_t *)p;

    tick_stat_node(st, st_str_packets, 0, false);
    stats_tree_tick_pivot(st, st_node_packet_types,
                          val_to_str(pi->e2ap_mtype, mtype_names,
                                     "Unknown packet type (%d)"));
    return TAP_PACKET_REDRAW;
}


/* Main dissection function */
static int
dissect_e2ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *e2ap_item = NULL;
  proto_tree *e2ap_tree = NULL;

  struct e2ap_tap_t *tap_info;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "E2AP");
  col_clear(pinfo->cinfo, COL_INFO);

  tap_info = wmem_new(pinfo->pool, struct e2ap_tap_t);
  tap_info->e2ap_mtype = 0; /* unknown/invalid */

  /* Add stats tap to private struct */
  struct e2ap_private_data *priv_data = e2ap_get_private_data(pinfo);
  priv_data->stats_tap = tap_info;

  /* Store top-level tree */
  top_tree = e2ap_tree;

  /* create the e2ap protocol tree */
  e2ap_item = proto_tree_add_item(tree, proto_e2ap, tvb, 0, -1, ENC_NA);
  e2ap_tree = proto_item_add_subtree(e2ap_item, ett_e2ap);

  dissect_E2AP_PDU_PDU(tvb, pinfo, e2ap_tree, NULL);

  tap_queue_packet(e2ap_tap, pinfo, tap_info);
  return tvb_captured_length(tvb);
}


static void e2ap_init_protocol(void)
{
  s_gnb_ran_functions_table.num_gnbs = 0;
}


/*--- proto_reg_handoff_e2ap ---------------------------------------*/
void
proto_reg_handoff_e2ap(void)
{
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_E2AP, e2ap_handle);
  dissector_add_uint("sctp.ppi", E2_CP_PROTOCOL_ID, e2ap_handle);
  dissector_add_uint("sctp.ppi", E2_UP_PROTOCOL_ID, e2ap_handle);
  dissector_add_uint("sctp.ppi", E2_DU_PROTOCOL_ID, e2ap_handle);

  dissector_add_uint("e2ap.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_GlobalE2node_ID, create_dissector_handle(dissect_GlobalE2node_ID_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_GlobalRIC_ID, create_dissector_handle(dissect_GlobalRIC_ID_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RANfunctionID, create_dissector_handle(dissect_RANfunctionID_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RANfunctionID_Item, create_dissector_handle(dissect_RANfunctionID_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RANfunctionIEcause_Item, create_dissector_handle(dissect_RANfunctionIDcause_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RANfunction_Item, create_dissector_handle(dissect_RANfunction_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RANfunctionsAccepted, create_dissector_handle(dissect_RANfunctionsID_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RANfunctionsAdded, create_dissector_handle(dissect_RANfunctions_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RANfunctionsDeleted, create_dissector_handle(dissect_RANfunctionsID_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RANfunctionsModified, create_dissector_handle(dissect_RANfunctions_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RANfunctionsRejected, create_dissector_handle(dissect_RANfunctionsIDcause_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_Admitted_Item, create_dissector_handle(dissect_RICaction_Admitted_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionID, create_dissector_handle(dissect_RICactionID_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_NotAdmitted_Item, create_dissector_handle(dissect_RICaction_NotAdmitted_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactions_Admitted, create_dissector_handle(dissect_RICaction_Admitted_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_ToBeSetup_Item, create_dissector_handle(dissect_RICaction_ToBeSetup_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICcallProcessID, create_dissector_handle(dissect_RICcallProcessID_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactions_NotAdmitted, create_dissector_handle(dissect_RICaction_NotAdmitted_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICcontrolAckRequest, create_dissector_handle(dissect_RICcontrolAckRequest_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICcontrolHeader, create_dissector_handle(dissect_RICcontrolHeader_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICcontrolMessage, create_dissector_handle(dissect_RICcontrolMessage_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICcontrolOutcome, create_dissector_handle(dissect_RICcontrolOutcome_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICindicationHeader, create_dissector_handle(dissect_RICindicationHeader_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICindicationMessage, create_dissector_handle(dissect_RICindicationMessage_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICindicationSN, create_dissector_handle(dissect_RICindicationSN_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICindicationType, create_dissector_handle(dissect_RICindicationType_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICrequestID, create_dissector_handle(dissect_RICrequestID_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICsubscriptionDetails, create_dissector_handle(dissect_RICsubscriptionDetails_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_TimeToWait, create_dissector_handle(dissect_TimeToWait_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeComponentConfigUpdate, create_dissector_handle(dissect_E2nodeComponentConfigUpdate_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeComponentConfigUpdate_Item, create_dissector_handle(dissect_E2nodeComponentConfigUpdate_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeComponentConfigUpdateAck, create_dissector_handle(dissect_E2nodeComponentConfigUpdateAck_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeComponentConfigUpdateAck_Item, create_dissector_handle(dissect_E2nodeComponentConfigUpdateAck_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2connectionSetup, create_dissector_handle(dissect_E2connectionUpdate_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2connectionSetupFailed, create_dissector_handle(dissect_E2connectionSetupFailed_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2connectionSetupFailed_Item, create_dissector_handle(dissect_E2connectionSetupFailed_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2connectionUpdate_Item, create_dissector_handle(dissect_E2connectionUpdate_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2connectionUpdateAdd, create_dissector_handle(dissect_E2connectionUpdate_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2connectionUpdateModify, create_dissector_handle(dissect_E2connectionUpdate_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2connectionUpdateRemove, create_dissector_handle(dissect_E2connectionUpdateRemove_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2connectionUpdateRemove_Item, create_dissector_handle(dissect_E2connectionUpdateRemove_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_TNLinformation, create_dissector_handle(dissect_TNLinformation_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_TransactionID, create_dissector_handle(dissect_TransactionID_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeComponentConfigAddition, create_dissector_handle(dissect_E2nodeComponentConfigAddition_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeComponentConfigAddition_Item, create_dissector_handle(dissect_E2nodeComponentConfigAddition_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeComponentConfigAdditionAck, create_dissector_handle(dissect_E2nodeComponentConfigAdditionAck_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeComponentConfigAdditionAck_Item, create_dissector_handle(dissect_E2nodeComponentConfigAdditionAck_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeComponentConfigRemoval, create_dissector_handle(dissect_E2nodeComponentConfigRemoval_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeComponentConfigRemoval_Item, create_dissector_handle(dissect_E2nodeComponentConfigRemoval_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeComponentConfigRemovalAck, create_dissector_handle(dissect_E2nodeComponentConfigRemovalAck_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeComponentConfigRemovalAck_Item, create_dissector_handle(dissect_E2nodeComponentConfigRemovalAck_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeTNLassociationRemoval, create_dissector_handle(dissect_E2nodeTNLassociationRemoval_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_E2nodeTNLassociationRemoval_Item, create_dissector_handle(dissect_E2nodeTNLassociationRemoval_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICsubscriptionToBeRemoved, create_dissector_handle(dissect_RICsubscription_List_withCause_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICsubscription_withCause_Item, create_dissector_handle(dissect_RICsubscription_withCause_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICsubscriptionStartTime, create_dissector_handle(dissect_RICsubscriptionTime_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICsubscriptionEndTime, create_dissector_handle(dissect_RICsubscriptionTime_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICeventTriggerDefinitionToBeModified, create_dissector_handle(dissect_RICeventTriggerDefinition_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsToBeRemovedForModification_List, create_dissector_handle(dissect_RICactions_ToBeRemovedForModification_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_ToBeRemovedForModification_Item, create_dissector_handle(dissect_RICaction_ToBeRemovedForModification_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsToBeModifiedForModification_List, create_dissector_handle(dissect_RICactions_ToBeModifiedForModification_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_ToBeModifiedForModification_Item, create_dissector_handle(dissect_RICaction_ToBeModifiedForModification_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsToBeAddedForModification_List, create_dissector_handle(dissect_RICactions_ToBeAddedForModification_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_ToBeAddedForModification_Item, create_dissector_handle(dissect_RICaction_ToBeAddedForModification_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsRemovedForModification_List, create_dissector_handle(dissect_RICactions_RemovedForModification_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_RemovedForModification_Item, create_dissector_handle(dissect_RICaction_RemovedForModification_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsFailedToBeRemovedForModification_List, create_dissector_handle(dissect_RICactions_FailedToBeRemovedForModification_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_FailedToBeRemovedForModification_Item, create_dissector_handle(dissect_RICaction_FailedToBeRemovedForModification_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsModifiedForModification_List, create_dissector_handle(dissect_RICactions_ModifiedForModification_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_ModifiedForModification_Item, create_dissector_handle(dissect_RICaction_ModifiedForModification_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsFailedToBeModifiedForModification_List, create_dissector_handle(dissect_RICactions_FailedToBeModifiedForModification_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_FailedToBeModifiedForModification_Item, create_dissector_handle(dissect_RICaction_FailedToBeModifiedForModification_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsAddedForModification_List, create_dissector_handle(dissect_RICactions_AddedForModification_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_AddedForModification_Item, create_dissector_handle(dissect_RICaction_AddedForModification_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsFailedToBeAddedForModification_List, create_dissector_handle(dissect_RICactions_FailedToBeAddedForModification_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_FailedToBeAddedForModification_Item, create_dissector_handle(dissect_RICaction_FailedToBeAddedForModification_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsRequiredToBeModified_List, create_dissector_handle(dissect_RICactions_RequiredToBeModified_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_RequiredToBeModified_Item, create_dissector_handle(dissect_RICaction_RequiredToBeModified_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsRequiredToBeRemoved_List, create_dissector_handle(dissect_RICactions_RequiredToBeRemoved_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_RequiredToBeRemoved_Item, create_dissector_handle(dissect_RICaction_RequiredToBeRemoved_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsConfirmedForModification_List, create_dissector_handle(dissect_RICactions_ConfirmedForModification_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_ConfirmedForModification_Item, create_dissector_handle(dissect_RICaction_ConfirmedForModification_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsRefusedToBeModified_List, create_dissector_handle(dissect_RICactions_RefusedToBeModified_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_RefusedToBeModified_Item, create_dissector_handle(dissect_RICaction_RefusedToBeModified_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsConfirmedForRemoval_List, create_dissector_handle(dissect_RICactions_ConfirmedForRemoval_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_ConfirmedForRemoval_Item, create_dissector_handle(dissect_RICaction_ConfirmedForRemoval_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICactionsRefusedToBeRemoved_List, create_dissector_handle(dissect_RICactions_RefusedToBeRemoved_List_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICaction_RefusedToBeRemoved_Item, create_dissector_handle(dissect_RICaction_RefusedToBeRemoved_Item_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICqueryHeader, create_dissector_handle(dissect_RICqueryHeader_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICqueryDefinition, create_dissector_handle(dissect_RICqueryDefinition_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICqueryOutcome, create_dissector_handle(dissect_RICqueryOutcome_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_E2connectionUpdate, create_dissector_handle(dissect_E2connectionUpdate_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.sout", id_E2connectionUpdate, create_dissector_handle(dissect_E2connectionUpdateAcknowledge_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.uout", id_E2connectionUpdate, create_dissector_handle(dissect_E2connectionUpdateFailure_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_E2nodeConfigurationUpdate, create_dissector_handle(dissect_E2nodeConfigurationUpdate_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.sout", id_E2nodeConfigurationUpdate, create_dissector_handle(dissect_E2nodeConfigurationUpdateAcknowledge_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.uout", id_E2nodeConfigurationUpdate, create_dissector_handle(dissect_E2nodeConfigurationUpdateFailure_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.uout", id_E2setup, create_dissector_handle(dissect_E2setupFailure_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_E2setup, create_dissector_handle(dissect_E2setupRequest_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.sout", id_E2setup, create_dissector_handle(dissect_E2setupResponse_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_ErrorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_Reset, create_dissector_handle(dissect_ResetRequest_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.sout", id_Reset, create_dissector_handle(dissect_ResetResponse_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.sout", id_RICcontrol, create_dissector_handle(dissect_RICcontrolAcknowledge_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.uout", id_RICcontrol, create_dissector_handle(dissect_RICcontrolFailure_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_RICcontrol, create_dissector_handle(dissect_RICcontrolRequest_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_RICindication, create_dissector_handle(dissect_RICindication_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_RICserviceQuery, create_dissector_handle(dissect_RICserviceQuery_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_RICserviceUpdate, create_dissector_handle(dissect_RICserviceUpdate_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.sout", id_RICserviceUpdate, create_dissector_handle(dissect_RICserviceUpdateAcknowledge_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.uout", id_RICserviceUpdate, create_dissector_handle(dissect_RICserviceUpdateFailure_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.uout", id_RICsubscription, create_dissector_handle(dissect_RICsubscriptionFailure_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_RICsubscription, create_dissector_handle(dissect_RICsubscriptionRequest_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.sout", id_RICsubscription, create_dissector_handle(dissect_RICsubscriptionResponse_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.uout", id_RICsubscriptionDelete, create_dissector_handle(dissect_RICsubscriptionDeleteFailure_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_RICsubscriptionDelete, create_dissector_handle(dissect_RICsubscriptionDeleteRequest_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.sout", id_RICsubscriptionDelete, create_dissector_handle(dissect_RICsubscriptionDeleteResponse_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.sout", id_RICsubscriptionDeleteRequired, create_dissector_handle(dissect_RICsubscriptionDeleteRequired_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.uout", id_E2removal, create_dissector_handle(dissect_E2RemovalFailure_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_E2removal, create_dissector_handle(dissect_E2RemovalRequest_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.sout", id_E2removal, create_dissector_handle(dissect_E2RemovalResponse_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.uout", id_RICsubscriptionModification, create_dissector_handle(dissect_RICsubscriptionModificationFailure_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_RICsubscriptionModification, create_dissector_handle(dissect_RICsubscriptionModificationRequest_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.sout", id_RICsubscriptionModification, create_dissector_handle(dissect_RICsubscriptionModificationResponse_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.uout", id_RICsubscriptionModificationRequired, create_dissector_handle(dissect_RICsubscriptionModificationRefuse_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_RICsubscriptionModificationRequired, create_dissector_handle(dissect_RICsubscriptionModificationRequired_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.sout", id_RICsubscriptionModificationRequired, create_dissector_handle(dissect_RICsubscriptionModificationConfirm_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.uout", id_RICquery, create_dissector_handle(dissect_RICQueryFailure_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.imsg", id_RICquery, create_dissector_handle(dissect_RICQueryRequest_PDU, proto_e2ap));
  dissector_add_uint("e2ap.proc.sout", id_RICquery, create_dissector_handle(dissect_RICQueryResponse_PDU, proto_e2ap));


  /********************************/
  /* Known OIDs for RAN providers */
  /* N.B. These appear in the RAN Function ASN.1 definitions (except for CCC, which is based on JSON).
   * There is a registry of known OIDs though in the E2SM specification
   */

  /* KPM */
  oid_add_from_string("KPM v1",         "1.3.6.1.4.1.53148.1.1.2.2");
  oid_add_from_string("KPM v2",         "1.3.6.1.4.1.53148.1.2.2.2");
  oid_add_from_string("KPM v3",         "1.2.6.1.4.1.53148.1.3.2.2");

  /* RC */
  // TODO: appears to be the same???  Asking for clarification from ORAN..
  oid_add_from_string("RC  v1",         "1.3.6.1.4.1.53148.1.1.2.3");
  //oid_add_from_string("RC  v3",         "1.3.6.1.4.1.53148.1.1.2.3");
  //oid_add_from_string("RC  v4",         "1.3.6.1.4.1.53148.1.1.2.3");

  /* NI */
  oid_add_from_string("NI  v1",         "1.3.6.1.4.1.53148.1.1.2.1");

  /* CCC */
  oid_add_from_string("CCC v1",         "1.3.6.1.4.1.53148.1.1.2.4");
  oid_add_from_string("CCC v2",         "1.3.6.1.4.1.53148.1.2.2.4");
  oid_add_from_string("CCC v3",         "1.3.6.1.4.1.53148.1.3.2.4");
  oid_add_from_string("CCC v4",         "1.3.6.1.4.1.53148.1.4.2.4");
  oid_add_from_string("CCC v5",         "1.3.6.1.4.1.53148.1.5.2.4");


  /********************************/
  /* Register 'built-in' dissectors */

  static ran_function_dissector_t kpm_v3 =
  { "ORAN-E2SM-KPM", "1.2.6.1.4.1.53148.1.3.2.2", 3, 0,
    {  dissect_E2SM_KPM_RANfunction_Description_PDU,

       NULL,
       NULL,
       NULL,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_KPM_ActionDefinition_PDU,
       dissect_E2SM_KPM_IndicationMessage_PDU,
       dissect_E2SM_KPM_IndicationHeader_PDU,
       NULL, /* no dissect_E2SM_KPM_CallProcessID_PDU */
       dissect_E2SM_KPM_EventTriggerDefinition_PDU
     }
  };

  static ran_function_dissector_t rc_v1 =
  { "ORAN-E2SM-RC",  "1.3.6.1.4.1.53148.1.1.2.3", 1, 3,
    {  dissect_E2SM_RC_RANFunctionDefinition_PDU,

       dissect_E2SM_RC_ControlHeader_PDU,
       dissect_E2SM_RC_ControlMessage_PDU,
       dissect_E2SM_RC_ControlOutcome_PDU,
       /* new for v3 */
       NULL,
       NULL,
       NULL,

       dissect_E2SM_RC_ActionDefinition_PDU,
       dissect_E2SM_RC_IndicationMessage_PDU,
       dissect_E2SM_RC_IndicationHeader_PDU,
       dissect_E2SM_RC_CallProcessID_PDU,
       dissect_E2SM_RC_EventTrigger_PDU
    }
  };

  static ran_function_dissector_t ni_v1 =
  { "ORAN-E2SM-NI",  "1.3.6.1.4.1.53148.1.1.2.1", 1, 0,
    {  dissect_E2SM_NI_RANfunction_Description_PDU,

       dissect_E2SM_NI_ControlHeader_PDU,
       dissect_E2SM_NI_ControlMessage_PDU,
       dissect_E2SM_NI_ControlOutcome_PDU,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_NI_ActionDefinition_PDU,
       dissect_E2SM_NI_IndicationMessage_PDU,
       dissect_E2SM_NI_IndicationHeader_PDU,
       dissect_E2SM_NI_CallProcessID_PDU,
       dissect_E2SM_NI_EventTriggerDefinition_PDU
    }
  };

  static ran_function_dissector_t ccc_v1 =
  { "{", /*"ORAN-E2SM-CCC",*/  "1.3.6.1.4.1.53148.1.1.2.4", 1, 0,
    /* See table 5.1 */
    {  dissect_E2SM_NI_JSON_PDU,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU
    }
  };

  static ran_function_dissector_t ccc_v2 =
  { "{", /*"ORAN-E2SM-CCC",*/  "1.3.6.1.4.1.53148.1.2.2.4", 2, 0,
    /* See table 5.1 */
    {  dissect_E2SM_NI_JSON_PDU,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU
    }
  };

  static ran_function_dissector_t ccc_v3 =
  { "{", /*"ORAN-E2SM-CCC",*/  "1.3.6.1.4.1.53148.1.3.2.4", 3, 0,
    /* See table 5.1 */
    {  dissect_E2SM_NI_JSON_PDU,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU
    }
  };

  static ran_function_dissector_t ccc_v4 =
  { "{", /*"ORAN-E2SM-CCC",*/  "1.3.6.1.4.1.53148.1.4.2.4", 4, 0,
    /* See table 5.1 */
    {  dissect_E2SM_NI_JSON_PDU,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU
    }
  };

  static ran_function_dissector_t ccc_v5 =
  { "{", /*"ORAN-E2SM-CCC",*/  "1.3.6.1.4.1.53148.1.5.2.4", 5, 0,
    /* See table 5.1 */
    {  dissect_E2SM_NI_JSON_PDU,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       NULL,
       NULL,
       NULL,

       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU,
       dissect_E2SM_NI_JSON_PDU
    }
  };


  /* Register available dissectors.
   * Registering one version of each RAN Function here - others will need to be
   * registered in sepparate dissectors (e.g. kpm_v2) */
  register_e2ap_ran_function_dissector(KPM_RANFUNCTIONS, &kpm_v3);
  register_e2ap_ran_function_dissector(RC_RANFUNCTIONS,  &rc_v1);
  register_e2ap_ran_function_dissector(NI_RANFUNCTIONS,  &ni_v1);

  register_e2ap_ran_function_dissector(CCC_RANFUNCTIONS,  &ccc_v1);
  register_e2ap_ran_function_dissector(CCC_RANFUNCTIONS,  &ccc_v2);
  register_e2ap_ran_function_dissector(CCC_RANFUNCTIONS,  &ccc_v3);
  register_e2ap_ran_function_dissector(CCC_RANFUNCTIONS,  &ccc_v4);
  register_e2ap_ran_function_dissector(CCC_RANFUNCTIONS,  &ccc_v5);


  /* Cache JSON dissector */
  json_handle = find_dissector("json");

  stats_tree_register("e2ap", "e2ap", "E2AP", 0,
                      e2ap_stats_tree_packet, e2ap_stats_tree_init, NULL);

}



/*--- proto_register_e2ap -------------------------------------------*/
void proto_register_e2ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_e2ap_Cause_PDU,
      { "Cause", "e2ap.Cause",
        FT_UINT32, BASE_DEC, VALS(e2ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "e2ap.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_GlobalE2node_ID_PDU,
      { "GlobalE2node-ID", "e2ap.GlobalE2node_ID",
        FT_UINT32, BASE_DEC, VALS(e2ap_GlobalE2node_ID_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_GlobalRIC_ID_PDU,
      { "GlobalRIC-ID", "e2ap.GlobalRIC_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RANfunctionID_PDU,
      { "RANfunctionID", "e2ap.RANfunctionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactionID_PDU,
      { "RICactionID", "e2ap.RICactionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICcallProcessID_PDU,
      { "RICcallProcessID", "e2ap.RICcallProcessID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICcontrolAckRequest_PDU,
      { "RICcontrolAckRequest", "e2ap.RICcontrolAckRequest",
        FT_UINT32, BASE_DEC, VALS(e2ap_RICcontrolAckRequest_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_RICcontrolHeader_PDU,
      { "RICcontrolHeader", "e2ap.RICcontrolHeader",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICcontrolMessage_PDU,
      { "RICcontrolMessage", "e2ap.RICcontrolMessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICcontrolOutcome_PDU,
      { "RICcontrolOutcome", "e2ap.RICcontrolOutcome",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICeventTriggerDefinition_PDU,
      { "RICeventTriggerDefinition", "e2ap.RICeventTriggerDefinition",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICindicationHeader_PDU,
      { "RICindicationHeader", "e2ap.RICindicationHeader",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICindicationMessage_PDU,
      { "RICindicationMessage", "e2ap.RICindicationMessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICindicationSN_PDU,
      { "RICindicationSN", "e2ap.RICindicationSN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICindicationType_PDU,
      { "RICindicationType", "e2ap.RICindicationType",
        FT_UINT32, BASE_DEC, VALS(e2ap_RICindicationType_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_RICrequestID_PDU,
      { "RICrequestID", "e2ap.RICrequestID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionTime_PDU,
      { "RICsubscriptionTime", "e2ap.RICsubscriptionTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICqueryHeader_PDU,
      { "RICqueryHeader", "e2ap.RICqueryHeader",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICqueryDefinition_PDU,
      { "RICqueryDefinition", "e2ap.RICqueryDefinition",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICqueryOutcome_PDU,
      { "RICqueryOutcome", "e2ap.RICqueryOutcome",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_TimeToWait_PDU,
      { "TimeToWait", "e2ap.TimeToWait",
        FT_UINT32, BASE_DEC, VALS(e2ap_TimeToWait_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_TNLinformation_PDU,
      { "TNLinformation", "e2ap.TNLinformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_TransactionID_PDU,
      { "TransactionID", "e2ap.TransactionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionRequest_PDU,
      { "RICsubscriptionRequest", "e2ap.RICsubscriptionRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionDetails_PDU,
      { "RICsubscriptionDetails", "e2ap.RICsubscriptionDetails_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_ToBeSetup_Item_PDU,
      { "RICaction-ToBeSetup-Item", "e2ap.RICaction_ToBeSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionResponse_PDU,
      { "RICsubscriptionResponse", "e2ap.RICsubscriptionResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_Admitted_List_PDU,
      { "RICaction-Admitted-List", "e2ap.RICaction_Admitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_Admitted_Item_PDU,
      { "RICaction-Admitted-Item", "e2ap.RICaction_Admitted_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_NotAdmitted_List_PDU,
      { "RICaction-NotAdmitted-List", "e2ap.RICaction_NotAdmitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_NotAdmitted_Item_PDU,
      { "RICaction-NotAdmitted-Item", "e2ap.RICaction_NotAdmitted_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionFailure_PDU,
      { "RICsubscriptionFailure", "e2ap.RICsubscriptionFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionDeleteRequest_PDU,
      { "RICsubscriptionDeleteRequest", "e2ap.RICsubscriptionDeleteRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionDeleteResponse_PDU,
      { "RICsubscriptionDeleteResponse", "e2ap.RICsubscriptionDeleteResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionDeleteFailure_PDU,
      { "RICsubscriptionDeleteFailure", "e2ap.RICsubscriptionDeleteFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionDeleteRequired_PDU,
      { "RICsubscriptionDeleteRequired", "e2ap.RICsubscriptionDeleteRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscription_List_withCause_PDU,
      { "RICsubscription-List-withCause", "e2ap.RICsubscription_List_withCause",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscription_withCause_Item_PDU,
      { "RICsubscription-withCause-Item", "e2ap.RICsubscription_withCause_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionModificationRequest_PDU,
      { "RICsubscriptionModificationRequest", "e2ap.RICsubscriptionModificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_ToBeRemovedForModification_List_PDU,
      { "RICactions-ToBeRemovedForModification-List", "e2ap.RICactions_ToBeRemovedForModification_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_ToBeRemovedForModification_Item_PDU,
      { "RICaction-ToBeRemovedForModification-Item", "e2ap.RICaction_ToBeRemovedForModification_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_ToBeModifiedForModification_List_PDU,
      { "RICactions-ToBeModifiedForModification-List", "e2ap.RICactions_ToBeModifiedForModification_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_ToBeModifiedForModification_Item_PDU,
      { "RICaction-ToBeModifiedForModification-Item", "e2ap.RICaction_ToBeModifiedForModification_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_ToBeAddedForModification_List_PDU,
      { "RICactions-ToBeAddedForModification-List", "e2ap.RICactions_ToBeAddedForModification_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_ToBeAddedForModification_Item_PDU,
      { "RICaction-ToBeAddedForModification-Item", "e2ap.RICaction_ToBeAddedForModification_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionModificationResponse_PDU,
      { "RICsubscriptionModificationResponse", "e2ap.RICsubscriptionModificationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_RemovedForModification_List_PDU,
      { "RICactions-RemovedForModification-List", "e2ap.RICactions_RemovedForModification_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_RemovedForModification_Item_PDU,
      { "RICaction-RemovedForModification-Item", "e2ap.RICaction_RemovedForModification_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_FailedToBeRemovedForModification_List_PDU,
      { "RICactions-FailedToBeRemovedForModification-List", "e2ap.RICactions_FailedToBeRemovedForModification_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_FailedToBeRemovedForModification_Item_PDU,
      { "RICaction-FailedToBeRemovedForModification-Item", "e2ap.RICaction_FailedToBeRemovedForModification_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_ModifiedForModification_List_PDU,
      { "RICactions-ModifiedForModification-List", "e2ap.RICactions_ModifiedForModification_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_ModifiedForModification_Item_PDU,
      { "RICaction-ModifiedForModification-Item", "e2ap.RICaction_ModifiedForModification_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_FailedToBeModifiedForModification_List_PDU,
      { "RICactions-FailedToBeModifiedForModification-List", "e2ap.RICactions_FailedToBeModifiedForModification_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_FailedToBeModifiedForModification_Item_PDU,
      { "RICaction-FailedToBeModifiedForModification-Item", "e2ap.RICaction_FailedToBeModifiedForModification_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_AddedForModification_List_PDU,
      { "RICactions-AddedForModification-List", "e2ap.RICactions_AddedForModification_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_AddedForModification_Item_PDU,
      { "RICaction-AddedForModification-Item", "e2ap.RICaction_AddedForModification_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_FailedToBeAddedForModification_List_PDU,
      { "RICactions-FailedToBeAddedForModification-List", "e2ap.RICactions_FailedToBeAddedForModification_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_FailedToBeAddedForModification_Item_PDU,
      { "RICaction-FailedToBeAddedForModification-Item", "e2ap.RICaction_FailedToBeAddedForModification_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionModificationFailure_PDU,
      { "RICsubscriptionModificationFailure", "e2ap.RICsubscriptionModificationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionModificationRequired_PDU,
      { "RICsubscriptionModificationRequired", "e2ap.RICsubscriptionModificationRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_RequiredToBeModified_List_PDU,
      { "RICactions-RequiredToBeModified-List", "e2ap.RICactions_RequiredToBeModified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_RequiredToBeModified_Item_PDU,
      { "RICaction-RequiredToBeModified-Item", "e2ap.RICaction_RequiredToBeModified_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_RequiredToBeRemoved_List_PDU,
      { "RICactions-RequiredToBeRemoved-List", "e2ap.RICactions_RequiredToBeRemoved_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_RequiredToBeRemoved_Item_PDU,
      { "RICaction-RequiredToBeRemoved-Item", "e2ap.RICaction_RequiredToBeRemoved_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionModificationConfirm_PDU,
      { "RICsubscriptionModificationConfirm", "e2ap.RICsubscriptionModificationConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_ConfirmedForModification_List_PDU,
      { "RICactions-ConfirmedForModification-List", "e2ap.RICactions_ConfirmedForModification_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_ConfirmedForModification_Item_PDU,
      { "RICaction-ConfirmedForModification-Item", "e2ap.RICaction_ConfirmedForModification_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_RefusedToBeModified_List_PDU,
      { "RICactions-RefusedToBeModified-List", "e2ap.RICactions_RefusedToBeModified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_RefusedToBeModified_Item_PDU,
      { "RICaction-RefusedToBeModified-Item", "e2ap.RICaction_RefusedToBeModified_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_ConfirmedForRemoval_List_PDU,
      { "RICactions-ConfirmedForRemoval-List", "e2ap.RICactions_ConfirmedForRemoval_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_ConfirmedForRemoval_Item_PDU,
      { "RICaction-ConfirmedForRemoval-Item", "e2ap.RICaction_ConfirmedForRemoval_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_RefusedToBeRemoved_List_PDU,
      { "RICactions-RefusedToBeRemoved-List", "e2ap.RICactions_RefusedToBeRemoved_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_RefusedToBeRemoved_Item_PDU,
      { "RICaction-RefusedToBeRemoved-Item", "e2ap.RICaction_RefusedToBeRemoved_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscriptionModificationRefuse_PDU,
      { "RICsubscriptionModificationRefuse", "e2ap.RICsubscriptionModificationRefuse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICindication_PDU,
      { "RICindication", "e2ap.RICindication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICcontrolRequest_PDU,
      { "RICcontrolRequest", "e2ap.RICcontrolRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICcontrolAcknowledge_PDU,
      { "RICcontrolAcknowledge", "e2ap.RICcontrolAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICcontrolFailure_PDU,
      { "RICcontrolFailure", "e2ap.RICcontrolFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICQueryRequest_PDU,
      { "RICQueryRequest", "e2ap.RICQueryRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICQueryResponse_PDU,
      { "RICQueryResponse", "e2ap.RICQueryResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICQueryFailure_PDU,
      { "RICQueryFailure", "e2ap.RICQueryFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ErrorIndication_PDU,
      { "ErrorIndication", "e2ap.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2setupRequest_PDU,
      { "E2setupRequest", "e2ap.E2setupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2setupResponse_PDU,
      { "E2setupResponse", "e2ap.E2setupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2setupFailure_PDU,
      { "E2setupFailure", "e2ap.E2setupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2connectionUpdate_PDU,
      { "E2connectionUpdate", "e2ap.E2connectionUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2connectionUpdate_List_PDU,
      { "E2connectionUpdate-List", "e2ap.E2connectionUpdate_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2connectionUpdate_Item_PDU,
      { "E2connectionUpdate-Item", "e2ap.E2connectionUpdate_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2connectionUpdateRemove_List_PDU,
      { "E2connectionUpdateRemove-List", "e2ap.E2connectionUpdateRemove_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2connectionUpdateRemove_Item_PDU,
      { "E2connectionUpdateRemove-Item", "e2ap.E2connectionUpdateRemove_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2connectionUpdateAcknowledge_PDU,
      { "E2connectionUpdateAcknowledge", "e2ap.E2connectionUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2connectionSetupFailed_List_PDU,
      { "E2connectionSetupFailed-List", "e2ap.E2connectionSetupFailed_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2connectionSetupFailed_Item_PDU,
      { "E2connectionSetupFailed-Item", "e2ap.E2connectionSetupFailed_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2connectionUpdateFailure_PDU,
      { "E2connectionUpdateFailure", "e2ap.E2connectionUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeConfigurationUpdate_PDU,
      { "E2nodeConfigurationUpdate", "e2ap.E2nodeConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigAddition_List_PDU,
      { "E2nodeComponentConfigAddition-List", "e2ap.E2nodeComponentConfigAddition_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigAddition_Item_PDU,
      { "E2nodeComponentConfigAddition-Item", "e2ap.E2nodeComponentConfigAddition_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigUpdate_List_PDU,
      { "E2nodeComponentConfigUpdate-List", "e2ap.E2nodeComponentConfigUpdate_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigUpdate_Item_PDU,
      { "E2nodeComponentConfigUpdate-Item", "e2ap.E2nodeComponentConfigUpdate_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigRemoval_List_PDU,
      { "E2nodeComponentConfigRemoval-List", "e2ap.E2nodeComponentConfigRemoval_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigRemoval_Item_PDU,
      { "E2nodeComponentConfigRemoval-Item", "e2ap.E2nodeComponentConfigRemoval_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeTNLassociationRemoval_List_PDU,
      { "E2nodeTNLassociationRemoval-List", "e2ap.E2nodeTNLassociationRemoval_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeTNLassociationRemoval_Item_PDU,
      { "E2nodeTNLassociationRemoval-Item", "e2ap.E2nodeTNLassociationRemoval_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeConfigurationUpdateAcknowledge_PDU,
      { "E2nodeConfigurationUpdateAcknowledge", "e2ap.E2nodeConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigAdditionAck_List_PDU,
      { "E2nodeComponentConfigAdditionAck-List", "e2ap.E2nodeComponentConfigAdditionAck_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigAdditionAck_Item_PDU,
      { "E2nodeComponentConfigAdditionAck-Item", "e2ap.E2nodeComponentConfigAdditionAck_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigUpdateAck_List_PDU,
      { "E2nodeComponentConfigUpdateAck-List", "e2ap.E2nodeComponentConfigUpdateAck_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigUpdateAck_Item_PDU,
      { "E2nodeComponentConfigUpdateAck-Item", "e2ap.E2nodeComponentConfigUpdateAck_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigRemovalAck_List_PDU,
      { "E2nodeComponentConfigRemovalAck-List", "e2ap.E2nodeComponentConfigRemovalAck_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigRemovalAck_Item_PDU,
      { "E2nodeComponentConfigRemovalAck-Item", "e2ap.E2nodeComponentConfigRemovalAck_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeConfigurationUpdateFailure_PDU,
      { "E2nodeConfigurationUpdateFailure", "e2ap.E2nodeConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ResetRequest_PDU,
      { "ResetRequest", "e2ap.ResetRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ResetResponse_PDU,
      { "ResetResponse", "e2ap.ResetResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICserviceUpdate_PDU,
      { "RICserviceUpdate", "e2ap.RICserviceUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RANfunctions_List_PDU,
      { "RANfunctions-List", "e2ap.RANfunctions_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RANfunction_Item_PDU,
      { "RANfunction-Item", "e2ap.RANfunction_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RANfunctionsID_List_PDU,
      { "RANfunctionsID-List", "e2ap.RANfunctionsID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RANfunctionID_Item_PDU,
      { "RANfunctionID-Item", "e2ap.RANfunctionID_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICserviceUpdateAcknowledge_PDU,
      { "RICserviceUpdateAcknowledge", "e2ap.RICserviceUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RANfunctionsIDcause_List_PDU,
      { "RANfunctionsIDcause-List", "e2ap.RANfunctionsIDcause_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RANfunctionIDcause_Item_PDU,
      { "RANfunctionIDcause-Item", "e2ap.RANfunctionIDcause_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICserviceUpdateFailure_PDU,
      { "RICserviceUpdateFailure", "e2ap.RICserviceUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICserviceQuery_PDU,
      { "RICserviceQuery", "e2ap.RICserviceQuery_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2RemovalRequest_PDU,
      { "E2RemovalRequest", "e2ap.E2RemovalRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2RemovalResponse_PDU,
      { "E2RemovalResponse", "e2ap.E2RemovalResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2RemovalFailure_PDU,
      { "E2RemovalFailure", "e2ap.E2RemovalFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2AP_PDU_PDU,
      { "E2AP-PDU", "e2ap.E2AP_PDU",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2AP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_RC_EventTrigger_PDU,
      { "E2SM-RC-EventTrigger", "e2ap.E2SM_RC_EventTrigger_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_RC_ActionDefinition_PDU,
      { "E2SM-RC-ActionDefinition", "e2ap.E2SM_RC_ActionDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_RC_IndicationHeader_PDU,
      { "E2SM-RC-IndicationHeader", "e2ap.E2SM_RC_IndicationHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_RC_IndicationMessage_PDU,
      { "E2SM-RC-IndicationMessage", "e2ap.E2SM_RC_IndicationMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_RC_CallProcessID_PDU,
      { "E2SM-RC-CallProcessID", "e2ap.E2SM_RC_CallProcessID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_RC_ControlHeader_PDU,
      { "E2SM-RC-ControlHeader", "e2ap.E2SM_RC_ControlHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_RC_ControlMessage_PDU,
      { "E2SM-RC-ControlMessage", "e2ap.E2SM_RC_ControlMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_RC_ControlOutcome_PDU,
      { "E2SM-RC-ControlOutcome", "e2ap.E2SM_RC_ControlOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_RC_RANFunctionDefinition_PDU,
      { "E2SM-RC-RANFunctionDefinition", "e2ap.E2SM_RC_RANFunctionDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_KPM_EventTriggerDefinition_PDU,
      { "E2SM-KPM-EventTriggerDefinition", "e2ap.E2SM_KPM_EventTriggerDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_KPM_ActionDefinition_PDU,
      { "E2SM-KPM-ActionDefinition", "e2ap.E2SM_KPM_ActionDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_KPM_IndicationHeader_PDU,
      { "E2SM-KPM-IndicationHeader", "e2ap.E2SM_KPM_IndicationHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_KPM_IndicationMessage_PDU,
      { "E2SM-KPM-IndicationMessage", "e2ap.E2SM_KPM_IndicationMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_KPM_RANfunction_Description_PDU,
      { "E2SM-KPM-RANfunction-Description", "e2ap.E2SM_KPM_RANfunction_Description_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_NI_EventTriggerDefinition_PDU,
      { "E2SM-NI-EventTriggerDefinition", "e2ap.E2SM_NI_EventTriggerDefinition",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2SM_NI_EventTriggerDefinition_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_NI_ActionDefinition_PDU,
      { "E2SM-NI-ActionDefinition", "e2ap.E2SM_NI_ActionDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_NI_IndicationHeader_PDU,
      { "E2SM-NI-IndicationHeader", "e2ap.E2SM_NI_IndicationHeader",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2SM_NI_IndicationHeader_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_NI_IndicationMessage_PDU,
      { "E2SM-NI-IndicationMessage", "e2ap.E2SM_NI_IndicationMessage",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2SM_NI_IndicationMessage_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_NI_CallProcessID_PDU,
      { "E2SM-NI-CallProcessID", "e2ap.E2SM_NI_CallProcessID",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2SM_NI_CallProcessID_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_NI_ControlHeader_PDU,
      { "E2SM-NI-ControlHeader", "e2ap.E2SM_NI_ControlHeader",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2SM_NI_ControlHeader_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_NI_ControlMessage_PDU,
      { "E2SM-NI-ControlMessage", "e2ap.E2SM_NI_ControlMessage",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2SM_NI_ControlMessage_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_NI_ControlOutcome_PDU,
      { "E2SM-NI-ControlOutcome", "e2ap.E2SM_NI_ControlOutcome",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2SM_NI_ControlOutcome_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_NI_RANfunction_Description_PDU,
      { "E2SM-NI-RANfunction-Description", "e2ap.E2SM_NI_RANfunction_Description_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "e2ap.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_id,
      { "id", "e2ap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &e2ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_e2ap_criticality,
      { "criticality", "e2ap.criticality",
        FT_UINT32, BASE_DEC, VALS(e2ap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_value,
      { "value", "e2ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ricRequest,
      { "ricRequest", "e2ap.ricRequest",
        FT_UINT32, BASE_DEC, VALS(e2ap_CauseRICrequest_vals), 0,
        "CauseRICrequest", HFILL }},
    { &hf_e2ap_ricService,
      { "ricService", "e2ap.ricService",
        FT_UINT32, BASE_DEC, VALS(e2ap_CauseRICservice_vals), 0,
        "CauseRICservice", HFILL }},
    { &hf_e2ap_e2Node,
      { "e2Node", "e2ap.e2Node",
        FT_UINT32, BASE_DEC, VALS(e2ap_CauseE2node_vals), 0,
        "CauseE2node", HFILL }},
    { &hf_e2ap_transport,
      { "transport", "e2ap.transport",
        FT_UINT32, BASE_DEC, VALS(e2ap_CauseTransport_vals), 0,
        "CauseTransport", HFILL }},
    { &hf_e2ap_protocol,
      { "protocol", "e2ap.protocol",
        FT_UINT32, BASE_DEC, VALS(e2ap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_e2ap_misc,
      { "misc", "e2ap.misc",
        FT_UINT32, BASE_DEC, VALS(e2ap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_e2ap_procedureCode,
      { "procedureCode", "e2ap.procedureCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &e2ap_ProcedureCode_vals_ext, 0,
        NULL, HFILL }},
    { &hf_e2ap_triggeringMessage,
      { "triggeringMessage", "e2ap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(e2ap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_procedureCriticality,
      { "procedureCriticality", "e2ap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(e2ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_e2ap_ricRequestorID,
      { "ricRequestorID", "e2ap.ricRequestorID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RICrequestID", HFILL }},
    { &hf_e2ap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "e2ap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_e2ap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-Item", "e2ap.CriticalityDiagnostics_IE_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_iECriticality,
      { "iECriticality", "e2ap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(e2ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_e2ap_iE_ID,
      { "iE-ID", "e2ap.iE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &e2ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_e2ap_typeOfError,
      { "typeOfError", "e2ap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(e2ap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_e2nodeComponentRequestPart,
      { "e2nodeComponentRequestPart", "e2ap.e2nodeComponentRequestPart",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_e2nodeComponentResponsePart,
      { "e2nodeComponentResponsePart", "e2ap.e2nodeComponentResponsePart",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_updateOutcome,
      { "updateOutcome", "e2ap.updateOutcome",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_updateOutcome_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_failureCause,
      { "failureCause", "e2ap.failureCause",
        FT_UINT32, BASE_DEC, VALS(e2ap_Cause_vals), 0,
        "Cause", HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceTypeNG,
      { "e2nodeComponentInterfaceTypeNG", "e2ap.e2nodeComponentInterfaceTypeNG_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceTypeXn,
      { "e2nodeComponentInterfaceTypeXn", "e2ap.e2nodeComponentInterfaceTypeXn_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceTypeE1,
      { "e2nodeComponentInterfaceTypeE1", "e2ap.e2nodeComponentInterfaceTypeE1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceTypeF1,
      { "e2nodeComponentInterfaceTypeF1", "e2ap.e2nodeComponentInterfaceTypeF1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceTypeW1,
      { "e2nodeComponentInterfaceTypeW1", "e2ap.e2nodeComponentInterfaceTypeW1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2nodeComponentInterfaceW1", HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceTypeS1,
      { "e2nodeComponentInterfaceTypeS1", "e2ap.e2nodeComponentInterfaceTypeS1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceTypeX2,
      { "e2nodeComponentInterfaceTypeX2", "e2ap.e2nodeComponentInterfaceTypeX2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_gNB_CU_UP_ID,
      { "gNB-CU-UP-ID", "e2ap.gNB_CU_UP_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_gNB_DU_ID,
      { "gNB-DU-ID", "e2ap.gNB_DU_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_amf_name,
      { "amf-name", "e2ap.amf_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "AMFName", HFILL }},
    { &hf_e2ap_mme_name,
      { "mme-name", "e2ap.mme_name",
        FT_STRING, BASE_NONE, NULL, 0,
        "MMEname", HFILL }},
    { &hf_e2ap_global_eNB_ID,
      { "global-eNB-ID", "e2ap.global_eNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalENB_ID", HFILL }},
    { &hf_e2ap_global_en_gNB_ID,
      { "global-en-gNB-ID", "e2ap.global_en_gNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalenGNB_ID", HFILL }},
    { &hf_e2ap_global_NG_RAN_Node_ID,
      { "global-NG-RAN-Node-ID", "e2ap.global_NG_RAN_Node_ID",
        FT_UINT32, BASE_DEC, VALS(e2ap_GlobalNG_RANNode_ID_vals), 0,
        "GlobalNG_RANNode_ID", HFILL }},
    { &hf_e2ap_ng_eNB_DU_ID,
      { "ng-eNB-DU-ID", "e2ap.ng_eNB_DU_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        "NGENB_DU_ID", HFILL }},
    { &hf_e2ap_macro_eNB_ID,
      { "macro-eNB-ID", "e2ap.macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_e2ap_home_eNB_ID,
      { "home-eNB-ID", "e2ap.home_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_28", HFILL }},
    { &hf_e2ap_short_Macro_eNB_ID,
      { "short-Macro-eNB-ID", "e2ap.short_Macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_e2ap_long_Macro_eNB_ID,
      { "long-Macro-eNB-ID", "e2ap.long_Macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_e2ap_enb_ID_macro,
      { "enb-ID-macro", "e2ap.enb_ID_macro",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_e2ap_enb_ID_shortmacro,
      { "enb-ID-shortmacro", "e2ap.enb_ID_shortmacro",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_e2ap_enb_ID_longmacro,
      { "enb-ID-longmacro", "e2ap.enb_ID_longmacro",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_e2ap_gNB_ID,
      { "gNB-ID", "e2ap.gNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22_32", HFILL }},
    { &hf_e2ap_gNB,
      { "gNB", "e2ap.gNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalE2node_gNB_ID", HFILL }},
    { &hf_e2ap_en_gNB,
      { "en-gNB", "e2ap.en_gNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalE2node_en_gNB_ID", HFILL }},
    { &hf_e2ap_ng_eNB,
      { "ng-eNB", "e2ap.ng_eNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalE2node_ng_eNB_ID", HFILL }},
    { &hf_e2ap_eNB,
      { "eNB", "e2ap.eNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalE2node_eNB_ID", HFILL }},
    { &hf_e2ap_en_gNB_CU_UP_ID,
      { "en-gNB-CU-UP-ID", "e2ap.en_gNB_CU_UP_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        "GNB_CU_UP_ID", HFILL }},
    { &hf_e2ap_en_gNB_DU_ID,
      { "en-gNB-DU-ID", "e2ap.en_gNB_DU_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        "GNB_DU_ID", HFILL }},
    { &hf_e2ap_global_gNB_ID,
      { "global-gNB-ID", "e2ap.global_gNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalgNB_ID", HFILL }},
    { &hf_e2ap_global_ng_eNB_ID,
      { "global-ng-eNB-ID", "e2ap.global_ng_eNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalngeNB_ID", HFILL }},
    { &hf_e2ap_ngENB_DU_ID,
      { "ngENB-DU-ID", "e2ap.ngENB_DU_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_pLMN_Identity,
      { "pLMN-Identity", "e2ap.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_eNB_ID,
      { "eNB-ID", "e2ap.eNB_ID",
        FT_UINT32, BASE_DEC, VALS(e2ap_ENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_gNB_ID_01,
      { "gNB-ID", "e2ap.gNB_ID",
        FT_UINT32, BASE_DEC, VALS(e2ap_ENGNB_ID_vals), 0,
        "ENGNB_ID", HFILL }},
    { &hf_e2ap_plmn_id,
      { "plmn-id", "e2ap.plmn_id",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Identity", HFILL }},
    { &hf_e2ap_gnb_id,
      { "gnb-id", "e2ap.gnb_id",
        FT_UINT32, BASE_DEC, VALS(e2ap_GNB_ID_Choice_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_enb_id,
      { "enb-id", "e2ap.enb_id",
        FT_UINT32, BASE_DEC, VALS(e2ap_ENB_ID_Choice_vals), 0,
        "ENB_ID_Choice", HFILL }},
    { &hf_e2ap_gNB_01,
      { "gNB", "e2ap.gNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalgNB_ID", HFILL }},
    { &hf_e2ap_ng_eNB_01,
      { "ng-eNB", "e2ap.ng_eNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalngeNB_ID", HFILL }},
    { &hf_e2ap_ric_ID,
      { "ric-ID", "e2ap.ric_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_e2ap_gnb_ID,
      { "gnb-ID", "e2ap.gnb_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22_32", HFILL }},
    { &hf_e2ap_ricRequestorID_01,
      { "ricRequestorID", "e2ap.ricRequestorID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_e2ap_ricInstanceID,
      { "ricInstanceID", "e2ap.ricInstanceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_e2ap_ricSubsequentActionType,
      { "ricSubsequentActionType", "e2ap.ricSubsequentActionType",
        FT_UINT32, BASE_DEC, VALS(e2ap_RICsubsequentActionType_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ricTimeToWait,
      { "ricTimeToWait", "e2ap.ricTimeToWait",
        FT_UINT32, BASE_DEC, VALS(e2ap_RICtimeToWait_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_tnlAddress,
      { "tnlAddress", "e2ap.tnlAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_tnlPort,
      { "tnlPort", "e2ap.tnlPort",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_protocolIEs,
      { "protocolIEs", "e2ap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_e2ap_ricEventTriggerDefinition,
      { "ricEventTriggerDefinition", "e2ap.ricEventTriggerDefinition",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ricAction_ToBeSetup_List,
      { "ricAction-ToBeSetup-List", "e2ap.ricAction_ToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RICactions_ToBeSetup_List", HFILL }},
    { &hf_e2ap_RICactions_ToBeSetup_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ricActionID,
      { "ricActionID", "e2ap.ricActionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ricActionType,
      { "ricActionType", "e2ap.ricActionType",
        FT_UINT32, BASE_DEC, VALS(e2ap_RICactionType_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ricActionDefinition,
      { "ricActionDefinition", "e2ap.ricActionDefinition",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ricSubsequentAction,
      { "ricSubsequentAction", "e2ap.ricSubsequentAction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ricActionExecutionOrder,
      { "ricActionExecutionOrder", "e2ap.ricActionExecutionOrder",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_Admitted_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICaction_NotAdmitted_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_cause,
      { "cause", "e2ap.cause",
        FT_UINT32, BASE_DEC, VALS(e2ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_RICsubscription_List_withCause_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ricRequestID,
      { "ricRequestID", "e2ap.ricRequestID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunctionID,
      { "ranFunctionID", "e2ap.ranFunctionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_ToBeRemovedForModification_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_ToBeModifiedForModification_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_ToBeAddedForModification_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_RemovedForModification_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_FailedToBeRemovedForModification_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_ModifiedForModification_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_FailedToBeModifiedForModification_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_AddedForModification_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_FailedToBeAddedForModification_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_RequiredToBeModified_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_RequiredToBeRemoved_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_ConfirmedForModification_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_RefusedToBeModified_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_ConfirmedForRemoval_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RICactions_RefusedToBeRemoved_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2connectionUpdate_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_tnlInformation,
      { "tnlInformation", "e2ap.tnlInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_tnlUsage,
      { "tnlUsage", "e2ap.tnlUsage",
        FT_UINT32, BASE_DEC, VALS(e2ap_TNLusage_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_E2connectionUpdateRemove_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2connectionSetupFailed_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigAddition_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceType,
      { "e2nodeComponentInterfaceType", "e2ap.e2nodeComponentInterfaceType",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2nodeComponentInterfaceType_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_e2nodeComponentID,
      { "e2nodeComponentID", "e2ap.e2nodeComponentID",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2nodeComponentID_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_e2nodeComponentConfiguration,
      { "e2nodeComponentConfiguration", "e2ap.e2nodeComponentConfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigUpdate_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigRemoval_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeTNLassociationRemoval_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_tnlInformationRIC,
      { "tnlInformationRIC", "e2ap.tnlInformationRIC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TNLinformation", HFILL }},
    { &hf_e2ap_E2nodeComponentConfigAdditionAck_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_e2nodeComponentConfigurationAck,
      { "e2nodeComponentConfigurationAck", "e2ap.e2nodeComponentConfigurationAck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigUpdateAck_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2nodeComponentConfigRemovalAck_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RANfunctions_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunctionDefinition,
      { "ranFunctionDefinition", "e2ap.ranFunctionDefinition",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunctionRevision,
      { "ranFunctionRevision", "e2ap.ranFunctionRevision",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunctionOID,
      { "ranFunctionOID", "e2ap.ranFunctionOID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RANfunctionsID_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RANfunctionsIDcause_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_initiatingMessage,
      { "initiatingMessage", "e2ap.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_successfulOutcome,
      { "successfulOutcome", "e2ap.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "e2ap.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_initiatingMessagevalue,
      { "value", "e2ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_e2ap_successfulOutcome_value,
      { "value", "e2ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_e2ap_unsuccessfulOutcome_value,
      { "value", "e2ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},
    { &hf_e2ap_nR_CGI,
      { "nR-CGI", "e2ap.nR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_eUTRA_CGI,
      { "eUTRA-CGI", "e2ap.eUTRA_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_nG,
      { "nG", "e2ap.nG_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_NG", HFILL }},
    { &hf_e2ap_xN,
      { "xN", "e2ap.xN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_Xn", HFILL }},
    { &hf_e2ap_f1,
      { "f1", "e2ap.f1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_F1", HFILL }},
    { &hf_e2ap_e1,
      { "e1", "e2ap.e1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_E1", HFILL }},
    { &hf_e2ap_s1,
      { "s1", "e2ap.s1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_S1", HFILL }},
    { &hf_e2ap_x2,
      { "x2", "e2ap.x2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_X2", HFILL }},
    { &hf_e2ap_w1,
      { "w1", "e2ap.w1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_W1", HFILL }},
    { &hf_e2ap_guami,
      { "guami", "e2ap.guami_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_global_NG_RAN_ID,
      { "global-NG-RAN-ID", "e2ap.global_NG_RAN_ID",
        FT_UINT32, BASE_DEC, VALS(e2ap_GlobalNGRANNodeID_vals), 0,
        "GlobalNGRANNodeID", HFILL }},
    { &hf_e2ap_globalGNB_ID,
      { "globalGNB-ID", "e2ap.globalGNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_gUMMEI,
      { "gUMMEI", "e2ap.gUMMEI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_nodeType,
      { "nodeType", "e2ap.nodeType",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_nodeType_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_global_ng_eNB_ID_01,
      { "global-ng-eNB-ID", "e2ap.global_ng_eNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalNgENB_ID", HFILL }},
    { &hf_e2ap_interfaceProcedureID,
      { "interfaceProcedureID", "e2ap.interfaceProcedureID",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_e2ap_messageType,
      { "messageType", "e2ap.messageType",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_messageType_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunction_ShortName,
      { "ranFunction-ShortName", "e2ap.ranFunction_ShortName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunction_E2SM_OID,
      { "ranFunction-E2SM-OID", "e2ap.ranFunction_E2SM_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_1000_", HFILL }},
    { &hf_e2ap_ranFunction_Description,
      { "ranFunction-Description", "e2ap.ranFunction_Description",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_150_", HFILL }},
    { &hf_e2ap_ranFunction_Instance,
      { "ranFunction-Instance", "e2ap.ranFunction_Instance",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_e2ap_rrcType,
      { "rrcType", "e2ap.rrcType",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_rrcType_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_lTE,
      { "lTE", "e2ap.lTE",
        FT_UINT32, BASE_DEC, VALS(e2ap_RRCclass_LTE_vals), 0,
        "RRCclass_LTE", HFILL }},
    { &hf_e2ap_nR,
      { "nR", "e2ap.nR",
        FT_UINT32, BASE_DEC, VALS(e2ap_RRCclass_NR_vals), 0,
        "RRCclass_NR", HFILL }},
    { &hf_e2ap_messageID,
      { "messageID", "e2ap.messageID",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_e2ap_nR_01,
      { "nR", "e2ap.nR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_ARFCN", HFILL }},
    { &hf_e2ap_eUTRA,
      { "eUTRA", "e2ap.eUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRA_ARFCN", HFILL }},
    { &hf_e2ap_nR_02,
      { "nR", "e2ap.nR",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NR_PCI", HFILL }},
    { &hf_e2ap_eUTRA_01,
      { "eUTRA", "e2ap.eUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRA_PCI", HFILL }},
    { &hf_e2ap_gNB_UEID,
      { "gNB-UEID", "e2ap.gNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_GNB", HFILL }},
    { &hf_e2ap_gNB_DU_UEID,
      { "gNB-DU-UEID", "e2ap.gNB_DU_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_GNB_DU", HFILL }},
    { &hf_e2ap_gNB_CU_UP_UEID,
      { "gNB-CU-UP-UEID", "e2ap.gNB_CU_UP_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_GNB_CU_UP", HFILL }},
    { &hf_e2ap_ng_eNB_UEID,
      { "ng-eNB-UEID", "e2ap.ng_eNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_NG_ENB", HFILL }},
    { &hf_e2ap_ng_eNB_DU_UEID,
      { "ng-eNB-DU-UEID", "e2ap.ng_eNB_DU_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_NG_ENB_DU", HFILL }},
    { &hf_e2ap_en_gNB_UEID,
      { "en-gNB-UEID", "e2ap.en_gNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_EN_GNB", HFILL }},
    { &hf_e2ap_eNB_UEID,
      { "eNB-UEID", "e2ap.eNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_ENB", HFILL }},
    { &hf_e2ap_amf_UE_NGAP_ID,
      { "amf-UE-NGAP-ID", "e2ap.amf_UE_NGAP_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_gNB_CU_UE_F1AP_ID_List,
      { "gNB-CU-UE-F1AP-ID-List", "e2ap.gNB_CU_UE_F1AP_ID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UEID_GNB_CU_F1AP_ID_List", HFILL }},
    { &hf_e2ap_gNB_CU_CP_UE_E1AP_ID_List,
      { "gNB-CU-CP-UE-E1AP-ID-List", "e2ap.gNB_CU_CP_UE_E1AP_ID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UEID_GNB_CU_CP_E1AP_ID_List", HFILL }},
    { &hf_e2ap_ran_UEID,
      { "ran-UEID", "e2ap.ran_UEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RANUEID", HFILL }},
    { &hf_e2ap_m_NG_RAN_UE_XnAP_ID,
      { "m-NG-RAN-UE-XnAP-ID", "e2ap.m_NG_RAN_UE_XnAP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NG_RANnodeUEXnAPID", HFILL }},
    { &hf_e2ap_globalNG_RANNode_ID,
      { "globalNG-RANNode-ID", "e2ap.globalNG_RANNode_ID",
        FT_UINT32, BASE_DEC, VALS(e2ap_GlobalNGRANNodeID_vals), 0,
        "GlobalNGRANNodeID", HFILL }},
    { &hf_e2ap_UEID_GNB_CU_CP_E1AP_ID_List_item,
      { "UEID-GNB-CU-CP-E1AP-ID-Item", "e2ap.UEID_GNB_CU_CP_E1AP_ID_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_gNB_CU_CP_UE_E1AP_ID,
      { "gNB-CU-CP-UE-E1AP-ID", "e2ap.gNB_CU_CP_UE_E1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_UEID_GNB_CU_F1AP_ID_List_item,
      { "UEID-GNB-CU-CP-F1AP-ID-Item", "e2ap.UEID_GNB_CU_CP_F1AP_ID_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_gNB_CU_UE_F1AP_ID,
      { "gNB-CU-UE-F1AP-ID", "e2ap.gNB_CU_UE_F1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ng_eNB_CU_UE_W1AP_ID,
      { "ng-eNB-CU-UE-W1AP-ID", "e2ap.ng_eNB_CU_UE_W1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NGENB_CU_UE_W1AP_ID", HFILL }},
    { &hf_e2ap_globalNgENB_ID,
      { "globalNgENB-ID", "e2ap.globalNgENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_m_eNB_UE_X2AP_ID,
      { "m-eNB-UE-X2AP-ID", "e2ap.m_eNB_UE_X2AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ENB_UE_X2AP_ID", HFILL }},
    { &hf_e2ap_m_eNB_UE_X2AP_ID_Extension,
      { "m-eNB-UE-X2AP-ID-Extension", "e2ap.m_eNB_UE_X2AP_ID_Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ENB_UE_X2AP_ID_Extension", HFILL }},
    { &hf_e2ap_globalENB_ID,
      { "globalENB-ID", "e2ap.globalENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_mME_UE_S1AP_ID,
      { "mME-UE-S1AP-ID", "e2ap.mME_UE_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_pLMN_Identity_01,
      { "pLMN-Identity", "e2ap.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMNIdentity", HFILL }},
    { &hf_e2ap_mME_Group_ID,
      { "mME-Group-ID", "e2ap.mME_Group_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_mME_Code,
      { "mME-Code", "e2ap.mME_Code",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_pLMNIdentity,
      { "pLMNIdentity", "e2ap.pLMNIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_eUTRACellIdentity,
      { "eUTRACellIdentity", "e2ap.eUTRACellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_gNB_ID_02,
      { "gNB-ID", "e2ap.gNB_ID",
        FT_UINT32, BASE_DEC, VALS(e2ap_GNB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ngENB_ID,
      { "ngENB-ID", "e2ap.ngENB_ID",
        FT_UINT32, BASE_DEC, VALS(e2ap_NgENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_aMFRegionID,
      { "aMFRegionID", "e2ap.aMFRegionID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_aMFSetID,
      { "aMFSetID", "e2ap.aMFSetID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_aMFPointer,
      { "aMFPointer", "e2ap.aMFPointer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_macroNgENB_ID,
      { "macroNgENB-ID", "e2ap.macroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_e2ap_shortMacroNgENB_ID,
      { "shortMacroNgENB-ID", "e2ap.shortMacroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_e2ap_longMacroNgENB_ID,
      { "longMacroNgENB-ID", "e2ap.longMacroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_e2ap_nRCellIdentity,
      { "nRCellIdentity", "e2ap.nRCellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_sST,
      { "sST", "e2ap.sST",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_sD,
      { "sD", "e2ap.sD",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_gNB_02,
      { "gNB", "e2ap.gNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalGNB_ID", HFILL }},
    { &hf_e2ap_ng_eNB_02,
      { "ng-eNB", "e2ap.ng_eNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalNgENB_ID", HFILL }},
    { &hf_e2ap_nRARFCN,
      { "nRARFCN", "e2ap.nRARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxNRARFCN", HFILL }},
    { &hf_e2ap_NRFrequencyBand_List_item,
      { "NRFrequencyBandItem", "e2ap.NRFrequencyBandItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_freqBandIndicatorNr,
      { "freqBandIndicatorNr", "e2ap.freqBandIndicatorNr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1024_", HFILL }},
    { &hf_e2ap_supportedSULBandList,
      { "supportedSULBandList", "e2ap.supportedSULBandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_nrARFCN,
      { "nrARFCN", "e2ap.nrARFCN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_ARFCN", HFILL }},
    { &hf_e2ap_frequencyBand_List,
      { "frequencyBand-List", "e2ap.frequencyBand_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NRFrequencyBand_List", HFILL }},
    { &hf_e2ap_frequencyShift7p5khz,
      { "frequencyShift7p5khz", "e2ap.frequencyShift7p5khz",
        FT_UINT32, BASE_DEC, VALS(e2ap_NRFrequencyShift7p5khz_vals), 0,
        "NRFrequencyShift7p5khz", HFILL }},
    { &hf_e2ap_SupportedSULBandList_item,
      { "SupportedSULFreqBandItem", "e2ap.SupportedSULFreqBandItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_NeighborCell_List_item,
      { "NeighborCell-Item", "e2ap.NeighborCell_Item",
        FT_UINT32, BASE_DEC, VALS(e2ap_NeighborCell_Item_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ranType_Choice_NR,
      { "ranType-Choice-NR", "e2ap.ranType_Choice_NR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NeighborCell_Item_Choice_NR", HFILL }},
    { &hf_e2ap_ranType_Choice_EUTRA,
      { "ranType-Choice-EUTRA", "e2ap.ranType_Choice_EUTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NeighborCell_Item_Choice_E_UTRA", HFILL }},
    { &hf_e2ap_nR_PCI,
      { "nR-PCI", "e2ap.nR_PCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_fiveGS_TAC,
      { "fiveGS-TAC", "e2ap.fiveGS_TAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_nR_mode_info,
      { "nR-mode-info", "e2ap.nR_mode_info",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_nR_mode_info_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_nR_FreqInfo,
      { "nR-FreqInfo", "e2ap.nR_FreqInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRFrequencyInfo", HFILL }},
    { &hf_e2ap_x2_Xn_established,
      { "x2-Xn-established", "e2ap.x2_Xn_established",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_x2_Xn_established_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_hO_validated,
      { "hO-validated", "e2ap.hO_validated",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_hO_validated_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_version,
      { "version", "e2ap.version",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_e2ap_eUTRA_PCI,
      { "eUTRA-PCI", "e2ap.eUTRA_PCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRA_PCI", HFILL }},
    { &hf_e2ap_eUTRA_ARFCN,
      { "eUTRA-ARFCN", "e2ap.eUTRA_ARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRA_ARFCN", HFILL }},
    { &hf_e2ap_eUTRA_TAC,
      { "eUTRA-TAC", "e2ap.eUTRA_TAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "E_UTRA_TAC", HFILL }},
    { &hf_e2ap_x2_Xn_established_01,
      { "x2-Xn-established", "e2ap.x2_Xn_established",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_x2_Xn_established_01_vals), 0,
        "T_x2_Xn_established_01", HFILL }},
    { &hf_e2ap_hO_validated_01,
      { "hO-validated", "e2ap.hO_validated",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_hO_validated_01_vals), 0,
        "T_hO_validated_01", HFILL }},
    { &hf_e2ap_servingCellPCI,
      { "servingCellPCI", "e2ap.servingCellPCI",
        FT_UINT32, BASE_DEC, VALS(e2ap_ServingCell_PCI_vals), 0,
        "ServingCell_PCI", HFILL }},
    { &hf_e2ap_servingCellARFCN,
      { "servingCellARFCN", "e2ap.servingCellARFCN",
        FT_UINT32, BASE_DEC, VALS(e2ap_ServingCell_ARFCN_vals), 0,
        "ServingCell_ARFCN", HFILL }},
    { &hf_e2ap_neighborCell_List,
      { "neighborCell-List", "e2ap.neighborCell_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_cellInfo_List,
      { "cellInfo-List", "e2ap.cellInfo_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item", HFILL }},
    { &hf_e2ap_cellInfo_List_item,
      { "EventTrigger-Cell-Info-Item", "e2ap.EventTrigger_Cell_Info_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_eventTriggerCellID,
      { "eventTriggerCellID", "e2ap.eventTriggerCellID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RIC_EventTrigger_Cell_ID", HFILL }},
    { &hf_e2ap_cellType,
      { "cellType", "e2ap.cellType",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_cellType_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_cellType_Choice_Individual,
      { "cellType-Choice-Individual", "e2ap.cellType_Choice_Individual_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_Cell_Info_Item_Choice_Individual", HFILL }},
    { &hf_e2ap_cellType_Choice_Group,
      { "cellType-Choice-Group", "e2ap.cellType_Choice_Group_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_Cell_Info_Item_Choice_Group", HFILL }},
    { &hf_e2ap_logicalOR,
      { "logicalOR", "e2ap.logicalOR",
        FT_UINT32, BASE_DEC, VALS(e2ap_LogicalOR_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_cellGlobalID,
      { "cellGlobalID", "e2ap.cellGlobalID",
        FT_UINT32, BASE_DEC, VALS(e2ap_CGI_vals), 0,
        "CGI", HFILL }},
    { &hf_e2ap_ranParameterTesting,
      { "ranParameterTesting", "e2ap.ranParameterTesting",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing", HFILL }},
    { &hf_e2ap_ueInfo_List,
      { "ueInfo-List", "e2ap.ueInfo_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item", HFILL }},
    { &hf_e2ap_ueInfo_List_item,
      { "EventTrigger-UE-Info-Item", "e2ap.EventTrigger_UE_Info_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_eventTriggerUEID,
      { "eventTriggerUEID", "e2ap.eventTriggerUEID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RIC_EventTrigger_UE_ID", HFILL }},
    { &hf_e2ap_ueType,
      { "ueType", "e2ap.ueType",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ueType_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ueType_Choice_Individual,
      { "ueType-Choice-Individual", "e2ap.ueType_Choice_Individual_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UE_Info_Item_Choice_Individual", HFILL }},
    { &hf_e2ap_ueType_Choice_Group,
      { "ueType-Choice-Group", "e2ap.ueType_Choice_Group_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UE_Info_Item_Choice_Group", HFILL }},
    { &hf_e2ap_ueID,
      { "ueID", "e2ap.ueID",
        FT_UINT32, BASE_DEC, VALS(e2ap_UEID_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ueEvent_List,
      { "ueEvent-List", "e2ap.ueEvent_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item", HFILL }},
    { &hf_e2ap_ueEvent_List_item,
      { "EventTrigger-UEevent-Info-Item", "e2ap.EventTrigger_UEevent_Info_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ueEventID,
      { "ueEventID", "e2ap.ueEventID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RIC_EventTrigger_UEevent_ID", HFILL }},
    { &hf_e2ap_ranParameter_Definition_Choice,
      { "ranParameter-Definition-Choice", "e2ap.ranParameter_Definition_Choice",
        FT_UINT32, BASE_DEC, VALS(e2ap_RANParameter_Definition_Choice_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_choiceLIST,
      { "choiceLIST", "e2ap.choiceLIST_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_Definition_Choice_LIST", HFILL }},
    { &hf_e2ap_choiceSTRUCTURE,
      { "choiceSTRUCTURE", "e2ap.choiceSTRUCTURE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_Definition_Choice_STRUCTURE", HFILL }},
    { &hf_e2ap_ranParameter_List,
      { "ranParameter-List", "e2ap.ranParameter_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item", HFILL }},
    { &hf_e2ap_ranParameter_List_item,
      { "RANParameter-Definition-Choice-LIST-Item", "e2ap.RANParameter_Definition_Choice_LIST_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranParameter_ID,
      { "ranParameter-ID", "e2ap.ranParameter_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranParameter_name,
      { "ranParameter-name", "e2ap.ranParameter_name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranParameter_Definition,
      { "ranParameter-Definition", "e2ap.ranParameter_Definition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranParameter_STRUCTURE,
      { "ranParameter-STRUCTURE", "e2ap.ranParameter_STRUCTURE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item", HFILL }},
    { &hf_e2ap_ranParameter_STRUCTURE_item,
      { "RANParameter-Definition-Choice-STRUCTURE-Item", "e2ap.RANParameter_Definition_Choice_STRUCTURE_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_valueBoolean,
      { "valueBoolean", "e2ap.valueBoolean",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_e2ap_valueInt,
      { "valueInt", "e2ap.valueInt",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_e2ap_valueReal,
      { "valueReal", "e2ap.valueReal",
        FT_DOUBLE, BASE_NONE, NULL, 0,
        "REAL", HFILL }},
    { &hf_e2ap_valueBitS,
      { "valueBitS", "e2ap.valueBitS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_e2ap_valueOctS,
      { "valueOctS", "e2ap.valueOctS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_e2ap_valuePrintableString,
      { "valuePrintableString", "e2ap.valuePrintableString",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_e2ap_ranP_Choice_ElementTrue,
      { "ranP-Choice-ElementTrue", "e2ap.ranP_Choice_ElementTrue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_ValueType_Choice_ElementTrue", HFILL }},
    { &hf_e2ap_ranP_Choice_ElementFalse,
      { "ranP-Choice-ElementFalse", "e2ap.ranP_Choice_ElementFalse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_ValueType_Choice_ElementFalse", HFILL }},
    { &hf_e2ap_ranP_Choice_Structure,
      { "ranP-Choice-Structure", "e2ap.ranP_Choice_Structure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_ValueType_Choice_Structure", HFILL }},
    { &hf_e2ap_ranP_Choice_List,
      { "ranP-Choice-List", "e2ap.ranP_Choice_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_ValueType_Choice_List", HFILL }},
    { &hf_e2ap_ranParameter_value,
      { "ranParameter-value", "e2ap.ranParameter_value",
        FT_UINT32, BASE_DEC, VALS(e2ap_RANParameter_Value_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ranParameter_Structure,
      { "ranParameter-Structure", "e2ap.ranParameter_Structure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranParameter_List_01,
      { "ranParameter-List", "e2ap.ranParameter_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_sequence_of_ranParameters,
      { "sequence-of-ranParameters", "e2ap.sequence_of_ranParameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item", HFILL }},
    { &hf_e2ap_sequence_of_ranParameters_item,
      { "RANParameter-STRUCTURE-Item", "e2ap.RANParameter_STRUCTURE_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranParameter_valueType,
      { "ranParameter-valueType", "e2ap.ranParameter_valueType",
        FT_UINT32, BASE_DEC, VALS(e2ap_RANParameter_ValueType_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_list_of_ranParameter,
      { "list-of-ranParameter", "e2ap.list_of_ranParameter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE", HFILL }},
    { &hf_e2ap_list_of_ranParameter_item,
      { "RANParameter-STRUCTURE", "e2ap.RANParameter_STRUCTURE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RANParameter_Testing_item,
      { "RANParameter-Testing-Item", "e2ap.RANParameter_Testing_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranP_Choice_comparison,
      { "ranP-Choice-comparison", "e2ap.ranP_Choice_comparison",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ranP_Choice_comparison_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ranP_Choice_presence,
      { "ranP-Choice-presence", "e2ap.ranP_Choice_presence",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ranP_Choice_presence_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ranParameter_Type,
      { "ranParameter-Type", "e2ap.ranParameter_Type",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ranParameter_Type_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ranP_Choice_List_01,
      { "ranP-Choice-List", "e2ap.ranP_Choice_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_Testing_Item_Choice_List", HFILL }},
    { &hf_e2ap_ranP_Choice_Structure_01,
      { "ranP-Choice-Structure", "e2ap.ranP_Choice_Structure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_Testing_Item_Choice_Structure", HFILL }},
    { &hf_e2ap_ranP_Choice_ElementTrue_01,
      { "ranP-Choice-ElementTrue", "e2ap.ranP_Choice_ElementTrue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_Testing_Item_Choice_ElementTrue", HFILL }},
    { &hf_e2ap_ranP_Choice_ElementFalse_01,
      { "ranP-Choice-ElementFalse", "e2ap.ranP_Choice_ElementFalse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_Testing_Item_Choice_ElementFalse", HFILL }},
    { &hf_e2ap_ranParameter_List_02,
      { "ranParameter-List", "e2ap.ranParameter_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing_LIST", HFILL }},
    { &hf_e2ap_ranParameter_Structure_01,
      { "ranParameter-Structure", "e2ap.ranParameter_Structure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing_STRUCTURE", HFILL }},
    { &hf_e2ap_ranParameter_TestCondition,
      { "ranParameter-TestCondition", "e2ap.ranParameter_TestCondition",
        FT_UINT32, BASE_DEC, VALS(e2ap_RANParameter_TestingCondition_vals), 0,
        "RANParameter_TestingCondition", HFILL }},
    { &hf_e2ap_ranParameter_Value,
      { "ranParameter-Value", "e2ap.ranParameter_Value",
        FT_UINT32, BASE_DEC, VALS(e2ap_RANParameter_Value_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_RANParameter_Testing_LIST_item,
      { "RANParameter-Testing-Item", "e2ap.RANParameter_Testing_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RANParameter_Testing_STRUCTURE_item,
      { "RANParameter-Testing-Item", "e2ap.RANParameter_Testing_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_PolicyAction_ID,
      { "ric-PolicyAction-ID", "e2ap.ric_PolicyAction_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RIC_ControlAction_ID", HFILL }},
    { &hf_e2ap_ranParameters_List,
      { "ranParameters-List", "e2ap.ranParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item", HFILL }},
    { &hf_e2ap_ranParameters_List_item,
      { "RIC-PolicyAction-RANParameter-Item", "e2ap.RIC_PolicyAction_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_PolicyDecision,
      { "ric-PolicyDecision", "e2ap.ric_PolicyDecision",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ric_PolicyDecision_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_eventTrigger_formats,
      { "ric-eventTrigger-formats", "e2ap.ric_eventTrigger_formats",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ric_eventTrigger_formats_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_eventTrigger_Format1,
      { "eventTrigger-Format1", "e2ap.eventTrigger_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_EventTrigger_Format1", HFILL }},
    { &hf_e2ap_eventTrigger_Format2,
      { "eventTrigger-Format2", "e2ap.eventTrigger_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_EventTrigger_Format2", HFILL }},
    { &hf_e2ap_eventTrigger_Format3,
      { "eventTrigger-Format3", "e2ap.eventTrigger_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_EventTrigger_Format3", HFILL }},
    { &hf_e2ap_eventTrigger_Format4,
      { "eventTrigger-Format4", "e2ap.eventTrigger_Format4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_EventTrigger_Format4", HFILL }},
    { &hf_e2ap_eventTrigger_Format5,
      { "eventTrigger-Format5", "e2ap.eventTrigger_Format5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_EventTrigger_Format5", HFILL }},
    { &hf_e2ap_message_List,
      { "message-List", "e2ap.message_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item", HFILL }},
    { &hf_e2ap_message_List_item,
      { "E2SM-RC-EventTrigger-Format1-Item", "e2ap.E2SM_RC_EventTrigger_Format1_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_globalAssociatedUEInfo,
      { "globalAssociatedUEInfo", "e2ap.globalAssociatedUEInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UE_Info", HFILL }},
    { &hf_e2ap_ric_eventTriggerCondition_ID,
      { "ric-eventTriggerCondition-ID", "e2ap.ric_eventTriggerCondition_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_messageType_01,
      { "messageType", "e2ap.messageType",
        FT_UINT32, BASE_DEC, VALS(e2ap_MessageType_Choice_vals), 0,
        "MessageType_Choice", HFILL }},
    { &hf_e2ap_messageDirection,
      { "messageDirection", "e2ap.messageDirection",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_messageDirection_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_associatedUEInfo,
      { "associatedUEInfo", "e2ap.associatedUEInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UE_Info", HFILL }},
    { &hf_e2ap_associatedUEEvent,
      { "associatedUEEvent", "e2ap.associatedUEEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UEevent_Info", HFILL }},
    { &hf_e2ap_messageType_Choice_NI,
      { "messageType-Choice-NI", "e2ap.messageType_Choice_NI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_messageType_Choice_RRC,
      { "messageType-Choice-RRC", "e2ap.messageType_Choice_RRC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_nI_Type,
      { "nI-Type", "e2ap.nI_Type",
        FT_UINT32, BASE_DEC, VALS(e2ap_InterfaceType_vals), 0,
        "InterfaceType", HFILL }},
    { &hf_e2ap_nI_Identifier,
      { "nI-Identifier", "e2ap.nI_Identifier",
        FT_UINT32, BASE_DEC, VALS(e2ap_InterfaceIdentifier_vals), 0,
        "InterfaceIdentifier", HFILL }},
    { &hf_e2ap_nI_Message,
      { "nI-Message", "e2ap.nI_Message_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Interface_MessageID", HFILL }},
    { &hf_e2ap_rRC_Message,
      { "rRC-Message", "e2ap.rRC_Message_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RRC_MessageID", HFILL }},
    { &hf_e2ap_ric_callProcessType_ID,
      { "ric-callProcessType-ID", "e2ap.ric_callProcessType_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_callProcessBreakpoint_ID,
      { "ric-callProcessBreakpoint-ID", "e2ap.ric_callProcessBreakpoint_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_associatedE2NodeInfo,
      { "associatedE2NodeInfo", "e2ap.associatedE2NodeInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing", HFILL }},
    { &hf_e2ap_e2NodeInfoChange_List,
      { "e2NodeInfoChange-List", "e2ap.e2NodeInfoChange_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item", HFILL }},
    { &hf_e2ap_e2NodeInfoChange_List_item,
      { "E2SM-RC-EventTrigger-Format3-Item", "e2ap.E2SM_RC_EventTrigger_Format3_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_e2NodeInfoChange_ID,
      { "e2NodeInfoChange-ID", "e2ap.e2NodeInfoChange_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_512_", HFILL }},
    { &hf_e2ap_associatedCellInfo,
      { "associatedCellInfo", "e2ap.associatedCellInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_Cell_Info", HFILL }},
    { &hf_e2ap_uEInfoChange_List,
      { "uEInfoChange-List", "e2ap.uEInfoChange_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item", HFILL }},
    { &hf_e2ap_uEInfoChange_List_item,
      { "E2SM-RC-EventTrigger-Format4-Item", "e2ap.E2SM_RC_EventTrigger_Format4_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_triggerType,
      { "triggerType", "e2ap.triggerType",
        FT_UINT32, BASE_DEC, VALS(e2ap_TriggerType_Choice_vals), 0,
        "TriggerType_Choice", HFILL }},
    { &hf_e2ap_triggerType_Choice_RRCstate,
      { "triggerType-Choice-RRCstate", "e2ap.triggerType_Choice_RRCstate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_triggerType_Choice_UEID,
      { "triggerType-Choice-UEID", "e2ap.triggerType_Choice_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_triggerType_Choice_L2state,
      { "triggerType-Choice-L2state", "e2ap.triggerType_Choice_L2state_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_rrcState_List,
      { "rrcState-List", "e2ap.rrcState_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item", HFILL }},
    { &hf_e2ap_rrcState_List_item,
      { "TriggerType-Choice-RRCstate-Item", "e2ap.TriggerType_Choice_RRCstate_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_stateChangedTo,
      { "stateChangedTo", "e2ap.stateChangedTo",
        FT_UINT32, BASE_DEC, VALS(e2ap_RRC_State_vals), 0,
        "RRC_State", HFILL }},
    { &hf_e2ap_ueIDchange_ID,
      { "ueIDchange-ID", "e2ap.ueIDchange_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_512_", HFILL }},
    { &hf_e2ap_associatedL2variables,
      { "associatedL2variables", "e2ap.associatedL2variables",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing", HFILL }},
    { &hf_e2ap_onDemand,
      { "onDemand", "e2ap.onDemand",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_onDemand_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_Style_Type,
      { "ric-Style-Type", "e2ap.ric_Style_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_actionDefinition_formats,
      { "ric-actionDefinition-formats", "e2ap.ric_actionDefinition_formats",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ric_actionDefinition_formats_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_actionDefinition_Format1,
      { "actionDefinition-Format1", "e2ap.actionDefinition_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ActionDefinition_Format1", HFILL }},
    { &hf_e2ap_actionDefinition_Format2,
      { "actionDefinition-Format2", "e2ap.actionDefinition_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ActionDefinition_Format2", HFILL }},
    { &hf_e2ap_actionDefinition_Format3,
      { "actionDefinition-Format3", "e2ap.actionDefinition_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ActionDefinition_Format3", HFILL }},
    { &hf_e2ap_actionDefinition_Format4,
      { "actionDefinition-Format4", "e2ap.actionDefinition_Format4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ActionDefinition_Format4", HFILL }},
    { &hf_e2ap_ranP_ToBeReported_List,
      { "ranP-ToBeReported-List", "e2ap.ranP_ToBeReported_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item", HFILL }},
    { &hf_e2ap_ranP_ToBeReported_List_item,
      { "E2SM-RC-ActionDefinition-Format1-Item", "e2ap.E2SM_RC_ActionDefinition_Format1_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_PolicyConditions_List,
      { "ric-PolicyConditions-List", "e2ap.ric_PolicyConditions_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item", HFILL }},
    { &hf_e2ap_ric_PolicyConditions_List_item,
      { "E2SM-RC-ActionDefinition-Format2-Item", "e2ap.E2SM_RC_ActionDefinition_Format2_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_PolicyAction,
      { "ric-PolicyAction", "e2ap.ric_PolicyAction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_PolicyConditionDefinition,
      { "ric-PolicyConditionDefinition", "e2ap.ric_PolicyConditionDefinition",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing", HFILL }},
    { &hf_e2ap_ric_InsertIndication_ID,
      { "ric-InsertIndication-ID", "e2ap.ric_InsertIndication_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranP_InsertIndication_List,
      { "ranP-InsertIndication-List", "e2ap.ranP_InsertIndication_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item", HFILL }},
    { &hf_e2ap_ranP_InsertIndication_List_item,
      { "E2SM-RC-ActionDefinition-Format3-Item", "e2ap.E2SM_RC_ActionDefinition_Format3_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_InsertStyle_List,
      { "ric-InsertStyle-List", "e2ap.ric_InsertStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item", HFILL }},
    { &hf_e2ap_ric_InsertStyle_List_item,
      { "E2SM-RC-ActionDefinition-Format4-Style-Item", "e2ap.E2SM_RC_ActionDefinition_Format4_Style_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_requested_Insert_Style_Type,
      { "requested-Insert-Style-Type", "e2ap.requested_Insert_Style_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_e2ap_ric_InsertIndication_List,
      { "ric-InsertIndication-List", "e2ap.ric_InsertIndication_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item", HFILL }},
    { &hf_e2ap_ric_InsertIndication_List_item,
      { "E2SM-RC-ActionDefinition-Format4-Indication-Item", "e2ap.E2SM_RC_ActionDefinition_Format4_Indication_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranP_InsertIndication_List_01,
      { "ranP-InsertIndication-List", "e2ap.ranP_InsertIndication_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item", HFILL }},
    { &hf_e2ap_ranP_InsertIndication_List_item_01,
      { "E2SM-RC-ActionDefinition-Format4-RANP-Item", "e2ap.E2SM_RC_ActionDefinition_Format4_RANP_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_indicationHeader_formats,
      { "ric-indicationHeader-formats", "e2ap.ric_indicationHeader_formats",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ric_indicationHeader_formats_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_indicationHeader_Format1,
      { "indicationHeader-Format1", "e2ap.indicationHeader_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationHeader_Format1", HFILL }},
    { &hf_e2ap_indicationHeader_Format2,
      { "indicationHeader-Format2", "e2ap.indicationHeader_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationHeader_Format2", HFILL }},
    { &hf_e2ap_indicationHeader_Format3,
      { "indicationHeader-Format3", "e2ap.indicationHeader_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationHeader_Format3", HFILL }},
    { &hf_e2ap_ric_InsertStyle_Type,
      { "ric-InsertStyle-Type", "e2ap.ric_InsertStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_e2ap_ric_indicationMessage_formats,
      { "ric-indicationMessage-formats", "e2ap.ric_indicationMessage_formats",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ric_indicationMessage_formats_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_indicationMessage_Format1,
      { "indicationMessage-Format1", "e2ap.indicationMessage_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationMessage_Format1", HFILL }},
    { &hf_e2ap_indicationMessage_Format2,
      { "indicationMessage-Format2", "e2ap.indicationMessage_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationMessage_Format2", HFILL }},
    { &hf_e2ap_indicationMessage_Format3,
      { "indicationMessage-Format3", "e2ap.indicationMessage_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationMessage_Format3", HFILL }},
    { &hf_e2ap_indicationMessage_Format4,
      { "indicationMessage-Format4", "e2ap.indicationMessage_Format4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationMessage_Format4", HFILL }},
    { &hf_e2ap_indicationMessage_Format5,
      { "indicationMessage-Format5", "e2ap.indicationMessage_Format5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationMessage_Format5", HFILL }},
    { &hf_e2ap_indicationMessage_Format6,
      { "indicationMessage-Format6", "e2ap.indicationMessage_Format6_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationMessage_Format6", HFILL }},
    { &hf_e2ap_ranP_Reported_List,
      { "ranP-Reported-List", "e2ap.ranP_Reported_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item", HFILL }},
    { &hf_e2ap_ranP_Reported_List_item,
      { "E2SM-RC-IndicationMessage-Format1-Item", "e2ap.E2SM_RC_IndicationMessage_Format1_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ueParameter_List,
      { "ueParameter-List", "e2ap.ueParameter_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item", HFILL }},
    { &hf_e2ap_ueParameter_List_item,
      { "E2SM-RC-IndicationMessage-Format2-Item", "e2ap.E2SM_RC_IndicationMessage_Format2_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranP_List,
      { "ranP-List", "e2ap.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item", HFILL }},
    { &hf_e2ap_ranP_List_item,
      { "E2SM-RC-IndicationMessage-Format2-RANParameter-Item", "e2ap.E2SM_RC_IndicationMessage_Format2_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_cellInfo_List_01,
      { "cellInfo-List", "e2ap.cellInfo_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item", HFILL }},
    { &hf_e2ap_cellInfo_List_item_01,
      { "E2SM-RC-IndicationMessage-Format3-Item", "e2ap.E2SM_RC_IndicationMessage_Format3_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_cellGlobal_ID,
      { "cellGlobal-ID", "e2ap.cellGlobal_ID",
        FT_UINT32, BASE_DEC, VALS(e2ap_CGI_vals), 0,
        "CGI", HFILL }},
    { &hf_e2ap_cellContextInfo,
      { "cellContextInfo", "e2ap.cellContextInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_e2ap_cellDeleted,
      { "cellDeleted", "e2ap.cellDeleted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_e2ap_neighborRelation_Table,
      { "neighborRelation-Table", "e2ap.neighborRelation_Table_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NeighborRelation_Info", HFILL }},
    { &hf_e2ap_ueInfo_List_01,
      { "ueInfo-List", "e2ap.ueInfo_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format4_ItemUE", HFILL }},
    { &hf_e2ap_ueInfo_List_item_01,
      { "E2SM-RC-IndicationMessage-Format4-ItemUE", "e2ap.E2SM_RC_IndicationMessage_Format4_ItemUE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_cellInfo_List_02,
      { "cellInfo-List", "e2ap.cellInfo_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format4_ItemCell", HFILL }},
    { &hf_e2ap_cellInfo_List_item_02,
      { "E2SM-RC-IndicationMessage-Format4-ItemCell", "e2ap.E2SM_RC_IndicationMessage_Format4_ItemCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ueContextInfo,
      { "ueContextInfo", "e2ap.ueContextInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_e2ap_ranP_Requested_List,
      { "ranP-Requested-List", "e2ap.ranP_Requested_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item", HFILL }},
    { &hf_e2ap_ranP_Requested_List_item,
      { "E2SM-RC-IndicationMessage-Format5-Item", "e2ap.E2SM_RC_IndicationMessage_Format5_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_InsertStyle_List_01,
      { "ric-InsertStyle-List", "e2ap.ric_InsertStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item", HFILL }},
    { &hf_e2ap_ric_InsertStyle_List_item_01,
      { "E2SM-RC-IndicationMessage-Format6-Style-Item", "e2ap.E2SM_RC_IndicationMessage_Format6_Style_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_indicated_Insert_Style_Type,
      { "indicated-Insert-Style-Type", "e2ap.indicated_Insert_Style_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_e2ap_ric_InsertIndication_List_01,
      { "ric-InsertIndication-List", "e2ap.ric_InsertIndication_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item", HFILL }},
    { &hf_e2ap_ric_InsertIndication_List_item_01,
      { "E2SM-RC-IndicationMessage-Format6-Indication-Item", "e2ap.E2SM_RC_IndicationMessage_Format6_Indication_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranP_InsertIndication_List_02,
      { "ranP-InsertIndication-List", "e2ap.ranP_InsertIndication_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item", HFILL }},
    { &hf_e2ap_ranP_InsertIndication_List_item_02,
      { "E2SM-RC-IndicationMessage-Format6-RANP-Item", "e2ap.E2SM_RC_IndicationMessage_Format6_RANP_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_callProcessID_formats,
      { "ric-callProcessID-formats", "e2ap.ric_callProcessID_formats",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ric_callProcessID_formats_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_callProcessID_Format1,
      { "callProcessID-Format1", "e2ap.callProcessID_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_CallProcessID_Format1", HFILL }},
    { &hf_e2ap_ric_callProcess_ID,
      { "ric-callProcess-ID", "e2ap.ric_callProcess_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAN_CallProcess_ID", HFILL }},
    { &hf_e2ap_ric_controlHeader_formats,
      { "ric-controlHeader-formats", "e2ap.ric_controlHeader_formats",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ric_controlHeader_formats_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_controlHeader_Format1,
      { "controlHeader-Format1", "e2ap.controlHeader_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlHeader_Format1", HFILL }},
    { &hf_e2ap_controlHeader_Format2,
      { "controlHeader-Format2", "e2ap.controlHeader_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlHeader_Format2", HFILL }},
    { &hf_e2ap_ric_ControlAction_ID,
      { "ric-ControlAction-ID", "e2ap.ric_ControlAction_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ControlDecision,
      { "ric-ControlDecision", "e2ap.ric_ControlDecision",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ric_ControlDecision_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ControlDecision_01,
      { "ric-ControlDecision", "e2ap.ric_ControlDecision",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ric_ControlDecision_01_vals), 0,
        "T_ric_ControlDecision_01", HFILL }},
    { &hf_e2ap_ric_controlMessage_formats,
      { "ric-controlMessage-formats", "e2ap.ric_controlMessage_formats",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ric_controlMessage_formats_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_controlMessage_Format1,
      { "controlMessage-Format1", "e2ap.controlMessage_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlMessage_Format1", HFILL }},
    { &hf_e2ap_controlMessage_Format2,
      { "controlMessage-Format2", "e2ap.controlMessage_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlMessage_Format2", HFILL }},
    { &hf_e2ap_ranP_List_01,
      { "ranP-List", "e2ap.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item", HFILL }},
    { &hf_e2ap_ranP_List_item_01,
      { "E2SM-RC-ControlMessage-Format1-Item", "e2ap.E2SM_RC_ControlMessage_Format1_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ControlStyle_List,
      { "ric-ControlStyle-List", "e2ap.ric_ControlStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item", HFILL }},
    { &hf_e2ap_ric_ControlStyle_List_item,
      { "E2SM-RC-ControlMessage-Format2-Style-Item", "e2ap.E2SM_RC_ControlMessage_Format2_Style_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_indicated_Control_Style_Type,
      { "indicated-Control-Style-Type", "e2ap.indicated_Control_Style_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_e2ap_ric_ControlAction_List,
      { "ric-ControlAction-List", "e2ap.ric_ControlAction_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item", HFILL }},
    { &hf_e2ap_ric_ControlAction_List_item,
      { "E2SM-RC-ControlMessage-Format2-ControlAction-Item", "e2ap.E2SM_RC_ControlMessage_Format2_ControlAction_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranP_List_02,
      { "ranP-List", "e2ap.ranP_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlMessage_Format1", HFILL }},
    { &hf_e2ap_ric_controlOutcome_formats,
      { "ric-controlOutcome-formats", "e2ap.ric_controlOutcome_formats",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ric_controlOutcome_formats_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_controlOutcome_Format1,
      { "controlOutcome-Format1", "e2ap.controlOutcome_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlOutcome_Format1", HFILL }},
    { &hf_e2ap_controlOutcome_Format2,
      { "controlOutcome-Format2", "e2ap.controlOutcome_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlOutcome_Format2", HFILL }},
    { &hf_e2ap_controlOutcome_Format3,
      { "controlOutcome-Format3", "e2ap.controlOutcome_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlOutcome_Format3", HFILL }},
    { &hf_e2ap_ranP_List_03,
      { "ranP-List", "e2ap.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item", HFILL }},
    { &hf_e2ap_ranP_List_item_02,
      { "E2SM-RC-ControlOutcome-Format1-Item", "e2ap.E2SM_RC_ControlOutcome_Format1_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ControlStyle_List_01,
      { "ric-ControlStyle-List", "e2ap.ric_ControlStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item", HFILL }},
    { &hf_e2ap_ric_ControlStyle_List_item_01,
      { "E2SM-RC-ControlOutcome-Format2-Style-Item", "e2ap.E2SM_RC_ControlOutcome_Format2_Style_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ControlOutcome_List,
      { "ric-ControlOutcome-List", "e2ap.ric_ControlOutcome_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item", HFILL }},
    { &hf_e2ap_ric_ControlOutcome_List_item,
      { "E2SM-RC-ControlOutcome-Format2-ControlOutcome-Item", "e2ap.E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranP_List_04,
      { "ranP-List", "e2ap.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item", HFILL }},
    { &hf_e2ap_ranP_List_item_03,
      { "E2SM-RC-ControlOutcome-Format2-RANP-Item", "e2ap.E2SM_RC_ControlOutcome_Format2_RANP_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranP_List_05,
      { "ranP-List", "e2ap.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item", HFILL }},
    { &hf_e2ap_ranP_List_item_04,
      { "E2SM-RC-ControlOutcome-Format3-Item", "e2ap.E2SM_RC_ControlOutcome_Format3_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunction_Name,
      { "ranFunction-Name", "e2ap.ranFunction_Name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunctionDefinition_EventTrigger,
      { "ranFunctionDefinition-EventTrigger", "e2ap.ranFunctionDefinition_EventTrigger_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunctionDefinition_Report,
      { "ranFunctionDefinition-Report", "e2ap.ranFunctionDefinition_Report_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunctionDefinition_Insert,
      { "ranFunctionDefinition-Insert", "e2ap.ranFunctionDefinition_Insert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunctionDefinition_Control,
      { "ranFunctionDefinition-Control", "e2ap.ranFunctionDefinition_Control_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunctionDefinition_Policy,
      { "ranFunctionDefinition-Policy", "e2ap.ranFunctionDefinition_Policy_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_EventTriggerStyle_List,
      { "ric-EventTriggerStyle-List", "e2ap.ric_EventTriggerStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item", HFILL }},
    { &hf_e2ap_ric_EventTriggerStyle_List_item,
      { "RANFunctionDefinition-EventTrigger-Style-Item", "e2ap.RANFunctionDefinition_EventTrigger_Style_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ran_L2Parameters_List,
      { "ran-L2Parameters-List", "e2ap.ran_L2Parameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item", HFILL }},
    { &hf_e2ap_ran_L2Parameters_List_item,
      { "L2Parameters-RANParameter-Item", "e2ap.L2Parameters_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ran_CallProcessTypes_List,
      { "ran-CallProcessTypes-List", "e2ap.ran_CallProcessTypes_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item", HFILL }},
    { &hf_e2ap_ran_CallProcessTypes_List_item,
      { "RANFunctionDefinition-EventTrigger-CallProcess-Item", "e2ap.RANFunctionDefinition_EventTrigger_CallProcess_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ran_UEIdentificationParameters_List,
      { "ran-UEIdentificationParameters-List", "e2ap.ran_UEIdentificationParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item", HFILL }},
    { &hf_e2ap_ran_UEIdentificationParameters_List_item,
      { "UEIdentification-RANParameter-Item", "e2ap.UEIdentification_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ran_CellIdentificationParameters_List,
      { "ran-CellIdentificationParameters-List", "e2ap.ran_CellIdentificationParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item", HFILL }},
    { &hf_e2ap_ran_CellIdentificationParameters_List_item,
      { "CellIdentification-RANParameter-Item", "e2ap.CellIdentification_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_EventTriggerStyle_Type,
      { "ric-EventTriggerStyle-Type", "e2ap.ric_EventTriggerStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_e2ap_ric_EventTriggerStyle_Name,
      { "ric-EventTriggerStyle-Name", "e2ap.ric_EventTriggerStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_e2ap_ric_EventTriggerFormat_Type,
      { "ric-EventTriggerFormat-Type", "e2ap.ric_EventTriggerFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_callProcessType_ID,
      { "callProcessType-ID", "e2ap.callProcessType_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RIC_CallProcessType_ID", HFILL }},
    { &hf_e2ap_callProcessType_Name,
      { "callProcessType-Name", "e2ap.callProcessType_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_CallProcessType_Name", HFILL }},
    { &hf_e2ap_callProcessBreakpoints_List,
      { "callProcessBreakpoints-List", "e2ap.callProcessBreakpoints_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item", HFILL }},
    { &hf_e2ap_callProcessBreakpoints_List_item,
      { "RANFunctionDefinition-EventTrigger-Breakpoint-Item", "e2ap.RANFunctionDefinition_EventTrigger_Breakpoint_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_callProcessBreakpoint_ID,
      { "callProcessBreakpoint-ID", "e2ap.callProcessBreakpoint_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RIC_CallProcessBreakpoint_ID", HFILL }},
    { &hf_e2ap_callProcessBreakpoint_Name,
      { "callProcessBreakpoint-Name", "e2ap.callProcessBreakpoint_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_CallProcessBreakpoint_Name", HFILL }},
    { &hf_e2ap_ran_CallProcessBreakpointParameters_List,
      { "ran-CallProcessBreakpointParameters-List", "e2ap.ran_CallProcessBreakpointParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item", HFILL }},
    { &hf_e2ap_ran_CallProcessBreakpointParameters_List_item,
      { "CallProcessBreakpoint-RANParameter-Item", "e2ap.CallProcessBreakpoint_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ReportStyle_List,
      { "ric-ReportStyle-List", "e2ap.ric_ReportStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item", HFILL }},
    { &hf_e2ap_ric_ReportStyle_List_item,
      { "RANFunctionDefinition-Report-Item", "e2ap.RANFunctionDefinition_Report_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ReportStyle_Type,
      { "ric-ReportStyle-Type", "e2ap.ric_ReportStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_e2ap_ric_ReportStyle_Name,
      { "ric-ReportStyle-Name", "e2ap.ric_ReportStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_e2ap_ric_SupportedEventTriggerStyle_Type,
      { "ric-SupportedEventTriggerStyle-Type", "e2ap.ric_SupportedEventTriggerStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_e2ap_ric_ReportActionFormat_Type,
      { "ric-ReportActionFormat-Type", "e2ap.ric_ReportActionFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_ric_IndicationHeaderFormat_Type,
      { "ric-IndicationHeaderFormat-Type", "e2ap.ric_IndicationHeaderFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_ric_IndicationMessageFormat_Type,
      { "ric-IndicationMessageFormat-Type", "e2ap.ric_IndicationMessageFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_ran_ReportParameters_List,
      { "ran-ReportParameters-List", "e2ap.ran_ReportParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item", HFILL }},
    { &hf_e2ap_ran_ReportParameters_List_item,
      { "Report-RANParameter-Item", "e2ap.Report_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_InsertStyle_List_02,
      { "ric-InsertStyle-List", "e2ap.ric_InsertStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item", HFILL }},
    { &hf_e2ap_ric_InsertStyle_List_item_02,
      { "RANFunctionDefinition-Insert-Item", "e2ap.RANFunctionDefinition_Insert_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_InsertStyle_Name,
      { "ric-InsertStyle-Name", "e2ap.ric_InsertStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_e2ap_ric_ActionDefinitionFormat_Type,
      { "ric-ActionDefinitionFormat-Type", "e2ap.ric_ActionDefinitionFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_ric_InsertIndication_List_02,
      { "ric-InsertIndication-List", "e2ap.ric_InsertIndication_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item", HFILL }},
    { &hf_e2ap_ric_InsertIndication_List_item_02,
      { "RANFunctionDefinition-Insert-Indication-Item", "e2ap.RANFunctionDefinition_Insert_Indication_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_CallProcessIDFormat_Type,
      { "ric-CallProcessIDFormat-Type", "e2ap.ric_CallProcessIDFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_ric_InsertIndication_Name,
      { "ric-InsertIndication-Name", "e2ap.ric_InsertIndication_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ran_InsertIndicationParameters_List,
      { "ran-InsertIndicationParameters-List", "e2ap.ran_InsertIndicationParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item", HFILL }},
    { &hf_e2ap_ran_InsertIndicationParameters_List_item,
      { "InsertIndication-RANParameter-Item", "e2ap.InsertIndication_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ControlStyle_List_02,
      { "ric-ControlStyle-List", "e2ap.ric_ControlStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item", HFILL }},
    { &hf_e2ap_ric_ControlStyle_List_item_02,
      { "RANFunctionDefinition-Control-Item", "e2ap.RANFunctionDefinition_Control_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ControlStyle_Type,
      { "ric-ControlStyle-Type", "e2ap.ric_ControlStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_e2ap_ric_ControlStyle_Name,
      { "ric-ControlStyle-Name", "e2ap.ric_ControlStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_e2ap_ric_ControlAction_List_01,
      { "ric-ControlAction-List", "e2ap.ric_ControlAction_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item", HFILL }},
    { &hf_e2ap_ric_ControlAction_List_item_01,
      { "RANFunctionDefinition-Control-Action-Item", "e2ap.RANFunctionDefinition_Control_Action_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ControlHeaderFormat_Type,
      { "ric-ControlHeaderFormat-Type", "e2ap.ric_ControlHeaderFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_ric_ControlMessageFormat_Type,
      { "ric-ControlMessageFormat-Type", "e2ap.ric_ControlMessageFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_ric_ControlOutcomeFormat_Type,
      { "ric-ControlOutcomeFormat-Type", "e2ap.ric_ControlOutcomeFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_ran_ControlOutcomeParameters_List,
      { "ran-ControlOutcomeParameters-List", "e2ap.ran_ControlOutcomeParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item", HFILL }},
    { &hf_e2ap_ran_ControlOutcomeParameters_List_item,
      { "ControlOutcome-RANParameter-Item", "e2ap.ControlOutcome_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ControlAction_Name,
      { "ric-ControlAction-Name", "e2ap.ric_ControlAction_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ran_ControlActionParameters_List,
      { "ran-ControlActionParameters-List", "e2ap.ran_ControlActionParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item", HFILL }},
    { &hf_e2ap_ran_ControlActionParameters_List_item,
      { "ControlAction-RANParameter-Item", "e2ap.ControlAction_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_PolicyStyle_List,
      { "ric-PolicyStyle-List", "e2ap.ric_PolicyStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item", HFILL }},
    { &hf_e2ap_ric_PolicyStyle_List_item,
      { "RANFunctionDefinition-Policy-Item", "e2ap.RANFunctionDefinition_Policy_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_PolicyStyle_Type,
      { "ric-PolicyStyle-Type", "e2ap.ric_PolicyStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_e2ap_ric_PolicyStyle_Name,
      { "ric-PolicyStyle-Name", "e2ap.ric_PolicyStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_e2ap_ric_PolicyAction_List,
      { "ric-PolicyAction-List", "e2ap.ric_PolicyAction_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item", HFILL }},
    { &hf_e2ap_ric_PolicyAction_List_item,
      { "RANFunctionDefinition-Policy-Action-Item", "e2ap.RANFunctionDefinition_Policy_Action_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_PolicyAction_Name,
      { "ric-PolicyAction-Name", "e2ap.ric_PolicyAction_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_ControlAction_Name", HFILL }},
    { &hf_e2ap_ran_PolicyActionParameters_List,
      { "ran-PolicyActionParameters-List", "e2ap.ran_PolicyActionParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item", HFILL }},
    { &hf_e2ap_ran_PolicyActionParameters_List_item,
      { "PolicyAction-RANParameter-Item", "e2ap.PolicyAction_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ran_PolicyConditionParameters_List,
      { "ran-PolicyConditionParameters-List", "e2ap.ran_PolicyConditionParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item", HFILL }},
    { &hf_e2ap_ran_PolicyConditionParameters_List_item,
      { "PolicyCondition-RANParameter-Item", "e2ap.PolicyCondition_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_measName,
      { "measName", "e2ap.measName",
        FT_STRING, BASE_NONE, NULL, 0,
        "MeasurementTypeName", HFILL }},
    { &hf_e2ap_measID,
      { "measID", "e2ap.measID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementTypeID", HFILL }},
    { &hf_e2ap_noLabel,
      { "noLabel", "e2ap.noLabel",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_noLabel_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_plmnID,
      { "plmnID", "e2ap.plmnID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMNIdentity", HFILL }},
    { &hf_e2ap_sliceID,
      { "sliceID", "e2ap.sliceID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "S_NSSAI", HFILL }},
    { &hf_e2ap_fiveQI,
      { "fiveQI", "e2ap.fiveQI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_qFI,
      { "qFI", "e2ap.qFI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QosFlowIdentifier", HFILL }},
    { &hf_e2ap_qCI,
      { "qCI", "e2ap.qCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_qCImax,
      { "qCImax", "e2ap.qCImax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QCI", HFILL }},
    { &hf_e2ap_qCImin,
      { "qCImin", "e2ap.qCImin",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QCI", HFILL }},
    { &hf_e2ap_aRPmax,
      { "aRPmax", "e2ap.aRPmax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_15_", HFILL }},
    { &hf_e2ap_aRPmin,
      { "aRPmin", "e2ap.aRPmin",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_15_", HFILL }},
    { &hf_e2ap_bitrateRange,
      { "bitrateRange", "e2ap.bitrateRange",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_e2ap_layerMU_MIMO,
      { "layerMU-MIMO", "e2ap.layerMU_MIMO",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_e2ap_sUM,
      { "sUM", "e2ap.sUM",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_sUM_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_distBinX,
      { "distBinX", "e2ap.distBinX",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_e2ap_distBinY,
      { "distBinY", "e2ap.distBinY",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_e2ap_distBinZ,
      { "distBinZ", "e2ap.distBinZ",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_e2ap_preLabelOverride,
      { "preLabelOverride", "e2ap.preLabelOverride",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_preLabelOverride_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_startEndInd,
      { "startEndInd", "e2ap.startEndInd",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_startEndInd_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_min,
      { "min", "e2ap.min",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_min_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_max,
      { "max", "e2ap.max",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_max_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_avg,
      { "avg", "e2ap.avg",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_avg_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ssbIndex,
      { "ssbIndex", "e2ap.ssbIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_e2ap_nonGoB_BFmode_Index,
      { "nonGoB-BFmode-Index", "e2ap.nonGoB_BFmode_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_e2ap_mIMO_mode_Index,
      { "mIMO-mode-Index", "e2ap.mIMO_mode_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_2_", HFILL }},
    { &hf_e2ap_testType,
      { "testType", "e2ap.testType",
        FT_UINT32, BASE_DEC, VALS(e2ap_TestCond_Type_vals), 0,
        "TestCond_Type", HFILL }},
    { &hf_e2ap_testExpr,
      { "testExpr", "e2ap.testExpr",
        FT_UINT32, BASE_DEC, VALS(e2ap_TestCond_Expression_vals), 0,
        "TestCond_Expression", HFILL }},
    { &hf_e2ap_testValue,
      { "testValue", "e2ap.testValue",
        FT_UINT32, BASE_DEC, VALS(e2ap_TestCond_Value_vals), 0,
        "TestCond_Value", HFILL }},
    { &hf_e2ap_gBR,
      { "gBR", "e2ap.gBR",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_gBR_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_aMBR,
      { "aMBR", "e2ap.aMBR",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_aMBR_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_isStat,
      { "isStat", "e2ap.isStat",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_isStat_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_isCatM,
      { "isCatM", "e2ap.isCatM",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_isCatM_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_rSRP,
      { "rSRP", "e2ap.rSRP",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_rSRP_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_rSRQ,
      { "rSRQ", "e2ap.rSRQ",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_rSRQ_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ul_rSRP,
      { "ul-rSRP", "e2ap.ul_rSRP",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_ul_rSRP_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_cQI,
      { "cQI", "e2ap.cQI",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_cQI_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_fiveQI_01,
      { "fiveQI", "e2ap.fiveQI",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_fiveQI_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_qCI_01,
      { "qCI", "e2ap.qCI",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_qCI_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_sNSSAI,
      { "sNSSAI", "e2ap.sNSSAI",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_sNSSAI_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_valueEnum,
      { "valueEnum", "e2ap.valueEnum",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_e2ap_valueBool,
      { "valueBool", "e2ap.valueBool",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_e2ap_valuePrtS,
      { "valuePrtS", "e2ap.valuePrtS",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_e2ap_binRangeListX,
      { "binRangeListX", "e2ap.binRangeListX",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BinRangeList", HFILL }},
    { &hf_e2ap_binRangeListY,
      { "binRangeListY", "e2ap.binRangeListY",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BinRangeList", HFILL }},
    { &hf_e2ap_binRangeListZ,
      { "binRangeListZ", "e2ap.binRangeListZ",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BinRangeList", HFILL }},
    { &hf_e2ap_BinRangeList_item,
      { "BinRangeItem", "e2ap.BinRangeItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_binIndex,
      { "binIndex", "e2ap.binIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_startValue,
      { "startValue", "e2ap.startValue",
        FT_UINT32, BASE_DEC, VALS(e2ap_BinRangeValue_vals), 0,
        "BinRangeValue", HFILL }},
    { &hf_e2ap_endValue,
      { "endValue", "e2ap.endValue",
        FT_UINT32, BASE_DEC, VALS(e2ap_BinRangeValue_vals), 0,
        "BinRangeValue", HFILL }},
    { &hf_e2ap_DistMeasurementBinRangeList_item,
      { "DistMeasurementBinRangeItem", "e2ap.DistMeasurementBinRangeItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_measType,
      { "measType", "e2ap.measType",
        FT_UINT32, BASE_DEC, VALS(e2ap_MeasurementType_vals), 0,
        "MeasurementType", HFILL }},
    { &hf_e2ap_binRangeDef,
      { "binRangeDef", "e2ap.binRangeDef_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "BinRangeDefinition", HFILL }},
    { &hf_e2ap_MeasurementInfoList_item,
      { "MeasurementInfoItem", "e2ap.MeasurementInfoItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_labelInfoList,
      { "labelInfoList", "e2ap.labelInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_LabelInfoList_item,
      { "LabelInfoItem", "e2ap.LabelInfoItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_measLabel,
      { "measLabel", "e2ap.measLabel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MeasurementLabel", HFILL }},
    { &hf_e2ap_MeasurementData_item,
      { "MeasurementDataItem", "e2ap.MeasurementDataItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_measRecord,
      { "measRecord", "e2ap.measRecord",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementRecord", HFILL }},
    { &hf_e2ap_incompleteFlag,
      { "incompleteFlag", "e2ap.incompleteFlag",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_incompleteFlag_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_MeasurementRecord_item,
      { "MeasurementRecordItem", "e2ap.MeasurementRecordItem",
        FT_UINT32, BASE_DEC, VALS(e2ap_MeasurementRecordItem_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_integer,
      { "integer", "e2ap.integer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_e2ap_real,
      { "real", "e2ap.real",
        FT_DOUBLE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_noValue,
      { "noValue", "e2ap.noValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_MeasurementInfo_Action_List_item,
      { "MeasurementInfo-Action-Item", "e2ap.MeasurementInfo_Action_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_MeasurementCondList_item,
      { "MeasurementCondItem", "e2ap.MeasurementCondItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_matchingCond,
      { "matchingCond", "e2ap.matchingCond",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MatchingCondList", HFILL }},
    { &hf_e2ap_MeasurementCondUEidList_item,
      { "MeasurementCondUEidItem", "e2ap.MeasurementCondUEidItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_matchingUEidList,
      { "matchingUEidList", "e2ap.matchingUEidList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_matchingUEidPerGP,
      { "matchingUEidPerGP", "e2ap.matchingUEidPerGP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_MatchingCondList_item,
      { "MatchingCondItem", "e2ap.MatchingCondItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_matchingCondChoice,
      { "matchingCondChoice", "e2ap.matchingCondChoice",
        FT_UINT32, BASE_DEC, VALS(e2ap_MatchingCondItem_Choice_vals), 0,
        "MatchingCondItem_Choice", HFILL }},
    { &hf_e2ap_testCondInfo,
      { "testCondInfo", "e2ap.testCondInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_MatchingUEidList_item,
      { "MatchingUEidItem", "e2ap.MatchingUEidItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_MatchingUEidPerGP_item,
      { "MatchingUEidPerGP-Item", "e2ap.MatchingUEidPerGP_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_matchedPerGP,
      { "matchedPerGP", "e2ap.matchedPerGP",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_matchedPerGP_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_noUEmatched,
      { "noUEmatched", "e2ap.noUEmatched",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_noUEmatched_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_oneOrMoreUEmatched,
      { "oneOrMoreUEmatched", "e2ap.oneOrMoreUEmatched",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MatchingUEidList_PerGP", HFILL }},
    { &hf_e2ap_MatchingUEidList_PerGP_item,
      { "MatchingUEidItem-PerGP", "e2ap.MatchingUEidItem_PerGP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_MatchingUeCondPerSubList_item,
      { "MatchingUeCondPerSubItem", "e2ap.MatchingUeCondPerSubItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_MatchingUEidPerSubList_item,
      { "MatchingUEidPerSubItem", "e2ap.MatchingUEidPerSubItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_UEMeasurementReportList_item,
      { "UEMeasurementReportItem", "e2ap.UEMeasurementReportItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_measReport,
      { "measReport", "e2ap.measReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_IndicationMessage_Format1", HFILL }},
    { &hf_e2ap_eventDefinition_formats,
      { "eventDefinition-formats", "e2ap.eventDefinition_formats",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_eventDefinition_formats_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_eventDefinition_Format1,
      { "eventDefinition-Format1", "e2ap.eventDefinition_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_EventTriggerDefinition_Format1", HFILL }},
    { &hf_e2ap_reportingPeriod,
      { "reportingPeriod", "e2ap.reportingPeriod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4294967295", HFILL }},
    { &hf_e2ap_actionDefinition_formats,
      { "actionDefinition-formats", "e2ap.actionDefinition_formats",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_actionDefinition_formats_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_actionDefinition_Format1_01,
      { "actionDefinition-Format1", "e2ap.actionDefinition_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format1", HFILL }},
    { &hf_e2ap_actionDefinition_Format2_01,
      { "actionDefinition-Format2", "e2ap.actionDefinition_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format2", HFILL }},
    { &hf_e2ap_actionDefinition_Format3_01,
      { "actionDefinition-Format3", "e2ap.actionDefinition_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format3", HFILL }},
    { &hf_e2ap_actionDefinition_Format4_01,
      { "actionDefinition-Format4", "e2ap.actionDefinition_Format4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format4", HFILL }},
    { &hf_e2ap_actionDefinition_Format5,
      { "actionDefinition-Format5", "e2ap.actionDefinition_Format5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format5", HFILL }},
    { &hf_e2ap_measInfoList,
      { "measInfoList", "e2ap.measInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementInfoList", HFILL }},
    { &hf_e2ap_granulPeriod,
      { "granulPeriod", "e2ap.granulPeriod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GranularityPeriod", HFILL }},
    { &hf_e2ap_distMeasBinRangeInfo,
      { "distMeasBinRangeInfo", "e2ap.distMeasBinRangeInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistMeasurementBinRangeList", HFILL }},
    { &hf_e2ap_subscriptInfo,
      { "subscriptInfo", "e2ap.subscriptInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format1", HFILL }},
    { &hf_e2ap_measCondList,
      { "measCondList", "e2ap.measCondList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementCondList", HFILL }},
    { &hf_e2ap_matchingUeCondList,
      { "matchingUeCondList", "e2ap.matchingUeCondList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MatchingUeCondPerSubList", HFILL }},
    { &hf_e2ap_subscriptionInfo,
      { "subscriptionInfo", "e2ap.subscriptionInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format1", HFILL }},
    { &hf_e2ap_matchingUEidList_01,
      { "matchingUEidList", "e2ap.matchingUEidList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MatchingUEidPerSubList", HFILL }},
    { &hf_e2ap_indicationHeader_formats,
      { "indicationHeader-formats", "e2ap.indicationHeader_formats",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_indicationHeader_formats_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_indicationHeader_Format1_01,
      { "indicationHeader-Format1", "e2ap.indicationHeader_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_IndicationHeader_Format1", HFILL }},
    { &hf_e2ap_colletStartTime,
      { "colletStartTime", "e2ap.colletStartTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_fileFormatversion,
      { "fileFormatversion", "e2ap.fileFormatversion",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_0_15_", HFILL }},
    { &hf_e2ap_senderName,
      { "senderName", "e2ap.senderName",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_0_400_", HFILL }},
    { &hf_e2ap_senderType,
      { "senderType", "e2ap.senderType",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_0_8_", HFILL }},
    { &hf_e2ap_vendorName,
      { "vendorName", "e2ap.vendorName",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_0_32_", HFILL }},
    { &hf_e2ap_indicationMessage_formats,
      { "indicationMessage-formats", "e2ap.indicationMessage_formats",
        FT_UINT32, BASE_DEC, VALS(e2ap_T_indicationMessage_formats_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_indicationMessage_Format1_01,
      { "indicationMessage-Format1", "e2ap.indicationMessage_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_IndicationMessage_Format1", HFILL }},
    { &hf_e2ap_indicationMessage_Format2_01,
      { "indicationMessage-Format2", "e2ap.indicationMessage_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_IndicationMessage_Format2", HFILL }},
    { &hf_e2ap_indicationMessage_Format3_01,
      { "indicationMessage-Format3", "e2ap.indicationMessage_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_IndicationMessage_Format3", HFILL }},
    { &hf_e2ap_measData,
      { "measData", "e2ap.measData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementData", HFILL }},
    { &hf_e2ap_measCondUEidList,
      { "measCondUEidList", "e2ap.measCondUEidList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementCondUEidList", HFILL }},
    { &hf_e2ap_ueMeasReportList,
      { "ueMeasReportList", "e2ap.ueMeasReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UEMeasurementReportList", HFILL }},
    { &hf_e2ap_ric_EventTriggerStyle_List_01,
      { "ric-EventTriggerStyle-List", "e2ap.ric_EventTriggerStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item", HFILL }},
    { &hf_e2ap_ric_EventTriggerStyle_List_item_01,
      { "RIC-EventTriggerStyle-Item", "e2ap.RIC_EventTriggerStyle_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ReportStyle_List_01,
      { "ric-ReportStyle-List", "e2ap.ric_ReportStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item", HFILL }},
    { &hf_e2ap_ric_ReportStyle_List_item_01,
      { "RIC-ReportStyle-Item", "e2ap.RIC_ReportStyle_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ActionFormat_Type,
      { "ric-ActionFormat-Type", "e2ap.ric_ActionFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_measInfo_Action_List,
      { "measInfo-Action-List", "e2ap.measInfo_Action_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementInfo_Action_List", HFILL }},
    { &hf_e2ap_eventDefinition_Format1_01,
      { "eventDefinition-Format1", "e2ap.eventDefinition_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_NI_EventTriggerDefinition_Format1", HFILL }},
    { &hf_e2ap_interface_type,
      { "interface-type", "e2ap.interface_type",
        FT_UINT32, BASE_DEC, VALS(e2ap_NI_Type_vals), 0,
        "NI_Type", HFILL }},
    { &hf_e2ap_interface_ID,
      { "interface-ID", "e2ap.interface_ID",
        FT_UINT32, BASE_DEC, VALS(e2ap_NI_Identifier_vals), 0,
        "NI_Identifier", HFILL }},
    { &hf_e2ap_interfaceDirection,
      { "interfaceDirection", "e2ap.interfaceDirection",
        FT_UINT32, BASE_DEC, VALS(e2ap_NI_Direction_vals), 0,
        "NI_Direction", HFILL }},
    { &hf_e2ap_interfaceMessageType,
      { "interfaceMessageType", "e2ap.interfaceMessageType",
        FT_UINT32, BASE_DEC, VALS(e2ap_NI_MessageType_vals), 0,
        "NI_MessageType", HFILL }},
    { &hf_e2ap_interfaceProtocolIE_List,
      { "interfaceProtocolIE-List", "e2ap.interfaceProtocolIE_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofInterfaceProtocolTests_OF_NI_ProtocolIE_Item", HFILL }},
    { &hf_e2ap_interfaceProtocolIE_List_item,
      { "NI-ProtocolIE-Item", "e2ap.NI_ProtocolIE_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_action_Definition_Format,
      { "action-Definition-Format", "e2ap.action_Definition_Format",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2SM_NI_ActionDefinitionFormat_vals), 0,
        "E2SM_NI_ActionDefinitionFormat", HFILL }},
    { &hf_e2ap_actionDefinition_Format1_02,
      { "actionDefinition-Format1", "e2ap.actionDefinition_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_NI_ActionDefinition_Format1", HFILL }},
    { &hf_e2ap_actionDefinition_Format2_02,
      { "actionDefinition-Format2", "e2ap.actionDefinition_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_NI_ActionDefinition_Format2", HFILL }},
    { &hf_e2ap_actionParameter_List,
      { "actionParameter-List", "e2ap.actionParameter_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofActionParameters_OF_RANparameter_Item", HFILL }},
    { &hf_e2ap_actionParameter_List_item,
      { "RANparameter-Item", "e2ap.RANparameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranUEgroup_List,
      { "ranUEgroup-List", "e2ap.ranUEgroup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRANueGroups_OF_RANueGroup_Item", HFILL }},
    { &hf_e2ap_ranUEgroup_List_item,
      { "RANueGroup-Item", "e2ap.RANueGroup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_indicationHeader_Format1_02,
      { "indicationHeader-Format1", "e2ap.indicationHeader_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_NI_IndicationHeader_Format1", HFILL }},
    { &hf_e2ap_timestamp,
      { "timestamp", "e2ap.timestamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NI_TimeStamp", HFILL }},
    { &hf_e2ap_indicationMessage_Format1_02,
      { "indicationMessage-Format1", "e2ap.indicationMessage_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_NI_IndicationMessage_Format1", HFILL }},
    { &hf_e2ap_interfaceMessage,
      { "interfaceMessage", "e2ap.interfaceMessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NI_Message", HFILL }},
    { &hf_e2ap_callProcessID_Format1_01,
      { "callProcessID-Format1", "e2ap.callProcessID_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_NI_CallProcessID_Format1", HFILL }},
    { &hf_e2ap_callProcessID_Format2,
      { "callProcessID-Format2", "e2ap.callProcessID_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_NI_CallProcessID_Format2", HFILL }},
    { &hf_e2ap_callProcess_ID,
      { "callProcess-ID", "e2ap.callProcess_ID",
        FT_INT32, BASE_DEC, NULL, 0,
        "RANcallProcess_ID_number", HFILL }},
    { &hf_e2ap_callProcess_ID_01,
      { "callProcess-ID", "e2ap.callProcess_ID",
        FT_STRING, BASE_NONE, NULL, 0,
        "RANcallProcess_ID_string", HFILL }},
    { &hf_e2ap_controlHeader_Format1_01,
      { "controlHeader-Format1", "e2ap.controlHeader_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_NI_ControlHeader_Format1", HFILL }},
    { &hf_e2ap_interface_Direction,
      { "interface-Direction", "e2ap.interface_Direction",
        FT_UINT32, BASE_DEC, VALS(e2ap_NI_Direction_vals), 0,
        "NI_Direction", HFILL }},
    { &hf_e2ap_ric_Control_Message_Priority,
      { "ric-Control-Message-Priority", "e2ap.ric_Control_Message_Priority",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_controlMessage_Format1_01,
      { "controlMessage-Format1", "e2ap.controlMessage_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_NI_ControlMessage_Format1", HFILL }},
    { &hf_e2ap_controlOutcome_Format1_01,
      { "controlOutcome-Format1", "e2ap.controlOutcome_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_NI_ControlOutcome_Format1", HFILL }},
    { &hf_e2ap_outcomeElement_List,
      { "outcomeElement-List", "e2ap.outcomeElement_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameter_Item", HFILL }},
    { &hf_e2ap_outcomeElement_List_item,
      { "RANparameter-Item", "e2ap.RANparameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ni_Type_List,
      { "ni-Type-List", "e2ap.ni_Type_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofNItypes_OF_E2SM_NI_RANfunction_Item", HFILL }},
    { &hf_e2ap_ni_Type_List_item,
      { "E2SM-NI-RANfunction-Item", "e2ap.E2SM_NI_RANfunction_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_EventTriggerStyle_List_02,
      { "ric-EventTriggerStyle-List", "e2ap.ric_EventTriggerStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List", HFILL }},
    { &hf_e2ap_ric_EventTriggerStyle_List_item_02,
      { "RIC-EventTriggerStyle-List", "e2ap.RIC_EventTriggerStyle_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ReportStyle_List_02,
      { "ric-ReportStyle-List", "e2ap.ric_ReportStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List", HFILL }},
    { &hf_e2ap_ric_ReportStyle_List_item_02,
      { "RIC-ReportStyle-List", "e2ap.RIC_ReportStyle_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_InsertStyle_List_03,
      { "ric-InsertStyle-List", "e2ap.ric_InsertStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_InsertStyle_List", HFILL }},
    { &hf_e2ap_ric_InsertStyle_List_item_03,
      { "RIC-InsertStyle-List", "e2ap.RIC_InsertStyle_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ControlStyle_List_03,
      { "ric-ControlStyle-List", "e2ap.ric_ControlStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ControlStyle_List", HFILL }},
    { &hf_e2ap_ric_ControlStyle_List_item_03,
      { "RIC-ControlStyle-List", "e2ap.RIC_ControlStyle_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_PolicyStyle_List_01,
      { "ric-PolicyStyle-List", "e2ap.ric_PolicyStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_PolicyStyle_List", HFILL }},
    { &hf_e2ap_ric_PolicyStyle_List_item_01,
      { "RIC-PolicyStyle-List", "e2ap.RIC_PolicyStyle_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_global_ng_RAN_ID,
      { "global-ng-RAN-ID", "e2ap.global_ng_RAN_ID",
        FT_UINT32, BASE_DEC, VALS(e2ap_GlobalNG_RANNode_ID_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_global_eNB_ID_01,
      { "global-eNB-ID", "e2ap.global_eNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_global_en_gNB_ID_01,
      { "global-en-gNB-ID", "e2ap.global_en_gNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_global_gNB_DU_ID,
      { "global-gNB-DU-ID", "e2ap.global_gNB_DU_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_global_gNB_CU_UP_ID,
      { "global-gNB-CU-UP-ID", "e2ap.global_gNB_CU_UP_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_s1MessageType,
      { "s1MessageType", "e2ap.s1MessageType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NI_MessageTypeS1", HFILL }},
    { &hf_e2ap_x2MessageType,
      { "x2MessageType", "e2ap.x2MessageType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NI_MessageTypeX2", HFILL }},
    { &hf_e2ap_ngMessageType,
      { "ngMessageType", "e2ap.ngMessageType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NI_MessageTypeNG", HFILL }},
    { &hf_e2ap_xnMessageType,
      { "xnMessageType", "e2ap.xnMessageType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NI_MessageTypeXn", HFILL }},
    { &hf_e2ap_f1MessageType,
      { "f1MessageType", "e2ap.f1MessageType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NI_MessageTypeF1", HFILL }},
    { &hf_e2ap_e1MessageType,
      { "e1MessageType", "e2ap.e1MessageType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NI_MessageTypeE1", HFILL }},
    { &hf_e2ap_typeOfMessage,
      { "typeOfMessage", "e2ap.typeOfMessage",
        FT_UINT32, BASE_DEC, VALS(e2ap_TypeOfMessage_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_interfaceProtocolIE_ID,
      { "interfaceProtocolIE-ID", "e2ap.interfaceProtocolIE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &e2ap_ProtocolIE_ID_vals_ext, 0,
        "NI_ProtocolIE_ID", HFILL }},
    { &hf_e2ap_interfaceProtocolIE_Test,
      { "interfaceProtocolIE-Test", "e2ap.interfaceProtocolIE_Test",
        FT_UINT32, BASE_DEC, VALS(e2ap_NI_ProtocolIE_Test_vals), 0,
        "NI_ProtocolIE_Test", HFILL }},
    { &hf_e2ap_interfaceProtocolIE_Value,
      { "interfaceProtocolIE-Value", "e2ap.interfaceProtocolIE_Value",
        FT_UINT32, BASE_DEC, VALS(e2ap_NI_ProtocolIE_Value_vals), 0,
        "NI_ProtocolIE_Value", HFILL }},
    { &hf_e2ap_ranImperativePolicy_List,
      { "ranImperativePolicy-List", "e2ap.ranImperativePolicy_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameter_Item", HFILL }},
    { &hf_e2ap_ranImperativePolicy_List_item,
      { "RANparameter-Item", "e2ap.RANparameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranParameter_ID_01,
      { "ranParameter-ID", "e2ap.ranParameter_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranParameter_Value_01,
      { "ranParameter-Value", "e2ap.ranParameter_Value",
        FT_UINT32, BASE_DEC, VALS(e2ap_RANparameter_Value_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ranParameter_Name,
      { "ranParameter-Name", "e2ap.ranParameter_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranParameter_Type_01,
      { "ranParameter-Type", "e2ap.ranParameter_Type",
        FT_UINT32, BASE_DEC, VALS(e2ap_RANparameter_Type_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_ranUEgroupID,
      { "ranUEgroupID", "e2ap.ranUEgroupID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranUEgroupDefinition,
      { "ranUEgroupDefinition", "e2ap.ranUEgroupDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranPolicy,
      { "ranPolicy", "e2ap.ranPolicy_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANimperativePolicy", HFILL }},
    { &hf_e2ap_ranUEgroupDef_List,
      { "ranUEgroupDef-List", "e2ap.ranUEgroupDef_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRANparameters_OF_RANueGroupDef_Item", HFILL }},
    { &hf_e2ap_ranUEgroupDef_List_item,
      { "RANueGroupDef-Item", "e2ap.RANueGroupDef_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranParameter_Test,
      { "ranParameter-Test", "e2ap.ranParameter_Test",
        FT_UINT32, BASE_DEC, VALS(e2ap_RANparameter_Test_Condition_vals), 0,
        "RANparameter_Test_Condition", HFILL }},
    { &hf_e2ap_ric_ControlFormat_Type,
      { "ric-ControlFormat-Type", "e2ap.ric_ControlFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_ric_ControlOutcomeRanParaDef_List,
      { "ric-ControlOutcomeRanParaDef-List", "e2ap.ric_ControlOutcomeRanParaDef_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item", HFILL }},
    { &hf_e2ap_ric_ControlOutcomeRanParaDef_List_item,
      { "RANparameterDef-Item", "e2ap.RANparameterDef_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_InsertActionFormat_Type,
      { "ric-InsertActionFormat-Type", "e2ap.ric_InsertActionFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_ric_InsertRanParameterDef_List,
      { "ric-InsertRanParameterDef-List", "e2ap.ric_InsertRanParameterDef_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item", HFILL }},
    { &hf_e2ap_ric_InsertRanParameterDef_List_item,
      { "RANparameterDef-Item", "e2ap.RANparameterDef_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_PolicyActionFormat_Type,
      { "ric-PolicyActionFormat-Type", "e2ap.ric_PolicyActionFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_ric_PolicyRanParameterDef_List,
      { "ric-PolicyRanParameterDef-List", "e2ap.ric_PolicyRanParameterDef_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item", HFILL }},
    { &hf_e2ap_ric_PolicyRanParameterDef_List_item,
      { "RANparameterDef-Item", "e2ap.RANparameterDef_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ReportRanParameterDef_List,
      { "ric-ReportRanParameterDef-List", "e2ap.ric_ReportRanParameterDef_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item", HFILL }},
    { &hf_e2ap_ric_ReportRanParameterDef_List_item,
      { "RANparameterDef-Item", "e2ap.RANparameterDef_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
      { &hf_e2ap_unmapped_ran_function_id,
          { "Unmapped RANfunctionID", "e2ap.unmapped-ran-function-id",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
      { &hf_e2ap_ran_function_name_not_recognised,
          { "RANfunction name not recognised", "e2ap.ran-function-name-not-recognised",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
      { &hf_e2ap_ran_function_setup_frame,
          { "RANfunction setup frame", "e2ap.setup-frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

      { &hf_e2ap_dissector_version,
          { "Version (dissector)", "e2ap.version.dissector",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
      { &hf_e2ap_frame_version,
          { "Version (frame)", "e2ap.version.frame",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

      { &hf_e2ap_timestamp_string,
          { "Timestamp string", "e2ap.timestamp-string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_e2ap,
    &ett_e2ap_ProtocolIE_Container,
    &ett_e2ap_ProtocolIE_Field,
    &ett_e2ap_Cause,
    &ett_e2ap_CriticalityDiagnostics,
    &ett_e2ap_CriticalityDiagnostics_IE_List,
    &ett_e2ap_CriticalityDiagnostics_IE_Item,
    &ett_e2ap_E2nodeComponentConfiguration,
    &ett_e2ap_E2nodeComponentConfigurationAck,
    &ett_e2ap_E2nodeComponentID,
    &ett_e2ap_E2nodeComponentInterfaceE1,
    &ett_e2ap_E2nodeComponentInterfaceF1,
    &ett_e2ap_E2nodeComponentInterfaceNG,
    &ett_e2ap_E2nodeComponentInterfaceS1,
    &ett_e2ap_E2nodeComponentInterfaceX2,
    &ett_e2ap_E2nodeComponentInterfaceXn,
    &ett_e2ap_E2nodeComponentInterfaceW1,
    &ett_e2ap_ENB_ID,
    &ett_e2ap_ENB_ID_Choice,
    &ett_e2ap_ENGNB_ID,
    &ett_e2ap_GlobalE2node_ID,
    &ett_e2ap_GlobalE2node_en_gNB_ID,
    &ett_e2ap_GlobalE2node_eNB_ID,
    &ett_e2ap_GlobalE2node_gNB_ID,
    &ett_e2ap_GlobalE2node_ng_eNB_ID,
    &ett_e2ap_GlobalENB_ID,
    &ett_e2ap_GlobalenGNB_ID,
    &ett_e2ap_GlobalgNB_ID,
    &ett_e2ap_GlobalngeNB_ID,
    &ett_e2ap_GlobalNG_RANNode_ID,
    &ett_e2ap_GlobalRIC_ID,
    &ett_e2ap_GNB_ID_Choice,
    &ett_e2ap_RICrequestID,
    &ett_e2ap_RICsubsequentAction,
    &ett_e2ap_TNLinformation,
    &ett_e2ap_RICsubscriptionRequest,
    &ett_e2ap_RICsubscriptionDetails,
    &ett_e2ap_RICactions_ToBeSetup_List,
    &ett_e2ap_RICaction_ToBeSetup_Item,
    &ett_e2ap_RICsubscriptionResponse,
    &ett_e2ap_RICaction_Admitted_List,
    &ett_e2ap_RICaction_Admitted_Item,
    &ett_e2ap_RICaction_NotAdmitted_List,
    &ett_e2ap_RICaction_NotAdmitted_Item,
    &ett_e2ap_RICsubscriptionFailure,
    &ett_e2ap_RICsubscriptionDeleteRequest,
    &ett_e2ap_RICsubscriptionDeleteResponse,
    &ett_e2ap_RICsubscriptionDeleteFailure,
    &ett_e2ap_RICsubscriptionDeleteRequired,
    &ett_e2ap_RICsubscription_List_withCause,
    &ett_e2ap_RICsubscription_withCause_Item,
    &ett_e2ap_RICsubscriptionModificationRequest,
    &ett_e2ap_RICactions_ToBeRemovedForModification_List,
    &ett_e2ap_RICaction_ToBeRemovedForModification_Item,
    &ett_e2ap_RICactions_ToBeModifiedForModification_List,
    &ett_e2ap_RICaction_ToBeModifiedForModification_Item,
    &ett_e2ap_RICactions_ToBeAddedForModification_List,
    &ett_e2ap_RICaction_ToBeAddedForModification_Item,
    &ett_e2ap_RICsubscriptionModificationResponse,
    &ett_e2ap_RICactions_RemovedForModification_List,
    &ett_e2ap_RICaction_RemovedForModification_Item,
    &ett_e2ap_RICactions_FailedToBeRemovedForModification_List,
    &ett_e2ap_RICaction_FailedToBeRemovedForModification_Item,
    &ett_e2ap_RICactions_ModifiedForModification_List,
    &ett_e2ap_RICaction_ModifiedForModification_Item,
    &ett_e2ap_RICactions_FailedToBeModifiedForModification_List,
    &ett_e2ap_RICaction_FailedToBeModifiedForModification_Item,
    &ett_e2ap_RICactions_AddedForModification_List,
    &ett_e2ap_RICaction_AddedForModification_Item,
    &ett_e2ap_RICactions_FailedToBeAddedForModification_List,
    &ett_e2ap_RICaction_FailedToBeAddedForModification_Item,
    &ett_e2ap_RICsubscriptionModificationFailure,
    &ett_e2ap_RICsubscriptionModificationRequired,
    &ett_e2ap_RICactions_RequiredToBeModified_List,
    &ett_e2ap_RICaction_RequiredToBeModified_Item,
    &ett_e2ap_RICactions_RequiredToBeRemoved_List,
    &ett_e2ap_RICaction_RequiredToBeRemoved_Item,
    &ett_e2ap_RICsubscriptionModificationConfirm,
    &ett_e2ap_RICactions_ConfirmedForModification_List,
    &ett_e2ap_RICaction_ConfirmedForModification_Item,
    &ett_e2ap_RICactions_RefusedToBeModified_List,
    &ett_e2ap_RICaction_RefusedToBeModified_Item,
    &ett_e2ap_RICactions_ConfirmedForRemoval_List,
    &ett_e2ap_RICaction_ConfirmedForRemoval_Item,
    &ett_e2ap_RICactions_RefusedToBeRemoved_List,
    &ett_e2ap_RICaction_RefusedToBeRemoved_Item,
    &ett_e2ap_RICsubscriptionModificationRefuse,
    &ett_e2ap_RICindication,
    &ett_e2ap_RICcontrolRequest,
    &ett_e2ap_RICcontrolAcknowledge,
    &ett_e2ap_RICcontrolFailure,
    &ett_e2ap_RICQueryRequest,
    &ett_e2ap_RICQueryResponse,
    &ett_e2ap_RICQueryFailure,
    &ett_e2ap_ErrorIndication,
    &ett_e2ap_E2setupRequest,
    &ett_e2ap_E2setupResponse,
    &ett_e2ap_E2setupFailure,
    &ett_e2ap_E2connectionUpdate,
    &ett_e2ap_E2connectionUpdate_List,
    &ett_e2ap_E2connectionUpdate_Item,
    &ett_e2ap_E2connectionUpdateRemove_List,
    &ett_e2ap_E2connectionUpdateRemove_Item,
    &ett_e2ap_E2connectionUpdateAcknowledge,
    &ett_e2ap_E2connectionSetupFailed_List,
    &ett_e2ap_E2connectionSetupFailed_Item,
    &ett_e2ap_E2connectionUpdateFailure,
    &ett_e2ap_E2nodeConfigurationUpdate,
    &ett_e2ap_E2nodeComponentConfigAddition_List,
    &ett_e2ap_E2nodeComponentConfigAddition_Item,
    &ett_e2ap_E2nodeComponentConfigUpdate_List,
    &ett_e2ap_E2nodeComponentConfigUpdate_Item,
    &ett_e2ap_E2nodeComponentConfigRemoval_List,
    &ett_e2ap_E2nodeComponentConfigRemoval_Item,
    &ett_e2ap_E2nodeTNLassociationRemoval_List,
    &ett_e2ap_E2nodeTNLassociationRemoval_Item,
    &ett_e2ap_E2nodeConfigurationUpdateAcknowledge,
    &ett_e2ap_E2nodeComponentConfigAdditionAck_List,
    &ett_e2ap_E2nodeComponentConfigAdditionAck_Item,
    &ett_e2ap_E2nodeComponentConfigUpdateAck_List,
    &ett_e2ap_E2nodeComponentConfigUpdateAck_Item,
    &ett_e2ap_E2nodeComponentConfigRemovalAck_List,
    &ett_e2ap_E2nodeComponentConfigRemovalAck_Item,
    &ett_e2ap_E2nodeConfigurationUpdateFailure,
    &ett_e2ap_ResetRequest,
    &ett_e2ap_ResetResponse,
    &ett_e2ap_RICserviceUpdate,
    &ett_e2ap_RANfunctions_List,
    &ett_e2ap_RANfunction_Item,
    &ett_e2ap_RANfunctionsID_List,
    &ett_e2ap_RANfunctionID_Item,
    &ett_e2ap_RICserviceUpdateAcknowledge,
    &ett_e2ap_RANfunctionsIDcause_List,
    &ett_e2ap_RANfunctionIDcause_Item,
    &ett_e2ap_RICserviceUpdateFailure,
    &ett_e2ap_RICserviceQuery,
    &ett_e2ap_E2RemovalRequest,
    &ett_e2ap_E2RemovalResponse,
    &ett_e2ap_E2RemovalFailure,
    &ett_e2ap_E2AP_PDU,
    &ett_e2ap_InitiatingMessage,
    &ett_e2ap_SuccessfulOutcome,
    &ett_e2ap_UnsuccessfulOutcome,
    &ett_e2ap_CGI,
    &ett_e2ap_InterfaceIdentifier,
    &ett_e2ap_InterfaceID_NG,
    &ett_e2ap_InterfaceID_Xn,
    &ett_e2ap_InterfaceID_F1,
    &ett_e2ap_InterfaceID_E1,
    &ett_e2ap_InterfaceID_S1,
    &ett_e2ap_InterfaceID_X2,
    &ett_e2ap_T_nodeType,
    &ett_e2ap_InterfaceID_W1,
    &ett_e2ap_Interface_MessageID,
    &ett_e2ap_RANfunction_Name,
    &ett_e2ap_RRC_MessageID,
    &ett_e2ap_T_rrcType,
    &ett_e2ap_ServingCell_ARFCN,
    &ett_e2ap_ServingCell_PCI,
    &ett_e2ap_UEID,
    &ett_e2ap_UEID_GNB,
    &ett_e2ap_UEID_GNB_CU_CP_E1AP_ID_List,
    &ett_e2ap_UEID_GNB_CU_CP_E1AP_ID_Item,
    &ett_e2ap_UEID_GNB_CU_F1AP_ID_List,
    &ett_e2ap_UEID_GNB_CU_CP_F1AP_ID_Item,
    &ett_e2ap_UEID_GNB_DU,
    &ett_e2ap_UEID_GNB_CU_UP,
    &ett_e2ap_UEID_NG_ENB,
    &ett_e2ap_UEID_NG_ENB_DU,
    &ett_e2ap_UEID_EN_GNB,
    &ett_e2ap_UEID_ENB,
    &ett_e2ap_GUMMEI,
    &ett_e2ap_EUTRA_CGI,
    &ett_e2ap_GlobalGNB_ID,
    &ett_e2ap_GlobalNgENB_ID,
    &ett_e2ap_GNB_ID,
    &ett_e2ap_GUAMI,
    &ett_e2ap_NgENB_ID,
    &ett_e2ap_NR_CGI,
    &ett_e2ap_S_NSSAI,
    &ett_e2ap_GlobalNGRANNodeID,
    &ett_e2ap_NR_ARFCN,
    &ett_e2ap_NRFrequencyBand_List,
    &ett_e2ap_NRFrequencyBandItem,
    &ett_e2ap_NRFrequencyInfo,
    &ett_e2ap_SupportedSULBandList,
    &ett_e2ap_SupportedSULFreqBandItem,
    &ett_e2ap_NeighborCell_List,
    &ett_e2ap_NeighborCell_Item,
    &ett_e2ap_NeighborCell_Item_Choice_NR,
    &ett_e2ap_NeighborCell_Item_Choice_E_UTRA,
    &ett_e2ap_NeighborRelation_Info,
    &ett_e2ap_EventTrigger_Cell_Info,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item,
    &ett_e2ap_EventTrigger_Cell_Info_Item,
    &ett_e2ap_T_cellType,
    &ett_e2ap_EventTrigger_Cell_Info_Item_Choice_Individual,
    &ett_e2ap_EventTrigger_Cell_Info_Item_Choice_Group,
    &ett_e2ap_EventTrigger_UE_Info,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item,
    &ett_e2ap_EventTrigger_UE_Info_Item,
    &ett_e2ap_T_ueType,
    &ett_e2ap_EventTrigger_UE_Info_Item_Choice_Individual,
    &ett_e2ap_EventTrigger_UE_Info_Item_Choice_Group,
    &ett_e2ap_EventTrigger_UEevent_Info,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item,
    &ett_e2ap_EventTrigger_UEevent_Info_Item,
    &ett_e2ap_RANParameter_Definition,
    &ett_e2ap_RANParameter_Definition_Choice,
    &ett_e2ap_RANParameter_Definition_Choice_LIST,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item,
    &ett_e2ap_RANParameter_Definition_Choice_LIST_Item,
    &ett_e2ap_RANParameter_Definition_Choice_STRUCTURE,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item,
    &ett_e2ap_RANParameter_Definition_Choice_STRUCTURE_Item,
    &ett_e2ap_RANParameter_Value,
    &ett_e2ap_RANParameter_ValueType,
    &ett_e2ap_RANParameter_ValueType_Choice_ElementTrue,
    &ett_e2ap_RANParameter_ValueType_Choice_ElementFalse,
    &ett_e2ap_RANParameter_ValueType_Choice_Structure,
    &ett_e2ap_RANParameter_ValueType_Choice_List,
    &ett_e2ap_RANParameter_STRUCTURE,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item,
    &ett_e2ap_RANParameter_STRUCTURE_Item,
    &ett_e2ap_RANParameter_LIST,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE,
    &ett_e2ap_RANParameter_Testing,
    &ett_e2ap_RANParameter_TestingCondition,
    &ett_e2ap_RANParameter_Testing_Item,
    &ett_e2ap_T_ranParameter_Type,
    &ett_e2ap_RANParameter_Testing_Item_Choice_List,
    &ett_e2ap_RANParameter_Testing_Item_Choice_Structure,
    &ett_e2ap_RANParameter_Testing_Item_Choice_ElementTrue,
    &ett_e2ap_RANParameter_Testing_Item_Choice_ElementFalse,
    &ett_e2ap_RANParameter_Testing_LIST,
    &ett_e2ap_RANParameter_Testing_STRUCTURE,
    &ett_e2ap_RIC_PolicyAction,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item,
    &ett_e2ap_RIC_PolicyAction_RANParameter_Item,
    &ett_e2ap_E2SM_RC_EventTrigger,
    &ett_e2ap_T_ric_eventTrigger_formats,
    &ett_e2ap_E2SM_RC_EventTrigger_Format1,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item,
    &ett_e2ap_E2SM_RC_EventTrigger_Format1_Item,
    &ett_e2ap_MessageType_Choice,
    &ett_e2ap_MessageType_Choice_NI,
    &ett_e2ap_MessageType_Choice_RRC,
    &ett_e2ap_E2SM_RC_EventTrigger_Format2,
    &ett_e2ap_E2SM_RC_EventTrigger_Format3,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item,
    &ett_e2ap_E2SM_RC_EventTrigger_Format3_Item,
    &ett_e2ap_E2SM_RC_EventTrigger_Format4,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item,
    &ett_e2ap_E2SM_RC_EventTrigger_Format4_Item,
    &ett_e2ap_TriggerType_Choice,
    &ett_e2ap_TriggerType_Choice_RRCstate,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item,
    &ett_e2ap_TriggerType_Choice_RRCstate_Item,
    &ett_e2ap_TriggerType_Choice_UEID,
    &ett_e2ap_TriggerType_Choice_L2state,
    &ett_e2ap_E2SM_RC_EventTrigger_Format5,
    &ett_e2ap_E2SM_RC_ActionDefinition,
    &ett_e2ap_T_ric_actionDefinition_formats,
    &ett_e2ap_E2SM_RC_ActionDefinition_Format1,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item,
    &ett_e2ap_E2SM_RC_ActionDefinition_Format1_Item,
    &ett_e2ap_E2SM_RC_ActionDefinition_Format2,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item,
    &ett_e2ap_E2SM_RC_ActionDefinition_Format2_Item,
    &ett_e2ap_E2SM_RC_ActionDefinition_Format3,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item,
    &ett_e2ap_E2SM_RC_ActionDefinition_Format3_Item,
    &ett_e2ap_E2SM_RC_ActionDefinition_Format4,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item,
    &ett_e2ap_E2SM_RC_ActionDefinition_Format4_Style_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item,
    &ett_e2ap_E2SM_RC_ActionDefinition_Format4_Indication_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item,
    &ett_e2ap_E2SM_RC_ActionDefinition_Format4_RANP_Item,
    &ett_e2ap_E2SM_RC_IndicationHeader,
    &ett_e2ap_T_ric_indicationHeader_formats,
    &ett_e2ap_E2SM_RC_IndicationHeader_Format1,
    &ett_e2ap_E2SM_RC_IndicationHeader_Format2,
    &ett_e2ap_E2SM_RC_IndicationHeader_Format3,
    &ett_e2ap_E2SM_RC_IndicationMessage,
    &ett_e2ap_T_ric_indicationMessage_formats,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format1,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format1_Item,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format2,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format2_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format2_RANParameter_Item,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format3,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format3_Item,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format4,
    &ett_e2ap_SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format4_ItemUE,
    &ett_e2ap_SEQUENCE_SIZE_0_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format4_ItemCell,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format4_ItemUE,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format4_ItemCell,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format5,
    &ett_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format5_Item,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format6,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format6_Style_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format6_Indication_Item,
    &ett_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item,
    &ett_e2ap_E2SM_RC_IndicationMessage_Format6_RANP_Item,
    &ett_e2ap_E2SM_RC_CallProcessID,
    &ett_e2ap_T_ric_callProcessID_formats,
    &ett_e2ap_E2SM_RC_CallProcessID_Format1,
    &ett_e2ap_E2SM_RC_ControlHeader,
    &ett_e2ap_T_ric_controlHeader_formats,
    &ett_e2ap_E2SM_RC_ControlHeader_Format1,
    &ett_e2ap_E2SM_RC_ControlHeader_Format2,
    &ett_e2ap_E2SM_RC_ControlMessage,
    &ett_e2ap_T_ric_controlMessage_formats,
    &ett_e2ap_E2SM_RC_ControlMessage_Format1,
    &ett_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item,
    &ett_e2ap_E2SM_RC_ControlMessage_Format1_Item,
    &ett_e2ap_E2SM_RC_ControlMessage_Format2,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item,
    &ett_e2ap_E2SM_RC_ControlMessage_Format2_Style_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item,
    &ett_e2ap_E2SM_RC_ControlMessage_Format2_ControlAction_Item,
    &ett_e2ap_E2SM_RC_ControlOutcome,
    &ett_e2ap_T_ric_controlOutcome_formats,
    &ett_e2ap_E2SM_RC_ControlOutcome_Format1,
    &ett_e2ap_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item,
    &ett_e2ap_E2SM_RC_ControlOutcome_Format1_Item,
    &ett_e2ap_E2SM_RC_ControlOutcome_Format2,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item,
    &ett_e2ap_E2SM_RC_ControlOutcome_Format2_Style_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item,
    &ett_e2ap_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item,
    &ett_e2ap_E2SM_RC_ControlOutcome_Format2_RANP_Item,
    &ett_e2ap_E2SM_RC_ControlOutcome_Format3,
    &ett_e2ap_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item,
    &ett_e2ap_E2SM_RC_ControlOutcome_Format3_Item,
    &ett_e2ap_E2SM_RC_RANFunctionDefinition,
    &ett_e2ap_RANFunctionDefinition_EventTrigger,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item,
    &ett_e2ap_RANFunctionDefinition_EventTrigger_Style_Item,
    &ett_e2ap_L2Parameters_RANParameter_Item,
    &ett_e2ap_UEIdentification_RANParameter_Item,
    &ett_e2ap_CellIdentification_RANParameter_Item,
    &ett_e2ap_RANFunctionDefinition_EventTrigger_CallProcess_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item,
    &ett_e2ap_RANFunctionDefinition_EventTrigger_Breakpoint_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item,
    &ett_e2ap_CallProcessBreakpoint_RANParameter_Item,
    &ett_e2ap_RANFunctionDefinition_Report,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item,
    &ett_e2ap_RANFunctionDefinition_Report_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item,
    &ett_e2ap_Report_RANParameter_Item,
    &ett_e2ap_RANFunctionDefinition_Insert,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item,
    &ett_e2ap_RANFunctionDefinition_Insert_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item,
    &ett_e2ap_RANFunctionDefinition_Insert_Indication_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item,
    &ett_e2ap_InsertIndication_RANParameter_Item,
    &ett_e2ap_RANFunctionDefinition_Control,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item,
    &ett_e2ap_RANFunctionDefinition_Control_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item,
    &ett_e2ap_ControlOutcome_RANParameter_Item,
    &ett_e2ap_RANFunctionDefinition_Control_Action_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item,
    &ett_e2ap_ControlAction_RANParameter_Item,
    &ett_e2ap_RANFunctionDefinition_Policy,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item,
    &ett_e2ap_RANFunctionDefinition_Policy_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item,
    &ett_e2ap_RANFunctionDefinition_Policy_Action_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item,
    &ett_e2ap_PolicyAction_RANParameter_Item,
    &ett_e2ap_PolicyCondition_RANParameter_Item,
    &ett_e2ap_BinRangeValue,
    &ett_e2ap_MeasurementType,
    &ett_e2ap_MeasurementLabel,
    &ett_e2ap_TestCondInfo,
    &ett_e2ap_TestCond_Type,
    &ett_e2ap_TestCond_Value,
    &ett_e2ap_BinRangeDefinition,
    &ett_e2ap_BinRangeList,
    &ett_e2ap_BinRangeItem,
    &ett_e2ap_DistMeasurementBinRangeList,
    &ett_e2ap_DistMeasurementBinRangeItem,
    &ett_e2ap_MeasurementInfoList,
    &ett_e2ap_MeasurementInfoItem,
    &ett_e2ap_LabelInfoList,
    &ett_e2ap_LabelInfoItem,
    &ett_e2ap_MeasurementData,
    &ett_e2ap_MeasurementDataItem,
    &ett_e2ap_MeasurementRecord,
    &ett_e2ap_MeasurementRecordItem,
    &ett_e2ap_MeasurementInfo_Action_List,
    &ett_e2ap_MeasurementInfo_Action_Item,
    &ett_e2ap_MeasurementCondList,
    &ett_e2ap_MeasurementCondItem,
    &ett_e2ap_MeasurementCondUEidList,
    &ett_e2ap_MeasurementCondUEidItem,
    &ett_e2ap_MatchingCondList,
    &ett_e2ap_MatchingCondItem,
    &ett_e2ap_MatchingCondItem_Choice,
    &ett_e2ap_MatchingUEidList,
    &ett_e2ap_MatchingUEidItem,
    &ett_e2ap_MatchingUEidPerGP,
    &ett_e2ap_MatchingUEidPerGP_Item,
    &ett_e2ap_T_matchedPerGP,
    &ett_e2ap_MatchingUEidList_PerGP,
    &ett_e2ap_MatchingUEidItem_PerGP,
    &ett_e2ap_MatchingUeCondPerSubList,
    &ett_e2ap_MatchingUeCondPerSubItem,
    &ett_e2ap_MatchingUEidPerSubList,
    &ett_e2ap_MatchingUEidPerSubItem,
    &ett_e2ap_UEMeasurementReportList,
    &ett_e2ap_UEMeasurementReportItem,
    &ett_e2ap_E2SM_KPM_EventTriggerDefinition,
    &ett_e2ap_T_eventDefinition_formats,
    &ett_e2ap_E2SM_KPM_EventTriggerDefinition_Format1,
    &ett_e2ap_E2SM_KPM_ActionDefinition,
    &ett_e2ap_T_actionDefinition_formats,
    &ett_e2ap_E2SM_KPM_ActionDefinition_Format1,
    &ett_e2ap_E2SM_KPM_ActionDefinition_Format2,
    &ett_e2ap_E2SM_KPM_ActionDefinition_Format3,
    &ett_e2ap_E2SM_KPM_ActionDefinition_Format4,
    &ett_e2ap_E2SM_KPM_ActionDefinition_Format5,
    &ett_e2ap_E2SM_KPM_IndicationHeader,
    &ett_e2ap_T_indicationHeader_formats,
    &ett_e2ap_E2SM_KPM_IndicationHeader_Format1,
    &ett_e2ap_E2SM_KPM_IndicationMessage,
    &ett_e2ap_T_indicationMessage_formats,
    &ett_e2ap_E2SM_KPM_IndicationMessage_Format1,
    &ett_e2ap_E2SM_KPM_IndicationMessage_Format2,
    &ett_e2ap_E2SM_KPM_IndicationMessage_Format3,
    &ett_e2ap_E2SM_KPM_RANfunction_Description,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item,
    &ett_e2ap_RIC_EventTriggerStyle_Item,
    &ett_e2ap_RIC_ReportStyle_Item,
    &ett_e2ap_E2SM_NI_EventTriggerDefinition,
    &ett_e2ap_E2SM_NI_EventTriggerDefinition_Format1,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofInterfaceProtocolTests_OF_NI_ProtocolIE_Item,
    &ett_e2ap_E2SM_NI_ActionDefinition,
    &ett_e2ap_E2SM_NI_ActionDefinitionFormat,
    &ett_e2ap_E2SM_NI_ActionDefinition_Format1,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofActionParameters_OF_RANparameter_Item,
    &ett_e2ap_E2SM_NI_ActionDefinition_Format2,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofRANueGroups_OF_RANueGroup_Item,
    &ett_e2ap_E2SM_NI_IndicationHeader,
    &ett_e2ap_E2SM_NI_IndicationHeader_Format1,
    &ett_e2ap_E2SM_NI_IndicationMessage,
    &ett_e2ap_E2SM_NI_IndicationMessage_Format1,
    &ett_e2ap_E2SM_NI_CallProcessID,
    &ett_e2ap_E2SM_NI_CallProcessID_Format1,
    &ett_e2ap_E2SM_NI_CallProcessID_Format2,
    &ett_e2ap_E2SM_NI_ControlHeader,
    &ett_e2ap_E2SM_NI_ControlHeader_Format1,
    &ett_e2ap_E2SM_NI_ControlMessage,
    &ett_e2ap_E2SM_NI_ControlMessage_Format1,
    &ett_e2ap_E2SM_NI_ControlOutcome,
    &ett_e2ap_E2SM_NI_ControlOutcome_Format1,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameter_Item,
    &ett_e2ap_E2SM_NI_RANfunction_Description,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofNItypes_OF_E2SM_NI_RANfunction_Item,
    &ett_e2ap_E2SM_NI_RANfunction_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_InsertStyle_List,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ControlStyle_List,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_PolicyStyle_List,
    &ett_e2ap_Global_gNB_DU_ID,
    &ett_e2ap_Global_gNB_CU_UP_ID,
    &ett_e2ap_NI_Identifier,
    &ett_e2ap_NI_MessageType,
    &ett_e2ap_NI_MessageTypeApproach1,
    &ett_e2ap_NI_ProtocolIE_Item,
    &ett_e2ap_NI_ProtocolIE_Value,
    &ett_e2ap_RANimperativePolicy,
    &ett_e2ap_RANparameter_Item,
    &ett_e2ap_RANparameterDef_Item,
    &ett_e2ap_RANparameter_Value,
    &ett_e2ap_RANueGroup_Item,
    &ett_e2ap_RANueGroupDefinition,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANueGroupDef_Item,
    &ett_e2ap_RANueGroupDef_Item,
    &ett_e2ap_RIC_ControlStyle_List,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofRANparameters_OF_RANparameterDef_Item,
    &ett_e2ap_RIC_EventTriggerStyle_List,
    &ett_e2ap_RIC_InsertStyle_List,
    &ett_e2ap_RIC_PolicyStyle_List,
    &ett_e2ap_RIC_ReportStyle_List,
  };

  static ei_register_info ei[] = {
     { &ei_e2ap_ran_function_names_no_match, { "e2ap.ran-function-names-no-match", PI_PROTOCOL, PI_WARN, "RAN Function name doesn't match known service models", EXPFILL }},
     { &ei_e2ap_ran_function_id_not_mapped,   { "e2ap.ran-function-id-not-known", PI_PROTOCOL, PI_WARN, "Service Model not known for RANFunctionID", EXPFILL }},
     { &ei_e2ap_ran_function_dissector_mismatch,   { "e2ap.ran-function-dissector-version-mismatch", PI_PROTOCOL, PI_WARN, "Available dissector does not match signalled", EXPFILL }},
     { &ei_e2ap_ran_function_max_dissectors_registered,   { "e2ap.ran-function-max-dissectors-registered", PI_PROTOCOL, PI_WARN, "Available dissector does not match signalled", EXPFILL }},

  };

  expert_module_t* expert_e2ap;

  /* Register protocol */
  proto_e2ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_e2ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


  /* Register dissector */
  e2ap_handle = register_dissector("e2ap", dissect_e2ap, proto_e2ap);

  expert_e2ap = expert_register_protocol(proto_e2ap);
  expert_register_field_array(expert_e2ap, ei, array_length(ei));

  /* Register dissector tables */
  e2ap_ies_dissector_table = register_dissector_table("e2ap.ies", "E2AP-PROTOCOL-IES", proto_e2ap, FT_UINT32, BASE_DEC);

  //  e2ap_ies_p1_dissector_table = register_dissector_table("e2ap.ies.pair.first", "E2AP-PROTOCOL-IES-PAIR FirstValue", proto_e2ap, FT_UINT32, BASE_DEC);
  //  e2ap_ies_p2_dissector_table = register_dissector_table("e2ap.ies.pair.second", "E2AP-PROTOCOL-IES-PAIR SecondValue", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_extension_dissector_table = register_dissector_table("e2ap.extension", "E2AP-PROTOCOL-EXTENSION", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_proc_imsg_dissector_table = register_dissector_table("e2ap.proc.imsg", "E2AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_proc_sout_dissector_table = register_dissector_table("e2ap.proc.sout", "E2AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_proc_uout_dissector_table = register_dissector_table("e2ap.proc.uout", "E2AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_n2_ie_type_dissector_table = register_dissector_table("e2ap.n2_ie_type", "E2AP N2 IE Type", proto_e2ap, FT_STRING, STRING_CASE_SENSITIVE);

  register_init_routine(&e2ap_init_protocol);

  e2ap_tap = register_tap("e2ap");
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
