/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-e2ap.c                                                              */
/* asn2wrs.py -L -p e2ap -c ./e2ap.cnf -s ./packet-e2ap-template -D . -O ../.. E2AP-CommonDataTypes.asn E2AP-Constants.asn E2AP-Containers.asn E2AP-IEs.asn E2AP-PDU-Contents.asn E2AP-PDU-Descriptions.asn e2sm-v2.01.asn e2sm-ric-v1.02.asn e2sm-kpm-v2.02.asn */

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
 * References: ORAN-WG3.E2AP-v02.01, ORAN-WG3.E2SM-KPM-v02.02, ORAN-WG3.E2SM-RC.01.02
 */

#include "config.h"
#include <stdio.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/to_str.h>

#include "packet-e2ap.h"
#include "packet-per.h"
#define PNAME  "E2 Application Protocol"
#define PSNAME "E2AP"
#define PFNAME "e2ap"

/* Dissector will use SCTP PPID 18 or SCTP port. IANA assigned port = 37464 */
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
#define maxnoofCellID                  65535
#define maxnoofRANOutcomeParameters    255
#define maxnoofParametersinStructure   65535
#define maxnoofItemsinList             65535
#define maxnoofUEInfo                  65535
#define maxnoofCellInfo                65535
#define maxnoofUEeventInfo             65535
#define maxnoofRANparamTest            255
#define maxnoofNeighbourCell           65535
#define maxnoofCallProcessTypes        65535
#define maxnoofCallProcessBreakpoints  65535
#define maxnoofInsertIndication        65535
#define maxnoofControlAction           65535
#define maxnoofPolicyAction            65535
#define maxnoofInsertIndicationActions 63
#define maxnoofMulCtrlActions          63
#define maxnoofCells                   16384
#define maxnoofRICStyles               63
#define maxnoofMeasurementInfo         65535
#define maxnoofLabelInfo               2147483647
#define maxnoofMeasurementRecord       65535
#define maxnoofMeasurementValue        2147483647
#define maxnoofConditionInfo           32768
#define maxnoofUEID                    65535
#define maxnoofConditionInfoPerSub     32768
#define maxnoofUEIDPerSub              65535
#define maxnoofUEMeasReport            65535

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
  id_E2removal =  13
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
  id_RICsubscription_withCause_Item =  61
} ProtocolIE_ID_enum;

/* Initialize the protocol and registered fields */
static int proto_e2ap = -1;
static int hf_e2ap_Cause_PDU = -1;                /* Cause */
static int hf_e2ap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_e2ap_GlobalE2node_ID_PDU = -1;      /* GlobalE2node_ID */
static int hf_e2ap_GlobalRIC_ID_PDU = -1;         /* GlobalRIC_ID */
static int hf_e2ap_RANfunctionID_PDU = -1;        /* RANfunctionID */
static int hf_e2ap_RICactionID_PDU = -1;          /* RICactionID */
static int hf_e2ap_RICcallProcessID_PDU = -1;     /* RICcallProcessID */
static int hf_e2ap_RICcontrolAckRequest_PDU = -1;  /* RICcontrolAckRequest */
static int hf_e2ap_RICcontrolHeader_PDU = -1;     /* RICcontrolHeader */
static int hf_e2ap_RICcontrolMessage_PDU = -1;    /* RICcontrolMessage */
static int hf_e2ap_RICcontrolOutcome_PDU = -1;    /* RICcontrolOutcome */
static int hf_e2ap_RICindicationHeader_PDU = -1;  /* RICindicationHeader */
static int hf_e2ap_RICindicationMessage_PDU = -1;  /* RICindicationMessage */
static int hf_e2ap_RICindicationSN_PDU = -1;      /* RICindicationSN */
static int hf_e2ap_RICindicationType_PDU = -1;    /* RICindicationType */
static int hf_e2ap_RICrequestID_PDU = -1;         /* RICrequestID */
static int hf_e2ap_TimeToWait_PDU = -1;           /* TimeToWait */
static int hf_e2ap_TNLinformation_PDU = -1;       /* TNLinformation */
static int hf_e2ap_TransactionID_PDU = -1;        /* TransactionID */
static int hf_e2ap_RICsubscriptionRequest_PDU = -1;  /* RICsubscriptionRequest */
static int hf_e2ap_RICsubscriptionDetails_PDU = -1;  /* RICsubscriptionDetails */
static int hf_e2ap_RICaction_ToBeSetup_Item_PDU = -1;  /* RICaction_ToBeSetup_Item */
static int hf_e2ap_RICsubscriptionResponse_PDU = -1;  /* RICsubscriptionResponse */
static int hf_e2ap_RICaction_Admitted_List_PDU = -1;  /* RICaction_Admitted_List */
static int hf_e2ap_RICaction_Admitted_Item_PDU = -1;  /* RICaction_Admitted_Item */
static int hf_e2ap_RICaction_NotAdmitted_List_PDU = -1;  /* RICaction_NotAdmitted_List */
static int hf_e2ap_RICaction_NotAdmitted_Item_PDU = -1;  /* RICaction_NotAdmitted_Item */
static int hf_e2ap_RICsubscriptionFailure_PDU = -1;  /* RICsubscriptionFailure */
static int hf_e2ap_RICsubscriptionDeleteRequest_PDU = -1;  /* RICsubscriptionDeleteRequest */
static int hf_e2ap_RICsubscriptionDeleteResponse_PDU = -1;  /* RICsubscriptionDeleteResponse */
static int hf_e2ap_RICsubscriptionDeleteFailure_PDU = -1;  /* RICsubscriptionDeleteFailure */
static int hf_e2ap_RICsubscriptionDeleteRequired_PDU = -1;  /* RICsubscriptionDeleteRequired */
static int hf_e2ap_RICsubscription_List_withCause_PDU = -1;  /* RICsubscription_List_withCause */
static int hf_e2ap_RICsubscription_withCause_Item_PDU = -1;  /* RICsubscription_withCause_Item */
static int hf_e2ap_RICindication_PDU = -1;        /* RICindication */
static int hf_e2ap_RICcontrolRequest_PDU = -1;    /* RICcontrolRequest */
static int hf_e2ap_RICcontrolAcknowledge_PDU = -1;  /* RICcontrolAcknowledge */
static int hf_e2ap_RICcontrolFailure_PDU = -1;    /* RICcontrolFailure */
static int hf_e2ap_ErrorIndication_PDU = -1;      /* ErrorIndication */
static int hf_e2ap_E2setupRequest_PDU = -1;       /* E2setupRequest */
static int hf_e2ap_E2setupResponse_PDU = -1;      /* E2setupResponse */
static int hf_e2ap_E2setupFailure_PDU = -1;       /* E2setupFailure */
static int hf_e2ap_E2connectionUpdate_PDU = -1;   /* E2connectionUpdate */
static int hf_e2ap_E2connectionUpdate_List_PDU = -1;  /* E2connectionUpdate_List */
static int hf_e2ap_E2connectionUpdate_Item_PDU = -1;  /* E2connectionUpdate_Item */
static int hf_e2ap_E2connectionUpdateRemove_List_PDU = -1;  /* E2connectionUpdateRemove_List */
static int hf_e2ap_E2connectionUpdateRemove_Item_PDU = -1;  /* E2connectionUpdateRemove_Item */
static int hf_e2ap_E2connectionUpdateAcknowledge_PDU = -1;  /* E2connectionUpdateAcknowledge */
static int hf_e2ap_E2connectionSetupFailed_List_PDU = -1;  /* E2connectionSetupFailed_List */
static int hf_e2ap_E2connectionSetupFailed_Item_PDU = -1;  /* E2connectionSetupFailed_Item */
static int hf_e2ap_E2connectionUpdateFailure_PDU = -1;  /* E2connectionUpdateFailure */
static int hf_e2ap_E2nodeConfigurationUpdate_PDU = -1;  /* E2nodeConfigurationUpdate */
static int hf_e2ap_E2nodeComponentConfigAddition_List_PDU = -1;  /* E2nodeComponentConfigAddition_List */
static int hf_e2ap_E2nodeComponentConfigAddition_Item_PDU = -1;  /* E2nodeComponentConfigAddition_Item */
static int hf_e2ap_E2nodeComponentConfigUpdate_List_PDU = -1;  /* E2nodeComponentConfigUpdate_List */
static int hf_e2ap_E2nodeComponentConfigUpdate_Item_PDU = -1;  /* E2nodeComponentConfigUpdate_Item */
static int hf_e2ap_E2nodeComponentConfigRemoval_List_PDU = -1;  /* E2nodeComponentConfigRemoval_List */
static int hf_e2ap_E2nodeComponentConfigRemoval_Item_PDU = -1;  /* E2nodeComponentConfigRemoval_Item */
static int hf_e2ap_E2nodeTNLassociationRemoval_List_PDU = -1;  /* E2nodeTNLassociationRemoval_List */
static int hf_e2ap_E2nodeTNLassociationRemoval_Item_PDU = -1;  /* E2nodeTNLassociationRemoval_Item */
static int hf_e2ap_E2nodeConfigurationUpdateAcknowledge_PDU = -1;  /* E2nodeConfigurationUpdateAcknowledge */
static int hf_e2ap_E2nodeComponentConfigAdditionAck_List_PDU = -1;  /* E2nodeComponentConfigAdditionAck_List */
static int hf_e2ap_E2nodeComponentConfigAdditionAck_Item_PDU = -1;  /* E2nodeComponentConfigAdditionAck_Item */
static int hf_e2ap_E2nodeComponentConfigUpdateAck_List_PDU = -1;  /* E2nodeComponentConfigUpdateAck_List */
static int hf_e2ap_E2nodeComponentConfigUpdateAck_Item_PDU = -1;  /* E2nodeComponentConfigUpdateAck_Item */
static int hf_e2ap_E2nodeComponentConfigRemovalAck_List_PDU = -1;  /* E2nodeComponentConfigRemovalAck_List */
static int hf_e2ap_E2nodeComponentConfigRemovalAck_Item_PDU = -1;  /* E2nodeComponentConfigRemovalAck_Item */
static int hf_e2ap_E2nodeConfigurationUpdateFailure_PDU = -1;  /* E2nodeConfigurationUpdateFailure */
static int hf_e2ap_ResetRequest_PDU = -1;         /* ResetRequest */
static int hf_e2ap_ResetResponse_PDU = -1;        /* ResetResponse */
static int hf_e2ap_RICserviceUpdate_PDU = -1;     /* RICserviceUpdate */
static int hf_e2ap_RANfunctions_List_PDU = -1;    /* RANfunctions_List */
static int hf_e2ap_RANfunction_Item_PDU = -1;     /* RANfunction_Item */
static int hf_e2ap_RANfunctionsID_List_PDU = -1;  /* RANfunctionsID_List */
static int hf_e2ap_RANfunctionID_Item_PDU = -1;   /* RANfunctionID_Item */
static int hf_e2ap_RICserviceUpdateAcknowledge_PDU = -1;  /* RICserviceUpdateAcknowledge */
static int hf_e2ap_RANfunctionsIDcause_List_PDU = -1;  /* RANfunctionsIDcause_List */
static int hf_e2ap_RANfunctionIDcause_Item_PDU = -1;  /* RANfunctionIDcause_Item */
static int hf_e2ap_RICserviceUpdateFailure_PDU = -1;  /* RICserviceUpdateFailure */
static int hf_e2ap_RICserviceQuery_PDU = -1;      /* RICserviceQuery */
static int hf_e2ap_E2RemovalRequest_PDU = -1;     /* E2RemovalRequest */
static int hf_e2ap_E2RemovalResponse_PDU = -1;    /* E2RemovalResponse */
static int hf_e2ap_E2RemovalFailure_PDU = -1;     /* E2RemovalFailure */
static int hf_e2ap_E2AP_PDU_PDU = -1;             /* E2AP_PDU */
static int hf_e2ap_E2SM_RC_EventTrigger_PDU = -1;  /* E2SM_RC_EventTrigger */
static int hf_e2ap_E2SM_RC_ActionDefinition_PDU = -1;  /* E2SM_RC_ActionDefinition */
static int hf_e2ap_E2SM_RC_IndicationHeader_PDU = -1;  /* E2SM_RC_IndicationHeader */
static int hf_e2ap_E2SM_RC_IndicationMessage_PDU = -1;  /* E2SM_RC_IndicationMessage */
static int hf_e2ap_E2SM_RC_CallProcessID_PDU = -1;  /* E2SM_RC_CallProcessID */
static int hf_e2ap_E2SM_RC_ControlHeader_PDU = -1;  /* E2SM_RC_ControlHeader */
static int hf_e2ap_E2SM_RC_ControlMessage_PDU = -1;  /* E2SM_RC_ControlMessage */
static int hf_e2ap_E2SM_RC_ControlOutcome_PDU = -1;  /* E2SM_RC_ControlOutcome */
static int hf_e2ap_E2SM_RC_RANFunctionDefinition_PDU = -1;  /* E2SM_RC_RANFunctionDefinition */
static int hf_e2ap_E2SM_KPM_EventTriggerDefinition_PDU = -1;  /* E2SM_KPM_EventTriggerDefinition */
static int hf_e2ap_E2SM_KPM_ActionDefinition_PDU = -1;  /* E2SM_KPM_ActionDefinition */
static int hf_e2ap_E2SM_KPM_IndicationHeader_PDU = -1;  /* E2SM_KPM_IndicationHeader */
static int hf_e2ap_E2SM_KPM_IndicationMessage_PDU = -1;  /* E2SM_KPM_IndicationMessage */
static int hf_e2ap_E2SM_KPM_RANfunction_Description_PDU = -1;  /* E2SM_KPM_RANfunction_Description */
static int hf_e2ap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_e2ap_id = -1;                       /* ProtocolIE_ID */
static int hf_e2ap_criticality = -1;              /* Criticality */
static int hf_e2ap_value = -1;                    /* T_value */
static int hf_e2ap_ricRequest = -1;               /* CauseRICrequest */
static int hf_e2ap_ricService = -1;               /* CauseRICservice */
static int hf_e2ap_e2Node = -1;                   /* CauseE2node */
static int hf_e2ap_transport = -1;                /* CauseTransport */
static int hf_e2ap_protocol = -1;                 /* CauseProtocol */
static int hf_e2ap_misc = -1;                     /* CauseMisc */
static int hf_e2ap_procedureCode = -1;            /* ProcedureCode */
static int hf_e2ap_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_e2ap_procedureCriticality = -1;     /* Criticality */
static int hf_e2ap_ricRequestorID = -1;           /* RICrequestID */
static int hf_e2ap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_e2ap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_Item */
static int hf_e2ap_iECriticality = -1;            /* Criticality */
static int hf_e2ap_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_e2ap_typeOfError = -1;              /* TypeOfError */
static int hf_e2ap_e2nodeComponentRequestPart = -1;  /* OCTET_STRING */
static int hf_e2ap_e2nodeComponentResponsePart = -1;  /* OCTET_STRING */
static int hf_e2ap_updateOutcome = -1;            /* T_updateOutcome */
static int hf_e2ap_failureCause = -1;             /* Cause */
static int hf_e2ap_e2nodeComponentInterfaceTypeNG = -1;  /* E2nodeComponentInterfaceNG */
static int hf_e2ap_e2nodeComponentInterfaceTypeXn = -1;  /* E2nodeComponentInterfaceXn */
static int hf_e2ap_e2nodeComponentInterfaceTypeE1 = -1;  /* E2nodeComponentInterfaceE1 */
static int hf_e2ap_e2nodeComponentInterfaceTypeF1 = -1;  /* E2nodeComponentInterfaceF1 */
static int hf_e2ap_e2nodeComponentInterfaceTypeW1 = -1;  /* E2nodeComponentInterfaceW1 */
static int hf_e2ap_e2nodeComponentInterfaceTypeS1 = -1;  /* E2nodeComponentInterfaceS1 */
static int hf_e2ap_e2nodeComponentInterfaceTypeX2 = -1;  /* E2nodeComponentInterfaceX2 */
static int hf_e2ap_gNB_CU_CP_ID = -1;             /* GNB_CU_UP_ID */
static int hf_e2ap_gNB_DU_ID = -1;                /* GNB_DU_ID */
static int hf_e2ap_amf_name = -1;                 /* AMFName */
static int hf_e2ap_mme_name = -1;                 /* MMEname */
static int hf_e2ap_global_eNB_ID = -1;            /* GlobalENB_ID */
static int hf_e2ap_global_en_gNB_ID = -1;         /* GlobalenGNB_ID */
static int hf_e2ap_global_NG_RAN_Node_ID = -1;    /* GlobalNG_RANNode_ID */
static int hf_e2ap_ng_eNB_DU_ID = -1;             /* NGENB_DU_ID */
static int hf_e2ap_macro_eNB_ID = -1;             /* BIT_STRING_SIZE_20 */
static int hf_e2ap_home_eNB_ID = -1;              /* BIT_STRING_SIZE_28 */
static int hf_e2ap_short_Macro_eNB_ID = -1;       /* BIT_STRING_SIZE_18 */
static int hf_e2ap_long_Macro_eNB_ID = -1;        /* BIT_STRING_SIZE_21 */
static int hf_e2ap_enb_ID_macro = -1;             /* BIT_STRING_SIZE_20 */
static int hf_e2ap_enb_ID_shortmacro = -1;        /* BIT_STRING_SIZE_18 */
static int hf_e2ap_enb_ID_longmacro = -1;         /* BIT_STRING_SIZE_21 */
static int hf_e2ap_gNB_ID = -1;                   /* BIT_STRING_SIZE_22_32 */
static int hf_e2ap_gNB = -1;                      /* GlobalE2node_gNB_ID */
static int hf_e2ap_en_gNB = -1;                   /* GlobalE2node_en_gNB_ID */
static int hf_e2ap_ng_eNB = -1;                   /* GlobalE2node_ng_eNB_ID */
static int hf_e2ap_eNB = -1;                      /* GlobalE2node_eNB_ID */
static int hf_e2ap_en_gNB_CU_UP_ID = -1;          /* GNB_CU_UP_ID */
static int hf_e2ap_en_gNB_DU_ID = -1;             /* GNB_DU_ID */
static int hf_e2ap_global_gNB_ID = -1;            /* GlobalgNB_ID */
static int hf_e2ap_gNB_CU_UP_ID = -1;             /* GNB_CU_UP_ID */
static int hf_e2ap_global_ng_eNB_ID = -1;         /* GlobalngeNB_ID */
static int hf_e2ap_ngENB_DU_ID = -1;              /* NGENB_DU_ID */
static int hf_e2ap_pLMN_Identity = -1;            /* PLMN_Identity */
static int hf_e2ap_eNB_ID = -1;                   /* ENB_ID */
static int hf_e2ap_gNB_ID_01 = -1;                /* ENGNB_ID */
static int hf_e2ap_plmn_id = -1;                  /* PLMN_Identity */
static int hf_e2ap_gnb_id = -1;                   /* T_gnb_id */
static int hf_e2ap_enb_id = -1;                   /* ENB_ID_Choice */
static int hf_e2ap_gNB_01 = -1;                   /* GlobalgNB_ID */
static int hf_e2ap_ng_eNB_01 = -1;                /* GlobalngeNB_ID */
static int hf_e2ap_ric_ID = -1;                   /* BIT_STRING_SIZE_20 */
static int hf_e2ap_gnb_ID = -1;                   /* BIT_STRING_SIZE_22_32 */
static int hf_e2ap_ricRequestorID_01 = -1;        /* INTEGER_0_65535 */
static int hf_e2ap_ricInstanceID = -1;            /* INTEGER_0_65535 */
static int hf_e2ap_ricSubsequentActionType = -1;  /* RICsubsequentActionType */
static int hf_e2ap_ricTimeToWait = -1;            /* RICtimeToWait */
static int hf_e2ap_tnlAddress = -1;               /* T_tnlAddress */
static int hf_e2ap_tnlPort = -1;                  /* T_tnlPort */
static int hf_e2ap_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_e2ap_ricEventTriggerDefinition = -1;  /* RICeventTriggerDefinition */
static int hf_e2ap_ricAction_ToBeSetup_List = -1;  /* RICactions_ToBeSetup_List */
static int hf_e2ap_RICactions_ToBeSetup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_ricActionID = -1;              /* RICactionID */
static int hf_e2ap_ricActionType = -1;            /* RICactionType */
static int hf_e2ap_ricActionDefinition = -1;      /* RICactionDefinition */
static int hf_e2ap_ricSubsequentAction = -1;      /* RICsubsequentAction */
static int hf_e2ap_RICaction_Admitted_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RICaction_NotAdmitted_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_cause = -1;                    /* Cause */
static int hf_e2ap_RICsubscription_List_withCause_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_ricRequestID = -1;             /* RICrequestID */
static int hf_e2ap_ranFunctionID = -1;            /* RANfunctionID */
static int hf_e2ap_E2connectionUpdate_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_tnlInformation = -1;           /* TNLinformation */
static int hf_e2ap_tnlUsage = -1;                 /* TNLusage */
static int hf_e2ap_E2connectionUpdateRemove_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_E2connectionSetupFailed_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_E2nodeComponentConfigAddition_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_e2nodeComponentInterfaceType = -1;  /* E2nodeComponentInterfaceType */
static int hf_e2ap_e2nodeComponentID = -1;        /* E2nodeComponentID */
static int hf_e2ap_e2nodeComponentConfiguration = -1;  /* E2nodeComponentConfiguration */
static int hf_e2ap_E2nodeComponentConfigUpdate_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_E2nodeComponentConfigRemoval_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_E2nodeTNLassociationRemoval_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_tnlInformationRIC = -1;        /* TNLinformation */
static int hf_e2ap_E2nodeComponentConfigAdditionAck_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_e2nodeComponentConfigurationAck = -1;  /* E2nodeComponentConfigurationAck */
static int hf_e2ap_E2nodeComponentConfigUpdateAck_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_E2nodeComponentConfigRemovalAck_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RANfunctions_List_item = -1;   /* ProtocolIE_SingleContainer */
static int hf_e2ap_ranFunctionDefinition = -1;    /* RANfunctionDefinition */
static int hf_e2ap_ranFunctionRevision = -1;      /* RANfunctionRevision */
static int hf_e2ap_ranFunctionOID = -1;           /* RANfunctionOID */
static int hf_e2ap_RANfunctionsID_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RANfunctionsIDcause_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_e2ap_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_e2ap_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_e2ap_initiatingMessagevalue = -1;   /* InitiatingMessage_value */
static int hf_e2ap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_e2ap_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */
static int hf_e2ap_nR_CGI = -1;                   /* NR_CGI */
static int hf_e2ap_eUTRA_CGI = -1;                /* EUTRA_CGI */
static int hf_e2ap_nG = -1;                       /* InterfaceID_NG */
static int hf_e2ap_xN = -1;                       /* InterfaceID_Xn */
static int hf_e2ap_f1 = -1;                       /* InterfaceID_F1 */
static int hf_e2ap_e1 = -1;                       /* InterfaceID_E1 */
static int hf_e2ap_s1 = -1;                       /* InterfaceID_S1 */
static int hf_e2ap_x2 = -1;                       /* InterfaceID_X2 */
static int hf_e2ap_w1 = -1;                       /* InterfaceID_W1 */
static int hf_e2ap_guami = -1;                    /* GUAMI */
static int hf_e2ap_global_NG_RAN_ID = -1;         /* GlobalNGRANNodeID */
static int hf_e2ap_globalGNB_ID = -1;             /* GlobalGNB_ID */
static int hf_e2ap_gUMMEI = -1;                   /* GUMMEI */
static int hf_e2ap_nodeType = -1;                 /* T_nodeType */
static int hf_e2ap_global_ng_eNB_ID_01 = -1;      /* GlobalNgENB_ID */
static int hf_e2ap_interfaceProcedureID = -1;     /* INTEGER */
static int hf_e2ap_messageType = -1;              /* T_messageType */
static int hf_e2ap_ranFunction_ShortName = -1;    /* T_ranFunction_ShortName */
static int hf_e2ap_ranFunction_E2SM_OID = -1;     /* PrintableString_SIZE_1_1000_ */
static int hf_e2ap_ranFunction_Description = -1;  /* PrintableString_SIZE_1_150_ */
static int hf_e2ap_ranFunction_Instance = -1;     /* INTEGER */
static int hf_e2ap_rrcType = -1;                  /* T_rrcType */
static int hf_e2ap_lTE = -1;                      /* RRCclass_LTE */
static int hf_e2ap_nR = -1;                       /* RRCclass_NR */
static int hf_e2ap_messageID = -1;                /* INTEGER */
static int hf_e2ap_nR_01 = -1;                    /* NR_ARFCN */
static int hf_e2ap_eUTRA = -1;                    /* E_UTRA_ARFCN */
static int hf_e2ap_nR_02 = -1;                    /* NR_PCI */
static int hf_e2ap_eUTRA_01 = -1;                 /* E_UTRA_PCI */
static int hf_e2ap_gNB_UEID = -1;                 /* UEID_GNB */
static int hf_e2ap_gNB_DU_UEID = -1;              /* UEID_GNB_DU */
static int hf_e2ap_gNB_CU_UP_UEID = -1;           /* UEID_GNB_CU_UP */
static int hf_e2ap_ng_eNB_UEID = -1;              /* UEID_NG_ENB */
static int hf_e2ap_ng_eNB_DU_UEID = -1;           /* UEID_NG_ENB_DU */
static int hf_e2ap_en_gNB_UEID = -1;              /* UEID_EN_GNB */
static int hf_e2ap_eNB_UEID = -1;                 /* UEID_ENB */
static int hf_e2ap_amf_UE_NGAP_ID = -1;           /* AMF_UE_NGAP_ID */
static int hf_e2ap_gNB_CU_UE_F1AP_ID_List = -1;   /* UEID_GNB_CU_F1AP_ID_List */
static int hf_e2ap_gNB_CU_CP_UE_E1AP_ID_List = -1;  /* UEID_GNB_CU_CP_E1AP_ID_List */
static int hf_e2ap_ran_UEID = -1;                 /* RANUEID */
static int hf_e2ap_m_NG_RAN_UE_XnAP_ID = -1;      /* NG_RANnodeUEXnAPID */
static int hf_e2ap_globalNG_RANNode_ID = -1;      /* GlobalNGRANNodeID */
static int hf_e2ap_UEID_GNB_CU_CP_E1AP_ID_List_item = -1;  /* UEID_GNB_CU_CP_E1AP_ID_Item */
static int hf_e2ap_gNB_CU_CP_UE_E1AP_ID = -1;     /* GNB_CU_CP_UE_E1AP_ID */
static int hf_e2ap_UEID_GNB_CU_F1AP_ID_List_item = -1;  /* UEID_GNB_CU_CP_F1AP_ID_Item */
static int hf_e2ap_gNB_CU_UE_F1AP_ID = -1;        /* GNB_CU_UE_F1AP_ID */
static int hf_e2ap_ng_eNB_CU_UE_W1AP_ID = -1;     /* NGENB_CU_UE_W1AP_ID */
static int hf_e2ap_globalNgENB_ID = -1;           /* GlobalNgENB_ID */
static int hf_e2ap_m_eNB_UE_X2AP_ID = -1;         /* ENB_UE_X2AP_ID */
static int hf_e2ap_m_eNB_UE_X2AP_ID_Extension = -1;  /* ENB_UE_X2AP_ID_Extension */
static int hf_e2ap_globalENB_ID = -1;             /* GlobalENB_ID */
static int hf_e2ap_mME_UE_S1AP_ID = -1;           /* MME_UE_S1AP_ID */
static int hf_e2ap_pLMN_Identity_01 = -1;         /* PLMNIdentity */
static int hf_e2ap_mME_Group_ID = -1;             /* MME_Group_ID */
static int hf_e2ap_mME_Code = -1;                 /* MME_Code */
static int hf_e2ap_pLMNIdentity = -1;             /* PLMNIdentity */
static int hf_e2ap_eUTRACellIdentity = -1;        /* EUTRACellIdentity */
static int hf_e2ap_gNB_ID_02 = -1;                /* GNB_ID */
static int hf_e2ap_ngENB_ID = -1;                 /* NgENB_ID */
static int hf_e2ap_aMFRegionID = -1;              /* AMFRegionID */
static int hf_e2ap_aMFSetID = -1;                 /* AMFSetID */
static int hf_e2ap_aMFPointer = -1;               /* AMFPointer */
static int hf_e2ap_macroNgENB_ID = -1;            /* BIT_STRING_SIZE_20 */
static int hf_e2ap_shortMacroNgENB_ID = -1;       /* BIT_STRING_SIZE_18 */
static int hf_e2ap_longMacroNgENB_ID = -1;        /* BIT_STRING_SIZE_21 */
static int hf_e2ap_sST = -1;                      /* SST */
static int hf_e2ap_sD = -1;                       /* SD */
static int hf_e2ap_gNB_02 = -1;                   /* GlobalGNB_ID */
static int hf_e2ap_ng_eNB_02 = -1;                /* GlobalNgENB_ID */
static int hf_e2ap_nRARFCN = -1;                  /* INTEGER_0_maxNRARFCN */
static int hf_e2ap_NRFrequencyBand_List_item = -1;  /* NRFrequencyBandItem */
static int hf_e2ap_freqBandIndicatorNr = -1;      /* INTEGER_1_1024_ */
static int hf_e2ap_supportedSULBandList = -1;     /* SupportedSULBandList */
static int hf_e2ap_nrARFCN = -1;                  /* NR_ARFCN */
static int hf_e2ap_frequencyBand_List = -1;       /* NRFrequencyBand_List */
static int hf_e2ap_frequencyShift7p5khz = -1;     /* NRFrequencyShift7p5khz */
static int hf_e2ap_SupportedSULBandList_item = -1;  /* SupportedSULFreqBandItem */
static int hf_e2ap_nRCellIdentity = -1;           /* NRCellIdentity */
static int hf_e2ap_NeighborCell_List_item = -1;   /* NeighborCell_Item */
static int hf_e2ap_ranType_Choice_NR = -1;        /* NeighborCell_Item_Choice_NR */
static int hf_e2ap_ranType_Choice_EUTRA = -1;     /* NeighborCell_Item_Choice_E_UTRA */
static int hf_e2ap_nR_PCI = -1;                   /* NR_PCI */
static int hf_e2ap_fiveGS_TAC = -1;               /* FiveGS_TAC */
static int hf_e2ap_nR_mode_info = -1;             /* T_nR_mode_info */
static int hf_e2ap_nR_FreqInfo = -1;              /* NRFrequencyInfo */
static int hf_e2ap_x2_Xn_established = -1;        /* T_x2_Xn_established */
static int hf_e2ap_hO_validated = -1;             /* T_hO_validated */
static int hf_e2ap_version = -1;                  /* INTEGER_1_65535_ */
static int hf_e2ap_eUTRA_PCI = -1;                /* E_UTRA_PCI */
static int hf_e2ap_eUTRA_ARFCN = -1;              /* E_UTRA_ARFCN */
static int hf_e2ap_eUTRA_TAC = -1;                /* E_UTRA_TAC */
static int hf_e2ap_x2_Xn_established_01 = -1;     /* T_x2_Xn_established_01 */
static int hf_e2ap_hO_validated_01 = -1;          /* T_hO_validated_01 */
static int hf_e2ap_servingCellPCI = -1;           /* ServingCell_PCI */
static int hf_e2ap_servingCellARFCN = -1;         /* ServingCell_ARFCN */
static int hf_e2ap_neighborCell_List = -1;        /* NeighborCell_List */
static int hf_e2ap_cellInfo_List = -1;            /* SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item */
static int hf_e2ap_cellInfo_List_item = -1;       /* EventTrigger_Cell_Info_Item */
static int hf_e2ap_eventTriggerCellID = -1;       /* RIC_EventTrigger_Cell_ID */
static int hf_e2ap_cellType = -1;                 /* T_cellType */
static int hf_e2ap_cellType_Choice_Individual = -1;  /* EventTrigger_Cell_Info_Item_Choice_Individual */
static int hf_e2ap_cellType_Choice_Group = -1;    /* EventTrigger_Cell_Info_Item_Choice_Group */
static int hf_e2ap_logicalOR = -1;                /* LogicalOR */
static int hf_e2ap_cellGlobalID = -1;             /* CGI */
static int hf_e2ap_ranParameterTesting = -1;      /* RANParameter_Testing */
static int hf_e2ap_ueInfo_List = -1;              /* SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item */
static int hf_e2ap_ueInfo_List_item = -1;         /* EventTrigger_UE_Info_Item */
static int hf_e2ap_eventTriggerUEID = -1;         /* RIC_EventTrigger_UE_ID */
static int hf_e2ap_ueType = -1;                   /* T_ueType */
static int hf_e2ap_ueType_Choice_Individual = -1;  /* EventTrigger_UE_Info_Item_Choice_Individual */
static int hf_e2ap_ueType_Choice_Group = -1;      /* EventTrigger_UE_Info_Item_Choice_Group */
static int hf_e2ap_ueID = -1;                     /* UEID */
static int hf_e2ap_ueEvent_List = -1;             /* SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item */
static int hf_e2ap_ueEvent_List_item = -1;        /* EventTrigger_UEevent_Info_Item */
static int hf_e2ap_ueEventID = -1;                /* RIC_EventTrigger_UEevent_ID */
static int hf_e2ap_ranParameter_Definition_Choice = -1;  /* RANParameter_Definition_Choice */
static int hf_e2ap_choiceLIST = -1;               /* RANParameter_Definition_Choice_LIST */
static int hf_e2ap_choiceSTRUCTURE = -1;          /* RANParameter_Definition_Choice_STRUCTURE */
static int hf_e2ap_ranParameter_List = -1;        /* SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item */
static int hf_e2ap_ranParameter_List_item = -1;   /* RANParameter_Definition_Choice_LIST_Item */
static int hf_e2ap_ranParameter_ID = -1;          /* RANParameter_ID */
static int hf_e2ap_ranParameter_name = -1;        /* RANParameter_Name */
static int hf_e2ap_ranParameter_Definition = -1;  /* RANParameter_Definition */
static int hf_e2ap_ranParameter_STRUCTURE = -1;   /* SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item */
static int hf_e2ap_ranParameter_STRUCTURE_item = -1;  /* RANParameter_Definition_Choice_STRUCTURE_Item */
static int hf_e2ap_valueBoolean = -1;             /* BOOLEAN */
static int hf_e2ap_valueInt = -1;                 /* INTEGER */
static int hf_e2ap_valueReal = -1;                /* REAL */
static int hf_e2ap_valueBitS = -1;                /* BIT_STRING */
static int hf_e2ap_valueOctS = -1;                /* OCTET_STRING */
static int hf_e2ap_valuePrintableString = -1;     /* PrintableString */
static int hf_e2ap_ranP_Choice_ElementTrue = -1;  /* RANParameter_ValueType_Choice_ElementTrue */
static int hf_e2ap_ranP_Choice_ElementFalse = -1;  /* RANParameter_ValueType_Choice_ElementFalse */
static int hf_e2ap_ranP_Choice_Structure = -1;    /* RANParameter_ValueType_Choice_Structure */
static int hf_e2ap_ranP_Choice_List = -1;         /* RANParameter_ValueType_Choice_List */
static int hf_e2ap_ranParameter_value = -1;       /* RANParameter_Value */
static int hf_e2ap_ranParameter_Structure = -1;   /* RANParameter_STRUCTURE */
static int hf_e2ap_ranParameter_List_01 = -1;     /* RANParameter_LIST */
static int hf_e2ap_sequence_of_ranParameters = -1;  /* SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item */
static int hf_e2ap_sequence_of_ranParameters_item = -1;  /* RANParameter_STRUCTURE_Item */
static int hf_e2ap_ranParameter_valueType = -1;   /* RANParameter_ValueType */
static int hf_e2ap_list_of_ranParameter = -1;     /* SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE */
static int hf_e2ap_list_of_ranParameter_item = -1;  /* RANParameter_STRUCTURE */
static int hf_e2ap_RANParameter_Testing_item = -1;  /* RANParameter_Testing_Item */
static int hf_e2ap_ranP_Choice_comparison = -1;   /* T_ranP_Choice_comparison */
static int hf_e2ap_ranP_Choice_presence = -1;     /* T_ranP_Choice_presence */
static int hf_e2ap_ranParameter_Type = -1;        /* T_ranParameter_Type */
static int hf_e2ap_ranP_Choice_List_01 = -1;      /* RANParameter_Testing_Item_Choice_List */
static int hf_e2ap_ranP_Choice_Structure_01 = -1;  /* RANParameter_Testing_Item_Choice_Structure */
static int hf_e2ap_ranP_Choice_ElementTrue_01 = -1;  /* RANParameter_Testing_Item_Choice_ElementTrue */
static int hf_e2ap_ranP_Choice_ElementFalse_01 = -1;  /* RANParameter_Testing_Item_Choice_ElementFalse */
static int hf_e2ap_ranParameter_List_02 = -1;     /* RANParameter_Testing_LIST */
static int hf_e2ap_ranParameter_Structure_01 = -1;  /* RANParameter_Testing_STRUCTURE */
static int hf_e2ap_ranParameter_TestCondition = -1;  /* RANParameter_TestingCondition */
static int hf_e2ap_ranParameter_Value = -1;       /* RANParameter_Value */
static int hf_e2ap_RANParameter_Testing_LIST_item = -1;  /* RANParameter_Testing_Item */
static int hf_e2ap_RANParameter_Testing_STRUCTURE_item = -1;  /* RANParameter_Testing_Item */
static int hf_e2ap_ric_PolicyAction_ID = -1;      /* RIC_ControlAction_ID */
static int hf_e2ap_ranParameters_List = -1;       /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item */
static int hf_e2ap_ranParameters_List_item = -1;  /* RIC_PolicyAction_RANParameter_Item */
static int hf_e2ap_ric_PolicyDecision = -1;       /* T_ric_PolicyDecision */
static int hf_e2ap_ric_eventTrigger_formats = -1;  /* T_ric_eventTrigger_formats */
static int hf_e2ap_eventTrigger_Format1 = -1;     /* E2SM_RC_EventTrigger_Format1 */
static int hf_e2ap_eventTrigger_Format2 = -1;     /* E2SM_RC_EventTrigger_Format2 */
static int hf_e2ap_eventTrigger_Format3 = -1;     /* E2SM_RC_EventTrigger_Format3 */
static int hf_e2ap_eventTrigger_Format4 = -1;     /* E2SM_RC_EventTrigger_Format4 */
static int hf_e2ap_eventTrigger_Format5 = -1;     /* E2SM_RC_EventTrigger_Format5 */
static int hf_e2ap_message_List = -1;             /* SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item */
static int hf_e2ap_message_List_item = -1;        /* E2SM_RC_EventTrigger_Format1_Item */
static int hf_e2ap_globalAssociatedUEInfo = -1;   /* EventTrigger_UE_Info */
static int hf_e2ap_ric_eventTriggerCondition_ID = -1;  /* RIC_EventTriggerCondition_ID */
static int hf_e2ap_messageType_01 = -1;           /* MessageType_Choice */
static int hf_e2ap_messageDirection = -1;         /* T_messageDirection */
static int hf_e2ap_associatedUEInfo = -1;         /* EventTrigger_UE_Info */
static int hf_e2ap_associatedUEEvent = -1;        /* EventTrigger_UEevent_Info */
static int hf_e2ap_messageType_Choice_NI = -1;    /* MessageType_Choice_NI */
static int hf_e2ap_messageType_Choice_RRC = -1;   /* MessageType_Choice_RRC */
static int hf_e2ap_nI_Type = -1;                  /* InterfaceType */
static int hf_e2ap_nI_Identifier = -1;            /* InterfaceIdentifier */
static int hf_e2ap_nI_Message = -1;               /* Interface_MessageID */
static int hf_e2ap_rRC_Message = -1;              /* RRC_MessageID */
static int hf_e2ap_ric_callProcessType_ID = -1;   /* RIC_CallProcessType_ID */
static int hf_e2ap_ric_callProcessBreakpoint_ID = -1;  /* RIC_CallProcessBreakpoint_ID */
static int hf_e2ap_associatedE2NodeInfo = -1;     /* RANParameter_Testing */
static int hf_e2ap_e2NodeInfoChange_List = -1;    /* SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item */
static int hf_e2ap_e2NodeInfoChange_List_item = -1;  /* E2SM_RC_EventTrigger_Format3_Item */
static int hf_e2ap_e2NodeInfoChange_ID = -1;      /* INTEGER_1_512_ */
static int hf_e2ap_associatedCellInfo = -1;       /* EventTrigger_Cell_Info */
static int hf_e2ap_uEInfoChange_List = -1;        /* SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item */
static int hf_e2ap_uEInfoChange_List_item = -1;   /* E2SM_RC_EventTrigger_Format4_Item */
static int hf_e2ap_triggerType = -1;              /* TriggerType_Choice */
static int hf_e2ap_triggerType_Choice_RRCstate = -1;  /* TriggerType_Choice_RRCstate */
static int hf_e2ap_triggerType_Choice_UEID = -1;  /* TriggerType_Choice_UEID */
static int hf_e2ap_triggerType_Choice_L2state = -1;  /* TriggerType_Choice_L2state */
static int hf_e2ap_rrcState_List = -1;            /* SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item */
static int hf_e2ap_rrcState_List_item = -1;       /* TriggerType_Choice_RRCstate_Item */
static int hf_e2ap_stateChangedTo = -1;           /* RRC_State */
static int hf_e2ap_ueIDchange_ID = -1;            /* INTEGER_1_512_ */
static int hf_e2ap_associatedL2variables = -1;    /* RANParameter_Testing */
static int hf_e2ap_onDemand = -1;                 /* T_onDemand */
static int hf_e2ap_ric_Style_Type = -1;           /* RIC_Style_Type */
static int hf_e2ap_ric_actionDefinition_formats = -1;  /* T_ric_actionDefinition_formats */
static int hf_e2ap_actionDefinition_Format1 = -1;  /* E2SM_RC_ActionDefinition_Format1 */
static int hf_e2ap_actionDefinition_Format2 = -1;  /* E2SM_RC_ActionDefinition_Format2 */
static int hf_e2ap_actionDefinition_Format3 = -1;  /* E2SM_RC_ActionDefinition_Format3 */
static int hf_e2ap_actionDefinition_Format4 = -1;  /* E2SM_RC_ActionDefinition_Format4 */
static int hf_e2ap_ranP_ToBeReported_List = -1;   /* SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item */
static int hf_e2ap_ranP_ToBeReported_List_item = -1;  /* E2SM_RC_ActionDefinition_Format1_Item */
static int hf_e2ap_ric_PolicyConditions_List = -1;  /* SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item */
static int hf_e2ap_ric_PolicyConditions_List_item = -1;  /* E2SM_RC_ActionDefinition_Format2_Item */
static int hf_e2ap_ric_PolicyAction = -1;         /* RIC_PolicyAction */
static int hf_e2ap_ric_PolicyConditionDefinition = -1;  /* RANParameter_Testing */
static int hf_e2ap_ric_InsertIndication_ID = -1;  /* RIC_InsertIndication_ID */
static int hf_e2ap_ranP_InsertIndication_List = -1;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item */
static int hf_e2ap_ranP_InsertIndication_List_item = -1;  /* E2SM_RC_ActionDefinition_Format3_Item */
static int hf_e2ap_ric_InsertStyle_List = -1;     /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item */
static int hf_e2ap_ric_InsertStyle_List_item = -1;  /* E2SM_RC_ActionDefinition_Format4_Style_Item */
static int hf_e2ap_requested_Insert_Style_Type = -1;  /* RIC_Style_Type */
static int hf_e2ap_ric_InsertIndication_List = -1;  /* SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item */
static int hf_e2ap_ric_InsertIndication_List_item = -1;  /* E2SM_RC_ActionDefinition_Format4_Indication_Item */
static int hf_e2ap_ranP_InsertIndication_List_01 = -1;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item */
static int hf_e2ap_ranP_InsertIndication_List_item_01 = -1;  /* E2SM_RC_ActionDefinition_Format4_RANP_Item */
static int hf_e2ap_ric_indicationHeader_formats = -1;  /* T_ric_indicationHeader_formats */
static int hf_e2ap_indicationHeader_Format1 = -1;  /* E2SM_RC_IndicationHeader_Format1 */
static int hf_e2ap_indicationHeader_Format2 = -1;  /* E2SM_RC_IndicationHeader_Format2 */
static int hf_e2ap_indicationHeader_Format3 = -1;  /* E2SM_RC_IndicationHeader_Format3 */
static int hf_e2ap_ric_InsertStyle_Type = -1;     /* RIC_Style_Type */
static int hf_e2ap_ric_indicationMessage_formats = -1;  /* T_ric_indicationMessage_formats */
static int hf_e2ap_indicationMessage_Format1 = -1;  /* E2SM_RC_IndicationMessage_Format1 */
static int hf_e2ap_indicationMessage_Format2 = -1;  /* E2SM_RC_IndicationMessage_Format2 */
static int hf_e2ap_indicationMessage_Format3 = -1;  /* E2SM_RC_IndicationMessage_Format3 */
static int hf_e2ap_indicationMessage_Format4 = -1;  /* E2SM_RC_IndicationMessage_Format4 */
static int hf_e2ap_indicationMessage_Format5 = -1;  /* E2SM_RC_IndicationMessage_Format5 */
static int hf_e2ap_indicationMessage_Format6 = -1;  /* E2SM_RC_IndicationMessage_Format6 */
static int hf_e2ap_ranP_Reported_List = -1;       /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item */
static int hf_e2ap_ranP_Reported_List_item = -1;  /* E2SM_RC_IndicationMessage_Format1_Item */
static int hf_e2ap_ueParameter_List = -1;         /* SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item */
static int hf_e2ap_ueParameter_List_item = -1;    /* E2SM_RC_IndicationMessage_Format2_Item */
static int hf_e2ap_ranP_List = -1;                /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item */
static int hf_e2ap_ranP_List_item = -1;           /* E2SM_RC_IndicationMessage_Format2_RANParameter_Item */
static int hf_e2ap_cellInfo_List_01 = -1;         /* SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item */
static int hf_e2ap_cellInfo_List_item_01 = -1;    /* E2SM_RC_IndicationMessage_Format3_Item */
static int hf_e2ap_cellGlobal_ID = -1;            /* CGI */
static int hf_e2ap_cellContextInfo = -1;          /* OCTET_STRING */
static int hf_e2ap_cellDeleted = -1;              /* BOOLEAN */
static int hf_e2ap_neighborRelation_Table = -1;   /* NeighborRelation_Info */
static int hf_e2ap_ueInfo_List_01 = -1;           /* SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format4_ItemUE */
static int hf_e2ap_ueInfo_List_item_01 = -1;      /* E2SM_RC_IndicationMessage_Format4_ItemUE */
static int hf_e2ap_cellInfo_List_02 = -1;         /* SEQUENCE_SIZE_0_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format4_ItemCell */
static int hf_e2ap_cellInfo_List_item_02 = -1;    /* E2SM_RC_IndicationMessage_Format4_ItemCell */
static int hf_e2ap_ueContextInfo = -1;            /* OCTET_STRING */
static int hf_e2ap_ranP_Requested_List = -1;      /* SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item */
static int hf_e2ap_ranP_Requested_List_item = -1;  /* E2SM_RC_IndicationMessage_Format5_Item */
static int hf_e2ap_ric_InsertStyle_List_01 = -1;  /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item */
static int hf_e2ap_ric_InsertStyle_List_item_01 = -1;  /* E2SM_RC_IndicationMessage_Format6_Style_Item */
static int hf_e2ap_indicated_Insert_Style_Type = -1;  /* RIC_Style_Type */
static int hf_e2ap_ric_InsertIndication_List_01 = -1;  /* SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item */
static int hf_e2ap_ric_InsertIndication_List_item_01 = -1;  /* E2SM_RC_IndicationMessage_Format6_Indication_Item */
static int hf_e2ap_ranP_InsertIndication_List_02 = -1;  /* SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item */
static int hf_e2ap_ranP_InsertIndication_List_item_02 = -1;  /* E2SM_RC_IndicationMessage_Format6_RANP_Item */
static int hf_e2ap_ric_callProcessID_formats = -1;  /* T_ric_callProcessID_formats */
static int hf_e2ap_callProcessID_Format1 = -1;    /* E2SM_RC_CallProcessID_Format1 */
static int hf_e2ap_ric_callProcess_ID = -1;       /* RAN_CallProcess_ID */
static int hf_e2ap_ric_controlHeader_formats = -1;  /* T_ric_controlHeader_formats */
static int hf_e2ap_controlHeader_Format1 = -1;    /* E2SM_RC_ControlHeader_Format1 */
static int hf_e2ap_controlHeader_Format2 = -1;    /* E2SM_RC_ControlHeader_Format2 */
static int hf_e2ap_ric_ControlAction_ID = -1;     /* RIC_ControlAction_ID */
static int hf_e2ap_ric_ControlDecision = -1;      /* T_ric_ControlDecision */
static int hf_e2ap_ric_ControlDecision_01 = -1;   /* T_ric_ControlDecision_01 */
static int hf_e2ap_ric_controlMessage_formats = -1;  /* T_ric_controlMessage_formats */
static int hf_e2ap_controlMessage_Format1 = -1;   /* E2SM_RC_ControlMessage_Format1 */
static int hf_e2ap_controlMessage_Format2 = -1;   /* E2SM_RC_ControlMessage_Format2 */
static int hf_e2ap_ranP_List_01 = -1;             /* SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item */
static int hf_e2ap_ranP_List_item_01 = -1;        /* E2SM_RC_ControlMessage_Format1_Item */
static int hf_e2ap_ric_ControlStyle_List = -1;    /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item */
static int hf_e2ap_ric_ControlStyle_List_item = -1;  /* E2SM_RC_ControlMessage_Format2_Style_Item */
static int hf_e2ap_indicated_Control_Style_Type = -1;  /* RIC_Style_Type */
static int hf_e2ap_ric_ControlAction_List = -1;   /* SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item */
static int hf_e2ap_ric_ControlAction_List_item = -1;  /* E2SM_RC_ControlMessage_Format2_ControlAction_Item */
static int hf_e2ap_ranP_List_02 = -1;             /* E2SM_RC_ControlMessage_Format1 */
static int hf_e2ap_ric_controlOutcome_formats = -1;  /* T_ric_controlOutcome_formats */
static int hf_e2ap_controlOutcome_Format1 = -1;   /* E2SM_RC_ControlOutcome_Format1 */
static int hf_e2ap_controlOutcome_Format2 = -1;   /* E2SM_RC_ControlOutcome_Format2 */
static int hf_e2ap_controlOutcome_Format3 = -1;   /* E2SM_RC_ControlOutcome_Format3 */
static int hf_e2ap_ranP_List_03 = -1;             /* SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item */
static int hf_e2ap_ranP_List_item_02 = -1;        /* E2SM_RC_ControlOutcome_Format1_Item */
static int hf_e2ap_ric_ControlStyle_List_01 = -1;  /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item */
static int hf_e2ap_ric_ControlStyle_List_item_01 = -1;  /* E2SM_RC_ControlOutcome_Format2_Style_Item */
static int hf_e2ap_ric_ControlOutcome_List = -1;  /* SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item */
static int hf_e2ap_ric_ControlOutcome_List_item = -1;  /* E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item */
static int hf_e2ap_ranP_List_04 = -1;             /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item */
static int hf_e2ap_ranP_List_item_03 = -1;        /* E2SM_RC_ControlOutcome_Format2_RANP_Item */
static int hf_e2ap_ranP_List_05 = -1;             /* SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item */
static int hf_e2ap_ranP_List_item_04 = -1;        /* E2SM_RC_ControlOutcome_Format3_Item */
static int hf_e2ap_ranFunction_Name = -1;         /* RANfunction_Name */
static int hf_e2ap_ranFunctionDefinition_EventTrigger = -1;  /* RANFunctionDefinition_EventTrigger */
static int hf_e2ap_ranFunctionDefinition_Report = -1;  /* RANFunctionDefinition_Report */
static int hf_e2ap_ranFunctionDefinition_Insert = -1;  /* RANFunctionDefinition_Insert */
static int hf_e2ap_ranFunctionDefinition_Control = -1;  /* RANFunctionDefinition_Control */
static int hf_e2ap_ranFunctionDefinition_Policy = -1;  /* RANFunctionDefinition_Policy */
static int hf_e2ap_ric_EventTriggerStyle_List = -1;  /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item */
static int hf_e2ap_ric_EventTriggerStyle_List_item = -1;  /* RANFunctionDefinition_EventTrigger_Style_Item */
static int hf_e2ap_ran_L2Parameters_List = -1;    /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item */
static int hf_e2ap_ran_L2Parameters_List_item = -1;  /* L2Parameters_RANParameter_Item */
static int hf_e2ap_ran_CallProcessTypes_List = -1;  /* SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item */
static int hf_e2ap_ran_CallProcessTypes_List_item = -1;  /* RANFunctionDefinition_EventTrigger_CallProcess_Item */
static int hf_e2ap_ran_UEIdentificationParameters_List = -1;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item */
static int hf_e2ap_ran_UEIdentificationParameters_List_item = -1;  /* UEIdentification_RANParameter_Item */
static int hf_e2ap_ran_CellIdentificationParameters_List = -1;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item */
static int hf_e2ap_ran_CellIdentificationParameters_List_item = -1;  /* CellIdentification_RANParameter_Item */
static int hf_e2ap_ric_EventTriggerStyle_Type = -1;  /* RIC_Style_Type */
static int hf_e2ap_ric_EventTriggerStyle_Name = -1;  /* RIC_Style_Name */
static int hf_e2ap_ric_EventTriggerFormat_Type = -1;  /* RIC_Format_Type */
static int hf_e2ap_callProcessType_ID = -1;       /* RIC_CallProcessType_ID */
static int hf_e2ap_callProcessType_Name = -1;     /* RIC_CallProcessType_Name */
static int hf_e2ap_callProcessBreakpoints_List = -1;  /* SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item */
static int hf_e2ap_callProcessBreakpoints_List_item = -1;  /* RANFunctionDefinition_EventTrigger_Breakpoint_Item */
static int hf_e2ap_callProcessBreakpoint_ID = -1;  /* RIC_CallProcessBreakpoint_ID */
static int hf_e2ap_callProcessBreakpoint_Name = -1;  /* RIC_CallProcessBreakpoint_Name */
static int hf_e2ap_ran_CallProcessBreakpointParameters_List = -1;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item */
static int hf_e2ap_ran_CallProcessBreakpointParameters_List_item = -1;  /* CallProcessBreakpoint_RANParameter_Item */
static int hf_e2ap_ric_ReportStyle_List = -1;     /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item */
static int hf_e2ap_ric_ReportStyle_List_item = -1;  /* RANFunctionDefinition_Report_Item */
static int hf_e2ap_ric_ReportStyle_Type = -1;     /* RIC_Style_Type */
static int hf_e2ap_ric_ReportStyle_Name = -1;     /* RIC_Style_Name */
static int hf_e2ap_ric_SupportedEventTriggerStyle_Type = -1;  /* RIC_Style_Type */
static int hf_e2ap_ric_ReportActionFormat_Type = -1;  /* RIC_Format_Type */
static int hf_e2ap_ric_IndicationHeaderFormat_Type = -1;  /* RIC_Format_Type */
static int hf_e2ap_ric_IndicationMessageFormat_Type = -1;  /* RIC_Format_Type */
static int hf_e2ap_ran_ReportParameters_List = -1;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item */
static int hf_e2ap_ran_ReportParameters_List_item = -1;  /* Report_RANParameter_Item */
static int hf_e2ap_ric_InsertStyle_List_02 = -1;  /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item */
static int hf_e2ap_ric_InsertStyle_List_item_02 = -1;  /* RANFunctionDefinition_Insert_Item */
static int hf_e2ap_ric_InsertStyle_Name = -1;     /* RIC_Style_Name */
static int hf_e2ap_ric_ActionDefinitionFormat_Type = -1;  /* RIC_Format_Type */
static int hf_e2ap_ric_InsertIndication_List_02 = -1;  /* SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item */
static int hf_e2ap_ric_InsertIndication_List_item_02 = -1;  /* RANFunctionDefinition_Insert_Indication_Item */
static int hf_e2ap_ric_CallProcessIDFormat_Type = -1;  /* RIC_Format_Type */
static int hf_e2ap_ric_InsertIndication_Name = -1;  /* RIC_InsertIndication_Name */
static int hf_e2ap_ran_InsertIndicationParameters_List = -1;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item */
static int hf_e2ap_ran_InsertIndicationParameters_List_item = -1;  /* InsertIndication_RANParameter_Item */
static int hf_e2ap_ric_ControlStyle_List_02 = -1;  /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item */
static int hf_e2ap_ric_ControlStyle_List_item_02 = -1;  /* RANFunctionDefinition_Control_Item */
static int hf_e2ap_ric_ControlStyle_Type = -1;    /* RIC_Style_Type */
static int hf_e2ap_ric_ControlStyle_Name = -1;    /* RIC_Style_Name */
static int hf_e2ap_ric_ControlAction_List_01 = -1;  /* SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item */
static int hf_e2ap_ric_ControlAction_List_item_01 = -1;  /* RANFunctionDefinition_Control_Action_Item */
static int hf_e2ap_ric_ControlHeaderFormat_Type = -1;  /* RIC_Format_Type */
static int hf_e2ap_ric_ControlMessageFormat_Type = -1;  /* RIC_Format_Type */
static int hf_e2ap_ric_ControlOutcomeFormat_Type = -1;  /* RIC_Format_Type */
static int hf_e2ap_ran_ControlOutcomeParameters_List = -1;  /* SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item */
static int hf_e2ap_ran_ControlOutcomeParameters_List_item = -1;  /* ControlOutcome_RANParameter_Item */
static int hf_e2ap_ric_ControlAction_Name = -1;   /* RIC_ControlAction_Name */
static int hf_e2ap_ran_ControlActionParameters_List = -1;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item */
static int hf_e2ap_ran_ControlActionParameters_List_item = -1;  /* ControlAction_RANParameter_Item */
static int hf_e2ap_ric_PolicyStyle_List = -1;     /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item */
static int hf_e2ap_ric_PolicyStyle_List_item = -1;  /* RANFunctionDefinition_Policy_Item */
static int hf_e2ap_ric_PolicyStyle_Type = -1;     /* RIC_Style_Type */
static int hf_e2ap_ric_PolicyStyle_Name = -1;     /* RIC_Style_Name */
static int hf_e2ap_ric_PolicyAction_List = -1;    /* SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item */
static int hf_e2ap_ric_PolicyAction_List_item = -1;  /* RANFunctionDefinition_Policy_Action_Item */
static int hf_e2ap_ric_PolicyAction_Name = -1;    /* RIC_ControlAction_Name */
static int hf_e2ap_ran_PolicyActionParameters_List = -1;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item */
static int hf_e2ap_ran_PolicyActionParameters_List_item = -1;  /* PolicyAction_RANParameter_Item */
static int hf_e2ap_ran_PolicyConditionParameters_List = -1;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item */
static int hf_e2ap_ran_PolicyConditionParameters_List_item = -1;  /* PolicyCondition_RANParameter_Item */
static int hf_e2ap_measName = -1;                 /* MeasurementTypeName */
static int hf_e2ap_measID = -1;                   /* MeasurementTypeID */
static int hf_e2ap_noLabel = -1;                  /* T_noLabel */
static int hf_e2ap_plmnID = -1;                   /* PLMN_Identity */
static int hf_e2ap_sliceID = -1;                  /* S_NSSAI */
static int hf_e2ap_fiveQI = -1;                   /* FiveQI */
static int hf_e2ap_qFI = -1;                      /* QosFlowIdentifier */
static int hf_e2ap_qCI = -1;                      /* QCI */
static int hf_e2ap_qCImax = -1;                   /* QCI */
static int hf_e2ap_qCImin = -1;                   /* QCI */
static int hf_e2ap_aRPmax = -1;                   /* INTEGER_1_15_ */
static int hf_e2ap_aRPmin = -1;                   /* INTEGER_1_15_ */
static int hf_e2ap_bitrateRange = -1;             /* INTEGER_1_65535_ */
static int hf_e2ap_layerMU_MIMO = -1;             /* INTEGER_1_65535_ */
static int hf_e2ap_sUM = -1;                      /* T_sUM */
static int hf_e2ap_distBinX = -1;                 /* INTEGER_1_65535_ */
static int hf_e2ap_distBinY = -1;                 /* INTEGER_1_65535_ */
static int hf_e2ap_distBinZ = -1;                 /* INTEGER_1_65535_ */
static int hf_e2ap_preLabelOverride = -1;         /* T_preLabelOverride */
static int hf_e2ap_startEndInd = -1;              /* T_startEndInd */
static int hf_e2ap_min = -1;                      /* T_min */
static int hf_e2ap_max = -1;                      /* T_max */
static int hf_e2ap_avg = -1;                      /* T_avg */
static int hf_e2ap_testType = -1;                 /* TestCond_Type */
static int hf_e2ap_testExpr = -1;                 /* TestCond_Expression */
static int hf_e2ap_testValue = -1;                /* TestCond_Value */
static int hf_e2ap_gBR = -1;                      /* T_gBR */
static int hf_e2ap_aMBR = -1;                     /* T_aMBR */
static int hf_e2ap_isStat = -1;                   /* T_isStat */
static int hf_e2ap_isCatM = -1;                   /* T_isCatM */
static int hf_e2ap_rSRP = -1;                     /* T_rSRP */
static int hf_e2ap_rSRQ = -1;                     /* T_rSRQ */
static int hf_e2ap_ul_rSRP = -1;                  /* T_ul_rSRP */
static int hf_e2ap_cQI = -1;                      /* T_cQI */
static int hf_e2ap_fiveQI_01 = -1;                /* T_fiveQI */
static int hf_e2ap_qCI_01 = -1;                   /* T_qCI */
static int hf_e2ap_sNSSAI = -1;                   /* T_sNSSAI */
static int hf_e2ap_valueEnum = -1;                /* INTEGER */
static int hf_e2ap_valueBool = -1;                /* BOOLEAN */
static int hf_e2ap_valuePrtS = -1;                /* PrintableString */
static int hf_e2ap_MeasurementInfoList_item = -1;  /* MeasurementInfoItem */
static int hf_e2ap_measType = -1;                 /* MeasurementType */
static int hf_e2ap_labelInfoList = -1;            /* LabelInfoList */
static int hf_e2ap_LabelInfoList_item = -1;       /* LabelInfoItem */
static int hf_e2ap_measLabel = -1;                /* MeasurementLabel */
static int hf_e2ap_MeasurementData_item = -1;     /* MeasurementDataItem */
static int hf_e2ap_measRecord = -1;               /* MeasurementRecord */
static int hf_e2ap_incompleteFlag = -1;           /* T_incompleteFlag */
static int hf_e2ap_MeasurementRecord_item = -1;   /* MeasurementRecordItem */
static int hf_e2ap_integer = -1;                  /* INTEGER_0_4294967295 */
static int hf_e2ap_real = -1;                     /* REAL */
static int hf_e2ap_noValue = -1;                  /* NULL */
static int hf_e2ap_MeasurementInfo_Action_List_item = -1;  /* MeasurementInfo_Action_Item */
static int hf_e2ap_MeasurementCondList_item = -1;  /* MeasurementCondItem */
static int hf_e2ap_matchingCond = -1;             /* MatchingCondList */
static int hf_e2ap_MeasurementCondUEidList_item = -1;  /* MeasurementCondUEidItem */
static int hf_e2ap_matchingUEidList = -1;         /* MatchingUEidList */
static int hf_e2ap_MatchingCondList_item = -1;    /* MatchingCondItem */
static int hf_e2ap_testCondInfo = -1;             /* TestCondInfo */
static int hf_e2ap_MatchingUEidList_item = -1;    /* MatchingUEidItem */
static int hf_e2ap_MatchingUeCondPerSubList_item = -1;  /* MatchingUeCondPerSubItem */
static int hf_e2ap_MatchingUEidPerSubList_item = -1;  /* MatchingUEidPerSubItem */
static int hf_e2ap_UEMeasurementReportList_item = -1;  /* UEMeasurementReportItem */
static int hf_e2ap_measReport = -1;               /* E2SM_KPM_IndicationMessage_Format1 */
static int hf_e2ap_eventDefinition_formats = -1;  /* T_eventDefinition_formats */
static int hf_e2ap_eventDefinition_Format1 = -1;  /* E2SM_KPM_EventTriggerDefinition_Format1 */
static int hf_e2ap_reportingPeriod = -1;          /* INTEGER_1_4294967295 */
static int hf_e2ap_actionDefinition_formats = -1;  /* T_actionDefinition_formats */
static int hf_e2ap_actionDefinition_Format1_01 = -1;  /* E2SM_KPM_ActionDefinition_Format1 */
static int hf_e2ap_actionDefinition_Format2_01 = -1;  /* E2SM_KPM_ActionDefinition_Format2 */
static int hf_e2ap_actionDefinition_Format3_01 = -1;  /* E2SM_KPM_ActionDefinition_Format3 */
static int hf_e2ap_actionDefinition_Format4_01 = -1;  /* E2SM_KPM_ActionDefinition_Format4 */
static int hf_e2ap_actionDefinition_Format5 = -1;  /* E2SM_KPM_ActionDefinition_Format5 */
static int hf_e2ap_measInfoList = -1;             /* MeasurementInfoList */
static int hf_e2ap_granulPeriod = -1;             /* GranularityPeriod */
static int hf_e2ap_subscriptInfo = -1;            /* E2SM_KPM_ActionDefinition_Format1 */
static int hf_e2ap_measCondList = -1;             /* MeasurementCondList */
static int hf_e2ap_matchingUeCondList = -1;       /* MatchingUeCondPerSubList */
static int hf_e2ap_subscriptionInfo = -1;         /* E2SM_KPM_ActionDefinition_Format1 */
static int hf_e2ap_matchingUEidList_01 = -1;      /* MatchingUEidPerSubList */
static int hf_e2ap_indicationHeader_formats = -1;  /* T_indicationHeader_formats */
static int hf_e2ap_indicationHeader_Format1_01 = -1;  /* E2SM_KPM_IndicationHeader_Format1 */
static int hf_e2ap_colletStartTime = -1;          /* TimeStamp */
static int hf_e2ap_fileFormatversion = -1;        /* PrintableString_SIZE_0_15_ */
static int hf_e2ap_senderName = -1;               /* PrintableString_SIZE_0_400_ */
static int hf_e2ap_senderType = -1;               /* PrintableString_SIZE_0_8_ */
static int hf_e2ap_vendorName = -1;               /* PrintableString_SIZE_0_32_ */
static int hf_e2ap_indicationMessage_formats = -1;  /* T_indicationMessage_formats */
static int hf_e2ap_indicationMessage_Format1_01 = -1;  /* E2SM_KPM_IndicationMessage_Format1 */
static int hf_e2ap_indicationMessage_Format2_01 = -1;  /* E2SM_KPM_IndicationMessage_Format2 */
static int hf_e2ap_indicationMessage_Format3_01 = -1;  /* E2SM_KPM_IndicationMessage_Format3 */
static int hf_e2ap_measData = -1;                 /* MeasurementData */
static int hf_e2ap_measCondUEidList = -1;         /* MeasurementCondUEidList */
static int hf_e2ap_ueMeasReportList = -1;         /* UEMeasurementReportList */
static int hf_e2ap_ric_EventTriggerStyle_List_01 = -1;  /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item */
static int hf_e2ap_ric_EventTriggerStyle_List_item_01 = -1;  /* RIC_EventTriggerStyle_Item */
static int hf_e2ap_ric_ReportStyle_List_01 = -1;  /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item */
static int hf_e2ap_ric_ReportStyle_List_item_01 = -1;  /* RIC_ReportStyle_Item */
static int hf_e2ap_ric_ActionFormat_Type = -1;    /* RIC_Format_Type */
static int hf_e2ap_measInfo_Action_List = -1;     /* MeasurementInfo_Action_List */

static int hf_e2ap_unmapped_ran_function_id = -1;
static int hf_e2ap_ran_function_name_not_recognised = -1;
static int hf_e2ap_ran_function_setup_frame = -1;



/* Initialize the subtree pointers */
static gint ett_e2ap = -1;

static expert_field ei_e2ap_ran_function_names_no_match = EI_INIT;
static expert_field ei_e2ap_ran_function_id_not_mapped = EI_INIT;

static gint ett_e2ap_ProtocolIE_Container = -1;
static gint ett_e2ap_ProtocolIE_Field = -1;
static gint ett_e2ap_Cause = -1;
static gint ett_e2ap_CriticalityDiagnostics = -1;
static gint ett_e2ap_CriticalityDiagnostics_IE_List = -1;
static gint ett_e2ap_CriticalityDiagnostics_IE_Item = -1;
static gint ett_e2ap_E2nodeComponentConfiguration = -1;
static gint ett_e2ap_E2nodeComponentConfigurationAck = -1;
static gint ett_e2ap_E2nodeComponentID = -1;
static gint ett_e2ap_E2nodeComponentInterfaceE1 = -1;
static gint ett_e2ap_E2nodeComponentInterfaceF1 = -1;
static gint ett_e2ap_E2nodeComponentInterfaceNG = -1;
static gint ett_e2ap_E2nodeComponentInterfaceS1 = -1;
static gint ett_e2ap_E2nodeComponentInterfaceX2 = -1;
static gint ett_e2ap_E2nodeComponentInterfaceXn = -1;
static gint ett_e2ap_E2nodeComponentInterfaceW1 = -1;
static gint ett_e2ap_ENB_ID = -1;
static gint ett_e2ap_ENB_ID_Choice = -1;
static gint ett_e2ap_ENGNB_ID = -1;
static gint ett_e2ap_GlobalE2node_ID = -1;
static gint ett_e2ap_GlobalE2node_en_gNB_ID = -1;
static gint ett_e2ap_GlobalE2node_eNB_ID = -1;
static gint ett_e2ap_GlobalE2node_gNB_ID = -1;
static gint ett_e2ap_GlobalE2node_ng_eNB_ID = -1;
static gint ett_e2ap_GlobalENB_ID = -1;
static gint ett_e2ap_GlobalenGNB_ID = -1;
static gint ett_e2ap_GlobalgNB_ID = -1;
static gint ett_e2ap_GlobalngeNB_ID = -1;
static gint ett_e2ap_GlobalNG_RANNode_ID = -1;
static gint ett_e2ap_GlobalRIC_ID = -1;
static gint ett_e2ap_GNB_ID_Choice = -1;
static gint ett_e2ap_RICrequestID = -1;
static gint ett_e2ap_RICsubsequentAction = -1;
static gint ett_e2ap_TNLinformation = -1;
static gint ett_e2ap_RICsubscriptionRequest = -1;
static gint ett_e2ap_RICsubscriptionDetails = -1;
static gint ett_e2ap_RICactions_ToBeSetup_List = -1;
static gint ett_e2ap_RICaction_ToBeSetup_Item = -1;
static gint ett_e2ap_RICsubscriptionResponse = -1;
static gint ett_e2ap_RICaction_Admitted_List = -1;
static gint ett_e2ap_RICaction_Admitted_Item = -1;
static gint ett_e2ap_RICaction_NotAdmitted_List = -1;
static gint ett_e2ap_RICaction_NotAdmitted_Item = -1;
static gint ett_e2ap_RICsubscriptionFailure = -1;
static gint ett_e2ap_RICsubscriptionDeleteRequest = -1;
static gint ett_e2ap_RICsubscriptionDeleteResponse = -1;
static gint ett_e2ap_RICsubscriptionDeleteFailure = -1;
static gint ett_e2ap_RICsubscriptionDeleteRequired = -1;
static gint ett_e2ap_RICsubscription_List_withCause = -1;
static gint ett_e2ap_RICsubscription_withCause_Item = -1;
static gint ett_e2ap_RICindication = -1;
static gint ett_e2ap_RICcontrolRequest = -1;
static gint ett_e2ap_RICcontrolAcknowledge = -1;
static gint ett_e2ap_RICcontrolFailure = -1;
static gint ett_e2ap_ErrorIndication = -1;
static gint ett_e2ap_E2setupRequest = -1;
static gint ett_e2ap_E2setupResponse = -1;
static gint ett_e2ap_E2setupFailure = -1;
static gint ett_e2ap_E2connectionUpdate = -1;
static gint ett_e2ap_E2connectionUpdate_List = -1;
static gint ett_e2ap_E2connectionUpdate_Item = -1;
static gint ett_e2ap_E2connectionUpdateRemove_List = -1;
static gint ett_e2ap_E2connectionUpdateRemove_Item = -1;
static gint ett_e2ap_E2connectionUpdateAcknowledge = -1;
static gint ett_e2ap_E2connectionSetupFailed_List = -1;
static gint ett_e2ap_E2connectionSetupFailed_Item = -1;
static gint ett_e2ap_E2connectionUpdateFailure = -1;
static gint ett_e2ap_E2nodeConfigurationUpdate = -1;
static gint ett_e2ap_E2nodeComponentConfigAddition_List = -1;
static gint ett_e2ap_E2nodeComponentConfigAddition_Item = -1;
static gint ett_e2ap_E2nodeComponentConfigUpdate_List = -1;
static gint ett_e2ap_E2nodeComponentConfigUpdate_Item = -1;
static gint ett_e2ap_E2nodeComponentConfigRemoval_List = -1;
static gint ett_e2ap_E2nodeComponentConfigRemoval_Item = -1;
static gint ett_e2ap_E2nodeTNLassociationRemoval_List = -1;
static gint ett_e2ap_E2nodeTNLassociationRemoval_Item = -1;
static gint ett_e2ap_E2nodeConfigurationUpdateAcknowledge = -1;
static gint ett_e2ap_E2nodeComponentConfigAdditionAck_List = -1;
static gint ett_e2ap_E2nodeComponentConfigAdditionAck_Item = -1;
static gint ett_e2ap_E2nodeComponentConfigUpdateAck_List = -1;
static gint ett_e2ap_E2nodeComponentConfigUpdateAck_Item = -1;
static gint ett_e2ap_E2nodeComponentConfigRemovalAck_List = -1;
static gint ett_e2ap_E2nodeComponentConfigRemovalAck_Item = -1;
static gint ett_e2ap_E2nodeConfigurationUpdateFailure = -1;
static gint ett_e2ap_ResetRequest = -1;
static gint ett_e2ap_ResetResponse = -1;
static gint ett_e2ap_RICserviceUpdate = -1;
static gint ett_e2ap_RANfunctions_List = -1;
static gint ett_e2ap_RANfunction_Item = -1;
static gint ett_e2ap_RANfunctionsID_List = -1;
static gint ett_e2ap_RANfunctionID_Item = -1;
static gint ett_e2ap_RICserviceUpdateAcknowledge = -1;
static gint ett_e2ap_RANfunctionsIDcause_List = -1;
static gint ett_e2ap_RANfunctionIDcause_Item = -1;
static gint ett_e2ap_RICserviceUpdateFailure = -1;
static gint ett_e2ap_RICserviceQuery = -1;
static gint ett_e2ap_E2RemovalRequest = -1;
static gint ett_e2ap_E2RemovalResponse = -1;
static gint ett_e2ap_E2RemovalFailure = -1;
static gint ett_e2ap_E2AP_PDU = -1;
static gint ett_e2ap_InitiatingMessage = -1;
static gint ett_e2ap_SuccessfulOutcome = -1;
static gint ett_e2ap_UnsuccessfulOutcome = -1;
static gint ett_e2ap_CGI = -1;
static gint ett_e2ap_InterfaceIdentifier = -1;
static gint ett_e2ap_InterfaceID_NG = -1;
static gint ett_e2ap_InterfaceID_Xn = -1;
static gint ett_e2ap_InterfaceID_F1 = -1;
static gint ett_e2ap_InterfaceID_E1 = -1;
static gint ett_e2ap_InterfaceID_S1 = -1;
static gint ett_e2ap_InterfaceID_X2 = -1;
static gint ett_e2ap_T_nodeType = -1;
static gint ett_e2ap_InterfaceID_W1 = -1;
static gint ett_e2ap_Interface_MessageID = -1;
static gint ett_e2ap_RANfunction_Name = -1;
static gint ett_e2ap_RRC_MessageID = -1;
static gint ett_e2ap_T_rrcType = -1;
static gint ett_e2ap_ServingCell_ARFCN = -1;
static gint ett_e2ap_ServingCell_PCI = -1;
static gint ett_e2ap_UEID = -1;
static gint ett_e2ap_UEID_GNB = -1;
static gint ett_e2ap_UEID_GNB_CU_CP_E1AP_ID_List = -1;
static gint ett_e2ap_UEID_GNB_CU_CP_E1AP_ID_Item = -1;
static gint ett_e2ap_UEID_GNB_CU_F1AP_ID_List = -1;
static gint ett_e2ap_UEID_GNB_CU_CP_F1AP_ID_Item = -1;
static gint ett_e2ap_UEID_GNB_DU = -1;
static gint ett_e2ap_UEID_GNB_CU_UP = -1;
static gint ett_e2ap_UEID_NG_ENB = -1;
static gint ett_e2ap_UEID_NG_ENB_DU = -1;
static gint ett_e2ap_UEID_EN_GNB = -1;
static gint ett_e2ap_UEID_ENB = -1;
static gint ett_e2ap_GUMMEI = -1;
static gint ett_e2ap_EUTRA_CGI = -1;
static gint ett_e2ap_GlobalGNB_ID = -1;
static gint ett_e2ap_GlobalNgENB_ID = -1;
static gint ett_e2ap_GNB_ID = -1;
static gint ett_e2ap_GUAMI = -1;
static gint ett_e2ap_NgENB_ID = -1;
static gint ett_e2ap_S_NSSAI = -1;
static gint ett_e2ap_GlobalNGRANNodeID = -1;
static gint ett_e2ap_NR_ARFCN = -1;
static gint ett_e2ap_NRFrequencyBand_List = -1;
static gint ett_e2ap_NRFrequencyBandItem = -1;
static gint ett_e2ap_NRFrequencyInfo = -1;
static gint ett_e2ap_SupportedSULBandList = -1;
static gint ett_e2ap_SupportedSULFreqBandItem = -1;
static gint ett_e2ap_NR_CGI = -1;
static gint ett_e2ap_NeighborCell_List = -1;
static gint ett_e2ap_NeighborCell_Item = -1;
static gint ett_e2ap_NeighborCell_Item_Choice_NR = -1;
static gint ett_e2ap_NeighborCell_Item_Choice_E_UTRA = -1;
static gint ett_e2ap_NeighborRelation_Info = -1;
static gint ett_e2ap_EventTrigger_Cell_Info = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item = -1;
static gint ett_e2ap_EventTrigger_Cell_Info_Item = -1;
static gint ett_e2ap_T_cellType = -1;
static gint ett_e2ap_EventTrigger_Cell_Info_Item_Choice_Individual = -1;
static gint ett_e2ap_EventTrigger_Cell_Info_Item_Choice_Group = -1;
static gint ett_e2ap_EventTrigger_UE_Info = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item = -1;
static gint ett_e2ap_EventTrigger_UE_Info_Item = -1;
static gint ett_e2ap_T_ueType = -1;
static gint ett_e2ap_EventTrigger_UE_Info_Item_Choice_Individual = -1;
static gint ett_e2ap_EventTrigger_UE_Info_Item_Choice_Group = -1;
static gint ett_e2ap_EventTrigger_UEevent_Info = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item = -1;
static gint ett_e2ap_EventTrigger_UEevent_Info_Item = -1;
static gint ett_e2ap_RANParameter_Definition = -1;
static gint ett_e2ap_RANParameter_Definition_Choice = -1;
static gint ett_e2ap_RANParameter_Definition_Choice_LIST = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item = -1;
static gint ett_e2ap_RANParameter_Definition_Choice_LIST_Item = -1;
static gint ett_e2ap_RANParameter_Definition_Choice_STRUCTURE = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item = -1;
static gint ett_e2ap_RANParameter_Definition_Choice_STRUCTURE_Item = -1;
static gint ett_e2ap_RANParameter_Value = -1;
static gint ett_e2ap_RANParameter_ValueType = -1;
static gint ett_e2ap_RANParameter_ValueType_Choice_ElementTrue = -1;
static gint ett_e2ap_RANParameter_ValueType_Choice_ElementFalse = -1;
static gint ett_e2ap_RANParameter_ValueType_Choice_Structure = -1;
static gint ett_e2ap_RANParameter_ValueType_Choice_List = -1;
static gint ett_e2ap_RANParameter_STRUCTURE = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item = -1;
static gint ett_e2ap_RANParameter_STRUCTURE_Item = -1;
static gint ett_e2ap_RANParameter_LIST = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE = -1;
static gint ett_e2ap_RANParameter_Testing = -1;
static gint ett_e2ap_RANParameter_TestingCondition = -1;
static gint ett_e2ap_RANParameter_Testing_Item = -1;
static gint ett_e2ap_T_ranParameter_Type = -1;
static gint ett_e2ap_RANParameter_Testing_Item_Choice_List = -1;
static gint ett_e2ap_RANParameter_Testing_Item_Choice_Structure = -1;
static gint ett_e2ap_RANParameter_Testing_Item_Choice_ElementTrue = -1;
static gint ett_e2ap_RANParameter_Testing_Item_Choice_ElementFalse = -1;
static gint ett_e2ap_RANParameter_Testing_LIST = -1;
static gint ett_e2ap_RANParameter_Testing_STRUCTURE = -1;
static gint ett_e2ap_RIC_PolicyAction = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item = -1;
static gint ett_e2ap_RIC_PolicyAction_RANParameter_Item = -1;
static gint ett_e2ap_E2SM_RC_EventTrigger = -1;
static gint ett_e2ap_T_ric_eventTrigger_formats = -1;
static gint ett_e2ap_E2SM_RC_EventTrigger_Format1 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item = -1;
static gint ett_e2ap_E2SM_RC_EventTrigger_Format1_Item = -1;
static gint ett_e2ap_MessageType_Choice = -1;
static gint ett_e2ap_MessageType_Choice_NI = -1;
static gint ett_e2ap_MessageType_Choice_RRC = -1;
static gint ett_e2ap_E2SM_RC_EventTrigger_Format2 = -1;
static gint ett_e2ap_E2SM_RC_EventTrigger_Format3 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item = -1;
static gint ett_e2ap_E2SM_RC_EventTrigger_Format3_Item = -1;
static gint ett_e2ap_E2SM_RC_EventTrigger_Format4 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item = -1;
static gint ett_e2ap_E2SM_RC_EventTrigger_Format4_Item = -1;
static gint ett_e2ap_TriggerType_Choice = -1;
static gint ett_e2ap_TriggerType_Choice_RRCstate = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item = -1;
static gint ett_e2ap_TriggerType_Choice_RRCstate_Item = -1;
static gint ett_e2ap_TriggerType_Choice_UEID = -1;
static gint ett_e2ap_TriggerType_Choice_L2state = -1;
static gint ett_e2ap_E2SM_RC_EventTrigger_Format5 = -1;
static gint ett_e2ap_E2SM_RC_ActionDefinition = -1;
static gint ett_e2ap_T_ric_actionDefinition_formats = -1;
static gint ett_e2ap_E2SM_RC_ActionDefinition_Format1 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item = -1;
static gint ett_e2ap_E2SM_RC_ActionDefinition_Format1_Item = -1;
static gint ett_e2ap_E2SM_RC_ActionDefinition_Format2 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item = -1;
static gint ett_e2ap_E2SM_RC_ActionDefinition_Format2_Item = -1;
static gint ett_e2ap_E2SM_RC_ActionDefinition_Format3 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item = -1;
static gint ett_e2ap_E2SM_RC_ActionDefinition_Format3_Item = -1;
static gint ett_e2ap_E2SM_RC_ActionDefinition_Format4 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item = -1;
static gint ett_e2ap_E2SM_RC_ActionDefinition_Format4_Style_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item = -1;
static gint ett_e2ap_E2SM_RC_ActionDefinition_Format4_Indication_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item = -1;
static gint ett_e2ap_E2SM_RC_ActionDefinition_Format4_RANP_Item = -1;
static gint ett_e2ap_E2SM_RC_IndicationHeader = -1;
static gint ett_e2ap_T_ric_indicationHeader_formats = -1;
static gint ett_e2ap_E2SM_RC_IndicationHeader_Format1 = -1;
static gint ett_e2ap_E2SM_RC_IndicationHeader_Format2 = -1;
static gint ett_e2ap_E2SM_RC_IndicationHeader_Format3 = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage = -1;
static gint ett_e2ap_T_ric_indicationMessage_formats = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format1 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format1_Item = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format2 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format2_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format2_RANParameter_Item = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format3 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format3_Item = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format4 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format4_ItemUE = -1;
static gint ett_e2ap_SEQUENCE_SIZE_0_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format4_ItemCell = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format4_ItemUE = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format4_ItemCell = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format5 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format5_Item = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format6 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format6_Style_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format6_Indication_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item = -1;
static gint ett_e2ap_E2SM_RC_IndicationMessage_Format6_RANP_Item = -1;
static gint ett_e2ap_E2SM_RC_CallProcessID = -1;
static gint ett_e2ap_T_ric_callProcessID_formats = -1;
static gint ett_e2ap_E2SM_RC_CallProcessID_Format1 = -1;
static gint ett_e2ap_E2SM_RC_ControlHeader = -1;
static gint ett_e2ap_T_ric_controlHeader_formats = -1;
static gint ett_e2ap_E2SM_RC_ControlHeader_Format1 = -1;
static gint ett_e2ap_E2SM_RC_ControlHeader_Format2 = -1;
static gint ett_e2ap_E2SM_RC_ControlMessage = -1;
static gint ett_e2ap_T_ric_controlMessage_formats = -1;
static gint ett_e2ap_E2SM_RC_ControlMessage_Format1 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item = -1;
static gint ett_e2ap_E2SM_RC_ControlMessage_Format1_Item = -1;
static gint ett_e2ap_E2SM_RC_ControlMessage_Format2 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item = -1;
static gint ett_e2ap_E2SM_RC_ControlMessage_Format2_Style_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item = -1;
static gint ett_e2ap_E2SM_RC_ControlMessage_Format2_ControlAction_Item = -1;
static gint ett_e2ap_E2SM_RC_ControlOutcome = -1;
static gint ett_e2ap_T_ric_controlOutcome_formats = -1;
static gint ett_e2ap_E2SM_RC_ControlOutcome_Format1 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item = -1;
static gint ett_e2ap_E2SM_RC_ControlOutcome_Format1_Item = -1;
static gint ett_e2ap_E2SM_RC_ControlOutcome_Format2 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item = -1;
static gint ett_e2ap_E2SM_RC_ControlOutcome_Format2_Style_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item = -1;
static gint ett_e2ap_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item = -1;
static gint ett_e2ap_E2SM_RC_ControlOutcome_Format2_RANP_Item = -1;
static gint ett_e2ap_E2SM_RC_ControlOutcome_Format3 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item = -1;
static gint ett_e2ap_E2SM_RC_ControlOutcome_Format3_Item = -1;
static gint ett_e2ap_E2SM_RC_RANFunctionDefinition = -1;
static gint ett_e2ap_RANFunctionDefinition_EventTrigger = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_EventTrigger_Style_Item = -1;
static gint ett_e2ap_L2Parameters_RANParameter_Item = -1;
static gint ett_e2ap_UEIdentification_RANParameter_Item = -1;
static gint ett_e2ap_CellIdentification_RANParameter_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_EventTrigger_CallProcess_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_EventTrigger_Breakpoint_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item = -1;
static gint ett_e2ap_CallProcessBreakpoint_RANParameter_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_Report = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_Report_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item = -1;
static gint ett_e2ap_Report_RANParameter_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_Insert = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_Insert_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_Insert_Indication_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item = -1;
static gint ett_e2ap_InsertIndication_RANParameter_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_Control = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_Control_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item = -1;
static gint ett_e2ap_ControlOutcome_RANParameter_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_Control_Action_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item = -1;
static gint ett_e2ap_ControlAction_RANParameter_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_Policy = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_Policy_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item = -1;
static gint ett_e2ap_RANFunctionDefinition_Policy_Action_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item = -1;
static gint ett_e2ap_PolicyAction_RANParameter_Item = -1;
static gint ett_e2ap_PolicyCondition_RANParameter_Item = -1;
static gint ett_e2ap_MeasurementType = -1;
static gint ett_e2ap_MeasurementLabel = -1;
static gint ett_e2ap_TestCondInfo = -1;
static gint ett_e2ap_TestCond_Type = -1;
static gint ett_e2ap_TestCond_Value = -1;
static gint ett_e2ap_MeasurementInfoList = -1;
static gint ett_e2ap_MeasurementInfoItem = -1;
static gint ett_e2ap_LabelInfoList = -1;
static gint ett_e2ap_LabelInfoItem = -1;
static gint ett_e2ap_MeasurementData = -1;
static gint ett_e2ap_MeasurementDataItem = -1;
static gint ett_e2ap_MeasurementRecord = -1;
static gint ett_e2ap_MeasurementRecordItem = -1;
static gint ett_e2ap_MeasurementInfo_Action_List = -1;
static gint ett_e2ap_MeasurementInfo_Action_Item = -1;
static gint ett_e2ap_MeasurementCondList = -1;
static gint ett_e2ap_MeasurementCondItem = -1;
static gint ett_e2ap_MeasurementCondUEidList = -1;
static gint ett_e2ap_MeasurementCondUEidItem = -1;
static gint ett_e2ap_MatchingCondList = -1;
static gint ett_e2ap_MatchingCondItem = -1;
static gint ett_e2ap_MatchingUEidList = -1;
static gint ett_e2ap_MatchingUEidItem = -1;
static gint ett_e2ap_MatchingUeCondPerSubList = -1;
static gint ett_e2ap_MatchingUeCondPerSubItem = -1;
static gint ett_e2ap_MatchingUEidPerSubList = -1;
static gint ett_e2ap_MatchingUEidPerSubItem = -1;
static gint ett_e2ap_UEMeasurementReportList = -1;
static gint ett_e2ap_UEMeasurementReportItem = -1;
static gint ett_e2ap_E2SM_KPM_EventTriggerDefinition = -1;
static gint ett_e2ap_T_eventDefinition_formats = -1;
static gint ett_e2ap_E2SM_KPM_EventTriggerDefinition_Format1 = -1;
static gint ett_e2ap_E2SM_KPM_ActionDefinition = -1;
static gint ett_e2ap_T_actionDefinition_formats = -1;
static gint ett_e2ap_E2SM_KPM_ActionDefinition_Format1 = -1;
static gint ett_e2ap_E2SM_KPM_ActionDefinition_Format2 = -1;
static gint ett_e2ap_E2SM_KPM_ActionDefinition_Format3 = -1;
static gint ett_e2ap_E2SM_KPM_ActionDefinition_Format4 = -1;
static gint ett_e2ap_E2SM_KPM_ActionDefinition_Format5 = -1;
static gint ett_e2ap_E2SM_KPM_IndicationHeader = -1;
static gint ett_e2ap_T_indicationHeader_formats = -1;
static gint ett_e2ap_E2SM_KPM_IndicationHeader_Format1 = -1;
static gint ett_e2ap_E2SM_KPM_IndicationMessage = -1;
static gint ett_e2ap_T_indicationMessage_formats = -1;
static gint ett_e2ap_E2SM_KPM_IndicationMessage_Format1 = -1;
static gint ett_e2ap_E2SM_KPM_IndicationMessage_Format2 = -1;
static gint ett_e2ap_E2SM_KPM_IndicationMessage_Format3 = -1;
static gint ett_e2ap_E2SM_KPM_RANfunction_Description = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item = -1;
static gint ett_e2ap_RIC_EventTriggerStyle_Item = -1;
static gint ett_e2ap_RIC_ReportStyle_Item = -1;


/* Forward declarations */
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



enum {
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

typedef struct _e2ap_ctx_t {
  guint32 message_type;
  guint32 ProcedureCode;
  guint32 ProtocolIE_ID;
  guint32 ProtocolExtensionID;
} e2ap_ctx_t;



struct e2ap_private_data {
  guint32 procedure_code;
  guint32 protocol_ie_id;
  guint32 protocol_extension_id;
  guint32 message_type;
  guint32 ran_ue_e2ap_id;

  guint32 ran_function_id;
  guint32 gnb_id_len;
#define MAX_GNB_ID_BYTES 6
  guint8  gnb_id_bytes[MAX_GNB_ID_BYTES];
};

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
/* We learn which set of RAN functions pointers corresponds to a given ranFunctionID when we see E2SetupRequest */
typedef int (*pdu_dissector_t)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

/* Function pointers for a RANFunction */
typedef struct {
    pdu_dissector_t ran_function_definition_dissector;

    pdu_dissector_t ric_control_header_dissector;
    pdu_dissector_t ric_control_message_dissector;
    pdu_dissector_t ric_control_outcome_dissector;

    pdu_dissector_t ran_action_definition_dissector;
    pdu_dissector_t ran_indication_message_dissector;
    pdu_dissector_t ran_indication_header_dissector;
    pdu_dissector_t ran_callprocessid_dissector;
    pdu_dissector_t ran_event_trigger_dissector;
} ran_function_pointers_t;

typedef enum {
    MIN_RANFUNCTIONS,
    KPM_RANFUNCTIONS=0,
    RIC_RANFUNCTIONS,
    MAX_RANFUNCTIONS
} ran_function_t;

typedef struct {
    const char* name;
    ran_function_pointers_t functions;
} ran_function_name_mapping_t;

/* Static table mapping from string -> ran_function */
static const ran_function_name_mapping_t g_ran_functioname_table[MAX_RANFUNCTIONS] =
{
  { "ORAN-E2SM-KPM", {  dissect_E2SM_KPM_RANfunction_Description_PDU,

                        NULL,
                        NULL,
                        NULL,

                        dissect_E2SM_KPM_ActionDefinition_PDU,
                        dissect_E2SM_KPM_IndicationMessage_PDU,
                        dissect_E2SM_KPM_IndicationHeader_PDU,
                        NULL, /* no dissect_E2SM_KPM_CallProcessID_PDU */
                        dissect_E2SM_KPM_EventTriggerDefinition_PDU
                     }
  },
  { "ORAN-E2SM-RC",  {  dissect_E2SM_RC_RANFunctionDefinition_PDU,

                        dissect_E2SM_RC_ControlHeader_PDU,
                        dissect_E2SM_RC_ControlMessage_PDU,
                        dissect_E2SM_RC_ControlOutcome_PDU,

                        dissect_E2SM_RC_ActionDefinition_PDU,
                        dissect_E2SM_RC_IndicationMessage_PDU,
                        dissect_E2SM_RC_IndicationHeader_PDU,
                        dissect_E2SM_RC_CallProcessID_PDU,
                        dissect_E2SM_RC_EventTrigger_PDU
                     }
  }
};



/* Per-conversation mapping: ranFunctionId -> ran_function */
typedef struct {
    guint32                  setup_frame;
    guint32                  ran_function_id;
    ran_function_t           ran_function;
    ran_function_pointers_t *ran_function_pointers;
} ran_function_id_mapping_t;

typedef struct  {
#define MAX_RANFUNCTION_ENTRIES 8
    guint32                   num_entries;
    ran_function_id_mapping_t entries[MAX_RANFUNCTION_ENTRIES];
} ran_functionid_table_t;

const char *ran_function_to_str(ran_function_t ran_function)
{
    switch (ran_function) {
        case KPM_RANFUNCTIONS:
            return "KPM";
        case RIC_RANFUNCTIONS:
            return "RIC";

        default:
            return "Unknown";
    }
}

typedef struct {
#define MAX_GNBS 6
    guint32 num_gnbs;
    struct {
        guint32 len;
        guint8  value[MAX_GNB_ID_BYTES];
        ran_functionid_table_t *ran_function_table;
    } gnb[MAX_GNBS];
} gnb_ran_functions_t;

static gnb_ran_functions_t s_gnb_ran_functions;


/* Get RANfunctionID table from conversation data - create new if necessary */
ran_functionid_table_t* get_ran_functionid_table(packet_info *pinfo)
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
static void store_ran_function_mapping(packet_info *pinfo, ran_functionid_table_t *table, struct e2ap_private_data *e2ap_data, const char *name)
{
    /* Stop if already reached table limit */
    if (table->num_entries == MAX_RANFUNCTION_ENTRIES) {
        /* TODO: expert info warning? */
        return;
    }

    guint32 ran_function_id = e2ap_data->ran_function_id;

    ran_function_t           ran_function = MAX_RANFUNCTIONS;  /* i.e. invalid */
    ran_function_pointers_t *ran_function_pointers = NULL;

    /* Check known RAN functions */
    for (int n=MIN_RANFUNCTIONS; n < MAX_RANFUNCTIONS; n++) {
        /* TODO: shouldn't need to check both positions! */
        if ((strcmp(name,   g_ran_functioname_table[n].name) == 0) ||
            (strcmp(name+1, g_ran_functioname_table[n].name) == 0)) {

            ran_function = n;
            ran_function_pointers = (ran_function_pointers_t*)&(g_ran_functioname_table[n].functions);
            break;
        }
    }

    /* Nothing to do if no matches */
    if (ran_function == MAX_RANFUNCTIONS) {
        return;
    }

    /* If ID already mapped, ignore */
    for (guint n=0; n < table->num_entries; n++) {
        if (table->entries[n].ran_function_id == ran_function_id) {
            return;
        }
    }

    /* OK, store this new entry */
    guint idx = table->num_entries++;
    table->entries[idx].setup_frame = pinfo->num;
    table->entries[idx].ran_function_id = ran_function_id;
    table->entries[idx].ran_function = ran_function;
    table->entries[idx].ran_function_pointers = ran_function_pointers;

    /* When add first entry, also want to set up table from gnbId -> table */
    if (idx == 0) {
        guint id_len = e2ap_data->gnb_id_len;
        guint8 *id_value = &e2ap_data->gnb_id_bytes[0];

        gboolean found = FALSE;
        for (guint n=0; n<s_gnb_ran_functions.num_gnbs; n++) {
            if ((s_gnb_ran_functions.gnb[n].len = id_len) &&
                (memcmp(s_gnb_ran_functions.gnb[n].value, id_value, id_len) == 0)) {
                // Already have an entry for this gnb.
                found = TRUE;
                break;
            }
        }

        if (!found) {
            /* Add entry (if room for 1 more) */
            guint32 new_idx = s_gnb_ran_functions.num_gnbs;
            if (new_idx < MAX_GNBS-1) {
                s_gnb_ran_functions.gnb[new_idx].len = id_len;
                memcpy(s_gnb_ran_functions.gnb[new_idx].value, id_value, id_len);
                s_gnb_ran_functions.gnb[new_idx].ran_function_table = table;

                s_gnb_ran_functions.num_gnbs++;
            }
        }
    }
}

/* Look for Service Model function pointers, based on current RANFunctionID in pinfo */
ran_function_pointers_t* lookup_ranfunction_pointers(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
    /* Get ranFunctionID from this frame */
    struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);
    guint ran_function_id = e2ap_data->ran_function_id;

    /* Look in table function pointers for this ranFunctionID */
    ran_functionid_table_t *table = get_ran_functionid_table(pinfo);
    for (guint n=0; n < table->num_entries; n++) {
        if (ran_function_id == table->entries[n].ran_function_id) {
            /* Point back at the setup frame where this ranfunction was mapped */
            proto_item *ti = proto_tree_add_uint(tree, hf_e2ap_ran_function_setup_frame,
                                                 tvb, 0, 0, table->entries[n].setup_frame);
            /* Also show that mapping */
            proto_item_append_text(ti, " (%u -> %s)", table->entries[n].ran_function_id, ran_function_to_str(table->entries[n].ran_function));
            proto_item_set_generated(ti);

            return table->entries[n].ran_function_pointers;
        }
    }

    /* No match found.. */
    proto_item *ti = proto_tree_add_item(tree, hf_e2ap_unmapped_ran_function_id, tvb, 0, 0, ENC_NA);
    expert_add_info_format(pinfo, ti, &ei_e2ap_ran_function_id_not_mapped,
                           "Service Model not mapped for FunctionID %u", ran_function_id);
    return NULL;
}

/* This will get used for E2nodeConfigurationUpdate, where we have a gnb-id but haven't seen E2setupRequest */
void update_conversation_from_gnb_id(asn1_ctx_t *actx _U_)
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
        guint id_len = e2ap_data->gnb_id_len;
        guint8 *id_value = &e2ap_data->gnb_id_bytes[0];

        for (guint n=0; n<s_gnb_ran_functions.num_gnbs; n++) {
            if ((s_gnb_ran_functions.gnb[n].len = id_len) &&
                (memcmp(s_gnb_ran_functions.gnb[n].value, id_value, id_len) == 0)) {

                /* Have an entry for this gnb.  Set direct pointer to existing data (used by original conversation). */
                /* N.B. This means that no further updates for the gNB are expected on different conversations.. */
                p_conv_data = s_gnb_ran_functions.gnb[n].ran_function_table;
                conversation_add_proto_data(p_conv, proto_e2ap, p_conv_data);

                /* TODO: may want to try to add a generated field to pass back to E2setupRequest where RAN function mappings were first seen? */
                break;
            }
        }
    }
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
                                     3, NULL, FALSE, 0, NULL);

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
  { 0, NULL }
};

static value_string_ext e2ap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(e2ap_ProcedureCode_vals);


static int
dissect_e2ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &e2ap_data->procedure_code, FALSE);

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
  { 0, NULL }
};

static value_string_ext e2ap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(e2ap_ProtocolIE_ID_vals);


static int
dissect_e2ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &e2ap_data->protocol_ie_id, FALSE);



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
                                     3, NULL, FALSE, 0, NULL);

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
                                                  0, maxProtocolIEs, FALSE);

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
                                          1, 150, TRUE);

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
  { 0, NULL }
};


static int
dissect_e2ap_CauseRICrequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, TRUE, 0, NULL);

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
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_CauseE2node_vals[] = {
  {   0, "e2node-component-unknown" },
  { 0, NULL }
};


static int
dissect_e2ap_CauseE2node(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     7, NULL, TRUE, 0, NULL);

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
                                     4, NULL, TRUE, 0, NULL);

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
                                                            0U, 65535U, NULL, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofErrors, FALSE);

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
dissect_e2ap_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t E2nodeComponentConfiguration_sequence[] = {
  { &hf_e2ap_e2nodeComponentRequestPart, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_OCTET_STRING },
  { &hf_e2ap_e2nodeComponentResponsePart, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_OCTET_STRING },
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
                                     2, NULL, TRUE, 0, NULL);

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
                                     7, NULL, TRUE, 0, NULL);

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
dissect_e2ap_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}



static int
dissect_e2ap_BIT_STRING_SIZE_22_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     22, 32, FALSE, NULL, 0, NULL, NULL);

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
                                     20, 20, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e2ap_BIT_STRING_SIZE_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     18, 18, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e2ap_BIT_STRING_SIZE_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     21, 21, FALSE, NULL, 0, NULL, NULL);

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
dissect_e2ap_GNB_CU_UP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(68719476735), NULL, FALSE);

  return offset;
}


static const per_sequence_t E2nodeComponentInterfaceE1_sequence[] = {
  { &hf_e2ap_gNB_CU_CP_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GNB_CU_UP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2nodeComponentInterfaceE1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2nodeComponentInterfaceE1, E2nodeComponentInterfaceE1_sequence);

  return offset;
}



static int
dissect_e2ap_GNB_DU_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(68719476735), NULL, FALSE);

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
dissect_e2ap_NGENB_DU_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(68719476735), NULL, FALSE);

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
                                          1, 150, TRUE);

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
dissect_e2ap_BIT_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL, 0, NULL, NULL);

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
  {   0, &hf_e2ap_e2nodeComponentInterfaceTypeNG, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2nodeComponentInterfaceNG },
  {   1, &hf_e2ap_e2nodeComponentInterfaceTypeXn, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2nodeComponentInterfaceXn },
  {   2, &hf_e2ap_e2nodeComponentInterfaceTypeE1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2nodeComponentInterfaceE1 },
  {   3, &hf_e2ap_e2nodeComponentInterfaceTypeF1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2nodeComponentInterfaceF1 },
  {   4, &hf_e2ap_e2nodeComponentInterfaceTypeW1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2nodeComponentInterfaceW1 },
  {   5, &hf_e2ap_e2nodeComponentInterfaceTypeS1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2nodeComponentInterfaceS1 },
  {   6, &hf_e2ap_e2nodeComponentInterfaceTypeX2, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2nodeComponentInterfaceX2 },
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
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  /* Looking for shortName string near beginning of tvb */
  gboolean found = FALSE;
  for (int n=KPM_RANFUNCTIONS; n<MAX_RANFUNCTIONS; n++) {
    guint32 tvb_len = tvb_captured_length(parameter_tvb);
    guint name_len = (gint)strlen(g_ran_functioname_table[n].name);
    for (int m=0; (m<30) && ((m+name_len+1))<tvb_len; m++) {
      if (tvb_strneql(parameter_tvb, m, g_ran_functioname_table[n].name, name_len) == 0) {
        /* Call the set's dissector */
        g_ran_functioname_table[n].functions.ran_function_definition_dissector(parameter_tvb, actx->pinfo, tree, NULL);
        found = TRUE;
        break;
      }
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
  guint32 value;
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, &value, FALSE);

  /* Store value in packet-private data */
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  e2ap_data->ran_function_id = value;



  return offset;
}



static int
dissect_e2ap_RANfunctionOID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 1000, TRUE);

  return offset;
}



static int
dissect_e2ap_RANfunctionRevision(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_e2ap_RICactionDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  ran_function_pointers_t* functions = lookup_ranfunction_pointers(actx->pinfo, tree, parameter_tvb);
  if (functions && functions->ran_action_definition_dissector) {
    functions->ran_action_definition_dissector(parameter_tvb, actx->pinfo, tree, NULL);
  }


  return offset;
}



static int
dissect_e2ap_RICactionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

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
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e2ap_RICcallProcessID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  ran_function_pointers_t* functions = lookup_ranfunction_pointers(actx->pinfo, tree, parameter_tvb);
  if (functions && functions->ran_callprocessid_dissector) {
    functions->ran_callprocessid_dissector(parameter_tvb, actx->pinfo, tree, NULL);
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
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e2ap_RICcontrolHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  ran_function_pointers_t* functions = lookup_ranfunction_pointers(actx->pinfo, tree, parameter_tvb);
  if (functions && functions->ric_control_header_dissector) {
    functions->ric_control_header_dissector(parameter_tvb, actx->pinfo, tree, NULL);
  }


  return offset;
}



static int
dissect_e2ap_RICcontrolMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  ran_function_pointers_t* functions = lookup_ranfunction_pointers(actx->pinfo, tree, parameter_tvb);
  if (functions && functions->ric_control_message_dissector) {
    functions->ric_control_message_dissector(parameter_tvb, actx->pinfo, tree, NULL);
  }


  return offset;
}



static int
dissect_e2ap_RICcontrolOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  ran_function_pointers_t* functions = lookup_ranfunction_pointers(actx->pinfo, tree, parameter_tvb);
  if (functions && functions->ric_control_outcome_dissector) {
    functions->ric_control_outcome_dissector(parameter_tvb, actx->pinfo, tree, NULL);
  }



  return offset;
}



static int
dissect_e2ap_RICeventTriggerDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  ran_function_pointers_t* functions = lookup_ranfunction_pointers(actx->pinfo, tree, parameter_tvb);
  if (functions && functions->ran_event_trigger_dissector) {
    functions->ran_event_trigger_dissector(parameter_tvb, actx->pinfo, tree, NULL);
  }


  return offset;
}



static int
dissect_e2ap_RICindicationHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  ran_function_pointers_t* functions = lookup_ranfunction_pointers(actx->pinfo, tree, parameter_tvb);
  if (functions && functions->ran_indication_header_dissector) {
    functions->ran_indication_header_dissector(parameter_tvb, actx->pinfo, tree, NULL);
  }


  return offset;
}



static int
dissect_e2ap_RICindicationMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  ran_function_pointers_t* functions = lookup_ranfunction_pointers(actx->pinfo, tree, parameter_tvb);
  if (functions && functions->ran_indication_message_dissector) {
    functions->ran_indication_message_dissector(parameter_tvb, actx->pinfo, tree, NULL);
  }


  return offset;
}



static int
dissect_e2ap_RICindicationSN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     17, NULL, TRUE, 0, NULL);

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
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e2ap_T_tnlAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *value_tvb;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, NULL, 0, &value_tvb, NULL);

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
                                     16, 16, FALSE, NULL, 0, NULL, NULL);




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
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e2ap_TransactionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, TRUE);

  return offset;
}


static const per_sequence_t RICsubscriptionRequest_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICsubscriptionRequest");

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
                                                  1, maxofRICactionID, FALSE);

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICsubscriptionResponse");



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
                                                  1, maxofRICactionID, FALSE);

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
                                                  0, maxofRICactionID, FALSE);

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICsubscriptionFailure");

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICsubscriptionDeleteRequest");

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICsubscriptionDeleteResponse");

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICsubscriptionDeleteFailure");

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICsubscriptionDeleteRequired");


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
                                                  1, maxofRICrequestID, FALSE);

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


static const per_sequence_t RICindication_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICindication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICindication");


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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICcontrolRequest");


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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICcontrolAcknowledge");

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICcontrolFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICcontrolFailure, RICcontrolFailure_sequence);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ErrorIndication");


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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E2setupRequest");

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E2setupResponse");


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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E2setupFailure");

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E2connectionUpdate");

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
                                                  1, maxofTNLA, FALSE);

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
                                                  1, maxofTNLA, FALSE);

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E2connectionUpdateAcknowledge");

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
                                                  1, maxofTNLA, FALSE);

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E2connectionUpdateFailure");


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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E2nodeConfigurationUpdate");

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
                                                  1, maxofE2nodeComponents, FALSE);

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
                                                  1, maxofE2nodeComponents, FALSE);

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
                                                  1, maxofE2nodeComponents, FALSE);

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
                                                  1, maxofTNLA, FALSE);

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E2nodeConfigurationUpdateAcknowledge");

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
                                                  1, maxofE2nodeComponents, FALSE);

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
                                                  1, maxofE2nodeComponents, FALSE);

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
                                                  1, maxofE2nodeComponents, FALSE);

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E2nodeConfigurationUpdateFailure");


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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResetRequest");

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResetResponse");


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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICserviceUpdate");

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
                                                  1, maxofRANfunctionID, FALSE);

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
                                                  1, maxofRANfunctionID, FALSE);

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICserviceUpdateAcknowledge");

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
                                                  1, maxofRANfunctionID, FALSE);

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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICserviceUpdateFailure");



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
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICserviceQuery");


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
                                       3, 3, FALSE, NULL);

  return offset;
}



static int
dissect_e2ap_NRCellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, FALSE, NULL, 0, NULL, NULL);

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
                                     28, 28, FALSE, NULL, 0, NULL, NULL);

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
                                     8, 8, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e2ap_AMFSetID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e2ap_AMFPointer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, FALSE, NULL, 0, NULL, NULL);

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
                                       2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_e2ap_MME_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

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
                                     3, NULL, TRUE, 0, NULL);

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
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e2ap_T_ranFunction_ShortName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  gint start_offset = offset;
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  /* TODO: is there a nicer/reliable way to get PrintableString here (VAL_PTR won't get assigned..) */
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  ran_functionid_table_t *table = get_ran_functionid_table(actx->pinfo);
  store_ran_function_mapping(actx->pinfo, table, e2ap_data,
                             tvb_get_stringz_enc(wmem_packet_scope(), tvb, (start_offset+15)/8, NULL, ENC_ASCII));


  return offset;
}



static int
dissect_e2ap_PrintableString_SIZE_1_1000_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 1000, TRUE);

  return offset;
}



static int
dissect_e2ap_PrintableString_SIZE_1_150_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

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
                                          1, 150, TRUE);

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
                                     12, NULL, TRUE, 0, NULL);

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
                                     8, NULL, TRUE, 0, NULL);

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
                                                            0U, maxNRARFCN, NULL, FALSE);

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
                                                            0U, maxEARFCN, NULL, FALSE);

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
                                                            0U, 1007U, NULL, FALSE);

  return offset;
}



static int
dissect_e2ap_E_UTRA_PCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 503U, NULL, TRUE);

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
                                                            0U, G_GUINT64_CONSTANT(1099511627775), NULL, FALSE);

  return offset;
}



static int
dissect_e2ap_GNB_CU_UE_F1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

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
                                                  1, maxF1APid, FALSE);

  return offset;
}



static int
dissect_e2ap_GNB_CU_CP_UE_E1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

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
                                                  1, maxE1APid, FALSE);

  return offset;
}



static int
dissect_e2ap_RANUEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, NULL);

  return offset;
}



static int
dissect_e2ap_NG_RANnodeUEXnAPID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

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
                                                            0U, 4294967295U, NULL, FALSE);

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
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_e2ap_ENB_UE_X2AP_ID_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

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
                                                            0U, 4294967295U, NULL, FALSE);

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
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_e2ap_E_UTRA_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_e2ap_FiveQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, TRUE);

  return offset;
}



static int
dissect_e2ap_QosFlowIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, TRUE);

  return offset;
}



static int
dissect_e2ap_SD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}



static int
dissect_e2ap_SST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

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
                                       3, 3, FALSE, NULL);

  return offset;
}



static int
dissect_e2ap_INTEGER_1_1024_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, TRUE);

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
                                                  0, maxnoofNrCellBands, FALSE);

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
                                                  1, maxnoofNrCellBands, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e2ap_INTEGER_1_65535_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, TRUE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofNeighbourCell, FALSE);

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
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e2ap_RIC_EventTrigger_Cell_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, TRUE);

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
                                                            1U, G_GUINT64_CONSTANT(4294967296), NULL, TRUE);

  return offset;
}


static const per_sequence_t RANParameter_Testing_LIST_sequence_of[1] = {
  { &hf_e2ap_RANParameter_Testing_LIST_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Testing_Item },
};

static int
dissect_e2ap_RANParameter_Testing_LIST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RANParameter_Testing_LIST, RANParameter_Testing_LIST_sequence_of,
                                                  1, maxnoofItemsinList, FALSE);

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
                                                  1, maxnoofParametersinStructure, FALSE);

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
                                     NO_BOUND, NO_BOUND, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e2ap_PrintableString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND, FALSE);

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
                                     6, NULL, TRUE, 0, NULL);

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
                                     4, NULL, TRUE, 0, NULL);

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
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_Testing_Item, RANParameter_Testing_Item_sequence);

  return offset;
}


static const per_sequence_t RANParameter_Testing_sequence_of[1] = {
  { &hf_e2ap_RANParameter_Testing_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RANParameter_Testing_Item },
};

static int
dissect_e2ap_RANParameter_Testing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_RANParameter_Testing, RANParameter_Testing_sequence_of,
                                                  1, maxnoofRANparamTest, FALSE);

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
                                                  1, maxnoofCellInfo, FALSE);

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
                                                            1U, 65535U, NULL, TRUE);

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
                                                  1, maxnoofUEInfo, FALSE);

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
                                                            1U, 65535U, NULL, TRUE);

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
                                                  1, maxnoofUEeventInfo, FALSE);

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
                                          1, 150, TRUE);

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
                                                  1, maxnoofItemsinList, FALSE);

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
                                                  1, maxnoofParametersinStructure, FALSE);

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
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RANParameter_Definition, RANParameter_Definition_sequence);

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
                                                  1, maxnoofParametersinStructure, FALSE);

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
                                                  1, maxnoofItemsinList, FALSE);

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
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_RANParameter_ValueType, RANParameter_ValueType_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_RAN_CallProcess_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 232U, NULL, TRUE);

  return offset;
}



static int
dissect_e2ap_RIC_CallProcessType_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, TRUE);

  return offset;
}



static int
dissect_e2ap_RIC_CallProcessType_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}



static int
dissect_e2ap_RIC_CallProcessBreakpoint_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, TRUE);

  return offset;
}



static int
dissect_e2ap_RIC_CallProcessBreakpoint_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}



static int
dissect_e2ap_RIC_ControlAction_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, TRUE);

  return offset;
}



static int
dissect_e2ap_RIC_ControlAction_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}



static int
dissect_e2ap_RIC_EventTriggerCondition_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, TRUE);

  return offset;
}



static int
dissect_e2ap_RIC_InsertIndication_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, TRUE);

  return offset;
}



static int
dissect_e2ap_RIC_InsertIndication_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofMessages, FALSE);

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
                                                            1U, 512U, NULL, TRUE);

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
                                                  1, maxnoofE2InfoChanges, FALSE);

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
                                                  1, maxnoofRRCstate, FALSE);

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
                                                  1, maxnoofUEInfoChanges, FALSE);

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
                                     1, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofParametersToReport, FALSE);

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
                                                  1, maxnoofPolicyConditions, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofInsertIndicationActions, FALSE);

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
                                                  1, maxnoofRICStyles, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofUEID, FALSE);

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
                                                  1, maxnoofCellID, FALSE);

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
                                                  0, maxnoofUEID, FALSE);

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
                                                  0, maxnoofCellID, FALSE);

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
                                                  0, maxnoofAssociatedRANParameters, FALSE);

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
                                                  0, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofInsertIndicationActions, FALSE);

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
                                                  1, maxnoofRICStyles, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  0, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofMulCtrlActions, FALSE);

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
                                                  1, maxnoofRICStyles, FALSE);

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
                                                  0, maxnoofRANOutcomeParameters, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofMulCtrlActions, FALSE);

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
                                                  1, maxnoofRICStyles, FALSE);

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
                                                  0, maxnoofRANOutcomeParameters, FALSE);

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
                                                  1, maxnoofRICStyles, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofCallProcessBreakpoints, FALSE);

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
                                                  1, maxnoofCallProcessTypes, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofRICStyles, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofInsertIndication, FALSE);

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
                                                  1, maxnoofRICStyles, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofControlAction, FALSE);

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
                                                  1, maxnoofRANOutcomeParameters, FALSE);

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
                                                  1, maxnoofRICStyles, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofAssociatedRANParameters, FALSE);

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
                                                  1, maxnoofPolicyAction, FALSE);

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
                                                  1, maxnoofRICStyles, FALSE);

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
                                       4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_e2ap_GranularityPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_e2ap_MeasurementTypeName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}



static int
dissect_e2ap_MeasurementTypeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65536U, NULL, TRUE);

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
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e2ap_INTEGER_1_15_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 15U, NULL, TRUE);

  return offset;
}


static const value_string e2ap_T_sUM_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_sUM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_preLabelOverride_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_preLabelOverride(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_min_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_min(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_max_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_max(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_avg_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_avg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t MeasurementLabel_sequence[] = {
  { &hf_e2ap_noLabel        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_T_noLabel },
  { &hf_e2ap_plmnID         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_PLMN_Identity },
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
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_aMBR_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_aMBR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_isStat_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_isStat(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_isCatM_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_isCatM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_rSRP_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_rSRP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_rSRQ_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_rSRQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_ul_rSRP_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_ul_rSRP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_cQI_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_cQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_fiveQI_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_fiveQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_qCI_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_qCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_T_sNSSAI_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_sNSSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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
                                     5, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofLabelInfo, FALSE);

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
                                                  1, maxnoofMeasurementInfo, FALSE);

  return offset;
}



static int
dissect_e2ap_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

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
                                                  1, maxnoofMeasurementValue, FALSE);

  return offset;
}


static const value_string e2ap_T_incompleteFlag_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_e2ap_T_incompleteFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofMeasurementRecord, FALSE);

  return offset;
}


static const per_sequence_t MeasurementInfo_Action_Item_sequence[] = {
  { &hf_e2ap_measName       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementTypeName },
  { &hf_e2ap_measID         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_MeasurementTypeID },
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
                                                  1, maxnoofMeasurementInfo, FALSE);

  return offset;
}


static const value_string e2ap_MatchingCondItem_vals[] = {
  {   0, "measLabel" },
  {   1, "testCondInfo" },
  { 0, NULL }
};

static const per_choice_t MatchingCondItem_choice[] = {
  {   0, &hf_e2ap_measLabel      , ASN1_EXTENSION_ROOT    , dissect_e2ap_MeasurementLabel },
  {   1, &hf_e2ap_testCondInfo   , ASN1_EXTENSION_ROOT    , dissect_e2ap_TestCondInfo },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_MatchingCondItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_MatchingCondItem, MatchingCondItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MatchingCondList_sequence_of[1] = {
  { &hf_e2ap_MatchingCondList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingCondItem },
};

static int
dissect_e2ap_MatchingCondList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_MatchingCondList, MatchingCondList_sequence_of,
                                                  1, maxnoofConditionInfo, FALSE);

  return offset;
}


static const per_sequence_t MeasurementCondItem_sequence[] = {
  { &hf_e2ap_measType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementType },
  { &hf_e2ap_matchingCond   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingCondList },
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
                                                  1, maxnoofMeasurementInfo, FALSE);

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
                                                  1, maxnoofUEID, FALSE);

  return offset;
}


static const per_sequence_t MeasurementCondUEidItem_sequence[] = {
  { &hf_e2ap_measType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MeasurementType },
  { &hf_e2ap_matchingCond   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_MatchingCondList },
  { &hf_e2ap_matchingUEidList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_MatchingUEidList },
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
                                                  1, maxnoofMeasurementInfo, FALSE);

  return offset;
}


static const per_sequence_t MatchingUeCondPerSubItem_sequence[] = {
  { &hf_e2ap_testCondInfo   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_TestCondInfo },
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
                                                  1, maxnoofConditionInfoPerSub, FALSE);

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
                                                  2, maxnoofUEIDPerSub, FALSE);

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
                                                  1, maxnoofUEMeasReport, FALSE);

  return offset;
}



static int
dissect_e2ap_INTEGER_1_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4294967295U, NULL, FALSE);

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
dissect_e2ap_PrintableString_SIZE_0_15_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          0, 15, TRUE);

  return offset;
}



static int
dissect_e2ap_PrintableString_SIZE_0_400_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          0, 400, TRUE);

  return offset;
}



static int
dissect_e2ap_PrintableString_SIZE_0_8_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          0, 8, TRUE);

  return offset;
}



static int
dissect_e2ap_PrintableString_SIZE_0_32_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          0, 32, TRUE);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationHeader_Format1_sequence[] = {
  { &hf_e2ap_colletStartTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_TimeStamp },
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
                                                  1, maxnoofRICStyles, FALSE);

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
                                                  1, maxnoofRICStyles, FALSE);

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

/*--- PDUs ---*/

static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_Cause(tvb, offset, &asn1_ctx, tree, hf_e2ap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_e2ap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalE2node_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_GlobalE2node_ID(tvb, offset, &asn1_ctx, tree, hf_e2ap_GlobalE2node_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalRIC_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_GlobalRIC_ID(tvb, offset, &asn1_ctx, tree, hf_e2ap_GlobalRIC_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunctionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RANfunctionID(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunctionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICactionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICactionID(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICactionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcallProcessID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICcallProcessID(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcallProcessID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolAckRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICcontrolAckRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolAckRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICcontrolHeader(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICcontrolMessage(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICcontrolOutcome(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolOutcome_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICindicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICindicationHeader(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICindicationHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICindicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICindicationMessage(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICindicationMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICindicationSN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICindicationSN(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICindicationSN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICindicationType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICindicationType(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICindicationType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICrequestID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICrequestID(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICrequestID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToWait_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_TimeToWait(tvb, offset, &asn1_ctx, tree, hf_e2ap_TimeToWait_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TNLinformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_TNLinformation(tvb, offset, &asn1_ctx, tree, hf_e2ap_TNLinformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransactionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_TransactionID(tvb, offset, &asn1_ctx, tree, hf_e2ap_TransactionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICsubscriptionRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionDetails_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICsubscriptionDetails(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionDetails_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_ToBeSetup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICaction_ToBeSetup_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_ToBeSetup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICsubscriptionResponse(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_Admitted_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICaction_Admitted_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_Admitted_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_Admitted_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICaction_Admitted_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_Admitted_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_NotAdmitted_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICaction_NotAdmitted_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_NotAdmitted_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICaction_NotAdmitted_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICaction_NotAdmitted_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICaction_NotAdmitted_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICsubscriptionFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionDeleteRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICsubscriptionDeleteRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionDeleteRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionDeleteResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICsubscriptionDeleteResponse(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionDeleteResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionDeleteFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICsubscriptionDeleteFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionDeleteFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscriptionDeleteRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICsubscriptionDeleteRequired(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscriptionDeleteRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscription_List_withCause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICsubscription_List_withCause(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscription_List_withCause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICsubscription_withCause_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICsubscription_withCause_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICsubscription_withCause_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICindication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICindication(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICindication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICcontrolRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICcontrolAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICcontrolFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICcontrolFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_e2ap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2setupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2setupRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2setupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2setupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2setupResponse(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2setupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2setupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2setupFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2setupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2connectionUpdate(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdate_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2connectionUpdate_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdate_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdate_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2connectionUpdate_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdate_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdateRemove_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2connectionUpdateRemove_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdateRemove_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdateRemove_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2connectionUpdateRemove_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdateRemove_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2connectionUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionSetupFailed_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2connectionSetupFailed_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionSetupFailed_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionSetupFailed_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2connectionSetupFailed_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionSetupFailed_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2connectionUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2connectionUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2connectionUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigAddition_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigAddition_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigAddition_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigAddition_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigAddition_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigAddition_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigUpdate_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigUpdate_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigUpdate_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigUpdate_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigUpdate_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigUpdate_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigRemoval_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigRemoval_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigRemoval_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigRemoval_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigRemoval_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigRemoval_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeTNLassociationRemoval_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeTNLassociationRemoval_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeTNLassociationRemoval_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeTNLassociationRemoval_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeTNLassociationRemoval_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeTNLassociationRemoval_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigAdditionAck_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigAdditionAck_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigAdditionAck_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigAdditionAck_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigAdditionAck_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigAdditionAck_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigUpdateAck_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigUpdateAck_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigUpdateAck_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigUpdateAck_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigUpdateAck_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigUpdateAck_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigRemovalAck_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigRemovalAck_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigRemovalAck_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeComponentConfigRemovalAck_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeComponentConfigRemovalAck_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeComponentConfigRemovalAck_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2nodeConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2nodeConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2nodeConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_ResetRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_ResetRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_ResetResponse(tvb, offset, &asn1_ctx, tree, hf_e2ap_ResetResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICserviceUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICserviceUpdate(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICserviceUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunctions_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RANfunctions_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunctions_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunction_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RANfunction_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunction_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunctionsID_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RANfunctionsID_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunctionsID_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunctionID_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RANfunctionID_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunctionID_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICserviceUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICserviceUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICserviceUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunctionsIDcause_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RANfunctionsIDcause_List(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunctionsIDcause_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANfunctionIDcause_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RANfunctionIDcause_Item(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANfunctionIDcause_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICserviceUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICserviceUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICserviceUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RICserviceQuery_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICserviceQuery(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICserviceQuery_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2RemovalRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2RemovalRequest(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2RemovalRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2RemovalResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2RemovalResponse(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2RemovalResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2RemovalFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2RemovalFailure(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2RemovalFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2AP_PDU(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2AP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_EventTrigger_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_RC_EventTrigger(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_EventTrigger_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_RC_ActionDefinition(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_ActionDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_RC_IndicationHeader(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_IndicationHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_RC_IndicationMessage(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_IndicationMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_CallProcessID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_RC_CallProcessID(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_CallProcessID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_ControlHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_RC_ControlHeader(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_ControlHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_ControlMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_RC_ControlMessage(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_ControlMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_ControlOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_RC_ControlOutcome(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_ControlOutcome_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_RANFunctionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_RC_RANFunctionDefinition(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_RC_RANFunctionDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_EventTriggerDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_KPM_EventTriggerDefinition(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_KPM_EventTriggerDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_KPM_ActionDefinition(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_KPM_ActionDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_KPM_IndicationHeader(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_KPM_IndicationHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_KPM_IndicationMessage(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_KPM_IndicationMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_RANfunction_Description_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_KPM_RANfunction_Description(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_KPM_RANfunction_Description_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  e2ap_ctx_t e2ap_ctx;
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  e2ap_ctx.message_type        = e2ap_data->message_type;
  e2ap_ctx.ProcedureCode       = e2ap_data->procedure_code;
  e2ap_ctx.ProtocolIE_ID       = e2ap_data->protocol_ie_id;
  e2ap_ctx.ProtocolExtensionID = e2ap_data->protocol_extension_id;

  return (dissector_try_uint_new(e2ap_ies_dissector_table, e2ap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, &e2ap_ctx)) ? tvb_captured_length(tvb) : 0;
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

  return (dissector_try_uint_new(e2ap_proc_imsg_dissector_table, e2ap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e2ap_proc_sout_dissector_table, e2ap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(pinfo);

  return (dissector_try_uint_new(e2ap_proc_uout_dissector_table, e2ap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_e2ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *e2ap_item = NULL;
  proto_tree *e2ap_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "E2AP");
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the e2ap protocol tree */
  e2ap_item = proto_tree_add_item(tree, proto_e2ap, tvb, 0, -1, ENC_NA);
  e2ap_tree = proto_item_add_subtree(e2ap_item, ett_e2ap);

  return dissect_E2AP_PDU_PDU(tvb, pinfo, e2ap_tree, NULL);
}


static void e2ap_init_protocol(void)
{
  s_gnb_ran_functions.num_gnbs = 0;
}


/*--- proto_reg_handoff_e2ap ---------------------------------------*/
void
proto_reg_handoff_e2ap(void)
{
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_E2AP, e2ap_handle);

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
        "OCTET_STRING", HFILL }},
    { &hf_e2ap_e2nodeComponentResponsePart,
      { "e2nodeComponentResponsePart", "e2ap.e2nodeComponentResponsePart",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
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
        "E2nodeComponentInterfaceNG", HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceTypeXn,
      { "e2nodeComponentInterfaceTypeXn", "e2ap.e2nodeComponentInterfaceTypeXn_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2nodeComponentInterfaceXn", HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceTypeE1,
      { "e2nodeComponentInterfaceTypeE1", "e2ap.e2nodeComponentInterfaceTypeE1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2nodeComponentInterfaceE1", HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceTypeF1,
      { "e2nodeComponentInterfaceTypeF1", "e2ap.e2nodeComponentInterfaceTypeF1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2nodeComponentInterfaceF1", HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceTypeW1,
      { "e2nodeComponentInterfaceTypeW1", "e2ap.e2nodeComponentInterfaceTypeW1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2nodeComponentInterfaceW1", HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceTypeS1,
      { "e2nodeComponentInterfaceTypeS1", "e2ap.e2nodeComponentInterfaceTypeS1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2nodeComponentInterfaceS1", HFILL }},
    { &hf_e2ap_e2nodeComponentInterfaceTypeX2,
      { "e2nodeComponentInterfaceTypeX2", "e2ap.e2nodeComponentInterfaceTypeX2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2nodeComponentInterfaceX2", HFILL }},
    { &hf_e2ap_gNB_CU_CP_ID,
      { "gNB-CU-CP-ID", "e2ap.gNB_CU_CP_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        "GNB_CU_UP_ID", HFILL }},
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
    { &hf_e2ap_gNB_CU_UP_ID,
      { "gNB-CU-UP-ID", "e2ap.gNB_CU_UP_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
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
    { &hf_e2ap_nRCellIdentity,
      { "nRCellIdentity", "e2ap.nRCellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
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
        "PLMN_Identity", HFILL }},
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
    { &hf_e2ap_MeasurementInfoList_item,
      { "MeasurementInfoItem", "e2ap.MeasurementInfoItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_measType,
      { "measType", "e2ap.measType",
        FT_UINT32, BASE_DEC, VALS(e2ap_MeasurementType_vals), 0,
        "MeasurementType", HFILL }},
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
    { &hf_e2ap_MatchingCondList_item,
      { "MatchingCondItem", "e2ap.MatchingCondItem",
        FT_UINT32, BASE_DEC, VALS(e2ap_MatchingCondItem_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_testCondInfo,
      { "testCondInfo", "e2ap.testCondInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_MatchingUEidList_item,
      { "MatchingUEidItem", "e2ap.MatchingUEidItem_element",
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
        "TimeStamp", HFILL }},
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
            NULL, HFILL }}
  };

  /* List of subtrees */
  static gint *ett[] = {
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
    &ett_e2ap_RICindication,
    &ett_e2ap_RICcontrolRequest,
    &ett_e2ap_RICcontrolAcknowledge,
    &ett_e2ap_RICcontrolFailure,
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
    &ett_e2ap_S_NSSAI,
    &ett_e2ap_GlobalNGRANNodeID,
    &ett_e2ap_NR_ARFCN,
    &ett_e2ap_NRFrequencyBand_List,
    &ett_e2ap_NRFrequencyBandItem,
    &ett_e2ap_NRFrequencyInfo,
    &ett_e2ap_SupportedSULBandList,
    &ett_e2ap_SupportedSULFreqBandItem,
    &ett_e2ap_NR_CGI,
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
    &ett_e2ap_MeasurementType,
    &ett_e2ap_MeasurementLabel,
    &ett_e2ap_TestCondInfo,
    &ett_e2ap_TestCond_Type,
    &ett_e2ap_TestCond_Value,
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
    &ett_e2ap_MatchingUEidList,
    &ett_e2ap_MatchingUEidItem,
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
  };

  static ei_register_info ei[] = {
     { &ei_e2ap_ran_function_names_no_match, { "e2ap.ran-function-names-no-match", PI_PROTOCOL, PI_WARN, "RAN Function name doesn't match known service models", EXPFILL }},
     { &ei_e2ap_ran_function_id_not_mapped,   { "e2ap.ran-function-id-not-known", PI_PROTOCOL, PI_WARN, "Service Model not known for RANFunctionID", EXPFILL }},
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
  e2ap_n2_ie_type_dissector_table = register_dissector_table("e2ap.n2_ie_type", "E2AP N2 IE Type", proto_e2ap, FT_STRING, FALSE);

  register_init_routine(&e2ap_init_protocol);
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
