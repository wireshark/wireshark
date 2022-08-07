/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-e2ap.c                                                              */
/* asn2wrs.py -p e2ap -c ./e2ap.cnf -s ./packet-e2ap-template -D . -O ../.. E2AP-CommonDataTypes.asn E2AP-Constants.asn E2AP-Containers.asn E2AP-IEs.asn E2AP-PDU-Contents.asn E2AP-PDU-Descriptions.asn e2sm-kpm-v1.asn */

/* Input file: packet-e2ap-template.c */

#line 1 "./asn1/e2ap/packet-e2ap-template.c"
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
 * References: ORAN-WG3.E2AP-v01.00, ORAN-WG3.E2SM-KPM-v01.00
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


/*--- Included file: packet-e2ap-val.h ---*/
#line 1 "./asn1/e2ap/packet-e2ap-val.h"
#define maxProtocolIEs                 65535
#define maxnoofErrors                  256
#define maxofRANfunctionID             256
#define maxofRICactionID               16
#define maxofMessageProtocolTests      15
#define maxofRICstyles                 63
#define maxnoofQCI                     256
#define maxnoofQoSFlows                64
#define maxnoofSliceItems              1024
#define maxnoofContainerListItems      3
#define maxCellingNBDU                 512
#define maxofContainers                8
#define maxPLMN                        12

typedef enum _ProcedureCode_enum {
  id_E2setup   =   1,
  id_ErrorIndication =   2,
  id_Reset     =   3,
  id_RICcontrol =   4,
  id_RICindication =   5,
  id_RICserviceQuery =   6,
  id_RICserviceUpdate =   7,
  id_RICsubscription =   8,
  id_RICsubscriptionDelete =   9
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
  id_RICcontrolOutcome =  32
} ProtocolIE_ID_enum;

/*--- End of included file: packet-e2ap-val.h ---*/
#line 43 "./asn1/e2ap/packet-e2ap-template.c"

/* Initialize the protocol and registered fields */
static int proto_e2ap = -1;

/*--- Included file: packet-e2ap-hf.c ---*/
#line 1 "./asn1/e2ap/packet-e2ap-hf.c"
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
static int hf_e2ap_RICcontrolStatus_PDU = -1;     /* RICcontrolStatus */
static int hf_e2ap_RICindicationHeader_PDU = -1;  /* RICindicationHeader */
static int hf_e2ap_RICindicationMessage_PDU = -1;  /* RICindicationMessage */
static int hf_e2ap_RICindicationSN_PDU = -1;      /* RICindicationSN */
static int hf_e2ap_RICindicationType_PDU = -1;    /* RICindicationType */
static int hf_e2ap_RICrequestID_PDU = -1;         /* RICrequestID */
static int hf_e2ap_TimeToWait_PDU = -1;           /* TimeToWait */
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
static int hf_e2ap_RICindication_PDU = -1;        /* RICindication */
static int hf_e2ap_RICcontrolRequest_PDU = -1;    /* RICcontrolRequest */
static int hf_e2ap_RICcontrolAcknowledge_PDU = -1;  /* RICcontrolAcknowledge */
static int hf_e2ap_RICcontrolFailure_PDU = -1;    /* RICcontrolFailure */
static int hf_e2ap_ErrorIndication_PDU = -1;      /* ErrorIndication */
static int hf_e2ap_E2setupRequest_PDU = -1;       /* E2setupRequest */
static int hf_e2ap_E2setupResponse_PDU = -1;      /* E2setupResponse */
static int hf_e2ap_E2setupFailure_PDU = -1;       /* E2setupFailure */
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
static int hf_e2ap_E2AP_PDU_PDU = -1;             /* E2AP_PDU */
static int hf_e2ap_E2SM_KPM_EventTriggerDefinition_PDU = -1;  /* E2SM_KPM_EventTriggerDefinition */
static int hf_e2ap_E2SM_KPM_ActionDefinition_PDU = -1;  /* E2SM_KPM_ActionDefinition */
static int hf_e2ap_E2SM_KPM_IndicationHeader_PDU = -1;  /* E2SM_KPM_IndicationHeader */
static int hf_e2ap_E2SM_KPM_IndicationMessage_Format1_PDU = -1;  /* E2SM_KPM_IndicationMessage_Format1 */
static int hf_e2ap_E2SM_KPM_RANfunction_Description_PDU = -1;  /* E2SM_KPM_RANfunction_Description */
static int hf_e2ap_RANcallProcess_ID_string_PDU = -1;  /* RANcallProcess_ID_string */
static int hf_e2ap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_e2ap_id = -1;                       /* ProtocolIE_ID */
static int hf_e2ap_criticality = -1;              /* Criticality */
static int hf_e2ap_value = -1;                    /* T_value */
static int hf_e2ap_ricRequest = -1;               /* CauseRIC */
static int hf_e2ap_ricService = -1;               /* CauseRICservice */
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
static int hf_e2ap_global_gNB_ID = -1;            /* GlobalenGNB_ID */
static int hf_e2ap_global_eNB_ID = -1;            /* GlobalENB_ID */
static int hf_e2ap_global_gNB_ID_01 = -1;         /* GlobalgNB_ID */
static int hf_e2ap_gNB_CU_UP_ID = -1;             /* GNB_CU_UP_ID */
static int hf_e2ap_gNB_DU_ID = -1;                /* GNB_DU_ID */
static int hf_e2ap_global_ng_eNB_ID = -1;         /* GlobalngeNB_ID */
static int hf_e2ap_pLMN_Identity = -1;            /* PLMN_Identity */
static int hf_e2ap_eNB_ID = -1;                   /* ENB_ID */
static int hf_e2ap_gNB_ID_01 = -1;                /* ENGNB_ID */
static int hf_e2ap_plmn_id = -1;                  /* PLMN_Identity */
static int hf_e2ap_gnb_id = -1;                   /* GNB_ID_Choice */
static int hf_e2ap_enb_id = -1;                   /* ENB_ID_Choice */
static int hf_e2ap_ric_ID = -1;                   /* BIT_STRING_SIZE_20 */
static int hf_e2ap_gnb_ID = -1;                   /* BIT_STRING_SIZE_22_32 */
static int hf_e2ap_ricRequestorID_01 = -1;        /* INTEGER_0_65535 */
static int hf_e2ap_ricInstanceID = -1;            /* INTEGER_0_65535 */
static int hf_e2ap_ricSubsequentActionType = -1;  /* RICsubsequentActionType */
static int hf_e2ap_ricTimeToWait = -1;            /* RICtimeToWait */
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
static int hf_e2ap_RANfunctions_List_item = -1;   /* ProtocolIE_SingleContainer */
static int hf_e2ap_ranFunctionID = -1;            /* RANfunctionID */
static int hf_e2ap_ranFunctionDefinition = -1;    /* RANfunctionDefinition */
static int hf_e2ap_ranFunctionRevision = -1;      /* RANfunctionRevision */
static int hf_e2ap_RANfunctionsID_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_RANfunctionsIDcause_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_e2ap_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_e2ap_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_e2ap_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_e2ap_initiatingMessagevalue = -1;   /* InitiatingMessage_value */
static int hf_e2ap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_e2ap_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */
static int hf_e2ap_gNB_01 = -1;                   /* GlobalKPMnode_gNB_ID */
static int hf_e2ap_en_gNB_01 = -1;                /* GlobalKPMnode_en_gNB_ID */
static int hf_e2ap_ng_eNB_01 = -1;                /* GlobalKPMnode_ng_eNB_ID */
static int hf_e2ap_eNB_01 = -1;                   /* GlobalKPMnode_eNB_ID */
static int hf_e2ap_nRCellIdentity = -1;           /* NRCellIdentity */
static int hf_e2ap_sST = -1;                      /* OCTET_STRING_SIZE_1 */
static int hf_e2ap_sD = -1;                       /* OCTET_STRING_SIZE_3 */
static int hf_e2ap_eventDefinition_Format1 = -1;  /* E2SM_KPM_EventTriggerDefinition_Format1 */
static int hf_e2ap_policyTest_List = -1;          /* SEQUENCE_SIZE_1_maxofMessageProtocolTests_OF_Trigger_ConditionIE_Item */
static int hf_e2ap_policyTest_List_item = -1;     /* Trigger_ConditionIE_Item */
static int hf_e2ap_ric_Style_Type = -1;           /* RIC_Style_Type */
static int hf_e2ap_indicationHeader_Format1 = -1;  /* E2SM_KPM_IndicationHeader_Format1 */
static int hf_e2ap_id_GlobalKPMnode_ID = -1;      /* GlobalKPMnode_ID */
static int hf_e2ap_nRCGI = -1;                    /* NRCGI */
static int hf_e2ap_sliceID = -1;                  /* SNSSAI */
static int hf_e2ap_fiveQI = -1;                   /* INTEGER_0_255 */
static int hf_e2ap_qci = -1;                      /* INTEGER_0_255 */
static int hf_e2ap_pm_Containers = -1;            /* SEQUENCE_SIZE_1_maxCellingNBDU_OF_PM_Containers_List */
static int hf_e2ap_pm_Containers_item = -1;       /* PM_Containers_List */
static int hf_e2ap_performanceContainer = -1;     /* PF_Container */
static int hf_e2ap_theRANContainer = -1;          /* RAN_Container */
static int hf_e2ap_ranFunction_Name = -1;         /* RANfunction_Name */
static int hf_e2ap_e2SM_KPM_RANfunction_Item = -1;  /* T_e2SM_KPM_RANfunction_Item */
static int hf_e2ap_ric_EventTriggerStyle_List = -1;  /* SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List */
static int hf_e2ap_ric_EventTriggerStyle_List_item = -1;  /* RIC_EventTriggerStyle_List */
static int hf_e2ap_ric_ReportStyle_List = -1;     /* SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List */
static int hf_e2ap_ric_ReportStyle_List_item = -1;  /* RIC_ReportStyle_List */
static int hf_e2ap_report_Period_IE = -1;         /* RT_Period_IE */
static int hf_e2ap_ranFunction_ShortName = -1;    /* PrintableString_SIZE_1_150_ */
static int hf_e2ap_ranFunction_E2SM_OID = -1;     /* PrintableString_SIZE_1_1000_ */
static int hf_e2ap_ranFunction_Description = -1;  /* PrintableString_SIZE_1_150_ */
static int hf_e2ap_ranFunction_Instance = -1;     /* INTEGER */
static int hf_e2ap_ric_EventTriggerStyle_Type = -1;  /* RIC_Style_Type */
static int hf_e2ap_ric_EventTriggerStyle_Name = -1;  /* RIC_Style_Name */
static int hf_e2ap_ric_EventTriggerFormat_Type = -1;  /* RIC_Format_Type */
static int hf_e2ap_ric_ReportStyle_Type = -1;     /* RIC_Style_Type */
static int hf_e2ap_ric_ReportStyle_Name = -1;     /* RIC_Style_Name */
static int hf_e2ap_ric_IndicationHeaderFormat_Type = -1;  /* RIC_Format_Type */
static int hf_e2ap_ric_IndicationMessageFormat_Type = -1;  /* RIC_Format_Type */
static int hf_e2ap_oDU = -1;                      /* ODU_PF_Container */
static int hf_e2ap_oCU_CP = -1;                   /* OCUCP_PF_Container */
static int hf_e2ap_oCU_UP = -1;                   /* OCUUP_PF_Container */
static int hf_e2ap_cellResourceReportList = -1;   /* SEQUENCE_SIZE_1_maxCellingNBDU_OF_CellResourceReportListItem */
static int hf_e2ap_cellResourceReportList_item = -1;  /* CellResourceReportListItem */
static int hf_e2ap_dl_TotalofAvailablePRBs = -1;  /* INTEGER_0_273 */
static int hf_e2ap_ul_TotalofAvailablePRBs = -1;  /* INTEGER_0_273 */
static int hf_e2ap_servedPlmnPerCellList = -1;    /* SEQUENCE_SIZE_1_maxPLMN_OF_ServedPlmnPerCellListItem */
static int hf_e2ap_servedPlmnPerCellList_item = -1;  /* ServedPlmnPerCellListItem */
static int hf_e2ap_du_PM_5GC = -1;                /* FGC_DU_PM_Container */
static int hf_e2ap_du_PM_EPC = -1;                /* EPC_DU_PM_Container */
static int hf_e2ap_slicePerPlmnPerCellList = -1;  /* SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SlicePerPlmnPerCellListItem */
static int hf_e2ap_slicePerPlmnPerCellList_item = -1;  /* SlicePerPlmnPerCellListItem */
static int hf_e2ap_fQIPERSlicesPerPlmnPerCellList = -1;  /* SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnPerCellListItem */
static int hf_e2ap_fQIPERSlicesPerPlmnPerCellList_item = -1;  /* FQIPERSlicesPerPlmnPerCellListItem */
static int hf_e2ap_dl_PRBUsage = -1;              /* INTEGER_0_273 */
static int hf_e2ap_ul_PRBUsage = -1;              /* INTEGER_0_273 */
static int hf_e2ap_perQCIReportList = -1;         /* SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItem */
static int hf_e2ap_perQCIReportList_item = -1;    /* PerQCIReportListItem */
static int hf_e2ap_dl_PRBUsage_01 = -1;           /* INTEGER_0_100 */
static int hf_e2ap_ul_PRBUsage_01 = -1;           /* INTEGER_0_100 */
static int hf_e2ap_gNB_CU_CP_Name = -1;           /* GNB_CU_CP_Name */
static int hf_e2ap_cu_CP_Resource_Status = -1;    /* T_cu_CP_Resource_Status */
static int hf_e2ap_numberOfActive_UEs = -1;       /* INTEGER_1_65536_ */
static int hf_e2ap_gNB_CU_UP_Name = -1;           /* GNB_CU_UP_Name */
static int hf_e2ap_pf_ContainerList = -1;         /* SEQUENCE_SIZE_1_maxnoofContainerListItems_OF_PF_ContainerListItem */
static int hf_e2ap_pf_ContainerList_item = -1;    /* PF_ContainerListItem */
static int hf_e2ap_interface_type = -1;           /* NI_Type */
static int hf_e2ap_o_CU_UP_PM_Container = -1;     /* CUUPMeasurement_Container */
static int hf_e2ap_plmnList = -1;                 /* SEQUENCE_SIZE_1_maxPLMN_OF_PlmnID_List */
static int hf_e2ap_plmnList_item = -1;            /* PlmnID_List */
static int hf_e2ap_cu_UP_PM_5GC = -1;             /* FGC_CUUP_PM_Format */
static int hf_e2ap_cu_UP_PM_EPC = -1;             /* EPC_CUUP_PM_Format */
static int hf_e2ap_sliceToReportList = -1;        /* SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SliceToReportListItem */
static int hf_e2ap_sliceToReportList_item = -1;   /* SliceToReportListItem */
static int hf_e2ap_fQIPERSlicesPerPlmnList = -1;  /* SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnListItem */
static int hf_e2ap_fQIPERSlicesPerPlmnList_item = -1;  /* FQIPERSlicesPerPlmnListItem */
static int hf_e2ap_pDCPBytesDL = -1;              /* INTEGER_0_10000000000_ */
static int hf_e2ap_pDCPBytesUL = -1;              /* INTEGER_0_10000000000_ */
static int hf_e2ap_perQCIReportList_01 = -1;      /* SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItemFormat */
static int hf_e2ap_perQCIReportList_item_01 = -1;  /* PerQCIReportListItemFormat */

/*--- End of included file: packet-e2ap-hf.c ---*/
#line 47 "./asn1/e2ap/packet-e2ap-template.c"

/* Initialize the subtree pointers */
static gint ett_e2ap = -1;


/*--- Included file: packet-e2ap-ett.c ---*/
#line 1 "./asn1/e2ap/packet-e2ap-ett.c"
static gint ett_e2ap_ProtocolIE_Container = -1;
static gint ett_e2ap_ProtocolIE_Field = -1;
static gint ett_e2ap_Cause = -1;
static gint ett_e2ap_CriticalityDiagnostics = -1;
static gint ett_e2ap_CriticalityDiagnostics_IE_List = -1;
static gint ett_e2ap_CriticalityDiagnostics_IE_Item = -1;
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
static gint ett_e2ap_GlobalRIC_ID = -1;
static gint ett_e2ap_GNB_ID_Choice = -1;
static gint ett_e2ap_RICrequestID = -1;
static gint ett_e2ap_RICsubsequentAction = -1;
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
static gint ett_e2ap_RICindication = -1;
static gint ett_e2ap_RICcontrolRequest = -1;
static gint ett_e2ap_RICcontrolAcknowledge = -1;
static gint ett_e2ap_RICcontrolFailure = -1;
static gint ett_e2ap_ErrorIndication = -1;
static gint ett_e2ap_E2setupRequest = -1;
static gint ett_e2ap_E2setupResponse = -1;
static gint ett_e2ap_E2setupFailure = -1;
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
static gint ett_e2ap_E2AP_PDU = -1;
static gint ett_e2ap_InitiatingMessage = -1;
static gint ett_e2ap_SuccessfulOutcome = -1;
static gint ett_e2ap_UnsuccessfulOutcome = -1;
static gint ett_e2ap_GlobalKPMnode_ID = -1;
static gint ett_e2ap_GlobalKPMnode_gNB_ID = -1;
static gint ett_e2ap_GlobalKPMnode_en_gNB_ID = -1;
static gint ett_e2ap_GlobalKPMnode_ng_eNB_ID = -1;
static gint ett_e2ap_GlobalKPMnode_eNB_ID = -1;
static gint ett_e2ap_NRCGI = -1;
static gint ett_e2ap_SNSSAI = -1;
static gint ett_e2ap_E2SM_KPM_EventTriggerDefinition = -1;
static gint ett_e2ap_E2SM_KPM_EventTriggerDefinition_Format1 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxofMessageProtocolTests_OF_Trigger_ConditionIE_Item = -1;
static gint ett_e2ap_E2SM_KPM_ActionDefinition = -1;
static gint ett_e2ap_E2SM_KPM_IndicationHeader = -1;
static gint ett_e2ap_E2SM_KPM_IndicationHeader_Format1 = -1;
static gint ett_e2ap_E2SM_KPM_IndicationMessage_Format1 = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxCellingNBDU_OF_PM_Containers_List = -1;
static gint ett_e2ap_PM_Containers_List = -1;
static gint ett_e2ap_E2SM_KPM_RANfunction_Description = -1;
static gint ett_e2ap_T_e2SM_KPM_RANfunction_Item = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List = -1;
static gint ett_e2ap_Trigger_ConditionIE_Item = -1;
static gint ett_e2ap_RANfunction_Name = -1;
static gint ett_e2ap_RIC_EventTriggerStyle_List = -1;
static gint ett_e2ap_RIC_ReportStyle_List = -1;
static gint ett_e2ap_PF_Container = -1;
static gint ett_e2ap_ODU_PF_Container = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxCellingNBDU_OF_CellResourceReportListItem = -1;
static gint ett_e2ap_CellResourceReportListItem = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxPLMN_OF_ServedPlmnPerCellListItem = -1;
static gint ett_e2ap_ServedPlmnPerCellListItem = -1;
static gint ett_e2ap_FGC_DU_PM_Container = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SlicePerPlmnPerCellListItem = -1;
static gint ett_e2ap_SlicePerPlmnPerCellListItem = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnPerCellListItem = -1;
static gint ett_e2ap_FQIPERSlicesPerPlmnPerCellListItem = -1;
static gint ett_e2ap_EPC_DU_PM_Container = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItem = -1;
static gint ett_e2ap_PerQCIReportListItem = -1;
static gint ett_e2ap_OCUCP_PF_Container = -1;
static gint ett_e2ap_T_cu_CP_Resource_Status = -1;
static gint ett_e2ap_OCUUP_PF_Container = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofContainerListItems_OF_PF_ContainerListItem = -1;
static gint ett_e2ap_PF_ContainerListItem = -1;
static gint ett_e2ap_CUUPMeasurement_Container = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxPLMN_OF_PlmnID_List = -1;
static gint ett_e2ap_PlmnID_List = -1;
static gint ett_e2ap_FGC_CUUP_PM_Format = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SliceToReportListItem = -1;
static gint ett_e2ap_SliceToReportListItem = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnListItem = -1;
static gint ett_e2ap_FQIPERSlicesPerPlmnListItem = -1;
static gint ett_e2ap_EPC_CUUP_PM_Format = -1;
static gint ett_e2ap_SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItemFormat = -1;
static gint ett_e2ap_PerQCIReportListItemFormat = -1;

/*--- End of included file: packet-e2ap-ett.c ---*/
#line 52 "./asn1/e2ap/packet-e2ap-template.c"


enum{
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
};

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

/* Forward declarations */
static int dissect_E2SM_KPM_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_RANfunction_Description_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_EventTriggerDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_RANcallProcess_ID_string_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_IndicationMessage_Format1_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);


static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

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


/*--- Included file: packet-e2ap-fn.c ---*/
#line 1 "./asn1/e2ap/packet-e2ap-fn.c"

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
  { 0, NULL }
};

static value_string_ext e2ap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(e2ap_ProcedureCode_vals);


static int
dissect_e2ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 102 "./asn1/e2ap/e2ap.cnf"
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
  { 0, NULL }
};

static value_string_ext e2ap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(e2ap_ProtocolIE_ID_vals);


static int
dissect_e2ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 75 "./asn1/e2ap/e2ap.cnf"
  struct e2ap_private_data *e2ap_data = e2ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &e2ap_data->protocol_ie_id, FALSE);




#line 79 "./asn1/e2ap/e2ap.cnf"
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


static const value_string e2ap_CauseRIC_vals[] = {
  {   0, "ran-function-id-Invalid" },
  {   1, "action-not-supported" },
  {   2, "excessive-actions" },
  {   3, "duplicate-action" },
  {   4, "duplicate-event" },
  {   5, "function-resource-limit" },
  {   6, "request-id-unknown" },
  {   7, "inconsistent-action-subsequent-action-sequence" },
  {   8, "control-message-invalid" },
  {   9, "call-process-id-invalid" },
  {  10, "unspecified" },
  { 0, NULL }
};


static int
dissect_e2ap_CauseRIC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     11, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string e2ap_CauseRICservice_vals[] = {
  {   0, "function-not-required" },
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
  {   2, "transport" },
  {   3, "protocol" },
  {   4, "misc" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_e2ap_ricRequest     , ASN1_EXTENSION_ROOT    , dissect_e2ap_CauseRIC },
  {   1, &hf_e2ap_ricService     , ASN1_EXTENSION_ROOT    , dissect_e2ap_CauseRICservice },
  {   2, &hf_e2ap_transport      , ASN1_EXTENSION_ROOT    , dissect_e2ap_CauseTransport },
  {   3, &hf_e2ap_protocol       , ASN1_EXTENSION_ROOT    , dissect_e2ap_CauseProtocol },
  {   4, &hf_e2ap_misc           , ASN1_EXTENSION_ROOT    , dissect_e2ap_CauseMisc },
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
dissect_e2ap_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_e2ap_BIT_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL, 0, NULL, NULL);

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



static int
dissect_e2ap_BIT_STRING_SIZE_22_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     22, 32, FALSE, NULL, 0, NULL, NULL);

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



static int
dissect_e2ap_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

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


static const per_sequence_t GlobalgNB_ID_sequence[] = {
  { &hf_e2ap_plmn_id        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMN_Identity },
  { &hf_e2ap_gnb_id         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GNB_ID_Choice },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalgNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalgNB_ID, GlobalgNB_ID_sequence);

  return offset;
}



static int
dissect_e2ap_GNB_CU_UP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(68719476735), NULL, FALSE);

  return offset;
}



static int
dissect_e2ap_GNB_DU_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(68719476735), NULL, FALSE);

  return offset;
}


static const per_sequence_t GlobalE2node_gNB_ID_sequence[] = {
  { &hf_e2ap_global_gNB_ID_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalgNB_ID },
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


static const per_sequence_t GlobalE2node_en_gNB_ID_sequence[] = {
  { &hf_e2ap_global_gNB_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalenGNB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalE2node_en_gNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalE2node_en_gNB_ID, GlobalE2node_en_gNB_ID_sequence);

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


static const per_sequence_t GlobalE2node_ng_eNB_ID_sequence[] = {
  { &hf_e2ap_global_ng_eNB_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalngeNB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalE2node_ng_eNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalE2node_ng_eNB_ID, GlobalE2node_ng_eNB_ID_sequence);

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
#line 242 "./asn1/e2ap/e2ap.cnf"
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  dissect_E2SM_KPM_RANfunction_Description_PDU(parameter_tvb, actx->pinfo, tree, NULL);



  return offset;
}



static int
dissect_e2ap_RANfunctionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

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
#line 221 "./asn1/e2ap/e2ap.cnf"
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  dissect_E2SM_KPM_ActionDefinition_PDU(parameter_tvb, actx->pinfo, tree, NULL);



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
#line 247 "./asn1/e2ap/e2ap.cnf"
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  dissect_RANcallProcess_ID_string_PDU(parameter_tvb, actx->pinfo, tree, NULL);





  return offset;
}


static const value_string e2ap_RICcontrolAckRequest_vals[] = {
  {   0, "noAck" },
  {   1, "ack" },
  {   2, "nAck" },
  { 0, NULL }
};


static int
dissect_e2ap_RICcontrolAckRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e2ap_RICcontrolHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_e2ap_RICcontrolMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_e2ap_RICcontrolOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const value_string e2ap_RICcontrolStatus_vals[] = {
  {   0, "success" },
  {   1, "rejected" },
  {   2, "failed" },
  { 0, NULL }
};


static int
dissect_e2ap_RICcontrolStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e2ap_RICeventTriggerDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 226 "./asn1/e2ap/e2ap.cnf"
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  dissect_E2SM_KPM_EventTriggerDefinition_PDU(parameter_tvb, actx->pinfo, tree, NULL);



  return offset;
}



static int
dissect_e2ap_RICindicationHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 231 "./asn1/e2ap/e2ap.cnf"
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  dissect_E2SM_KPM_IndicationHeader_PDU(parameter_tvb, actx->pinfo, tree, NULL);



  return offset;
}



static int
dissect_e2ap_RICindicationMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 236 "./asn1/e2ap/e2ap.cnf"
  tvbuff_t *parameter_tvb;
    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  /* It is believed that this is an error in the ASN in V1 of the spec... */
  dissect_E2SM_KPM_IndicationMessage_Format1_PDU(parameter_tvb, actx->pinfo, tree, NULL);



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
  {   0, "zero" },
  {   1, "w1ms" },
  {   2, "w2ms" },
  {   3, "w5ms" },
  {   4, "w10ms" },
  {   5, "w20ms" },
  {   6, "w30ms" },
  {   7, "w40ms" },
  {   8, "w50ms" },
  {   9, "w100ms" },
  {  10, "w200ms" },
  {  11, "w500ms" },
  {  12, "w1s" },
  {  13, "w2s" },
  {  14, "w5s" },
  {  15, "w10s" },
  {  16, "w20s" },
  {  17, "w60s" },
  { 0, NULL }
};


static int
dissect_e2ap_RICtimeToWait(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     18, NULL, TRUE, 0, NULL);

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


static const per_sequence_t RICsubscriptionRequest_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICsubscriptionRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 500 "./asn1/e2ap/e2ap.cnf"
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
#line 503 "./asn1/e2ap/e2ap.cnf"
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
#line 497 "./asn1/e2ap/e2ap.cnf"
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
#line 511 "./asn1/e2ap/e2ap.cnf"
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
#line 514 "./asn1/e2ap/e2ap.cnf"
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
#line 508 "./asn1/e2ap/e2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICsubscriptionDeleteFailure");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICsubscriptionDeleteFailure, RICsubscriptionDeleteFailure_sequence);

  return offset;
}


static const per_sequence_t RICindication_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_RICindication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 478 "./asn1/e2ap/e2ap.cnf"
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
#line 475 "./asn1/e2ap/e2ap.cnf"
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
#line 467 "./asn1/e2ap/e2ap.cnf"
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
#line 472 "./asn1/e2ap/e2ap.cnf"
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
#line 458 "./asn1/e2ap/e2ap.cnf"
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
#line 452 "./asn1/e2ap/e2ap.cnf"
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
#line 455 "./asn1/e2ap/e2ap.cnf"
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
#line 449 "./asn1/e2ap/e2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E2setupFailure");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2setupFailure, E2setupFailure_sequence);

  return offset;
}


static const per_sequence_t ResetRequest_sequence[] = {
  { &hf_e2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_ResetRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 461 "./asn1/e2ap/e2ap.cnf"
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
#line 464 "./asn1/e2ap/e2ap.cnf"
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
#line 485 "./asn1/e2ap/e2ap.cnf"
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
                                                  0, maxofRANfunctionID, FALSE);

  return offset;
}


static const per_sequence_t RANfunction_Item_sequence[] = {
  { &hf_e2ap_ranFunctionID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunctionID },
  { &hf_e2ap_ranFunctionDefinition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunctionDefinition },
  { &hf_e2ap_ranFunctionRevision, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunctionRevision },
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
                                                  0, maxofRANfunctionID, FALSE);

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
#line 489 "./asn1/e2ap/e2ap.cnf"
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
                                                  0, maxofRANfunctionID, FALSE);

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
#line 492 "./asn1/e2ap/e2ap.cnf"
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
#line 482 "./asn1/e2ap/e2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RICserviceQuery");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_RICserviceQuery, RICserviceQuery_sequence);

  return offset;
}



static int
dissect_e2ap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 111 "./asn1/e2ap/e2ap.cnf"
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
#line 115 "./asn1/e2ap/e2ap.cnf"
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
#line 119 "./asn1/e2ap/e2ap.cnf"
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


static const per_sequence_t GlobalKPMnode_gNB_ID_sequence[] = {
  { &hf_e2ap_global_gNB_ID_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalgNB_ID },
  { &hf_e2ap_gNB_CU_UP_ID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GNB_CU_UP_ID },
  { &hf_e2ap_gNB_DU_ID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GNB_DU_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalKPMnode_gNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalKPMnode_gNB_ID, GlobalKPMnode_gNB_ID_sequence);

  return offset;
}


static const per_sequence_t GlobalKPMnode_en_gNB_ID_sequence[] = {
  { &hf_e2ap_global_gNB_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalenGNB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalKPMnode_en_gNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalKPMnode_en_gNB_ID, GlobalKPMnode_en_gNB_ID_sequence);

  return offset;
}


static const per_sequence_t GlobalKPMnode_ng_eNB_ID_sequence[] = {
  { &hf_e2ap_global_ng_eNB_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalngeNB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalKPMnode_ng_eNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalKPMnode_ng_eNB_ID, GlobalKPMnode_ng_eNB_ID_sequence);

  return offset;
}


static const per_sequence_t GlobalKPMnode_eNB_ID_sequence[] = {
  { &hf_e2ap_global_eNB_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_GlobalENB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_GlobalKPMnode_eNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_GlobalKPMnode_eNB_ID, GlobalKPMnode_eNB_ID_sequence);

  return offset;
}


static const value_string e2ap_GlobalKPMnode_ID_vals[] = {
  {   0, "gNB" },
  {   1, "en-gNB" },
  {   2, "ng-eNB" },
  {   3, "eNB" },
  { 0, NULL }
};

static const per_choice_t GlobalKPMnode_ID_choice[] = {
  {   0, &hf_e2ap_gNB_01         , ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalKPMnode_gNB_ID },
  {   1, &hf_e2ap_en_gNB_01      , ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalKPMnode_en_gNB_ID },
  {   2, &hf_e2ap_ng_eNB_01      , ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalKPMnode_ng_eNB_ID },
  {   3, &hf_e2ap_eNB_01         , ASN1_EXTENSION_ROOT    , dissect_e2ap_GlobalKPMnode_eNB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_GlobalKPMnode_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_GlobalKPMnode_ID, GlobalKPMnode_ID_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_NRCellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NRCGI_sequence[] = {
  { &hf_e2ap_pLMN_Identity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMN_Identity },
  { &hf_e2ap_nRCellIdentity , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_NRCellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_NRCGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_NRCGI, NRCGI_sequence);

  return offset;
}



static int
dissect_e2ap_OCTET_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}



static int
dissect_e2ap_OCTET_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}


static const per_sequence_t SNSSAI_sequence[] = {
  { &hf_e2ap_sST            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_OCTET_STRING_SIZE_1 },
  { &hf_e2ap_sD             , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e2ap_OCTET_STRING_SIZE_3 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_SNSSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_SNSSAI, SNSSAI_sequence);

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



static int
dissect_e2ap_RIC_Format_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string e2ap_RT_Period_IE_vals[] = {
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


static int
dissect_e2ap_RT_Period_IE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     20, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t Trigger_ConditionIE_Item_sequence[] = {
  { &hf_e2ap_report_Period_IE, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RT_Period_IE },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_Trigger_ConditionIE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_Trigger_ConditionIE_Item, Trigger_ConditionIE_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxofMessageProtocolTests_OF_Trigger_ConditionIE_Item_sequence_of[1] = {
  { &hf_e2ap_policyTest_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_Trigger_ConditionIE_Item },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofMessageProtocolTests_OF_Trigger_ConditionIE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofMessageProtocolTests_OF_Trigger_ConditionIE_Item, SEQUENCE_SIZE_1_maxofMessageProtocolTests_OF_Trigger_ConditionIE_Item_sequence_of,
                                                  1, maxofMessageProtocolTests, FALSE);

  return offset;
}


static const per_sequence_t E2SM_KPM_EventTriggerDefinition_Format1_sequence[] = {
  { &hf_e2ap_policyTest_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofMessageProtocolTests_OF_Trigger_ConditionIE_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_EventTriggerDefinition_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_EventTriggerDefinition_Format1, E2SM_KPM_EventTriggerDefinition_Format1_sequence);

  return offset;
}


static const value_string e2ap_E2SM_KPM_EventTriggerDefinition_vals[] = {
  {   0, "eventDefinition-Format1" },
  { 0, NULL }
};

static const per_choice_t E2SM_KPM_EventTriggerDefinition_choice[] = {
  {   0, &hf_e2ap_eventDefinition_Format1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_KPM_EventTriggerDefinition_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_EventTriggerDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_E2SM_KPM_EventTriggerDefinition, E2SM_KPM_EventTriggerDefinition_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_KPM_ActionDefinition_sequence[] = {
  { &hf_e2ap_ric_Style_Type , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_ActionDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_ActionDefinition, E2SM_KPM_ActionDefinition_sequence);

  return offset;
}



static int
dissect_e2ap_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationHeader_Format1_sequence[] = {
  { &hf_e2ap_id_GlobalKPMnode_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GlobalKPMnode_ID },
  { &hf_e2ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_NRCGI },
  { &hf_e2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_PLMN_Identity },
  { &hf_e2ap_sliceID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SNSSAI },
  { &hf_e2ap_fiveQI         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_0_255 },
  { &hf_e2ap_qci            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_IndicationHeader_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_IndicationHeader_Format1, E2SM_KPM_IndicationHeader_Format1_sequence);

  return offset;
}


static const value_string e2ap_E2SM_KPM_IndicationHeader_vals[] = {
  {   0, "indicationHeader-Format1" },
  { 0, NULL }
};

static const per_choice_t E2SM_KPM_IndicationHeader_choice[] = {
  {   0, &hf_e2ap_indicationHeader_Format1, ASN1_EXTENSION_ROOT    , dissect_e2ap_E2SM_KPM_IndicationHeader_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_IndicationHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_E2SM_KPM_IndicationHeader, E2SM_KPM_IndicationHeader_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_INTEGER_0_273(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 273U, NULL, FALSE);

  return offset;
}


static const per_sequence_t FQIPERSlicesPerPlmnPerCellListItem_sequence[] = {
  { &hf_e2ap_fiveQI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_0_255 },
  { &hf_e2ap_dl_PRBUsage    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_0_273 },
  { &hf_e2ap_ul_PRBUsage    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_0_273 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_FQIPERSlicesPerPlmnPerCellListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_FQIPERSlicesPerPlmnPerCellListItem, FQIPERSlicesPerPlmnPerCellListItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnPerCellListItem_sequence_of[1] = {
  { &hf_e2ap_fQIPERSlicesPerPlmnPerCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_FQIPERSlicesPerPlmnPerCellListItem },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnPerCellListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnPerCellListItem, SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnPerCellListItem_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t SlicePerPlmnPerCellListItem_sequence[] = {
  { &hf_e2ap_sliceID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SNSSAI },
  { &hf_e2ap_fQIPERSlicesPerPlmnPerCellList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnPerCellListItem },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_SlicePerPlmnPerCellListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_SlicePerPlmnPerCellListItem, SlicePerPlmnPerCellListItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SlicePerPlmnPerCellListItem_sequence_of[1] = {
  { &hf_e2ap_slicePerPlmnPerCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_SlicePerPlmnPerCellListItem },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SlicePerPlmnPerCellListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SlicePerPlmnPerCellListItem, SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SlicePerPlmnPerCellListItem_sequence_of,
                                                  1, maxnoofSliceItems, FALSE);

  return offset;
}


static const per_sequence_t FGC_DU_PM_Container_sequence[] = {
  { &hf_e2ap_slicePerPlmnPerCellList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SlicePerPlmnPerCellListItem },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_FGC_DU_PM_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_FGC_DU_PM_Container, FGC_DU_PM_Container_sequence);

  return offset;
}



static int
dissect_e2ap_INTEGER_0_100(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PerQCIReportListItem_sequence[] = {
  { &hf_e2ap_qci            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_0_255 },
  { &hf_e2ap_dl_PRBUsage_01 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_0_100 },
  { &hf_e2ap_ul_PRBUsage_01 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_0_100 },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_PerQCIReportListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_PerQCIReportListItem, PerQCIReportListItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItem_sequence_of[1] = {
  { &hf_e2ap_perQCIReportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_PerQCIReportListItem },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItem, SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItem_sequence_of,
                                                  1, maxnoofQCI, FALSE);

  return offset;
}


static const per_sequence_t EPC_DU_PM_Container_sequence[] = {
  { &hf_e2ap_perQCIReportList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItem },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_EPC_DU_PM_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_EPC_DU_PM_Container, EPC_DU_PM_Container_sequence);

  return offset;
}


static const per_sequence_t ServedPlmnPerCellListItem_sequence[] = {
  { &hf_e2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMN_Identity },
  { &hf_e2ap_du_PM_5GC      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_FGC_DU_PM_Container },
  { &hf_e2ap_du_PM_EPC      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_EPC_DU_PM_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_ServedPlmnPerCellListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_ServedPlmnPerCellListItem, ServedPlmnPerCellListItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxPLMN_OF_ServedPlmnPerCellListItem_sequence_of[1] = {
  { &hf_e2ap_servedPlmnPerCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_ServedPlmnPerCellListItem },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxPLMN_OF_ServedPlmnPerCellListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxPLMN_OF_ServedPlmnPerCellListItem, SEQUENCE_SIZE_1_maxPLMN_OF_ServedPlmnPerCellListItem_sequence_of,
                                                  1, maxPLMN, FALSE);

  return offset;
}


static const per_sequence_t CellResourceReportListItem_sequence[] = {
  { &hf_e2ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NRCGI },
  { &hf_e2ap_dl_TotalofAvailablePRBs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_0_273 },
  { &hf_e2ap_ul_TotalofAvailablePRBs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_0_273 },
  { &hf_e2ap_servedPlmnPerCellList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxPLMN_OF_ServedPlmnPerCellListItem },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_CellResourceReportListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_CellResourceReportListItem, CellResourceReportListItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxCellingNBDU_OF_CellResourceReportListItem_sequence_of[1] = {
  { &hf_e2ap_cellResourceReportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_CellResourceReportListItem },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxCellingNBDU_OF_CellResourceReportListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxCellingNBDU_OF_CellResourceReportListItem, SEQUENCE_SIZE_1_maxCellingNBDU_OF_CellResourceReportListItem_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t ODU_PF_Container_sequence[] = {
  { &hf_e2ap_cellResourceReportList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxCellingNBDU_OF_CellResourceReportListItem },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_ODU_PF_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_ODU_PF_Container, ODU_PF_Container_sequence);

  return offset;
}



static int
dissect_e2ap_GNB_CU_CP_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}



static int
dissect_e2ap_INTEGER_1_65536_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65536U, NULL, TRUE);

  return offset;
}


static const per_sequence_t T_cu_CP_Resource_Status_sequence[] = {
  { &hf_e2ap_numberOfActive_UEs, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_1_65536_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_T_cu_CP_Resource_Status(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_T_cu_CP_Resource_Status, T_cu_CP_Resource_Status_sequence);

  return offset;
}


static const per_sequence_t OCUCP_PF_Container_sequence[] = {
  { &hf_e2ap_gNB_CU_CP_Name , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_e2ap_GNB_CU_CP_Name },
  { &hf_e2ap_cu_CP_Resource_Status, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_T_cu_CP_Resource_Status },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_OCUCP_PF_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_OCUCP_PF_Container, OCUCP_PF_Container_sequence);

  return offset;
}



static int
dissect_e2ap_GNB_CU_UP_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}


static const value_string e2ap_NI_Type_vals[] = {
  {   0, "x2-u" },
  {   1, "xn-u" },
  {   2, "f1-u" },
  { 0, NULL }
};


static int
dissect_e2ap_NI_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_e2ap_INTEGER_0_10000000000_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(10000000000), NULL, TRUE);

  return offset;
}


static const per_sequence_t FQIPERSlicesPerPlmnListItem_sequence[] = {
  { &hf_e2ap_fiveQI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_0_255 },
  { &hf_e2ap_pDCPBytesDL    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_0_10000000000_ },
  { &hf_e2ap_pDCPBytesUL    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_0_10000000000_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_FQIPERSlicesPerPlmnListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_FQIPERSlicesPerPlmnListItem, FQIPERSlicesPerPlmnListItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnListItem_sequence_of[1] = {
  { &hf_e2ap_fQIPERSlicesPerPlmnList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_FQIPERSlicesPerPlmnListItem },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnListItem, SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnListItem_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t SliceToReportListItem_sequence[] = {
  { &hf_e2ap_sliceID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SNSSAI },
  { &hf_e2ap_fQIPERSlicesPerPlmnList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnListItem },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_SliceToReportListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_SliceToReportListItem, SliceToReportListItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SliceToReportListItem_sequence_of[1] = {
  { &hf_e2ap_sliceToReportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_SliceToReportListItem },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SliceToReportListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SliceToReportListItem, SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SliceToReportListItem_sequence_of,
                                                  1, maxnoofSliceItems, FALSE);

  return offset;
}


static const per_sequence_t FGC_CUUP_PM_Format_sequence[] = {
  { &hf_e2ap_sliceToReportList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SliceToReportListItem },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_FGC_CUUP_PM_Format(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_FGC_CUUP_PM_Format, FGC_CUUP_PM_Format_sequence);

  return offset;
}


static const per_sequence_t PerQCIReportListItemFormat_sequence[] = {
  { &hf_e2ap_qci            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_INTEGER_0_255 },
  { &hf_e2ap_pDCPBytesDL    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_0_10000000000_ },
  { &hf_e2ap_pDCPBytesUL    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_INTEGER_0_10000000000_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_PerQCIReportListItemFormat(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_PerQCIReportListItemFormat, PerQCIReportListItemFormat_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItemFormat_sequence_of[1] = {
  { &hf_e2ap_perQCIReportList_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_PerQCIReportListItemFormat },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItemFormat(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItemFormat, SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItemFormat_sequence_of,
                                                  1, maxnoofQCI, FALSE);

  return offset;
}


static const per_sequence_t EPC_CUUP_PM_Format_sequence[] = {
  { &hf_e2ap_perQCIReportList_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItemFormat },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_EPC_CUUP_PM_Format(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_EPC_CUUP_PM_Format, EPC_CUUP_PM_Format_sequence);

  return offset;
}


static const per_sequence_t PlmnID_List_sequence[] = {
  { &hf_e2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PLMN_Identity },
  { &hf_e2ap_cu_UP_PM_5GC   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_FGC_CUUP_PM_Format },
  { &hf_e2ap_cu_UP_PM_EPC   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_EPC_CUUP_PM_Format },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_PlmnID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_PlmnID_List, PlmnID_List_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxPLMN_OF_PlmnID_List_sequence_of[1] = {
  { &hf_e2ap_plmnList_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_PlmnID_List },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxPLMN_OF_PlmnID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxPLMN_OF_PlmnID_List, SEQUENCE_SIZE_1_maxPLMN_OF_PlmnID_List_sequence_of,
                                                  1, maxPLMN, FALSE);

  return offset;
}


static const per_sequence_t CUUPMeasurement_Container_sequence[] = {
  { &hf_e2ap_plmnList       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxPLMN_OF_PlmnID_List },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_CUUPMeasurement_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_CUUPMeasurement_Container, CUUPMeasurement_Container_sequence);

  return offset;
}


static const per_sequence_t PF_ContainerListItem_sequence[] = {
  { &hf_e2ap_interface_type , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_NI_Type },
  { &hf_e2ap_o_CU_UP_PM_Container, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_CUUPMeasurement_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_PF_ContainerListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_PF_ContainerListItem, PF_ContainerListItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofContainerListItems_OF_PF_ContainerListItem_sequence_of[1] = {
  { &hf_e2ap_pf_ContainerList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_PF_ContainerListItem },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxnoofContainerListItems_OF_PF_ContainerListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxnoofContainerListItems_OF_PF_ContainerListItem, SEQUENCE_SIZE_1_maxnoofContainerListItems_OF_PF_ContainerListItem_sequence_of,
                                                  1, maxnoofContainerListItems, FALSE);

  return offset;
}


static const per_sequence_t OCUUP_PF_Container_sequence[] = {
  { &hf_e2ap_gNB_CU_UP_Name , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_GNB_CU_UP_Name },
  { &hf_e2ap_pf_ContainerList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxnoofContainerListItems_OF_PF_ContainerListItem },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_OCUUP_PF_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_OCUUP_PF_Container, OCUUP_PF_Container_sequence);

  return offset;
}


static const value_string e2ap_PF_Container_vals[] = {
  {   0, "oDU" },
  {   1, "oCU-CP" },
  {   2, "oCU-UP" },
  { 0, NULL }
};

static const per_choice_t PF_Container_choice[] = {
  {   0, &hf_e2ap_oDU            , ASN1_NO_EXTENSIONS     , dissect_e2ap_ODU_PF_Container },
  {   1, &hf_e2ap_oCU_CP         , ASN1_NO_EXTENSIONS     , dissect_e2ap_OCUCP_PF_Container },
  {   2, &hf_e2ap_oCU_UP         , ASN1_NO_EXTENSIONS     , dissect_e2ap_OCUUP_PF_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_e2ap_PF_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_e2ap_PF_Container, PF_Container_choice,
                                 NULL);

  return offset;
}



static int
dissect_e2ap_RAN_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t PM_Containers_List_sequence[] = {
  { &hf_e2ap_performanceContainer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_PF_Container },
  { &hf_e2ap_theRANContainer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_RAN_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_PM_Containers_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_PM_Containers_List, PM_Containers_List_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxCellingNBDU_OF_PM_Containers_List_sequence_of[1] = {
  { &hf_e2ap_pm_Containers_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_PM_Containers_List },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxCellingNBDU_OF_PM_Containers_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxCellingNBDU_OF_PM_Containers_List, SEQUENCE_SIZE_1_maxCellingNBDU_OF_PM_Containers_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationMessage_Format1_sequence[] = {
  { &hf_e2ap_pm_Containers  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_SEQUENCE_SIZE_1_maxCellingNBDU_OF_PM_Containers_List },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_IndicationMessage_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_IndicationMessage_Format1, E2SM_KPM_IndicationMessage_Format1_sequence);

  return offset;
}



static int
dissect_e2ap_PrintableString_SIZE_1_150_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}



static int
dissect_e2ap_PrintableString_SIZE_1_1000_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 1000, TRUE);

  return offset;
}



static int
dissect_e2ap_INTEGER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t RANfunction_Name_sequence[] = {
  { &hf_e2ap_ranFunction_ShortName, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_PrintableString_SIZE_1_150_ },
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
  { &hf_e2ap_ric_EventTriggerStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_EventTriggerStyle_List },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List, SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List_sequence_of,
                                                  1, maxofRICstyles, FALSE);

  return offset;
}


static const per_sequence_t RIC_ReportStyle_List_sequence[] = {
  { &hf_e2ap_ric_ReportStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Type },
  { &hf_e2ap_ric_ReportStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_Style_Name },
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
  { &hf_e2ap_ric_ReportStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_e2ap_RIC_ReportStyle_List },
};

static int
dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List, SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List_sequence_of,
                                                  1, maxofRICstyles, FALSE);

  return offset;
}


static const per_sequence_t T_e2SM_KPM_RANfunction_Item_sequence[] = {
  { &hf_e2ap_ric_EventTriggerStyle_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List },
  { &hf_e2ap_ric_ReportStyle_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_T_e2SM_KPM_RANfunction_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_T_e2SM_KPM_RANfunction_Item, T_e2SM_KPM_RANfunction_Item_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_RANfunction_Description_sequence[] = {
  { &hf_e2ap_ranFunction_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_RANfunction_Name },
  { &hf_e2ap_e2SM_KPM_RANfunction_Item, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_e2ap_T_e2SM_KPM_RANfunction_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_e2ap_E2SM_KPM_RANfunction_Description(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_e2ap_E2SM_KPM_RANfunction_Description, E2SM_KPM_RANfunction_Description_sequence);

  return offset;
}



static int
dissect_e2ap_RANcallProcess_ID_string(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

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
static int dissect_RICcontrolStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RICcontrolStatus(tvb, offset, &asn1_ctx, tree, hf_e2ap_RICcontrolStatus_PDU);
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
static int dissect_E2AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2AP_PDU(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2AP_PDU_PDU);
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
static int dissect_E2SM_KPM_IndicationMessage_Format1_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_E2SM_KPM_IndicationMessage_Format1(tvb, offset, &asn1_ctx, tree, hf_e2ap_E2SM_KPM_IndicationMessage_Format1_PDU);
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
static int dissect_RANcallProcess_ID_string_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_e2ap_RANcallProcess_ID_string(tvb, offset, &asn1_ctx, tree, hf_e2ap_RANcallProcess_ID_string_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-e2ap-fn.c ---*/
#line 118 "./asn1/e2ap/packet-e2ap-template.c"

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


/*--- proto_reg_handoff_e2ap ---------------------------------------*/
void
proto_reg_handoff_e2ap(void)
{
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_E2AP, e2ap_handle);
#if 0
  /* TODO: should one or more of these be registered? */
  dissector_add_uint("sctp.ppi", E2_CP_PROTOCOL_ID,   e2ap_handle);
  dissector_add_uint("sctp.ppi", E2_UP_PROTOCOL_ID,   e2ap_handle);
  dissector_add_uint("sctp.ppi", E2_DU_PROTOCOL_ID,   e2ap_handle);
#endif


/*--- Included file: packet-e2ap-dis-tab.c ---*/
#line 1 "./asn1/e2ap/packet-e2ap-dis-tab.c"
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
  dissector_add_uint("e2ap.ies", id_RICcontrolStatus, create_dissector_handle(dissect_RICcontrolStatus_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICindicationHeader, create_dissector_handle(dissect_RICindicationHeader_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICindicationMessage, create_dissector_handle(dissect_RICindicationMessage_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICindicationSN, create_dissector_handle(dissect_RICindicationSN_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICindicationType, create_dissector_handle(dissect_RICindicationType_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICrequestID, create_dissector_handle(dissect_RICrequestID_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_RICsubscriptionDetails, create_dissector_handle(dissect_RICsubscriptionDetails_PDU, proto_e2ap));
  dissector_add_uint("e2ap.ies", id_TimeToWait, create_dissector_handle(dissect_TimeToWait_PDU, proto_e2ap));
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


/*--- End of included file: packet-e2ap-dis-tab.c ---*/
#line 202 "./asn1/e2ap/packet-e2ap-template.c"

}

/*--- proto_register_e2ap -------------------------------------------*/
void proto_register_e2ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {

/*--- Included file: packet-e2ap-hfarr.c ---*/
#line 1 "./asn1/e2ap/packet-e2ap-hfarr.c"
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
    { &hf_e2ap_RICcontrolStatus_PDU,
      { "RICcontrolStatus", "e2ap.RICcontrolStatus",
        FT_UINT32, BASE_DEC, VALS(e2ap_RICcontrolStatus_vals), 0,
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
    { &hf_e2ap_E2AP_PDU_PDU,
      { "E2AP-PDU", "e2ap.E2AP_PDU",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2AP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_KPM_EventTriggerDefinition_PDU,
      { "E2SM-KPM-EventTriggerDefinition", "e2ap.E2SM_KPM_EventTriggerDefinition",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2SM_KPM_EventTriggerDefinition_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_KPM_ActionDefinition_PDU,
      { "E2SM-KPM-ActionDefinition", "e2ap.E2SM_KPM_ActionDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_KPM_IndicationHeader_PDU,
      { "E2SM-KPM-IndicationHeader", "e2ap.E2SM_KPM_IndicationHeader",
        FT_UINT32, BASE_DEC, VALS(e2ap_E2SM_KPM_IndicationHeader_vals), 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_KPM_IndicationMessage_Format1_PDU,
      { "E2SM-KPM-IndicationMessage-Format1", "e2ap.E2SM_KPM_IndicationMessage_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_E2SM_KPM_RANfunction_Description_PDU,
      { "E2SM-KPM-RANfunction-Description", "e2ap.E2SM_KPM_RANfunction_Description_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_RANcallProcess_ID_string_PDU,
      { "RANcallProcess-ID-string", "e2ap.RANcallProcess_ID_string",
        FT_STRING, BASE_NONE, NULL, 0,
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
        FT_UINT32, BASE_DEC, VALS(e2ap_CauseRIC_vals), 0,
        "CauseRIC", HFILL }},
    { &hf_e2ap_ricService,
      { "ricService", "e2ap.ricService",
        FT_UINT32, BASE_DEC, VALS(e2ap_CauseRICservice_vals), 0,
        "CauseRICservice", HFILL }},
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
    { &hf_e2ap_global_gNB_ID,
      { "global-gNB-ID", "e2ap.global_gNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalenGNB_ID", HFILL }},
    { &hf_e2ap_global_eNB_ID,
      { "global-eNB-ID", "e2ap.global_eNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalENB_ID", HFILL }},
    { &hf_e2ap_global_gNB_ID_01,
      { "global-gNB-ID", "e2ap.global_gNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalgNB_ID", HFILL }},
    { &hf_e2ap_gNB_CU_UP_ID,
      { "gNB-CU-UP-ID", "e2ap.gNB_CU_UP_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_gNB_DU_ID,
      { "gNB-DU-ID", "e2ap.gNB_DU_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_global_ng_eNB_ID,
      { "global-ng-eNB-ID", "e2ap.global_ng_eNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalngeNB_ID", HFILL }},
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
        "GNB_ID_Choice", HFILL }},
    { &hf_e2ap_enb_id,
      { "enb-id", "e2ap.enb_id",
        FT_UINT32, BASE_DEC, VALS(e2ap_ENB_ID_Choice_vals), 0,
        "ENB_ID_Choice", HFILL }},
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
    { &hf_e2ap_RANfunctions_List_item,
      { "ProtocolIE-SingleContainer", "e2ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunctionID,
      { "ranFunctionID", "e2ap.ranFunctionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunctionDefinition,
      { "ranFunctionDefinition", "e2ap.ranFunctionDefinition",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ranFunctionRevision,
      { "ranFunctionRevision", "e2ap.ranFunctionRevision",
        FT_UINT32, BASE_DEC, NULL, 0,
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
    { &hf_e2ap_gNB_01,
      { "gNB", "e2ap.gNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalKPMnode_gNB_ID", HFILL }},
    { &hf_e2ap_en_gNB_01,
      { "en-gNB", "e2ap.en_gNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalKPMnode_en_gNB_ID", HFILL }},
    { &hf_e2ap_ng_eNB_01,
      { "ng-eNB", "e2ap.ng_eNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalKPMnode_ng_eNB_ID", HFILL }},
    { &hf_e2ap_eNB_01,
      { "eNB", "e2ap.eNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalKPMnode_eNB_ID", HFILL }},
    { &hf_e2ap_nRCellIdentity,
      { "nRCellIdentity", "e2ap.nRCellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_sST,
      { "sST", "e2ap.sST",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_e2ap_sD,
      { "sD", "e2ap.sD",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_e2ap_eventDefinition_Format1,
      { "eventDefinition-Format1", "e2ap.eventDefinition_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_EventTriggerDefinition_Format1", HFILL }},
    { &hf_e2ap_policyTest_List,
      { "policyTest-List", "e2ap.policyTest_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofMessageProtocolTests_OF_Trigger_ConditionIE_Item", HFILL }},
    { &hf_e2ap_policyTest_List_item,
      { "Trigger-ConditionIE-Item", "e2ap.Trigger_ConditionIE_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_Style_Type,
      { "ric-Style-Type", "e2ap.ric_Style_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_indicationHeader_Format1,
      { "indicationHeader-Format1", "e2ap.indicationHeader_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_IndicationHeader_Format1", HFILL }},
    { &hf_e2ap_id_GlobalKPMnode_ID,
      { "id-GlobalKPMnode-ID", "e2ap.id_GlobalKPMnode_ID",
        FT_UINT32, BASE_DEC, VALS(e2ap_GlobalKPMnode_ID_vals), 0,
        "GlobalKPMnode_ID", HFILL }},
    { &hf_e2ap_nRCGI,
      { "nRCGI", "e2ap.nRCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_sliceID,
      { "sliceID", "e2ap.sliceID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SNSSAI", HFILL }},
    { &hf_e2ap_fiveQI,
      { "fiveQI", "e2ap.fiveQI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_e2ap_qci,
      { "qci", "e2ap.qci",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_e2ap_pm_Containers,
      { "pm-Containers", "e2ap.pm_Containers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxCellingNBDU_OF_PM_Containers_List", HFILL }},
    { &hf_e2ap_pm_Containers_item,
      { "PM-Containers-List", "e2ap.PM_Containers_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_performanceContainer,
      { "performanceContainer", "e2ap.performanceContainer",
        FT_UINT32, BASE_DEC, VALS(e2ap_PF_Container_vals), 0,
        "PF_Container", HFILL }},
    { &hf_e2ap_theRANContainer,
      { "theRANContainer", "e2ap.theRANContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RAN_Container", HFILL }},
    { &hf_e2ap_ranFunction_Name,
      { "ranFunction-Name", "e2ap.ranFunction_Name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_e2SM_KPM_RANfunction_Item,
      { "e2SM-KPM-RANfunction-Item", "e2ap.e2SM_KPM_RANfunction_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_EventTriggerStyle_List,
      { "ric-EventTriggerStyle-List", "e2ap.ric_EventTriggerStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List", HFILL }},
    { &hf_e2ap_ric_EventTriggerStyle_List_item,
      { "RIC-EventTriggerStyle-List", "e2ap.RIC_EventTriggerStyle_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_ric_ReportStyle_List,
      { "ric-ReportStyle-List", "e2ap.ric_ReportStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List", HFILL }},
    { &hf_e2ap_ric_ReportStyle_List_item,
      { "RIC-ReportStyle-List", "e2ap.RIC_ReportStyle_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_report_Period_IE,
      { "report-Period-IE", "e2ap.report_Period_IE",
        FT_UINT32, BASE_DEC, VALS(e2ap_RT_Period_IE_vals), 0,
        "RT_Period_IE", HFILL }},
    { &hf_e2ap_ranFunction_ShortName,
      { "ranFunction-ShortName", "e2ap.ranFunction_ShortName",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_150_", HFILL }},
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
    { &hf_e2ap_ric_ReportStyle_Type,
      { "ric-ReportStyle-Type", "e2ap.ric_ReportStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_e2ap_ric_ReportStyle_Name,
      { "ric-ReportStyle-Name", "e2ap.ric_ReportStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_e2ap_ric_IndicationHeaderFormat_Type,
      { "ric-IndicationHeaderFormat-Type", "e2ap.ric_IndicationHeaderFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_ric_IndicationMessageFormat_Type,
      { "ric-IndicationMessageFormat-Type", "e2ap.ric_IndicationMessageFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_e2ap_oDU,
      { "oDU", "e2ap.oDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ODU_PF_Container", HFILL }},
    { &hf_e2ap_oCU_CP,
      { "oCU-CP", "e2ap.oCU_CP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OCUCP_PF_Container", HFILL }},
    { &hf_e2ap_oCU_UP,
      { "oCU-UP", "e2ap.oCU_UP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OCUUP_PF_Container", HFILL }},
    { &hf_e2ap_cellResourceReportList,
      { "cellResourceReportList", "e2ap.cellResourceReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxCellingNBDU_OF_CellResourceReportListItem", HFILL }},
    { &hf_e2ap_cellResourceReportList_item,
      { "CellResourceReportListItem", "e2ap.CellResourceReportListItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_dl_TotalofAvailablePRBs,
      { "dl-TotalofAvailablePRBs", "e2ap.dl_TotalofAvailablePRBs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_273", HFILL }},
    { &hf_e2ap_ul_TotalofAvailablePRBs,
      { "ul-TotalofAvailablePRBs", "e2ap.ul_TotalofAvailablePRBs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_273", HFILL }},
    { &hf_e2ap_servedPlmnPerCellList,
      { "servedPlmnPerCellList", "e2ap.servedPlmnPerCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxPLMN_OF_ServedPlmnPerCellListItem", HFILL }},
    { &hf_e2ap_servedPlmnPerCellList_item,
      { "ServedPlmnPerCellListItem", "e2ap.ServedPlmnPerCellListItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_du_PM_5GC,
      { "du-PM-5GC", "e2ap.du_PM_5GC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FGC_DU_PM_Container", HFILL }},
    { &hf_e2ap_du_PM_EPC,
      { "du-PM-EPC", "e2ap.du_PM_EPC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EPC_DU_PM_Container", HFILL }},
    { &hf_e2ap_slicePerPlmnPerCellList,
      { "slicePerPlmnPerCellList", "e2ap.slicePerPlmnPerCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SlicePerPlmnPerCellListItem", HFILL }},
    { &hf_e2ap_slicePerPlmnPerCellList_item,
      { "SlicePerPlmnPerCellListItem", "e2ap.SlicePerPlmnPerCellListItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_fQIPERSlicesPerPlmnPerCellList,
      { "fQIPERSlicesPerPlmnPerCellList", "e2ap.fQIPERSlicesPerPlmnPerCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnPerCellListItem", HFILL }},
    { &hf_e2ap_fQIPERSlicesPerPlmnPerCellList_item,
      { "FQIPERSlicesPerPlmnPerCellListItem", "e2ap.FQIPERSlicesPerPlmnPerCellListItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_dl_PRBUsage,
      { "dl-PRBUsage", "e2ap.dl_PRBUsage",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_273", HFILL }},
    { &hf_e2ap_ul_PRBUsage,
      { "ul-PRBUsage", "e2ap.ul_PRBUsage",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_273", HFILL }},
    { &hf_e2ap_perQCIReportList,
      { "perQCIReportList", "e2ap.perQCIReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItem", HFILL }},
    { &hf_e2ap_perQCIReportList_item,
      { "PerQCIReportListItem", "e2ap.PerQCIReportListItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_dl_PRBUsage_01,
      { "dl-PRBUsage", "e2ap.dl_PRBUsage",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_e2ap_ul_PRBUsage_01,
      { "ul-PRBUsage", "e2ap.ul_PRBUsage",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_e2ap_gNB_CU_CP_Name,
      { "gNB-CU-CP-Name", "e2ap.gNB_CU_CP_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_cu_CP_Resource_Status,
      { "cu-CP-Resource-Status", "e2ap.cu_CP_Resource_Status_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_numberOfActive_UEs,
      { "numberOfActive-UEs", "e2ap.numberOfActive_UEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65536_", HFILL }},
    { &hf_e2ap_gNB_CU_UP_Name,
      { "gNB-CU-UP-Name", "e2ap.gNB_CU_UP_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_pf_ContainerList,
      { "pf-ContainerList", "e2ap.pf_ContainerList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofContainerListItems_OF_PF_ContainerListItem", HFILL }},
    { &hf_e2ap_pf_ContainerList_item,
      { "PF-ContainerListItem", "e2ap.PF_ContainerListItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_interface_type,
      { "interface-type", "e2ap.interface_type",
        FT_UINT32, BASE_DEC, VALS(e2ap_NI_Type_vals), 0,
        "NI_Type", HFILL }},
    { &hf_e2ap_o_CU_UP_PM_Container,
      { "o-CU-UP-PM-Container", "e2ap.o_CU_UP_PM_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CUUPMeasurement_Container", HFILL }},
    { &hf_e2ap_plmnList,
      { "plmnList", "e2ap.plmnList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxPLMN_OF_PlmnID_List", HFILL }},
    { &hf_e2ap_plmnList_item,
      { "PlmnID-List", "e2ap.PlmnID_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_cu_UP_PM_5GC,
      { "cu-UP-PM-5GC", "e2ap.cu_UP_PM_5GC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FGC_CUUP_PM_Format", HFILL }},
    { &hf_e2ap_cu_UP_PM_EPC,
      { "cu-UP-PM-EPC", "e2ap.cu_UP_PM_EPC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EPC_CUUP_PM_Format", HFILL }},
    { &hf_e2ap_sliceToReportList,
      { "sliceToReportList", "e2ap.sliceToReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SliceToReportListItem", HFILL }},
    { &hf_e2ap_sliceToReportList_item,
      { "SliceToReportListItem", "e2ap.SliceToReportListItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_fQIPERSlicesPerPlmnList,
      { "fQIPERSlicesPerPlmnList", "e2ap.fQIPERSlicesPerPlmnList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnListItem", HFILL }},
    { &hf_e2ap_fQIPERSlicesPerPlmnList_item,
      { "FQIPERSlicesPerPlmnListItem", "e2ap.FQIPERSlicesPerPlmnListItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_e2ap_pDCPBytesDL,
      { "pDCPBytesDL", "e2ap.pDCPBytesDL",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_10000000000_", HFILL }},
    { &hf_e2ap_pDCPBytesUL,
      { "pDCPBytesUL", "e2ap.pDCPBytesUL",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_10000000000_", HFILL }},
    { &hf_e2ap_perQCIReportList_01,
      { "perQCIReportList", "e2ap.perQCIReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItemFormat", HFILL }},
    { &hf_e2ap_perQCIReportList_item_01,
      { "PerQCIReportListItemFormat", "e2ap.PerQCIReportListItemFormat_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-e2ap-hfarr.c ---*/
#line 212 "./asn1/e2ap/packet-e2ap-template.c"

  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_e2ap,

/*--- Included file: packet-e2ap-ettarr.c ---*/
#line 1 "./asn1/e2ap/packet-e2ap-ettarr.c"
    &ett_e2ap_ProtocolIE_Container,
    &ett_e2ap_ProtocolIE_Field,
    &ett_e2ap_Cause,
    &ett_e2ap_CriticalityDiagnostics,
    &ett_e2ap_CriticalityDiagnostics_IE_List,
    &ett_e2ap_CriticalityDiagnostics_IE_Item,
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
    &ett_e2ap_GlobalRIC_ID,
    &ett_e2ap_GNB_ID_Choice,
    &ett_e2ap_RICrequestID,
    &ett_e2ap_RICsubsequentAction,
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
    &ett_e2ap_RICindication,
    &ett_e2ap_RICcontrolRequest,
    &ett_e2ap_RICcontrolAcknowledge,
    &ett_e2ap_RICcontrolFailure,
    &ett_e2ap_ErrorIndication,
    &ett_e2ap_E2setupRequest,
    &ett_e2ap_E2setupResponse,
    &ett_e2ap_E2setupFailure,
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
    &ett_e2ap_E2AP_PDU,
    &ett_e2ap_InitiatingMessage,
    &ett_e2ap_SuccessfulOutcome,
    &ett_e2ap_UnsuccessfulOutcome,
    &ett_e2ap_GlobalKPMnode_ID,
    &ett_e2ap_GlobalKPMnode_gNB_ID,
    &ett_e2ap_GlobalKPMnode_en_gNB_ID,
    &ett_e2ap_GlobalKPMnode_ng_eNB_ID,
    &ett_e2ap_GlobalKPMnode_eNB_ID,
    &ett_e2ap_NRCGI,
    &ett_e2ap_SNSSAI,
    &ett_e2ap_E2SM_KPM_EventTriggerDefinition,
    &ett_e2ap_E2SM_KPM_EventTriggerDefinition_Format1,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofMessageProtocolTests_OF_Trigger_ConditionIE_Item,
    &ett_e2ap_E2SM_KPM_ActionDefinition,
    &ett_e2ap_E2SM_KPM_IndicationHeader,
    &ett_e2ap_E2SM_KPM_IndicationHeader_Format1,
    &ett_e2ap_E2SM_KPM_IndicationMessage_Format1,
    &ett_e2ap_SEQUENCE_SIZE_1_maxCellingNBDU_OF_PM_Containers_List,
    &ett_e2ap_PM_Containers_List,
    &ett_e2ap_E2SM_KPM_RANfunction_Description,
    &ett_e2ap_T_e2SM_KPM_RANfunction_Item,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_EventTriggerStyle_List,
    &ett_e2ap_SEQUENCE_SIZE_1_maxofRICstyles_OF_RIC_ReportStyle_List,
    &ett_e2ap_Trigger_ConditionIE_Item,
    &ett_e2ap_RANfunction_Name,
    &ett_e2ap_RIC_EventTriggerStyle_List,
    &ett_e2ap_RIC_ReportStyle_List,
    &ett_e2ap_PF_Container,
    &ett_e2ap_ODU_PF_Container,
    &ett_e2ap_SEQUENCE_SIZE_1_maxCellingNBDU_OF_CellResourceReportListItem,
    &ett_e2ap_CellResourceReportListItem,
    &ett_e2ap_SEQUENCE_SIZE_1_maxPLMN_OF_ServedPlmnPerCellListItem,
    &ett_e2ap_ServedPlmnPerCellListItem,
    &ett_e2ap_FGC_DU_PM_Container,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SlicePerPlmnPerCellListItem,
    &ett_e2ap_SlicePerPlmnPerCellListItem,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnPerCellListItem,
    &ett_e2ap_FQIPERSlicesPerPlmnPerCellListItem,
    &ett_e2ap_EPC_DU_PM_Container,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItem,
    &ett_e2ap_PerQCIReportListItem,
    &ett_e2ap_OCUCP_PF_Container,
    &ett_e2ap_T_cu_CP_Resource_Status,
    &ett_e2ap_OCUUP_PF_Container,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofContainerListItems_OF_PF_ContainerListItem,
    &ett_e2ap_PF_ContainerListItem,
    &ett_e2ap_CUUPMeasurement_Container,
    &ett_e2ap_SEQUENCE_SIZE_1_maxPLMN_OF_PlmnID_List,
    &ett_e2ap_PlmnID_List,
    &ett_e2ap_FGC_CUUP_PM_Format,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofSliceItems_OF_SliceToReportListItem,
    &ett_e2ap_SliceToReportListItem,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofQoSFlows_OF_FQIPERSlicesPerPlmnListItem,
    &ett_e2ap_FQIPERSlicesPerPlmnListItem,
    &ett_e2ap_EPC_CUUP_PM_Format,
    &ett_e2ap_SEQUENCE_SIZE_1_maxnoofQCI_OF_PerQCIReportListItemFormat,
    &ett_e2ap_PerQCIReportListItemFormat,

/*--- End of included file: packet-e2ap-ettarr.c ---*/
#line 219 "./asn1/e2ap/packet-e2ap-template.c"
  };


  /* module_t *e2ap_module; */

  /* Register protocol */
  proto_e2ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_e2ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


  /* Register dissector */
  e2ap_handle = register_dissector("e2ap", dissect_e2ap, proto_e2ap);

  /* Register dissector tables */
  e2ap_ies_dissector_table = register_dissector_table("e2ap.ies", "E2AP-PROTOCOL-IES", proto_e2ap, FT_UINT32, BASE_DEC);
//  e2ap_ies_p1_dissector_table = register_dissector_table("e2ap.ies.pair.first", "E2AP-PROTOCOL-IES-PAIR FirstValue", proto_e2ap, FT_UINT32, BASE_DEC);
//  e2ap_ies_p2_dissector_table = register_dissector_table("e2ap.ies.pair.second", "E2AP-PROTOCOL-IES-PAIR SecondValue", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_extension_dissector_table = register_dissector_table("e2ap.extension", "E2AP-PROTOCOL-EXTENSION", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_proc_imsg_dissector_table = register_dissector_table("e2ap.proc.imsg", "E2AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_proc_sout_dissector_table = register_dissector_table("e2ap.proc.sout", "E2AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_proc_uout_dissector_table = register_dissector_table("e2ap.proc.uout", "E2AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_e2ap, FT_UINT32, BASE_DEC);
  e2ap_n2_ie_type_dissector_table = register_dissector_table("e2ap.n2_ie_type", "E2AP N2 IE Type", proto_e2ap, FT_STRING, FALSE);

  /* Register configuration options for ports */
  /* e2ap_module = prefs_register_protocol(proto_e2ap, NULL); */

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
