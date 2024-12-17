/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-rc-v3.c                                                             */
/* asn2wrs.py -q -L -p rc-v3 -c ./rc-v3.cnf -s ./packet-rc-v3-template -D . -O ../.. e2sm-rc-v3.05.asn e2sm-v3.05.asn */

/* packet-rc-v3-template.c
 * Copyright 2021, Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: ORAN-WG3.E2SM-rc-v03.05
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <wsutil/array.h>

#include "packet-e2ap.h"
#include "packet-per.h"
#include "packet-ntp.h"

#define PNAME  "RC V3"
#define PSNAME "RCv3"
#define PFNAME "rc-v3"


void proto_register_rc_v3(void);
void proto_reg_handoff_rc_v3(void);


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
#define maxGroupDefinitionIdentifierParameters 255
#define maxnoofAssociatedEntityFilters 255
#define maxnoofFormatTypes             63
#define maxE1APid                      65535
#define maxF1APid                      4
#define maxEARFCN                      65535
#define maxNRARFCN                     3279165
#define maxnoofNrCellBands             32
#define maxNrofSSBs_1                  63

/* Initialize the protocol and registered fields */
static int proto_rc_v3;
static int hf_rc_v3_E2SM_RC_EventTrigger_PDU;     /* E2SM_RC_EventTrigger */
static int hf_rc_v3_E2SM_RC_ActionDefinition_PDU;  /* E2SM_RC_ActionDefinition */
static int hf_rc_v3_E2SM_RC_IndicationHeader_PDU;  /* E2SM_RC_IndicationHeader */
static int hf_rc_v3_E2SM_RC_IndicationMessage_PDU;  /* E2SM_RC_IndicationMessage */
static int hf_rc_v3_E2SM_RC_CallProcessID_PDU;    /* E2SM_RC_CallProcessID */
static int hf_rc_v3_E2SM_RC_ControlHeader_PDU;    /* E2SM_RC_ControlHeader */
static int hf_rc_v3_E2SM_RC_ControlMessage_PDU;   /* E2SM_RC_ControlMessage */
static int hf_rc_v3_E2SM_RC_ControlOutcome_PDU;   /* E2SM_RC_ControlOutcome */
static int hf_rc_v3_E2SM_RC_QueryHeader_PDU;      /* E2SM_RC_QueryHeader */
static int hf_rc_v3_E2SM_RC_QueryDefinition_PDU;  /* E2SM_RC_QueryDefinition */
static int hf_rc_v3_E2SM_RC_QueryOutcome_PDU;     /* E2SM_RC_QueryOutcome */
static int hf_rc_v3_E2SM_RC_RANFunctionDefinition_PDU;  /* E2SM_RC_RANFunctionDefinition */
static int hf_rc_v3_NeighborCell_List_item;       /* NeighborCell_Item */
static int hf_rc_v3_ranType_Choice_NR;            /* NeighborCell_Item_Choice_NR */
static int hf_rc_v3_ranType_Choice_EUTRA;         /* NeighborCell_Item_Choice_E_UTRA */
static int hf_rc_v3_nR_CGI;                       /* NR_CGI */
static int hf_rc_v3_nR_PCI;                       /* NR_PCI */
static int hf_rc_v3_fiveGS_TAC;                   /* FiveGS_TAC */
static int hf_rc_v3_nR_mode_info;                 /* T_nR_mode_info */
static int hf_rc_v3_nR_FreqInfo;                  /* NRFrequencyInfo */
static int hf_rc_v3_x2_Xn_established;            /* T_x2_Xn_established */
static int hf_rc_v3_hO_validated;                 /* T_hO_validated */
static int hf_rc_v3_version;                      /* INTEGER_1_65535_ */
static int hf_rc_v3_eUTRA_CGI;                    /* EUTRA_CGI */
static int hf_rc_v3_eUTRA_PCI;                    /* E_UTRA_PCI */
static int hf_rc_v3_eUTRA_ARFCN;                  /* E_UTRA_ARFCN */
static int hf_rc_v3_eUTRA_TAC;                    /* E_UTRA_TAC */
static int hf_rc_v3_x2_Xn_established_01;         /* T_x2_Xn_established_01 */
static int hf_rc_v3_hO_validated_01;              /* T_hO_validated_01 */
static int hf_rc_v3_servingCellPCI;               /* ServingCell_PCI */
static int hf_rc_v3_servingCellARFCN;             /* ServingCell_ARFCN */
static int hf_rc_v3_neighborCell_List;            /* NeighborCell_List */
static int hf_rc_v3_cellInfo_List;                /* SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item */
static int hf_rc_v3_cellInfo_List_item;           /* EventTrigger_Cell_Info_Item */
static int hf_rc_v3_eventTriggerCellID;           /* RIC_EventTrigger_Cell_ID */
static int hf_rc_v3_cellType;                     /* T_cellType */
static int hf_rc_v3_cellType_Choice_Individual;   /* EventTrigger_Cell_Info_Item_Choice_Individual */
static int hf_rc_v3_cellType_Choice_Group;        /* EventTrigger_Cell_Info_Item_Choice_Group */
static int hf_rc_v3_logicalOR;                    /* LogicalOR */
static int hf_rc_v3_cellGlobalID;                 /* CGI */
static int hf_rc_v3_ranParameterTesting;          /* RANParameter_Testing */
static int hf_rc_v3_ueInfo_List;                  /* SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item */
static int hf_rc_v3_ueInfo_List_item;             /* EventTrigger_UE_Info_Item */
static int hf_rc_v3_eventTriggerUEID;             /* RIC_EventTrigger_UE_ID */
static int hf_rc_v3_ueType;                       /* T_ueType */
static int hf_rc_v3_ueType_Choice_Individual;     /* EventTrigger_UE_Info_Item_Choice_Individual */
static int hf_rc_v3_ueType_Choice_Group;          /* EventTrigger_UE_Info_Item_Choice_Group */
static int hf_rc_v3_ueID;                         /* UEID */
static int hf_rc_v3_ueEvent_List;                 /* SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item */
static int hf_rc_v3_ueEvent_List_item;            /* EventTrigger_UEevent_Info_Item */
static int hf_rc_v3_ueEventID;                    /* RIC_EventTrigger_UEevent_ID */
static int hf_rc_v3_ranParameter_Definition_Choice;  /* RANParameter_Definition_Choice */
static int hf_rc_v3_choiceLIST;                   /* RANParameter_Definition_Choice_LIST */
static int hf_rc_v3_choiceSTRUCTURE;              /* RANParameter_Definition_Choice_STRUCTURE */
static int hf_rc_v3_ranParameter_List;            /* SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item */
static int hf_rc_v3_ranParameter_List_item;       /* RANParameter_Definition_Choice_LIST_Item */
static int hf_rc_v3_ranParameter_ID;              /* RANParameter_ID */
static int hf_rc_v3_ranParameter_name;            /* RANParameter_Name */
static int hf_rc_v3_ranParameter_Definition;      /* RANParameter_Definition */
static int hf_rc_v3_ranParameter_STRUCTURE;       /* SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item */
static int hf_rc_v3_ranParameter_STRUCTURE_item;  /* RANParameter_Definition_Choice_STRUCTURE_Item */
static int hf_rc_v3_valueBoolean;                 /* BOOLEAN */
static int hf_rc_v3_valueInt;                     /* INTEGER */
static int hf_rc_v3_valueReal;                    /* REAL */
static int hf_rc_v3_valueBitS;                    /* BIT_STRING */
static int hf_rc_v3_valueOctS;                    /* OCTET_STRING */
static int hf_rc_v3_valuePrintableString;         /* PrintableString */
static int hf_rc_v3_ranP_Choice_ElementTrue;      /* RANParameter_ValueType_Choice_ElementTrue */
static int hf_rc_v3_ranP_Choice_ElementFalse;     /* RANParameter_ValueType_Choice_ElementFalse */
static int hf_rc_v3_ranP_Choice_Structure;        /* RANParameter_ValueType_Choice_Structure */
static int hf_rc_v3_ranP_Choice_List;             /* RANParameter_ValueType_Choice_List */
static int hf_rc_v3_ranParameter_value;           /* RANParameter_Value */
static int hf_rc_v3_ranParameter_Structure;       /* RANParameter_STRUCTURE */
static int hf_rc_v3_ranParameter_List_01;         /* RANParameter_LIST */
static int hf_rc_v3_sequence_of_ranParameters;    /* SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item */
static int hf_rc_v3_sequence_of_ranParameters_item;  /* RANParameter_STRUCTURE_Item */
static int hf_rc_v3_ranParameter_valueType;       /* RANParameter_ValueType */
static int hf_rc_v3_list_of_ranParameter;         /* SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE */
static int hf_rc_v3_list_of_ranParameter_item;    /* RANParameter_STRUCTURE */
static int hf_rc_v3_RANParameter_Testing_item;    /* RANParameter_Testing_Item */
static int hf_rc_v3_ranP_Choice_comparison;       /* T_ranP_Choice_comparison */
static int hf_rc_v3_ranP_Choice_presence;         /* T_ranP_Choice_presence */
static int hf_rc_v3_ranParameter_Type;            /* T_ranParameter_Type */
static int hf_rc_v3_ranP_Choice_List_01;          /* RANParameter_Testing_Item_Choice_List */
static int hf_rc_v3_ranP_Choice_Structure_01;     /* RANParameter_Testing_Item_Choice_Structure */
static int hf_rc_v3_ranP_Choice_ElementTrue_01;   /* RANParameter_Testing_Item_Choice_ElementTrue */
static int hf_rc_v3_ranP_Choice_ElementFalse_01;  /* RANParameter_Testing_Item_Choice_ElementFalse */
static int hf_rc_v3_ranParameter_List_02;         /* RANParameter_Testing_LIST */
static int hf_rc_v3_ranParameter_Structure_01;    /* RANParameter_Testing_STRUCTURE */
static int hf_rc_v3_ranParameter_TestCondition;   /* RANParameter_TestingCondition */
static int hf_rc_v3_ranParameter_Value;           /* RANParameter_Value */
static int hf_rc_v3_RANParameter_Testing_LIST_item;  /* RANParameter_Testing_Item */
static int hf_rc_v3_RANParameter_Testing_STRUCTURE_item;  /* RANParameter_Testing_Item */
static int hf_rc_v3_ueGroupDefinitionIdentifier_LIST;  /* SEQUENCE_SIZE_1_maxGroupDefinitionIdentifierParameters_OF_UEGroupDefinitionIdentifier_Item */
static int hf_rc_v3_ueGroupDefinitionIdentifier_LIST_item;  /* UEGroupDefinitionIdentifier_Item */
static int hf_rc_v3_ric_PolicyAction_ID;          /* RIC_ControlAction_ID */
static int hf_rc_v3_ranParameters_List;           /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item */
static int hf_rc_v3_ranParameters_List_item;      /* RIC_PolicyAction_RANParameter_Item */
static int hf_rc_v3_ric_PolicyDecision;           /* T_ric_PolicyDecision */
static int hf_rc_v3_associatedUEInfo_List;        /* SEQUENCE_SIZE_1_maxnoofUEInfo_OF_Associated_UE_Info_Item */
static int hf_rc_v3_associatedUEInfo_List_item;   /* Associated_UE_Info_Item */
static int hf_rc_v3_ueFilterID;                   /* UE_Filter_ID */
static int hf_rc_v3_ueType_01;                    /* T_ueType_01 */
static int hf_rc_v3_ueQuery;                      /* UEQuery */
static int hf_rc_v3_partialUEID;                  /* PartialUEID */
static int hf_rc_v3_ric_eventTrigger_formats;     /* T_ric_eventTrigger_formats */
static int hf_rc_v3_eventTrigger_Format1;         /* E2SM_RC_EventTrigger_Format1 */
static int hf_rc_v3_eventTrigger_Format2;         /* E2SM_RC_EventTrigger_Format2 */
static int hf_rc_v3_eventTrigger_Format3;         /* E2SM_RC_EventTrigger_Format3 */
static int hf_rc_v3_eventTrigger_Format4;         /* E2SM_RC_EventTrigger_Format4 */
static int hf_rc_v3_eventTrigger_Format5;         /* NULL */
static int hf_rc_v3_message_List;                 /* SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item */
static int hf_rc_v3_message_List_item;            /* E2SM_RC_EventTrigger_Format1_Item */
static int hf_rc_v3_globalAssociatedUEInfo;       /* EventTrigger_UE_Info */
static int hf_rc_v3_ric_eventTriggerCondition_ID;  /* RIC_EventTriggerCondition_ID */
static int hf_rc_v3_messageType;                  /* MessageType_Choice */
static int hf_rc_v3_messageDirection;             /* T_messageDirection */
static int hf_rc_v3_associatedUEInfo;             /* EventTrigger_UE_Info */
static int hf_rc_v3_associatedUEEvent;            /* EventTrigger_UEevent_Info */
static int hf_rc_v3_messageType_Choice_NI;        /* MessageType_Choice_NI */
static int hf_rc_v3_messageType_Choice_RRC;       /* MessageType_Choice_RRC */
static int hf_rc_v3_nI_Type;                      /* InterfaceType */
static int hf_rc_v3_nI_Identifier;                /* InterfaceIdentifier */
static int hf_rc_v3_nI_Message;                   /* Interface_MessageID */
static int hf_rc_v3_rRC_Message;                  /* RRC_MessageID */
static int hf_rc_v3_ric_callProcessType_ID;       /* RIC_CallProcessType_ID */
static int hf_rc_v3_ric_callProcessBreakpoint_ID;  /* RIC_CallProcessBreakpoint_ID */
static int hf_rc_v3_associatedE2NodeInfo;         /* RANParameter_Testing */
static int hf_rc_v3_e2NodeInfoChange_List;        /* SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item */
static int hf_rc_v3_e2NodeInfoChange_List_item;   /* E2SM_RC_EventTrigger_Format3_Item */
static int hf_rc_v3_e2NodeInfoChange_ID;          /* INTEGER_1_512_ */
static int hf_rc_v3_associatedCellInfo;           /* EventTrigger_Cell_Info */
static int hf_rc_v3_uEInfoChange_List;            /* SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item */
static int hf_rc_v3_uEInfoChange_List_item;       /* E2SM_RC_EventTrigger_Format4_Item */
static int hf_rc_v3_triggerType;                  /* TriggerType_Choice */
static int hf_rc_v3_triggerType_Choice_RRCstate;  /* TriggerType_Choice_RRCstate */
static int hf_rc_v3_triggerType_Choice_UEID;      /* TriggerType_Choice_UEID */
static int hf_rc_v3_triggerType_Choice_L2state;   /* TriggerType_Choice_L2state */
static int hf_rc_v3_triggerType_Choice_UEcontext;  /* TriggerType_Choice_UEcontext */
static int hf_rc_v3_triggerType_Choice_L2MACschChg;  /* TriggerType_Choice_L2MACschChg */
static int hf_rc_v3_rrcState_List;                /* SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item */
static int hf_rc_v3_rrcState_List_item;           /* TriggerType_Choice_RRCstate_Item */
static int hf_rc_v3_stateChangedTo;               /* RRC_State */
static int hf_rc_v3_ueIDchange_ID;                /* INTEGER_1_512_ */
static int hf_rc_v3_associatedL2variables;        /* RANParameter_Testing */
static int hf_rc_v3_associatedUECtxtVariables;    /* RANParameter_Testing */
static int hf_rc_v3_l2MACschChgType;              /* L2MACschChgType_Choice */
static int hf_rc_v3_triggerType_Choice_MIMOandBFconfig;  /* TriggerType_Choice_MIMOandBFconfig */
static int hf_rc_v3_mIMOtransModeState;           /* T_mIMOtransModeState */
static int hf_rc_v3_ric_Style_Type;               /* RIC_Style_Type */
static int hf_rc_v3_ric_actionDefinition_formats;  /* T_ric_actionDefinition_formats */
static int hf_rc_v3_actionDefinition_Format1;     /* E2SM_RC_ActionDefinition_Format1 */
static int hf_rc_v3_actionDefinition_Format2;     /* E2SM_RC_ActionDefinition_Format2 */
static int hf_rc_v3_actionDefinition_Format3;     /* E2SM_RC_ActionDefinition_Format3 */
static int hf_rc_v3_actionDefinition_Format4;     /* E2SM_RC_ActionDefinition_Format4 */
static int hf_rc_v3_ranP_ToBeReported_List;       /* SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item */
static int hf_rc_v3_ranP_ToBeReported_List_item;  /* E2SM_RC_ActionDefinition_Format1_Item */
static int hf_rc_v3_ric_PolicyConditions_List;    /* SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item */
static int hf_rc_v3_ric_PolicyConditions_List_item;  /* E2SM_RC_ActionDefinition_Format2_Item */
static int hf_rc_v3_ric_PolicyAction;             /* RIC_PolicyAction */
static int hf_rc_v3_ric_PolicyConditionDefinition;  /* RANParameter_Testing */
static int hf_rc_v3_ric_InsertIndication_ID;      /* RIC_InsertIndication_ID */
static int hf_rc_v3_ranP_InsertIndication_List;   /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item */
static int hf_rc_v3_ranP_InsertIndication_List_item;  /* E2SM_RC_ActionDefinition_Format3_Item */
static int hf_rc_v3_ric_InsertStyle_List;         /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item */
static int hf_rc_v3_ric_InsertStyle_List_item;    /* E2SM_RC_ActionDefinition_Format4_Style_Item */
static int hf_rc_v3_requested_Insert_Style_Type;  /* RIC_Style_Type */
static int hf_rc_v3_ric_InsertIndication_List;    /* SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item */
static int hf_rc_v3_ric_InsertIndication_List_item;  /* E2SM_RC_ActionDefinition_Format4_Indication_Item */
static int hf_rc_v3_ranP_InsertIndication_List_01;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item */
static int hf_rc_v3_ranP_InsertIndication_List_item_01;  /* E2SM_RC_ActionDefinition_Format4_RANP_Item */
static int hf_rc_v3_ric_indicationHeader_formats;  /* T_ric_indicationHeader_formats */
static int hf_rc_v3_indicationHeader_Format1;     /* E2SM_RC_IndicationHeader_Format1 */
static int hf_rc_v3_indicationHeader_Format2;     /* E2SM_RC_IndicationHeader_Format2 */
static int hf_rc_v3_indicationHeader_Format3;     /* E2SM_RC_IndicationHeader_Format3 */
static int hf_rc_v3_ric_InsertStyle_Type;         /* RIC_Style_Type */
static int hf_rc_v3_ric_indicationMessage_formats;  /* T_ric_indicationMessage_formats */
static int hf_rc_v3_indicationMessage_Format1;    /* E2SM_RC_IndicationMessage_Format1 */
static int hf_rc_v3_indicationMessage_Format2;    /* E2SM_RC_IndicationMessage_Format2 */
static int hf_rc_v3_indicationMessage_Format3;    /* E2SM_RC_IndicationMessage_Format3 */
static int hf_rc_v3_indicationMessage_Format4;    /* NULL */
static int hf_rc_v3_indicationMessage_Format5;    /* E2SM_RC_IndicationMessage_Format5 */
static int hf_rc_v3_indicationMessage_Format6;    /* E2SM_RC_IndicationMessage_Format6 */
static int hf_rc_v3_ranP_Reported_List;           /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item */
static int hf_rc_v3_ranP_Reported_List_item;      /* E2SM_RC_IndicationMessage_Format1_Item */
static int hf_rc_v3_ueParameter_List;             /* SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item */
static int hf_rc_v3_ueParameter_List_item;        /* E2SM_RC_IndicationMessage_Format2_Item */
static int hf_rc_v3_ranP_List;                    /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item */
static int hf_rc_v3_ranP_List_item;               /* E2SM_RC_IndicationMessage_Format2_RANParameter_Item */
static int hf_rc_v3_cellInfo_List_01;             /* SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item */
static int hf_rc_v3_cellInfo_List_item_01;        /* E2SM_RC_IndicationMessage_Format3_Item */
static int hf_rc_v3_cellGlobal_ID;                /* CGI */
static int hf_rc_v3_cellContextInfo;              /* OCTET_STRING */
static int hf_rc_v3_cellDeleted;                  /* BOOLEAN */
static int hf_rc_v3_neighborRelation_Table;       /* NeighborRelation_Info */
static int hf_rc_v3_ranP_Requested_List;          /* SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item */
static int hf_rc_v3_ranP_Requested_List_item;     /* E2SM_RC_IndicationMessage_Format5_Item */
static int hf_rc_v3_ric_InsertStyle_List_01;      /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item */
static int hf_rc_v3_ric_InsertStyle_List_item_01;  /* E2SM_RC_IndicationMessage_Format6_Style_Item */
static int hf_rc_v3_indicated_Insert_Style_Type;  /* RIC_Style_Type */
static int hf_rc_v3_ric_InsertIndication_List_01;  /* SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item */
static int hf_rc_v3_ric_InsertIndication_List_item_01;  /* E2SM_RC_IndicationMessage_Format6_Indication_Item */
static int hf_rc_v3_ranP_InsertIndication_List_02;  /* SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item */
static int hf_rc_v3_ranP_InsertIndication_List_item_02;  /* E2SM_RC_IndicationMessage_Format6_RANP_Item */
static int hf_rc_v3_ric_callProcessID_formats;    /* T_ric_callProcessID_formats */
static int hf_rc_v3_callProcessID_Format1;        /* E2SM_RC_CallProcessID_Format1 */
static int hf_rc_v3_ric_callProcess_ID;           /* RAN_CallProcess_ID */
static int hf_rc_v3_ric_controlHeader_formats;    /* T_ric_controlHeader_formats */
static int hf_rc_v3_controlHeader_Format1;        /* E2SM_RC_ControlHeader_Format1 */
static int hf_rc_v3_controlHeader_Format2;        /* E2SM_RC_ControlHeader_Format2 */
static int hf_rc_v3_controlHeader_Format3;        /* E2SM_RC_ControlHeader_Format3 */
static int hf_rc_v3_controlHeader_Format4;        /* E2SM_RC_ControlHeader_Format4 */
static int hf_rc_v3_ric_ControlAction_ID;         /* RIC_ControlAction_ID */
static int hf_rc_v3_ric_ControlDecision;          /* T_ric_ControlDecision */
static int hf_rc_v3_ric_ControlDecision_01;       /* T_ric_ControlDecision_01 */
static int hf_rc_v3_ue_Group_ID;                  /* UE_Group_ID */
static int hf_rc_v3_ue_Group_Definition;          /* UE_Group_Definition */
static int hf_rc_v3_partial_ueID;                 /* PartialUEID */
static int hf_rc_v3_ric_ControlDecision_02;       /* T_ric_ControlDecision_02 */
static int hf_rc_v3_ric_controlMessage_formats;   /* T_ric_controlMessage_formats */
static int hf_rc_v3_controlMessage_Format1;       /* E2SM_RC_ControlMessage_Format1 */
static int hf_rc_v3_controlMessage_Format2;       /* E2SM_RC_ControlMessage_Format2 */
static int hf_rc_v3_controlMessage_Format3;       /* E2SM_RC_ControlMessage_Format3 */
static int hf_rc_v3_controlMessage_Format4;       /* E2SM_RC_ControlMessage_Format4 */
static int hf_rc_v3_controlMessage_Format5;       /* E2SM_RC_ControlMessage_Format5 */
static int hf_rc_v3_ranP_List_01;                 /* SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item */
static int hf_rc_v3_ranP_List_item_01;            /* E2SM_RC_ControlMessage_Format1_Item */
static int hf_rc_v3_ric_ControlStyle_List;        /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item */
static int hf_rc_v3_ric_ControlStyle_List_item;   /* E2SM_RC_ControlMessage_Format2_Style_Item */
static int hf_rc_v3_indicated_Control_Style_Type;  /* RIC_Style_Type */
static int hf_rc_v3_ric_ControlAction_List;       /* SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item */
static int hf_rc_v3_ric_ControlAction_List_item;  /* E2SM_RC_ControlMessage_Format2_ControlAction_Item */
static int hf_rc_v3_ranP_List_02;                 /* E2SM_RC_ControlMessage_Format1 */
static int hf_rc_v3_listOfEntityFilters;          /* SEQUENCE_SIZE_0_maxnoofAssociatedEntityFilters_OF_E2SM_RC_EntityFilter */
static int hf_rc_v3_listOfEntityFilters_item;     /* E2SM_RC_EntityFilter */
static int hf_rc_v3_entityAgnosticControlRanP_List;  /* SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_EntityAgnostic_ranP_ControlParameters */
static int hf_rc_v3_entityAgnosticControlRanP_List_item;  /* EntityAgnostic_ranP_ControlParameters */
static int hf_rc_v3_entityFilter_ID;              /* EntityFilter_ID */
static int hf_rc_v3_entityFilter_Definition;      /* RANParameter_Testing */
static int hf_rc_v3_entitySpecificControlRanP_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_EntitySpecific_ranP_ControlParameters */
static int hf_rc_v3_entitySpecificControlRanP_List_item;  /* EntitySpecific_ranP_ControlParameters */
static int hf_rc_v3_ranP_List_03;                 /* SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format4_Item */
static int hf_rc_v3_ranP_List_item_02;            /* E2SM_RC_ControlMessage_Format4_Item */
static int hf_rc_v3_ric_controlOutcome_formats;   /* T_ric_controlOutcome_formats */
static int hf_rc_v3_controlOutcome_Format1;       /* E2SM_RC_ControlOutcome_Format1 */
static int hf_rc_v3_controlOutcome_Format2;       /* E2SM_RC_ControlOutcome_Format2 */
static int hf_rc_v3_controlOutcome_Format3;       /* E2SM_RC_ControlOutcome_Format3 */
static int hf_rc_v3_ranP_List_04;                 /* SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item */
static int hf_rc_v3_ranP_List_item_03;            /* E2SM_RC_ControlOutcome_Format1_Item */
static int hf_rc_v3_ric_ControlStyle_List_01;     /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item */
static int hf_rc_v3_ric_ControlStyle_List_item_01;  /* E2SM_RC_ControlOutcome_Format2_Style_Item */
static int hf_rc_v3_ric_ControlOutcome_List;      /* SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item */
static int hf_rc_v3_ric_ControlOutcome_List_item;  /* E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item */
static int hf_rc_v3_ranP_List_05;                 /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item */
static int hf_rc_v3_ranP_List_item_04;            /* E2SM_RC_ControlOutcome_Format2_RANP_Item */
static int hf_rc_v3_ranP_List_06;                 /* SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item */
static int hf_rc_v3_ranP_List_item_05;            /* E2SM_RC_ControlOutcome_Format3_Item */
static int hf_rc_v3_ric_queryHeader_formats;      /* T_ric_queryHeader_formats */
static int hf_rc_v3_queryHeader_Format1;          /* E2SM_RC_QueryHeader_Format1 */
static int hf_rc_v3_associatedUEInfo_01;          /* Associated_UE_Info */
static int hf_rc_v3_ric_queryDefinition_formats;  /* T_ric_queryDefinition_formats */
static int hf_rc_v3_queryRequest_Format1;         /* E2SM_RC_QueryDefinition_Format1 */
static int hf_rc_v3_ranP_List_07;                 /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryDefinition_Format1_Item */
static int hf_rc_v3_ranP_List_item_06;            /* E2SM_RC_QueryDefinition_Format1_Item */
static int hf_rc_v3_ric_queryOutcome_formats;     /* T_ric_queryOutcome_formats */
static int hf_rc_v3_queryOutcome_Format1;         /* E2SM_RC_QueryOutcome_Format1 */
static int hf_rc_v3_queryOutcome_Format2;         /* E2SM_RC_QueryOutcome_Format2 */
static int hf_rc_v3_cellInfo_List_02;             /* SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_QueryOutcome_Format1_ItemCell */
static int hf_rc_v3_cellInfo_List_item_02;        /* E2SM_RC_QueryOutcome_Format1_ItemCell */
static int hf_rc_v3_ranP_List_08;                 /* SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format1_ItemParameters */
static int hf_rc_v3_ranP_List_item_07;            /* E2SM_RC_QueryOutcome_Format1_ItemParameters */
static int hf_rc_v3_ueInfo_List_01;               /* SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_QueryOutcome_Format2_ItemUE */
static int hf_rc_v3_ueInfo_List_item_01;          /* E2SM_RC_QueryOutcome_Format2_ItemUE */
static int hf_rc_v3_ranP_List_09;                 /* SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format2_ItemParameters */
static int hf_rc_v3_ranP_List_item_08;            /* E2SM_RC_QueryOutcome_Format2_ItemParameters */
static int hf_rc_v3_ranFunction_Name;             /* RANfunction_Name */
static int hf_rc_v3_ranFunctionDefinition_EventTrigger;  /* RANFunctionDefinition_EventTrigger */
static int hf_rc_v3_ranFunctionDefinition_Report;  /* RANFunctionDefinition_Report */
static int hf_rc_v3_ranFunctionDefinition_Insert;  /* RANFunctionDefinition_Insert */
static int hf_rc_v3_ranFunctionDefinition_Control;  /* RANFunctionDefinition_Control */
static int hf_rc_v3_ranFunctionDefinition_Policy;  /* RANFunctionDefinition_Policy */
static int hf_rc_v3_ranFunctionDefinition_Query;  /* RANFunctionDefinition_Query */
static int hf_rc_v3_ric_EventTriggerStyle_List;   /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item */
static int hf_rc_v3_ric_EventTriggerStyle_List_item;  /* RANFunctionDefinition_EventTrigger_Style_Item */
static int hf_rc_v3_ran_L2Parameters_List;        /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item */
static int hf_rc_v3_ran_L2Parameters_List_item;   /* L2Parameters_RANParameter_Item */
static int hf_rc_v3_ran_CallProcessTypes_List;    /* SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item */
static int hf_rc_v3_ran_CallProcessTypes_List_item;  /* RANFunctionDefinition_EventTrigger_CallProcess_Item */
static int hf_rc_v3_ran_UEIdentificationParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item */
static int hf_rc_v3_ran_UEIdentificationParameters_List_item;  /* UEIdentification_RANParameter_Item */
static int hf_rc_v3_ran_CellIdentificationParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item */
static int hf_rc_v3_ran_CellIdentificationParameters_List_item;  /* CellIdentification_RANParameter_Item */
static int hf_rc_v3_ric_EventTriggerStyle_Type;   /* RIC_Style_Type */
static int hf_rc_v3_ric_EventTriggerStyle_Name;   /* RIC_Style_Name */
static int hf_rc_v3_ric_EventTriggerFormat_Type;  /* RIC_Format_Type */
static int hf_rc_v3_callProcessType_ID;           /* RIC_CallProcessType_ID */
static int hf_rc_v3_callProcessType_Name;         /* RIC_CallProcessType_Name */
static int hf_rc_v3_callProcessBreakpoints_List;  /* SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item */
static int hf_rc_v3_callProcessBreakpoints_List_item;  /* RANFunctionDefinition_EventTrigger_Breakpoint_Item */
static int hf_rc_v3_callProcessBreakpoint_ID;     /* RIC_CallProcessBreakpoint_ID */
static int hf_rc_v3_callProcessBreakpoint_Name;   /* RIC_CallProcessBreakpoint_Name */
static int hf_rc_v3_ran_CallProcessBreakpointParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item */
static int hf_rc_v3_ran_CallProcessBreakpointParameters_List_item;  /* CallProcessBreakpoint_RANParameter_Item */
static int hf_rc_v3_ric_ReportStyle_List;         /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item */
static int hf_rc_v3_ric_ReportStyle_List_item;    /* RANFunctionDefinition_Report_Item */
static int hf_rc_v3_ric_ReportStyle_Type;         /* RIC_Style_Type */
static int hf_rc_v3_ric_ReportStyle_Name;         /* RIC_Style_Name */
static int hf_rc_v3_ric_SupportedEventTriggerStyle_Type;  /* RIC_Style_Type */
static int hf_rc_v3_ric_ReportActionFormat_Type;  /* RIC_Format_Type */
static int hf_rc_v3_ric_IndicationHeaderFormat_Type;  /* RIC_Format_Type */
static int hf_rc_v3_ric_IndicationMessageFormat_Type;  /* RIC_Format_Type */
static int hf_rc_v3_ran_ReportParameters_List;    /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item */
static int hf_rc_v3_ran_ReportParameters_List_item;  /* Report_RANParameter_Item */
static int hf_rc_v3_ric_InsertStyle_List_02;      /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item */
static int hf_rc_v3_ric_InsertStyle_List_item_02;  /* RANFunctionDefinition_Insert_Item */
static int hf_rc_v3_ric_InsertStyle_Name;         /* RIC_Style_Name */
static int hf_rc_v3_ric_ActionDefinitionFormat_Type;  /* RIC_Format_Type */
static int hf_rc_v3_ric_InsertIndication_List_02;  /* SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item */
static int hf_rc_v3_ric_InsertIndication_List_item_02;  /* RANFunctionDefinition_Insert_Indication_Item */
static int hf_rc_v3_ric_CallProcessIDFormat_Type;  /* RIC_Format_Type */
static int hf_rc_v3_ric_InsertIndication_Name;    /* RIC_InsertIndication_Name */
static int hf_rc_v3_ran_InsertIndicationParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item */
static int hf_rc_v3_ran_InsertIndicationParameters_List_item;  /* InsertIndication_RANParameter_Item */
static int hf_rc_v3_ric_ControlStyle_List_02;     /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item */
static int hf_rc_v3_ric_ControlStyle_List_item_02;  /* RANFunctionDefinition_Control_Item */
static int hf_rc_v3_ric_ControlStyle_Type;        /* RIC_Style_Type */
static int hf_rc_v3_ric_ControlStyle_Name;        /* RIC_Style_Name */
static int hf_rc_v3_ric_ControlAction_List_01;    /* SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item */
static int hf_rc_v3_ric_ControlAction_List_item_01;  /* RANFunctionDefinition_Control_Action_Item */
static int hf_rc_v3_ric_ControlHeaderFormat_Type;  /* RIC_Format_Type */
static int hf_rc_v3_ric_ControlMessageFormat_Type;  /* RIC_Format_Type */
static int hf_rc_v3_ric_ControlOutcomeFormat_Type;  /* RIC_Format_Type */
static int hf_rc_v3_ran_ControlOutcomeParameters_List;  /* SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item */
static int hf_rc_v3_ran_ControlOutcomeParameters_List_item;  /* ControlOutcome_RANParameter_Item */
static int hf_rc_v3_listOfAdditionalSupportedFormats;  /* ListOfAdditionalSupportedFormats */
static int hf_rc_v3_ric_ControlAction_Name;       /* RIC_ControlAction_Name */
static int hf_rc_v3_ran_ControlActionParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item */
static int hf_rc_v3_ran_ControlActionParameters_List_item;  /* ControlAction_RANParameter_Item */
static int hf_rc_v3_ueGroup_ControlAction_Supported;  /* T_ueGroup_ControlAction_Supported */
static int hf_rc_v3_ListOfAdditionalSupportedFormats_item;  /* AdditionalSupportedFormat */
static int hf_rc_v3_ric_PolicyStyle_List;         /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item */
static int hf_rc_v3_ric_PolicyStyle_List_item;    /* RANFunctionDefinition_Policy_Item */
static int hf_rc_v3_ric_PolicyStyle_Type;         /* RIC_Style_Type */
static int hf_rc_v3_ric_PolicyStyle_Name;         /* RIC_Style_Name */
static int hf_rc_v3_ric_PolicyAction_List;        /* SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item */
static int hf_rc_v3_ric_PolicyAction_List_item;   /* RANFunctionDefinition_Policy_Action_Item */
static int hf_rc_v3_ric_PolicyAction_Name;        /* RIC_ControlAction_Name */
static int hf_rc_v3_ran_PolicyActionParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item */
static int hf_rc_v3_ran_PolicyActionParameters_List_item;  /* PolicyAction_RANParameter_Item */
static int hf_rc_v3_ran_PolicyConditionParameters_List;  /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item */
static int hf_rc_v3_ran_PolicyConditionParameters_List_item;  /* PolicyCondition_RANParameter_Item */
static int hf_rc_v3_ric_QueryStyle_List;          /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Query_Item */
static int hf_rc_v3_ric_QueryStyle_List_item;     /* RANFunctionDefinition_Query_Item */
static int hf_rc_v3_ric_QueryStyle_Type;          /* RIC_Style_Type */
static int hf_rc_v3_ric_QueryStyle_Name;          /* RIC_Style_Name */
static int hf_rc_v3_ric_QueryHeaderFormat_Type;   /* RIC_Format_Type */
static int hf_rc_v3_ric_QueryDefinitionFormat_Type;  /* RIC_Format_Type */
static int hf_rc_v3_ric_QueryOutcomeFormat_Type;  /* RIC_Format_Type */
static int hf_rc_v3_ran_QueryParameters_List;     /* SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Query_RANParameter_Item */
static int hf_rc_v3_ran_QueryParameters_List_item;  /* Query_RANParameter_Item */
static int hf_rc_v3_c_RNTI;                       /* RNTI_Value */
static int hf_rc_v3_cell_Global_ID;               /* CGI */
static int hf_rc_v3_nG;                           /* InterfaceID_NG */
static int hf_rc_v3_xN;                           /* InterfaceID_Xn */
static int hf_rc_v3_f1;                           /* InterfaceID_F1 */
static int hf_rc_v3_e1;                           /* InterfaceID_E1 */
static int hf_rc_v3_s1;                           /* InterfaceID_S1 */
static int hf_rc_v3_x2;                           /* InterfaceID_X2 */
static int hf_rc_v3_w1;                           /* InterfaceID_W1 */
static int hf_rc_v3_guami;                        /* GUAMI */
static int hf_rc_v3_global_NG_RAN_ID;             /* GlobalNGRANNodeID */
static int hf_rc_v3_globalGNB_ID;                 /* GlobalGNB_ID */
static int hf_rc_v3_gNB_DU_ID;                    /* GNB_DU_ID */
static int hf_rc_v3_gNB_CU_UP_ID;                 /* GNB_CU_UP_ID */
static int hf_rc_v3_gUMMEI;                       /* GUMMEI */
static int hf_rc_v3_nodeType;                     /* T_nodeType */
static int hf_rc_v3_global_eNB_ID;                /* GlobalENB_ID */
static int hf_rc_v3_global_en_gNB_ID;             /* GlobalenGNB_ID */
static int hf_rc_v3_global_ng_eNB_ID;             /* GlobalNgENB_ID */
static int hf_rc_v3_ng_eNB_DU_ID;                 /* NGENB_DU_ID */
static int hf_rc_v3_interfaceProcedureID;         /* INTEGER */
static int hf_rc_v3_messageType_01;               /* T_messageType */
static int hf_rc_v3_amf_UE_NGAP_ID;               /* AMF_UE_NGAP_ID */
static int hf_rc_v3_gNB_CU_UE_F1AP_ID;            /* GNB_CU_UE_F1AP_ID */
static int hf_rc_v3_gNB_CU_CP_UE_E1AP_ID;         /* GNB_CU_CP_UE_E1AP_ID */
static int hf_rc_v3_ran_UEID;                     /* RANUEID */
static int hf_rc_v3_m_NG_RAN_UE_XnAP_ID;          /* NG_RANnodeUEXnAPID */
static int hf_rc_v3_globalNG_RANNode_ID;          /* GlobalNGRANNodeID */
static int hf_rc_v3_cell_RNTI;                    /* Cell_RNTI */
static int hf_rc_v3_ng_eNB_CU_UE_W1AP_ID;         /* NGENB_CU_UE_W1AP_ID */
static int hf_rc_v3_m_eNB_UE_X2AP_ID;             /* ENB_UE_X2AP_ID */
static int hf_rc_v3_m_eNB_UE_X2AP_ID_Extension;   /* ENB_UE_X2AP_ID_Extension */
static int hf_rc_v3_globalENB_ID;                 /* GlobalENB_ID */
static int hf_rc_v3_mME_UE_S1AP_ID;               /* MME_UE_S1AP_ID */
static int hf_rc_v3_ranFunction_ShortName;        /* T_ranFunction_ShortName */
static int hf_rc_v3_ranFunction_E2SM_OID;         /* T_ranFunction_E2SM_OID */
static int hf_rc_v3_ranFunction_Description;      /* PrintableString_SIZE_1_150_ */
static int hf_rc_v3_ranFunction_Instance;         /* INTEGER */
static int hf_rc_v3_rrcType;                      /* T_rrcType */
static int hf_rc_v3_lTE;                          /* RRCclass_LTE */
static int hf_rc_v3_nR;                           /* RRCclass_NR */
static int hf_rc_v3_messageID;                    /* INTEGER */
static int hf_rc_v3_nR_01;                        /* NR_ARFCN */
static int hf_rc_v3_eUTRA;                        /* E_UTRA_ARFCN */
static int hf_rc_v3_nR_02;                        /* NR_PCI */
static int hf_rc_v3_eUTRA_01;                     /* E_UTRA_PCI */
static int hf_rc_v3_gNB_UEID;                     /* UEID_GNB */
static int hf_rc_v3_gNB_DU_UEID;                  /* UEID_GNB_DU */
static int hf_rc_v3_gNB_CU_UP_UEID;               /* UEID_GNB_CU_UP */
static int hf_rc_v3_ng_eNB_UEID;                  /* UEID_NG_ENB */
static int hf_rc_v3_ng_eNB_DU_UEID;               /* UEID_NG_ENB_DU */
static int hf_rc_v3_en_gNB_UEID;                  /* UEID_EN_GNB */
static int hf_rc_v3_eNB_UEID;                     /* UEID_ENB */
static int hf_rc_v3_gNB_CU_UE_F1AP_ID_List;       /* UEID_GNB_CU_F1AP_ID_List */
static int hf_rc_v3_gNB_CU_CP_UE_E1AP_ID_List;    /* UEID_GNB_CU_CP_E1AP_ID_List */
static int hf_rc_v3_UEID_GNB_CU_CP_E1AP_ID_List_item;  /* UEID_GNB_CU_CP_E1AP_ID_Item */
static int hf_rc_v3_UEID_GNB_CU_F1AP_ID_List_item;  /* UEID_GNB_CU_CP_F1AP_ID_Item */
static int hf_rc_v3_globalNgENB_ID;               /* GlobalNgENB_ID */
static int hf_rc_v3_macro_eNB_ID;                 /* BIT_STRING_SIZE_20 */
static int hf_rc_v3_home_eNB_ID;                  /* BIT_STRING_SIZE_28 */
static int hf_rc_v3_short_Macro_eNB_ID;           /* BIT_STRING_SIZE_18 */
static int hf_rc_v3_long_Macro_eNB_ID;            /* BIT_STRING_SIZE_21 */
static int hf_rc_v3_pLMNIdentity;                 /* PLMNIdentity */
static int hf_rc_v3_eNB_ID;                       /* ENB_ID */
static int hf_rc_v3_pLMN_Identity;                /* PLMNIdentity */
static int hf_rc_v3_mME_Group_ID;                 /* MME_Group_ID */
static int hf_rc_v3_mME_Code;                     /* MME_Code */
static int hf_rc_v3_en_gNB_ID;                    /* BIT_STRING_SIZE_22_32 */
static int hf_rc_v3_en_gNB_ID_choice;             /* EN_GNB_ID */
static int hf_rc_v3_eUTRACellIdentity;            /* EUTRACellIdentity */
static int hf_rc_v3_gNB_ID_choice;                /* GNB_ID */
static int hf_rc_v3_ngENB_ID;                     /* NgENB_ID */
static int hf_rc_v3_gNB_ID;                       /* BIT_STRING_SIZE_22_32 */
static int hf_rc_v3_aMFRegionID;                  /* AMFRegionID */
static int hf_rc_v3_aMFSetID;                     /* AMFSetID */
static int hf_rc_v3_aMFPointer;                   /* AMFPointer */
static int hf_rc_v3_macroNgENB_ID;                /* BIT_STRING_SIZE_20 */
static int hf_rc_v3_shortMacroNgENB_ID;           /* BIT_STRING_SIZE_18 */
static int hf_rc_v3_longMacroNgENB_ID;            /* BIT_STRING_SIZE_21 */
static int hf_rc_v3_nRCellIdentity;               /* NRCellIdentity */
static int hf_rc_v3_gNB;                          /* GlobalGNB_ID */
static int hf_rc_v3_ng_eNB;                       /* GlobalNgENB_ID */
static int hf_rc_v3_nRARFCN;                      /* INTEGER_0_maxNRARFCN */
static int hf_rc_v3_NRFrequencyBand_List_item;    /* NRFrequencyBandItem */
static int hf_rc_v3_freqBandIndicatorNr;          /* INTEGER_1_1024_ */
static int hf_rc_v3_supportedSULBandList;         /* SupportedSULBandList */
static int hf_rc_v3_nrARFCN;                      /* NR_ARFCN */
static int hf_rc_v3_frequencyBand_List;           /* NRFrequencyBand_List */
static int hf_rc_v3_frequencyShift7p5khz;         /* NRFrequencyShift7p5khz */
static int hf_rc_v3_SupportedSULBandList_item;    /* SupportedSULFreqBandItem */

static int hf_rc_v3_timestamp_string;


static int ett_rc_v3_NeighborCell_List;
static int ett_rc_v3_NeighborCell_Item;
static int ett_rc_v3_NeighborCell_Item_Choice_NR;
static int ett_rc_v3_NeighborCell_Item_Choice_E_UTRA;
static int ett_rc_v3_NeighborRelation_Info;
static int ett_rc_v3_EventTrigger_Cell_Info;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item;
static int ett_rc_v3_EventTrigger_Cell_Info_Item;
static int ett_rc_v3_T_cellType;
static int ett_rc_v3_EventTrigger_Cell_Info_Item_Choice_Individual;
static int ett_rc_v3_EventTrigger_Cell_Info_Item_Choice_Group;
static int ett_rc_v3_EventTrigger_UE_Info;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item;
static int ett_rc_v3_EventTrigger_UE_Info_Item;
static int ett_rc_v3_T_ueType;
static int ett_rc_v3_EventTrigger_UE_Info_Item_Choice_Individual;
static int ett_rc_v3_EventTrigger_UE_Info_Item_Choice_Group;
static int ett_rc_v3_EventTrigger_UEevent_Info;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item;
static int ett_rc_v3_EventTrigger_UEevent_Info_Item;
static int ett_rc_v3_RANParameter_Definition;
static int ett_rc_v3_RANParameter_Definition_Choice;
static int ett_rc_v3_RANParameter_Definition_Choice_LIST;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item;
static int ett_rc_v3_RANParameter_Definition_Choice_LIST_Item;
static int ett_rc_v3_RANParameter_Definition_Choice_STRUCTURE;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item;
static int ett_rc_v3_RANParameter_Definition_Choice_STRUCTURE_Item;
static int ett_rc_v3_RANParameter_Value;
static int ett_rc_v3_RANParameter_ValueType;
static int ett_rc_v3_RANParameter_ValueType_Choice_ElementTrue;
static int ett_rc_v3_RANParameter_ValueType_Choice_ElementFalse;
static int ett_rc_v3_RANParameter_ValueType_Choice_Structure;
static int ett_rc_v3_RANParameter_ValueType_Choice_List;
static int ett_rc_v3_RANParameter_STRUCTURE;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item;
static int ett_rc_v3_RANParameter_STRUCTURE_Item;
static int ett_rc_v3_RANParameter_LIST;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE;
static int ett_rc_v3_RANParameter_Testing;
static int ett_rc_v3_RANParameter_TestingCondition;
static int ett_rc_v3_RANParameter_Testing_Item;
static int ett_rc_v3_T_ranParameter_Type;
static int ett_rc_v3_RANParameter_Testing_Item_Choice_List;
static int ett_rc_v3_RANParameter_Testing_Item_Choice_Structure;
static int ett_rc_v3_RANParameter_Testing_Item_Choice_ElementTrue;
static int ett_rc_v3_RANParameter_Testing_Item_Choice_ElementFalse;
static int ett_rc_v3_RANParameter_Testing_LIST;
static int ett_rc_v3_RANParameter_Testing_STRUCTURE;
static int ett_rc_v3_UE_Group_Definition;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxGroupDefinitionIdentifierParameters_OF_UEGroupDefinitionIdentifier_Item;
static int ett_rc_v3_UEGroupDefinitionIdentifier_Item;
static int ett_rc_v3_RIC_PolicyAction;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item;
static int ett_rc_v3_RIC_PolicyAction_RANParameter_Item;
static int ett_rc_v3_Associated_UE_Info;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_Associated_UE_Info_Item;
static int ett_rc_v3_Associated_UE_Info_Item;
static int ett_rc_v3_T_ueType_01;
static int ett_rc_v3_UEQuery;
static int ett_rc_v3_E2SM_RC_EventTrigger;
static int ett_rc_v3_T_ric_eventTrigger_formats;
static int ett_rc_v3_E2SM_RC_EventTrigger_Format1;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item;
static int ett_rc_v3_E2SM_RC_EventTrigger_Format1_Item;
static int ett_rc_v3_MessageType_Choice;
static int ett_rc_v3_MessageType_Choice_NI;
static int ett_rc_v3_MessageType_Choice_RRC;
static int ett_rc_v3_E2SM_RC_EventTrigger_Format2;
static int ett_rc_v3_E2SM_RC_EventTrigger_Format3;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item;
static int ett_rc_v3_E2SM_RC_EventTrigger_Format3_Item;
static int ett_rc_v3_E2SM_RC_EventTrigger_Format4;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item;
static int ett_rc_v3_E2SM_RC_EventTrigger_Format4_Item;
static int ett_rc_v3_TriggerType_Choice;
static int ett_rc_v3_TriggerType_Choice_RRCstate;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item;
static int ett_rc_v3_TriggerType_Choice_RRCstate_Item;
static int ett_rc_v3_TriggerType_Choice_UEID;
static int ett_rc_v3_TriggerType_Choice_L2state;
static int ett_rc_v3_TriggerType_Choice_UEcontext;
static int ett_rc_v3_TriggerType_Choice_L2MACschChg;
static int ett_rc_v3_L2MACschChgType_Choice;
static int ett_rc_v3_TriggerType_Choice_MIMOandBFconfig;
static int ett_rc_v3_E2SM_RC_ActionDefinition;
static int ett_rc_v3_T_ric_actionDefinition_formats;
static int ett_rc_v3_E2SM_RC_ActionDefinition_Format1;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item;
static int ett_rc_v3_E2SM_RC_ActionDefinition_Format1_Item;
static int ett_rc_v3_E2SM_RC_ActionDefinition_Format2;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item;
static int ett_rc_v3_E2SM_RC_ActionDefinition_Format2_Item;
static int ett_rc_v3_E2SM_RC_ActionDefinition_Format3;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item;
static int ett_rc_v3_E2SM_RC_ActionDefinition_Format3_Item;
static int ett_rc_v3_E2SM_RC_ActionDefinition_Format4;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item;
static int ett_rc_v3_E2SM_RC_ActionDefinition_Format4_Style_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item;
static int ett_rc_v3_E2SM_RC_ActionDefinition_Format4_Indication_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item;
static int ett_rc_v3_E2SM_RC_ActionDefinition_Format4_RANP_Item;
static int ett_rc_v3_E2SM_RC_IndicationHeader;
static int ett_rc_v3_T_ric_indicationHeader_formats;
static int ett_rc_v3_E2SM_RC_IndicationHeader_Format1;
static int ett_rc_v3_E2SM_RC_IndicationHeader_Format2;
static int ett_rc_v3_E2SM_RC_IndicationHeader_Format3;
static int ett_rc_v3_E2SM_RC_IndicationMessage;
static int ett_rc_v3_T_ric_indicationMessage_formats;
static int ett_rc_v3_E2SM_RC_IndicationMessage_Format1;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item;
static int ett_rc_v3_E2SM_RC_IndicationMessage_Format1_Item;
static int ett_rc_v3_E2SM_RC_IndicationMessage_Format2;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item;
static int ett_rc_v3_E2SM_RC_IndicationMessage_Format2_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item;
static int ett_rc_v3_E2SM_RC_IndicationMessage_Format2_RANParameter_Item;
static int ett_rc_v3_E2SM_RC_IndicationMessage_Format3;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item;
static int ett_rc_v3_E2SM_RC_IndicationMessage_Format3_Item;
static int ett_rc_v3_E2SM_RC_IndicationMessage_Format5;
static int ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item;
static int ett_rc_v3_E2SM_RC_IndicationMessage_Format5_Item;
static int ett_rc_v3_E2SM_RC_IndicationMessage_Format6;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item;
static int ett_rc_v3_E2SM_RC_IndicationMessage_Format6_Style_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item;
static int ett_rc_v3_E2SM_RC_IndicationMessage_Format6_Indication_Item;
static int ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item;
static int ett_rc_v3_E2SM_RC_IndicationMessage_Format6_RANP_Item;
static int ett_rc_v3_E2SM_RC_CallProcessID;
static int ett_rc_v3_T_ric_callProcessID_formats;
static int ett_rc_v3_E2SM_RC_CallProcessID_Format1;
static int ett_rc_v3_E2SM_RC_ControlHeader;
static int ett_rc_v3_T_ric_controlHeader_formats;
static int ett_rc_v3_E2SM_RC_ControlHeader_Format1;
static int ett_rc_v3_E2SM_RC_ControlHeader_Format2;
static int ett_rc_v3_E2SM_RC_ControlHeader_Format3;
static int ett_rc_v3_E2SM_RC_ControlHeader_Format4;
static int ett_rc_v3_E2SM_RC_ControlMessage;
static int ett_rc_v3_T_ric_controlMessage_formats;
static int ett_rc_v3_E2SM_RC_ControlMessage_Format1;
static int ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item;
static int ett_rc_v3_E2SM_RC_ControlMessage_Format1_Item;
static int ett_rc_v3_E2SM_RC_ControlMessage_Format2;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item;
static int ett_rc_v3_E2SM_RC_ControlMessage_Format2_Style_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item;
static int ett_rc_v3_E2SM_RC_ControlMessage_Format2_ControlAction_Item;
static int ett_rc_v3_E2SM_RC_ControlMessage_Format3;
static int ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedEntityFilters_OF_E2SM_RC_EntityFilter;
static int ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_EntityAgnostic_ranP_ControlParameters;
static int ett_rc_v3_E2SM_RC_EntityFilter;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_EntitySpecific_ranP_ControlParameters;
static int ett_rc_v3_EntityAgnostic_ranP_ControlParameters;
static int ett_rc_v3_EntitySpecific_ranP_ControlParameters;
static int ett_rc_v3_E2SM_RC_ControlMessage_Format4;
static int ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format4_Item;
static int ett_rc_v3_E2SM_RC_ControlMessage_Format4_Item;
static int ett_rc_v3_E2SM_RC_ControlOutcome;
static int ett_rc_v3_T_ric_controlOutcome_formats;
static int ett_rc_v3_E2SM_RC_ControlOutcome_Format1;
static int ett_rc_v3_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item;
static int ett_rc_v3_E2SM_RC_ControlOutcome_Format1_Item;
static int ett_rc_v3_E2SM_RC_ControlOutcome_Format2;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item;
static int ett_rc_v3_E2SM_RC_ControlOutcome_Format2_Style_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item;
static int ett_rc_v3_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item;
static int ett_rc_v3_E2SM_RC_ControlOutcome_Format2_RANP_Item;
static int ett_rc_v3_E2SM_RC_ControlOutcome_Format3;
static int ett_rc_v3_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item;
static int ett_rc_v3_E2SM_RC_ControlOutcome_Format3_Item;
static int ett_rc_v3_E2SM_RC_QueryHeader;
static int ett_rc_v3_T_ric_queryHeader_formats;
static int ett_rc_v3_E2SM_RC_QueryHeader_Format1;
static int ett_rc_v3_E2SM_RC_QueryDefinition;
static int ett_rc_v3_T_ric_queryDefinition_formats;
static int ett_rc_v3_E2SM_RC_QueryDefinition_Format1;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryDefinition_Format1_Item;
static int ett_rc_v3_E2SM_RC_QueryDefinition_Format1_Item;
static int ett_rc_v3_E2SM_RC_QueryOutcome;
static int ett_rc_v3_T_ric_queryOutcome_formats;
static int ett_rc_v3_E2SM_RC_QueryOutcome_Format1;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_QueryOutcome_Format1_ItemCell;
static int ett_rc_v3_E2SM_RC_QueryOutcome_Format1_ItemCell;
static int ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format1_ItemParameters;
static int ett_rc_v3_E2SM_RC_QueryOutcome_Format1_ItemParameters;
static int ett_rc_v3_E2SM_RC_QueryOutcome_Format2;
static int ett_rc_v3_SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_QueryOutcome_Format2_ItemUE;
static int ett_rc_v3_E2SM_RC_QueryOutcome_Format2_ItemUE;
static int ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format2_ItemParameters;
static int ett_rc_v3_E2SM_RC_QueryOutcome_Format2_ItemParameters;
static int ett_rc_v3_E2SM_RC_RANFunctionDefinition;
static int ett_rc_v3_RANFunctionDefinition_EventTrigger;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item;
static int ett_rc_v3_RANFunctionDefinition_EventTrigger_Style_Item;
static int ett_rc_v3_L2Parameters_RANParameter_Item;
static int ett_rc_v3_UEIdentification_RANParameter_Item;
static int ett_rc_v3_CellIdentification_RANParameter_Item;
static int ett_rc_v3_RANFunctionDefinition_EventTrigger_CallProcess_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item;
static int ett_rc_v3_RANFunctionDefinition_EventTrigger_Breakpoint_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item;
static int ett_rc_v3_CallProcessBreakpoint_RANParameter_Item;
static int ett_rc_v3_RANFunctionDefinition_Report;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item;
static int ett_rc_v3_RANFunctionDefinition_Report_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item;
static int ett_rc_v3_Report_RANParameter_Item;
static int ett_rc_v3_RANFunctionDefinition_Insert;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item;
static int ett_rc_v3_RANFunctionDefinition_Insert_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item;
static int ett_rc_v3_RANFunctionDefinition_Insert_Indication_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item;
static int ett_rc_v3_InsertIndication_RANParameter_Item;
static int ett_rc_v3_RANFunctionDefinition_Control;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item;
static int ett_rc_v3_RANFunctionDefinition_Control_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item;
static int ett_rc_v3_ControlOutcome_RANParameter_Item;
static int ett_rc_v3_RANFunctionDefinition_Control_Action_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item;
static int ett_rc_v3_ControlAction_RANParameter_Item;
static int ett_rc_v3_ListOfAdditionalSupportedFormats;
static int ett_rc_v3_AdditionalSupportedFormat;
static int ett_rc_v3_RANFunctionDefinition_Policy;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item;
static int ett_rc_v3_RANFunctionDefinition_Policy_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item;
static int ett_rc_v3_RANFunctionDefinition_Policy_Action_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item;
static int ett_rc_v3_PolicyAction_RANParameter_Item;
static int ett_rc_v3_PolicyCondition_RANParameter_Item;
static int ett_rc_v3_RANFunctionDefinition_Query;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Query_Item;
static int ett_rc_v3_RANFunctionDefinition_Query_Item;
static int ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Query_RANParameter_Item;
static int ett_rc_v3_Query_RANParameter_Item;
static int ett_rc_v3_Cell_RNTI;
static int ett_rc_v3_CGI;
static int ett_rc_v3_InterfaceIdentifier;
static int ett_rc_v3_InterfaceID_NG;
static int ett_rc_v3_InterfaceID_Xn;
static int ett_rc_v3_InterfaceID_F1;
static int ett_rc_v3_InterfaceID_E1;
static int ett_rc_v3_InterfaceID_S1;
static int ett_rc_v3_InterfaceID_X2;
static int ett_rc_v3_T_nodeType;
static int ett_rc_v3_InterfaceID_W1;
static int ett_rc_v3_Interface_MessageID;
static int ett_rc_v3_PartialUEID;
static int ett_rc_v3_RANfunction_Name;
static int ett_rc_v3_RRC_MessageID;
static int ett_rc_v3_T_rrcType;
static int ett_rc_v3_ServingCell_ARFCN;
static int ett_rc_v3_ServingCell_PCI;
static int ett_rc_v3_UEID;
static int ett_rc_v3_UEID_GNB;
static int ett_rc_v3_UEID_GNB_CU_CP_E1AP_ID_List;
static int ett_rc_v3_UEID_GNB_CU_CP_E1AP_ID_Item;
static int ett_rc_v3_UEID_GNB_CU_F1AP_ID_List;
static int ett_rc_v3_UEID_GNB_CU_CP_F1AP_ID_Item;
static int ett_rc_v3_UEID_GNB_DU;
static int ett_rc_v3_UEID_GNB_CU_UP;
static int ett_rc_v3_UEID_NG_ENB;
static int ett_rc_v3_UEID_NG_ENB_DU;
static int ett_rc_v3_UEID_EN_GNB;
static int ett_rc_v3_UEID_ENB;
static int ett_rc_v3_ENB_ID;
static int ett_rc_v3_GlobalENB_ID;
static int ett_rc_v3_GUMMEI;
static int ett_rc_v3_EN_GNB_ID;
static int ett_rc_v3_GlobalenGNB_ID;
static int ett_rc_v3_EUTRA_CGI;
static int ett_rc_v3_GlobalGNB_ID;
static int ett_rc_v3_GlobalNgENB_ID;
static int ett_rc_v3_GNB_ID;
static int ett_rc_v3_GUAMI;
static int ett_rc_v3_NgENB_ID;
static int ett_rc_v3_NR_CGI;
static int ett_rc_v3_GlobalNGRANNodeID;
static int ett_rc_v3_NR_ARFCN;
static int ett_rc_v3_NRFrequencyBand_List;
static int ett_rc_v3_NRFrequencyBandItem;
static int ett_rc_v3_NRFrequencyInfo;
static int ett_rc_v3_SupportedSULBandList;
static int ett_rc_v3_SupportedSULFreqBandItem;


/* Forward declarations */
static int dissect_E2SM_RC_EventTrigger_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_RANFunctionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_CallProcessID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ControlHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ControlMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_ControlOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static int dissect_E2SM_RC_QueryOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_QueryDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_RC_QueryHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);



/*--- Cyclic dependencies ---*/

/* RANParameter-Testing-Item -> RANParameter-Testing-Item/ranParameter-Type -> RANParameter-Testing-Item-Choice-List -> RANParameter-Testing-LIST -> RANParameter-Testing-Item */
/* RANParameter-Testing-Item -> RANParameter-Testing-Item/ranParameter-Type -> RANParameter-Testing-Item-Choice-Structure -> RANParameter-Testing-STRUCTURE -> RANParameter-Testing-Item */
static int dissect_rc_v3_RANParameter_Testing_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* RANParameter-Definition -> RANParameter-Definition-Choice -> RANParameter-Definition-Choice-LIST -> RANParameter-Definition-Choice-LIST/ranParameter-List -> RANParameter-Definition-Choice-LIST-Item -> RANParameter-Definition */
/* RANParameter-Definition -> RANParameter-Definition-Choice -> RANParameter-Definition-Choice-STRUCTURE -> RANParameter-Definition-Choice-STRUCTURE/ranParameter-STRUCTURE -> RANParameter-Definition-Choice-STRUCTURE-Item -> RANParameter-Definition */
static int dissect_rc_v3_RANParameter_Definition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* RANParameter-ValueType -> RANParameter-ValueType-Choice-Structure -> RANParameter-STRUCTURE -> RANParameter-STRUCTURE/sequence-of-ranParameters -> RANParameter-STRUCTURE-Item -> RANParameter-ValueType */
static int dissect_rc_v3_RANParameter_ValueType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);



static const value_string rc_v3_LogicalOR_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_rc_v3_LogicalOR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_rc_v3_PLMNIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}



static int
dissect_rc_v3_NRCellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NR_CGI_sequence[] = {
  { &hf_rc_v3_pLMNIdentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_PLMNIdentity },
  { &hf_rc_v3_nRCellIdentity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_NRCellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_NR_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_NR_CGI, NR_CGI_sequence);

  return offset;
}



static int
dissect_rc_v3_NR_PCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1007U, NULL, false);

  return offset;
}



static int
dissect_rc_v3_FiveGS_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}


static const value_string rc_v3_T_nR_mode_info_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_nR_mode_info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_rc_v3_INTEGER_0_maxNRARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNRARFCN, NULL, false);

  return offset;
}


static const per_sequence_t NR_ARFCN_sequence[] = {
  { &hf_rc_v3_nRARFCN       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_INTEGER_0_maxNRARFCN },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_NR_ARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_NR_ARFCN, NR_ARFCN_sequence);

  return offset;
}



static int
dissect_rc_v3_INTEGER_1_1024_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, true);

  return offset;
}


static const per_sequence_t SupportedSULFreqBandItem_sequence[] = {
  { &hf_rc_v3_freqBandIndicatorNr, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_INTEGER_1_1024_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_SupportedSULFreqBandItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_SupportedSULFreqBandItem, SupportedSULFreqBandItem_sequence);

  return offset;
}


static const per_sequence_t SupportedSULBandList_sequence_of[1] = {
  { &hf_rc_v3_SupportedSULBandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_SupportedSULFreqBandItem },
};

static int
dissect_rc_v3_SupportedSULBandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SupportedSULBandList, SupportedSULBandList_sequence_of,
                                                  0, maxnoofNrCellBands, false);

  return offset;
}


static const per_sequence_t NRFrequencyBandItem_sequence[] = {
  { &hf_rc_v3_freqBandIndicatorNr, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_INTEGER_1_1024_ },
  { &hf_rc_v3_supportedSULBandList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SupportedSULBandList },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_NRFrequencyBandItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_NRFrequencyBandItem, NRFrequencyBandItem_sequence);

  return offset;
}


static const per_sequence_t NRFrequencyBand_List_sequence_of[1] = {
  { &hf_rc_v3_NRFrequencyBand_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_NRFrequencyBandItem },
};

static int
dissect_rc_v3_NRFrequencyBand_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_NRFrequencyBand_List, NRFrequencyBand_List_sequence_of,
                                                  1, maxnoofNrCellBands, false);

  return offset;
}


static const value_string rc_v3_NRFrequencyShift7p5khz_vals[] = {
  {   0, "false" },
  {   1, "true" },
  { 0, NULL }
};


static int
dissect_rc_v3_NRFrequencyShift7p5khz(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t NRFrequencyInfo_sequence[] = {
  { &hf_rc_v3_nrARFCN       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_NR_ARFCN },
  { &hf_rc_v3_frequencyBand_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_NRFrequencyBand_List },
  { &hf_rc_v3_frequencyShift7p5khz, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_NRFrequencyShift7p5khz },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_NRFrequencyInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_NRFrequencyInfo, NRFrequencyInfo_sequence);

  return offset;
}


static const value_string rc_v3_T_x2_Xn_established_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_x2_Xn_established(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string rc_v3_T_hO_validated_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_hO_validated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_rc_v3_INTEGER_1_65535_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}


static const per_sequence_t NeighborCell_Item_Choice_NR_sequence[] = {
  { &hf_rc_v3_nR_CGI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_NR_CGI },
  { &hf_rc_v3_nR_PCI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_NR_PCI },
  { &hf_rc_v3_fiveGS_TAC    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_FiveGS_TAC },
  { &hf_rc_v3_nR_mode_info  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_nR_mode_info },
  { &hf_rc_v3_nR_FreqInfo   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_NRFrequencyInfo },
  { &hf_rc_v3_x2_Xn_established, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_x2_Xn_established },
  { &hf_rc_v3_hO_validated  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_hO_validated },
  { &hf_rc_v3_version       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_INTEGER_1_65535_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_NeighborCell_Item_Choice_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_NeighborCell_Item_Choice_NR, NeighborCell_Item_Choice_NR_sequence);

  return offset;
}



static int
dissect_rc_v3_EUTRACellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t EUTRA_CGI_sequence[] = {
  { &hf_rc_v3_pLMNIdentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_PLMNIdentity },
  { &hf_rc_v3_eUTRACellIdentity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_EUTRACellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_EUTRA_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_EUTRA_CGI, EUTRA_CGI_sequence);

  return offset;
}



static int
dissect_rc_v3_E_UTRA_PCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 503U, NULL, true);

  return offset;
}



static int
dissect_rc_v3_E_UTRA_ARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxEARFCN, NULL, false);

  return offset;
}



static int
dissect_rc_v3_E_UTRA_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, NULL);

  return offset;
}


static const value_string rc_v3_T_x2_Xn_established_01_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_x2_Xn_established_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string rc_v3_T_hO_validated_01_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_hO_validated_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t NeighborCell_Item_Choice_E_UTRA_sequence[] = {
  { &hf_rc_v3_eUTRA_CGI     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_EUTRA_CGI },
  { &hf_rc_v3_eUTRA_PCI     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_E_UTRA_PCI },
  { &hf_rc_v3_eUTRA_ARFCN   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_E_UTRA_ARFCN },
  { &hf_rc_v3_eUTRA_TAC     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_E_UTRA_TAC },
  { &hf_rc_v3_x2_Xn_established_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_x2_Xn_established_01 },
  { &hf_rc_v3_hO_validated_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_hO_validated_01 },
  { &hf_rc_v3_version       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_INTEGER_1_65535_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_NeighborCell_Item_Choice_E_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_NeighborCell_Item_Choice_E_UTRA, NeighborCell_Item_Choice_E_UTRA_sequence);

  return offset;
}


static const value_string rc_v3_NeighborCell_Item_vals[] = {
  {   0, "ranType-Choice-NR" },
  {   1, "ranType-Choice-EUTRA" },
  { 0, NULL }
};

static const per_choice_t NeighborCell_Item_choice[] = {
  {   0, &hf_rc_v3_ranType_Choice_NR, ASN1_EXTENSION_ROOT    , dissect_rc_v3_NeighborCell_Item_Choice_NR },
  {   1, &hf_rc_v3_ranType_Choice_EUTRA, ASN1_EXTENSION_ROOT    , dissect_rc_v3_NeighborCell_Item_Choice_E_UTRA },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_NeighborCell_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_NeighborCell_Item, NeighborCell_Item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NeighborCell_List_sequence_of[1] = {
  { &hf_rc_v3_NeighborCell_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_NeighborCell_Item },
};

static int
dissect_rc_v3_NeighborCell_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_NeighborCell_List, NeighborCell_List_sequence_of,
                                                  1, maxnoofNeighbourCell, false);

  return offset;
}


static const value_string rc_v3_ServingCell_PCI_vals[] = {
  {   0, "nR" },
  {   1, "eUTRA" },
  { 0, NULL }
};

static const per_choice_t ServingCell_PCI_choice[] = {
  {   0, &hf_rc_v3_nR_02         , ASN1_EXTENSION_ROOT    , dissect_rc_v3_NR_PCI },
  {   1, &hf_rc_v3_eUTRA_01      , ASN1_EXTENSION_ROOT    , dissect_rc_v3_E_UTRA_PCI },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_ServingCell_PCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_ServingCell_PCI, ServingCell_PCI_choice,
                                 NULL);

  return offset;
}


static const value_string rc_v3_ServingCell_ARFCN_vals[] = {
  {   0, "nR" },
  {   1, "eUTRA" },
  { 0, NULL }
};

static const per_choice_t ServingCell_ARFCN_choice[] = {
  {   0, &hf_rc_v3_nR_01         , ASN1_EXTENSION_ROOT    , dissect_rc_v3_NR_ARFCN },
  {   1, &hf_rc_v3_eUTRA         , ASN1_EXTENSION_ROOT    , dissect_rc_v3_E_UTRA_ARFCN },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_ServingCell_ARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_ServingCell_ARFCN, ServingCell_ARFCN_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NeighborRelation_Info_sequence[] = {
  { &hf_rc_v3_servingCellPCI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_ServingCell_PCI },
  { &hf_rc_v3_servingCellARFCN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_ServingCell_ARFCN },
  { &hf_rc_v3_neighborCell_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_NeighborCell_List },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_NeighborRelation_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_NeighborRelation_Info, NeighborRelation_Info_sequence);

  return offset;
}


static const value_string rc_v3_RRC_State_vals[] = {
  {   0, "rrc-connected" },
  {   1, "rrc-inactive" },
  {   2, "rrc-idle" },
  {   3, "any" },
  { 0, NULL }
};


static int
dissect_rc_v3_RRC_State(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_rc_v3_RIC_EventTrigger_Cell_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}


static const value_string rc_v3_CGI_vals[] = {
  {   0, "nR-CGI" },
  {   1, "eUTRA-CGI" },
  { 0, NULL }
};

static const per_choice_t CGI_choice[] = {
  {   0, &hf_rc_v3_nR_CGI        , ASN1_EXTENSION_ROOT    , dissect_rc_v3_NR_CGI },
  {   1, &hf_rc_v3_eUTRA_CGI     , ASN1_EXTENSION_ROOT    , dissect_rc_v3_EUTRA_CGI },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_CGI, CGI_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t EventTrigger_Cell_Info_Item_Choice_Individual_sequence[] = {
  { &hf_rc_v3_cellGlobalID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_CGI },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_EventTrigger_Cell_Info_Item_Choice_Individual(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_EventTrigger_Cell_Info_Item_Choice_Individual, EventTrigger_Cell_Info_Item_Choice_Individual_sequence);

  return offset;
}



static int
dissect_rc_v3_RANParameter_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4294967295U, NULL, true);

  return offset;
}


static const per_sequence_t RANParameter_Testing_LIST_sequence_of[1] = {
  { &hf_rc_v3_RANParameter_Testing_LIST_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Testing_Item },
};

static int
dissect_rc_v3_RANParameter_Testing_LIST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_RANParameter_Testing_LIST, RANParameter_Testing_LIST_sequence_of,
                                                  1, maxnoofItemsinList, false);

  return offset;
}


static const per_sequence_t RANParameter_Testing_Item_Choice_List_sequence[] = {
  { &hf_rc_v3_ranParameter_List_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Testing_LIST },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_Testing_Item_Choice_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_Testing_Item_Choice_List, RANParameter_Testing_Item_Choice_List_sequence);

  return offset;
}


static const per_sequence_t RANParameter_Testing_STRUCTURE_sequence_of[1] = {
  { &hf_rc_v3_RANParameter_Testing_STRUCTURE_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Testing_Item },
};

static int
dissect_rc_v3_RANParameter_Testing_STRUCTURE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_RANParameter_Testing_STRUCTURE, RANParameter_Testing_STRUCTURE_sequence_of,
                                                  1, maxnoofParametersinStructure, false);

  return offset;
}


static const per_sequence_t RANParameter_Testing_Item_Choice_Structure_sequence[] = {
  { &hf_rc_v3_ranParameter_Structure_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Testing_STRUCTURE },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_Testing_Item_Choice_Structure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_Testing_Item_Choice_Structure, RANParameter_Testing_Item_Choice_Structure_sequence);

  return offset;
}



static int
dissect_rc_v3_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_rc_v3_INTEGER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_rc_v3_REAL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_real(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_rc_v3_BIT_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_rc_v3_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}



static int
dissect_rc_v3_PrintableString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND, false,
                                          NULL);

  return offset;
}


static const value_string rc_v3_RANParameter_Value_vals[] = {
  {   0, "valueBoolean" },
  {   1, "valueInt" },
  {   2, "valueReal" },
  {   3, "valueBitS" },
  {   4, "valueOctS" },
  {   5, "valuePrintableString" },
  { 0, NULL }
};

static const per_choice_t RANParameter_Value_choice[] = {
  {   0, &hf_rc_v3_valueBoolean  , ASN1_EXTENSION_ROOT    , dissect_rc_v3_BOOLEAN },
  {   1, &hf_rc_v3_valueInt      , ASN1_EXTENSION_ROOT    , dissect_rc_v3_INTEGER },
  {   2, &hf_rc_v3_valueReal     , ASN1_EXTENSION_ROOT    , dissect_rc_v3_REAL },
  {   3, &hf_rc_v3_valueBitS     , ASN1_EXTENSION_ROOT    , dissect_rc_v3_BIT_STRING },
  {   4, &hf_rc_v3_valueOctS     , ASN1_EXTENSION_ROOT    , dissect_rc_v3_OCTET_STRING },
  {   5, &hf_rc_v3_valuePrintableString, ASN1_EXTENSION_ROOT    , dissect_rc_v3_PrintableString },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_Value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_RANParameter_Value, RANParameter_Value_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RANParameter_Testing_Item_Choice_ElementTrue_sequence[] = {
  { &hf_rc_v3_ranParameter_value, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_Testing_Item_Choice_ElementTrue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_Testing_Item_Choice_ElementTrue, RANParameter_Testing_Item_Choice_ElementTrue_sequence);

  return offset;
}


static const value_string rc_v3_T_ranP_Choice_comparison_vals[] = {
  {   0, "equal" },
  {   1, "difference" },
  {   2, "greaterthan" },
  {   3, "lessthan" },
  {   4, "contains" },
  {   5, "starts-with" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_ranP_Choice_comparison(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}


static const value_string rc_v3_T_ranP_Choice_presence_vals[] = {
  {   0, "present" },
  {   1, "configured" },
  {   2, "rollover" },
  {   3, "non-zero" },
  {   4, "value-change" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_ranP_Choice_presence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 1, NULL);

  return offset;
}


static const value_string rc_v3_RANParameter_TestingCondition_vals[] = {
  {   0, "ranP-Choice-comparison" },
  {   1, "ranP-Choice-presence" },
  { 0, NULL }
};

static const per_choice_t RANParameter_TestingCondition_choice[] = {
  {   0, &hf_rc_v3_ranP_Choice_comparison, ASN1_EXTENSION_ROOT    , dissect_rc_v3_T_ranP_Choice_comparison },
  {   1, &hf_rc_v3_ranP_Choice_presence, ASN1_EXTENSION_ROOT    , dissect_rc_v3_T_ranP_Choice_presence },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_TestingCondition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_RANParameter_TestingCondition, RANParameter_TestingCondition_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RANParameter_Testing_Item_Choice_ElementFalse_sequence[] = {
  { &hf_rc_v3_ranParameter_TestCondition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_TestingCondition },
  { &hf_rc_v3_ranParameter_Value, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Value },
  { &hf_rc_v3_logicalOR     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_Testing_Item_Choice_ElementFalse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_Testing_Item_Choice_ElementFalse, RANParameter_Testing_Item_Choice_ElementFalse_sequence);

  return offset;
}


static const value_string rc_v3_T_ranParameter_Type_vals[] = {
  {   0, "ranP-Choice-List" },
  {   1, "ranP-Choice-Structure" },
  {   2, "ranP-Choice-ElementTrue" },
  {   3, "ranP-Choice-ElementFalse" },
  { 0, NULL }
};

static const per_choice_t T_ranParameter_Type_choice[] = {
  {   0, &hf_rc_v3_ranP_Choice_List_01, ASN1_EXTENSION_ROOT    , dissect_rc_v3_RANParameter_Testing_Item_Choice_List },
  {   1, &hf_rc_v3_ranP_Choice_Structure_01, ASN1_EXTENSION_ROOT    , dissect_rc_v3_RANParameter_Testing_Item_Choice_Structure },
  {   2, &hf_rc_v3_ranP_Choice_ElementTrue_01, ASN1_EXTENSION_ROOT    , dissect_rc_v3_RANParameter_Testing_Item_Choice_ElementTrue },
  {   3, &hf_rc_v3_ranP_Choice_ElementFalse_01, ASN1_EXTENSION_ROOT    , dissect_rc_v3_RANParameter_Testing_Item_Choice_ElementFalse },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ranParameter_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ranParameter_Type, T_ranParameter_Type_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RANParameter_Testing_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ranParameter_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_Testing_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // RANParameter-Testing-Item -> RANParameter-Testing-Item/ranParameter-Type -> RANParameter-Testing-Item-Choice-List -> RANParameter-Testing-LIST -> RANParameter-Testing-Item
  actx->pinfo->dissection_depth += 4;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_Testing_Item, RANParameter_Testing_Item_sequence);

  actx->pinfo->dissection_depth -= 4;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const per_sequence_t RANParameter_Testing_sequence_of[1] = {
  { &hf_rc_v3_RANParameter_Testing_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Testing_Item },
};

static int
dissect_rc_v3_RANParameter_Testing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_RANParameter_Testing, RANParameter_Testing_sequence_of,
                                                  1, maxnoofRANparamTest, false);

  return offset;
}


static const per_sequence_t EventTrigger_Cell_Info_Item_Choice_Group_sequence[] = {
  { &hf_rc_v3_ranParameterTesting, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Testing },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_EventTrigger_Cell_Info_Item_Choice_Group(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_EventTrigger_Cell_Info_Item_Choice_Group, EventTrigger_Cell_Info_Item_Choice_Group_sequence);

  return offset;
}


static const value_string rc_v3_T_cellType_vals[] = {
  {   0, "cellType-Choice-Individual" },
  {   1, "cellType-Choice-Group" },
  { 0, NULL }
};

static const per_choice_t T_cellType_choice[] = {
  {   0, &hf_rc_v3_cellType_Choice_Individual, ASN1_EXTENSION_ROOT    , dissect_rc_v3_EventTrigger_Cell_Info_Item_Choice_Individual },
  {   1, &hf_rc_v3_cellType_Choice_Group, ASN1_EXTENSION_ROOT    , dissect_rc_v3_EventTrigger_Cell_Info_Item_Choice_Group },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_cellType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_cellType, T_cellType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t EventTrigger_Cell_Info_Item_sequence[] = {
  { &hf_rc_v3_eventTriggerCellID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_EventTrigger_Cell_ID },
  { &hf_rc_v3_cellType      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_cellType },
  { &hf_rc_v3_logicalOR     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_EventTrigger_Cell_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_EventTrigger_Cell_Info_Item, EventTrigger_Cell_Info_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item_sequence_of[1] = {
  { &hf_rc_v3_cellInfo_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_EventTrigger_Cell_Info_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item, SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item_sequence_of,
                                                  1, maxnoofCellInfo, false);

  return offset;
}


static const per_sequence_t EventTrigger_Cell_Info_sequence[] = {
  { &hf_rc_v3_cellInfo_List , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_EventTrigger_Cell_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_EventTrigger_Cell_Info, EventTrigger_Cell_Info_sequence);

  return offset;
}



static int
dissect_rc_v3_RIC_EventTrigger_UE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_rc_v3_AMF_UE_NGAP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(1099511627775), NULL, false);

  return offset;
}



static int
dissect_rc_v3_AMFRegionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_rc_v3_AMFSetID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_rc_v3_AMFPointer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GUAMI_sequence[] = {
  { &hf_rc_v3_pLMNIdentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_PLMNIdentity },
  { &hf_rc_v3_aMFRegionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_AMFRegionID },
  { &hf_rc_v3_aMFSetID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_AMFSetID },
  { &hf_rc_v3_aMFPointer    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_AMFPointer },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_GUAMI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_GUAMI, GUAMI_sequence);

  return offset;
}



static int
dissect_rc_v3_GNB_CU_UE_F1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_CP_F1AP_ID_Item_sequence[] = {
  { &hf_rc_v3_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GNB_CU_UE_F1AP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_UEID_GNB_CU_CP_F1AP_ID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_UEID_GNB_CU_CP_F1AP_ID_Item, UEID_GNB_CU_CP_F1AP_ID_Item_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_F1AP_ID_List_sequence_of[1] = {
  { &hf_rc_v3_UEID_GNB_CU_F1AP_ID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_UEID_GNB_CU_CP_F1AP_ID_Item },
};

static int
dissect_rc_v3_UEID_GNB_CU_F1AP_ID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_UEID_GNB_CU_F1AP_ID_List, UEID_GNB_CU_F1AP_ID_List_sequence_of,
                                                  1, maxF1APid, false);

  return offset;
}



static int
dissect_rc_v3_GNB_CU_CP_UE_E1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_CP_E1AP_ID_Item_sequence[] = {
  { &hf_rc_v3_gNB_CU_CP_UE_E1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GNB_CU_CP_UE_E1AP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_UEID_GNB_CU_CP_E1AP_ID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_UEID_GNB_CU_CP_E1AP_ID_Item, UEID_GNB_CU_CP_E1AP_ID_Item_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_CP_E1AP_ID_List_sequence_of[1] = {
  { &hf_rc_v3_UEID_GNB_CU_CP_E1AP_ID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_UEID_GNB_CU_CP_E1AP_ID_Item },
};

static int
dissect_rc_v3_UEID_GNB_CU_CP_E1AP_ID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_UEID_GNB_CU_CP_E1AP_ID_List, UEID_GNB_CU_CP_E1AP_ID_List_sequence_of,
                                                  1, maxE1APid, false);

  return offset;
}



static int
dissect_rc_v3_RANUEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}



static int
dissect_rc_v3_NG_RANnodeUEXnAPID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_rc_v3_BIT_STRING_SIZE_22_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     22, 32, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string rc_v3_GNB_ID_vals[] = {
  {   0, "gNB-ID" },
  { 0, NULL }
};

static const per_choice_t GNB_ID_choice[] = {
  {   0, &hf_rc_v3_gNB_ID        , ASN1_EXTENSION_ROOT    , dissect_rc_v3_BIT_STRING_SIZE_22_32 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_GNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_GNB_ID, GNB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalGNB_ID_sequence[] = {
  { &hf_rc_v3_pLMNIdentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_PLMNIdentity },
  { &hf_rc_v3_gNB_ID_choice , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GNB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_GlobalGNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_GlobalGNB_ID, GlobalGNB_ID_sequence);

  return offset;
}



static int
dissect_rc_v3_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_rc_v3_BIT_STRING_SIZE_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     18, 18, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_rc_v3_BIT_STRING_SIZE_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     21, 21, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string rc_v3_NgENB_ID_vals[] = {
  {   0, "macroNgENB-ID" },
  {   1, "shortMacroNgENB-ID" },
  {   2, "longMacroNgENB-ID" },
  { 0, NULL }
};

static const per_choice_t NgENB_ID_choice[] = {
  {   0, &hf_rc_v3_macroNgENB_ID , ASN1_EXTENSION_ROOT    , dissect_rc_v3_BIT_STRING_SIZE_20 },
  {   1, &hf_rc_v3_shortMacroNgENB_ID, ASN1_EXTENSION_ROOT    , dissect_rc_v3_BIT_STRING_SIZE_18 },
  {   2, &hf_rc_v3_longMacroNgENB_ID, ASN1_EXTENSION_ROOT    , dissect_rc_v3_BIT_STRING_SIZE_21 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_NgENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_NgENB_ID, NgENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalNgENB_ID_sequence[] = {
  { &hf_rc_v3_pLMNIdentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_PLMNIdentity },
  { &hf_rc_v3_ngENB_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_NgENB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_GlobalNgENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_GlobalNgENB_ID, GlobalNgENB_ID_sequence);

  return offset;
}


static const value_string rc_v3_GlobalNGRANNodeID_vals[] = {
  {   0, "gNB" },
  {   1, "ng-eNB" },
  { 0, NULL }
};

static const per_choice_t GlobalNGRANNodeID_choice[] = {
  {   0, &hf_rc_v3_gNB           , ASN1_EXTENSION_ROOT    , dissect_rc_v3_GlobalGNB_ID },
  {   1, &hf_rc_v3_ng_eNB        , ASN1_EXTENSION_ROOT    , dissect_rc_v3_GlobalNgENB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_GlobalNGRANNodeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_GlobalNGRANNodeID, GlobalNGRANNodeID_choice,
                                 NULL);

  return offset;
}



static int
dissect_rc_v3_RNTI_Value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const per_sequence_t Cell_RNTI_sequence[] = {
  { &hf_rc_v3_c_RNTI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RNTI_Value },
  { &hf_rc_v3_cell_Global_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_CGI },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_Cell_RNTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_Cell_RNTI, Cell_RNTI_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_sequence[] = {
  { &hf_rc_v3_amf_UE_NGAP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_AMF_UE_NGAP_ID },
  { &hf_rc_v3_guami         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GUAMI },
  { &hf_rc_v3_gNB_CU_UE_F1AP_ID_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_UEID_GNB_CU_F1AP_ID_List },
  { &hf_rc_v3_gNB_CU_CP_UE_E1AP_ID_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_UEID_GNB_CU_CP_E1AP_ID_List },
  { &hf_rc_v3_ran_UEID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANUEID },
  { &hf_rc_v3_m_NG_RAN_UE_XnAP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_NG_RANnodeUEXnAPID },
  { &hf_rc_v3_globalGNB_ID  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_GlobalGNB_ID },
  { &hf_rc_v3_globalNG_RANNode_ID, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_GlobalNGRANNodeID },
  { &hf_rc_v3_cell_RNTI     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_Cell_RNTI },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_UEID_GNB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_UEID_GNB, UEID_GNB_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_DU_sequence[] = {
  { &hf_rc_v3_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GNB_CU_UE_F1AP_ID },
  { &hf_rc_v3_ran_UEID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANUEID },
  { &hf_rc_v3_cell_RNTI     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_Cell_RNTI },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_UEID_GNB_DU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_UEID_GNB_DU, UEID_GNB_DU_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_UP_sequence[] = {
  { &hf_rc_v3_gNB_CU_CP_UE_E1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GNB_CU_CP_UE_E1AP_ID },
  { &hf_rc_v3_ran_UEID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANUEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_UEID_GNB_CU_UP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_UEID_GNB_CU_UP, UEID_GNB_CU_UP_sequence);

  return offset;
}



static int
dissect_rc_v3_NGENB_CU_UE_W1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_NG_ENB_sequence[] = {
  { &hf_rc_v3_amf_UE_NGAP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_AMF_UE_NGAP_ID },
  { &hf_rc_v3_guami         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GUAMI },
  { &hf_rc_v3_ng_eNB_CU_UE_W1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_NGENB_CU_UE_W1AP_ID },
  { &hf_rc_v3_m_NG_RAN_UE_XnAP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_NG_RANnodeUEXnAPID },
  { &hf_rc_v3_globalNgENB_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_GlobalNgENB_ID },
  { &hf_rc_v3_globalNG_RANNode_ID, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_GlobalNGRANNodeID },
  { &hf_rc_v3_cell_RNTI     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_Cell_RNTI },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_UEID_NG_ENB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_UEID_NG_ENB, UEID_NG_ENB_sequence);

  return offset;
}


static const per_sequence_t UEID_NG_ENB_DU_sequence[] = {
  { &hf_rc_v3_ng_eNB_CU_UE_W1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_NGENB_CU_UE_W1AP_ID },
  { &hf_rc_v3_cell_RNTI     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_Cell_RNTI },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_UEID_NG_ENB_DU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_UEID_NG_ENB_DU, UEID_NG_ENB_DU_sequence);

  return offset;
}



static int
dissect_rc_v3_ENB_UE_X2AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}



static int
dissect_rc_v3_ENB_UE_X2AP_ID_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, true);

  return offset;
}



static int
dissect_rc_v3_BIT_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string rc_v3_ENB_ID_vals[] = {
  {   0, "macro-eNB-ID" },
  {   1, "home-eNB-ID" },
  {   2, "short-Macro-eNB-ID" },
  {   3, "long-Macro-eNB-ID" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_choice[] = {
  {   0, &hf_rc_v3_macro_eNB_ID  , ASN1_EXTENSION_ROOT    , dissect_rc_v3_BIT_STRING_SIZE_20 },
  {   1, &hf_rc_v3_home_eNB_ID   , ASN1_EXTENSION_ROOT    , dissect_rc_v3_BIT_STRING_SIZE_28 },
  {   2, &hf_rc_v3_short_Macro_eNB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_BIT_STRING_SIZE_18 },
  {   3, &hf_rc_v3_long_Macro_eNB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_BIT_STRING_SIZE_21 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_ENB_ID, ENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalENB_ID_sequence[] = {
  { &hf_rc_v3_pLMNIdentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_PLMNIdentity },
  { &hf_rc_v3_eNB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_ENB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_GlobalENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_GlobalENB_ID, GlobalENB_ID_sequence);

  return offset;
}


static const per_sequence_t UEID_EN_GNB_sequence[] = {
  { &hf_rc_v3_m_eNB_UE_X2AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_ENB_UE_X2AP_ID },
  { &hf_rc_v3_m_eNB_UE_X2AP_ID_Extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_ENB_UE_X2AP_ID_Extension },
  { &hf_rc_v3_globalENB_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GlobalENB_ID },
  { &hf_rc_v3_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_GNB_CU_UE_F1AP_ID },
  { &hf_rc_v3_gNB_CU_CP_UE_E1AP_ID_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_UEID_GNB_CU_CP_E1AP_ID_List },
  { &hf_rc_v3_ran_UEID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANUEID },
  { &hf_rc_v3_cell_RNTI     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_Cell_RNTI },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_UEID_EN_GNB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_UEID_EN_GNB, UEID_EN_GNB_sequence);

  return offset;
}



static int
dissect_rc_v3_MME_UE_S1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_rc_v3_MME_Group_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, NULL);

  return offset;
}



static int
dissect_rc_v3_MME_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const per_sequence_t GUMMEI_sequence[] = {
  { &hf_rc_v3_pLMN_Identity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_PLMNIdentity },
  { &hf_rc_v3_mME_Group_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_MME_Group_ID },
  { &hf_rc_v3_mME_Code      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_MME_Code },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_GUMMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_GUMMEI, GUMMEI_sequence);

  return offset;
}


static const per_sequence_t UEID_ENB_sequence[] = {
  { &hf_rc_v3_mME_UE_S1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_MME_UE_S1AP_ID },
  { &hf_rc_v3_gUMMEI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GUMMEI },
  { &hf_rc_v3_m_eNB_UE_X2AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_ENB_UE_X2AP_ID },
  { &hf_rc_v3_m_eNB_UE_X2AP_ID_Extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_ENB_UE_X2AP_ID_Extension },
  { &hf_rc_v3_globalENB_ID  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_GlobalENB_ID },
  { &hf_rc_v3_cell_RNTI     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_Cell_RNTI },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_UEID_ENB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_UEID_ENB, UEID_ENB_sequence);

  return offset;
}


static const value_string rc_v3_UEID_vals[] = {
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
  {   0, &hf_rc_v3_gNB_UEID      , ASN1_EXTENSION_ROOT    , dissect_rc_v3_UEID_GNB },
  {   1, &hf_rc_v3_gNB_DU_UEID   , ASN1_EXTENSION_ROOT    , dissect_rc_v3_UEID_GNB_DU },
  {   2, &hf_rc_v3_gNB_CU_UP_UEID, ASN1_EXTENSION_ROOT    , dissect_rc_v3_UEID_GNB_CU_UP },
  {   3, &hf_rc_v3_ng_eNB_UEID   , ASN1_EXTENSION_ROOT    , dissect_rc_v3_UEID_NG_ENB },
  {   4, &hf_rc_v3_ng_eNB_DU_UEID, ASN1_EXTENSION_ROOT    , dissect_rc_v3_UEID_NG_ENB_DU },
  {   5, &hf_rc_v3_en_gNB_UEID   , ASN1_EXTENSION_ROOT    , dissect_rc_v3_UEID_EN_GNB },
  {   6, &hf_rc_v3_eNB_UEID      , ASN1_EXTENSION_ROOT    , dissect_rc_v3_UEID_ENB },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_UEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_UEID, UEID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t EventTrigger_UE_Info_Item_Choice_Individual_sequence[] = {
  { &hf_rc_v3_ueID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_UEID },
  { &hf_rc_v3_ranParameterTesting, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Testing },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_EventTrigger_UE_Info_Item_Choice_Individual(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_EventTrigger_UE_Info_Item_Choice_Individual, EventTrigger_UE_Info_Item_Choice_Individual_sequence);

  return offset;
}


static const per_sequence_t EventTrigger_UE_Info_Item_Choice_Group_sequence[] = {
  { &hf_rc_v3_ranParameterTesting, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Testing },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_EventTrigger_UE_Info_Item_Choice_Group(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_EventTrigger_UE_Info_Item_Choice_Group, EventTrigger_UE_Info_Item_Choice_Group_sequence);

  return offset;
}


static const value_string rc_v3_T_ueType_vals[] = {
  {   0, "ueType-Choice-Individual" },
  {   1, "ueType-Choice-Group" },
  { 0, NULL }
};

static const per_choice_t T_ueType_choice[] = {
  {   0, &hf_rc_v3_ueType_Choice_Individual, ASN1_EXTENSION_ROOT    , dissect_rc_v3_EventTrigger_UE_Info_Item_Choice_Individual },
  {   1, &hf_rc_v3_ueType_Choice_Group, ASN1_EXTENSION_ROOT    , dissect_rc_v3_EventTrigger_UE_Info_Item_Choice_Group },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ueType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ueType, T_ueType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t EventTrigger_UE_Info_Item_sequence[] = {
  { &hf_rc_v3_eventTriggerUEID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_EventTrigger_UE_ID },
  { &hf_rc_v3_ueType        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ueType },
  { &hf_rc_v3_logicalOR     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_EventTrigger_UE_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_EventTrigger_UE_Info_Item, EventTrigger_UE_Info_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item_sequence_of[1] = {
  { &hf_rc_v3_ueInfo_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_EventTrigger_UE_Info_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item, SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item_sequence_of,
                                                  1, maxnoofUEInfo, false);

  return offset;
}


static const per_sequence_t EventTrigger_UE_Info_sequence[] = {
  { &hf_rc_v3_ueInfo_List   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_EventTrigger_UE_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_EventTrigger_UE_Info, EventTrigger_UE_Info_sequence);

  return offset;
}



static int
dissect_rc_v3_RIC_EventTrigger_UEevent_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}


static const per_sequence_t EventTrigger_UEevent_Info_Item_sequence[] = {
  { &hf_rc_v3_ueEventID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_EventTrigger_UEevent_ID },
  { &hf_rc_v3_logicalOR     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_EventTrigger_UEevent_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_EventTrigger_UEevent_Info_Item, EventTrigger_UEevent_Info_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item_sequence_of[1] = {
  { &hf_rc_v3_ueEvent_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_EventTrigger_UEevent_Info_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item, SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item_sequence_of,
                                                  1, maxnoofUEeventInfo, false);

  return offset;
}


static const per_sequence_t EventTrigger_UEevent_Info_sequence[] = {
  { &hf_rc_v3_ueEvent_List  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_EventTrigger_UEevent_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_EventTrigger_UEevent_Info, EventTrigger_UEevent_Info_sequence);

  return offset;
}



static int
dissect_rc_v3_RANParameter_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}


static const per_sequence_t RANParameter_Definition_Choice_LIST_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Name },
  { &hf_rc_v3_ranParameter_Definition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_Definition_Choice_LIST_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_Definition_Choice_LIST_Item, RANParameter_Definition_Choice_LIST_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item_sequence_of[1] = {
  { &hf_rc_v3_ranParameter_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Definition_Choice_LIST_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item, SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item_sequence_of,
                                                  1, maxnoofItemsinList, false);

  return offset;
}


static const per_sequence_t RANParameter_Definition_Choice_LIST_sequence[] = {
  { &hf_rc_v3_ranParameter_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_Definition_Choice_LIST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_Definition_Choice_LIST, RANParameter_Definition_Choice_LIST_sequence);

  return offset;
}


static const per_sequence_t RANParameter_Definition_Choice_STRUCTURE_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Name },
  { &hf_rc_v3_ranParameter_Definition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_Definition_Choice_STRUCTURE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_Definition_Choice_STRUCTURE_Item, RANParameter_Definition_Choice_STRUCTURE_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item_sequence_of[1] = {
  { &hf_rc_v3_ranParameter_STRUCTURE_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Definition_Choice_STRUCTURE_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item, SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item_sequence_of,
                                                  1, maxnoofParametersinStructure, false);

  return offset;
}


static const per_sequence_t RANParameter_Definition_Choice_STRUCTURE_sequence[] = {
  { &hf_rc_v3_ranParameter_STRUCTURE, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_Definition_Choice_STRUCTURE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_Definition_Choice_STRUCTURE, RANParameter_Definition_Choice_STRUCTURE_sequence);

  return offset;
}


static const value_string rc_v3_RANParameter_Definition_Choice_vals[] = {
  {   0, "choiceLIST" },
  {   1, "choiceSTRUCTURE" },
  { 0, NULL }
};

static const per_choice_t RANParameter_Definition_Choice_choice[] = {
  {   0, &hf_rc_v3_choiceLIST    , ASN1_EXTENSION_ROOT    , dissect_rc_v3_RANParameter_Definition_Choice_LIST },
  {   1, &hf_rc_v3_choiceSTRUCTURE, ASN1_EXTENSION_ROOT    , dissect_rc_v3_RANParameter_Definition_Choice_STRUCTURE },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_Definition_Choice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_RANParameter_Definition_Choice, RANParameter_Definition_Choice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RANParameter_Definition_sequence[] = {
  { &hf_rc_v3_ranParameter_Definition_Choice, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Definition_Choice },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_Definition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // RANParameter-Definition -> RANParameter-Definition-Choice -> RANParameter-Definition-Choice-LIST -> RANParameter-Definition-Choice-LIST/ranParameter-List -> RANParameter-Definition-Choice-LIST-Item -> RANParameter-Definition
  actx->pinfo->dissection_depth += 5;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_Definition, RANParameter_Definition_sequence);

  actx->pinfo->dissection_depth -= 5;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const per_sequence_t RANParameter_ValueType_Choice_ElementTrue_sequence[] = {
  { &hf_rc_v3_ranParameter_value, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_ValueType_Choice_ElementTrue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_ValueType_Choice_ElementTrue, RANParameter_ValueType_Choice_ElementTrue_sequence);

  return offset;
}


static const per_sequence_t RANParameter_ValueType_Choice_ElementFalse_sequence[] = {
  { &hf_rc_v3_ranParameter_value, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_ValueType_Choice_ElementFalse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_ValueType_Choice_ElementFalse, RANParameter_ValueType_Choice_ElementFalse_sequence);

  return offset;
}


static const per_sequence_t RANParameter_STRUCTURE_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_STRUCTURE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_STRUCTURE_Item, RANParameter_STRUCTURE_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item_sequence_of[1] = {
  { &hf_rc_v3_sequence_of_ranParameters_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_STRUCTURE_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item, SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item_sequence_of,
                                                  1, maxnoofParametersinStructure, false);

  return offset;
}


static const per_sequence_t RANParameter_STRUCTURE_sequence[] = {
  { &hf_rc_v3_sequence_of_ranParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_STRUCTURE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_STRUCTURE, RANParameter_STRUCTURE_sequence);

  return offset;
}


static const per_sequence_t RANParameter_ValueType_Choice_Structure_sequence[] = {
  { &hf_rc_v3_ranParameter_Structure, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_STRUCTURE },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_ValueType_Choice_Structure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_ValueType_Choice_Structure, RANParameter_ValueType_Choice_Structure_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE_sequence_of[1] = {
  { &hf_rc_v3_list_of_ranParameter_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_STRUCTURE },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE, SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE_sequence_of,
                                                  1, maxnoofItemsinList, false);

  return offset;
}


static const per_sequence_t RANParameter_LIST_sequence[] = {
  { &hf_rc_v3_list_of_ranParameter, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_LIST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_LIST, RANParameter_LIST_sequence);

  return offset;
}


static const per_sequence_t RANParameter_ValueType_Choice_List_sequence[] = {
  { &hf_rc_v3_ranParameter_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_LIST },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_ValueType_Choice_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANParameter_ValueType_Choice_List, RANParameter_ValueType_Choice_List_sequence);

  return offset;
}


static const value_string rc_v3_RANParameter_ValueType_vals[] = {
  {   0, "ranP-Choice-ElementTrue" },
  {   1, "ranP-Choice-ElementFalse" },
  {   2, "ranP-Choice-Structure" },
  {   3, "ranP-Choice-List" },
  { 0, NULL }
};

static const per_choice_t RANParameter_ValueType_choice[] = {
  {   0, &hf_rc_v3_ranP_Choice_ElementTrue, ASN1_EXTENSION_ROOT    , dissect_rc_v3_RANParameter_ValueType_Choice_ElementTrue },
  {   1, &hf_rc_v3_ranP_Choice_ElementFalse, ASN1_EXTENSION_ROOT    , dissect_rc_v3_RANParameter_ValueType_Choice_ElementFalse },
  {   2, &hf_rc_v3_ranP_Choice_Structure, ASN1_EXTENSION_ROOT    , dissect_rc_v3_RANParameter_ValueType_Choice_Structure },
  {   3, &hf_rc_v3_ranP_Choice_List, ASN1_EXTENSION_ROOT    , dissect_rc_v3_RANParameter_ValueType_Choice_List },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_RANParameter_ValueType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // RANParameter-ValueType -> RANParameter-ValueType-Choice-Structure -> RANParameter-STRUCTURE -> RANParameter-STRUCTURE/sequence-of-ranParameters -> RANParameter-STRUCTURE-Item -> RANParameter-ValueType
  actx->pinfo->dissection_depth += 5;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_RANParameter_ValueType, RANParameter_ValueType_choice,
                                 NULL);

  actx->pinfo->dissection_depth -= 5;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const per_sequence_t UEGroupDefinitionIdentifier_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ValueType },
  { &hf_rc_v3_logicalOR     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_UEGroupDefinitionIdentifier_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_UEGroupDefinitionIdentifier_Item, UEGroupDefinitionIdentifier_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxGroupDefinitionIdentifierParameters_OF_UEGroupDefinitionIdentifier_Item_sequence_of[1] = {
  { &hf_rc_v3_ueGroupDefinitionIdentifier_LIST_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_UEGroupDefinitionIdentifier_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxGroupDefinitionIdentifierParameters_OF_UEGroupDefinitionIdentifier_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxGroupDefinitionIdentifierParameters_OF_UEGroupDefinitionIdentifier_Item, SEQUENCE_SIZE_1_maxGroupDefinitionIdentifierParameters_OF_UEGroupDefinitionIdentifier_Item_sequence_of,
                                                  1, maxGroupDefinitionIdentifierParameters, false);

  return offset;
}


static const per_sequence_t UE_Group_Definition_sequence[] = {
  { &hf_rc_v3_ueGroupDefinitionIdentifier_LIST, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxGroupDefinitionIdentifierParameters_OF_UEGroupDefinitionIdentifier_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_UE_Group_Definition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_UE_Group_Definition, UE_Group_Definition_sequence);

  return offset;
}



static int
dissect_rc_v3_RAN_CallProcess_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4294967295U, NULL, true);

  return offset;
}



static int
dissect_rc_v3_RIC_CallProcessType_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_rc_v3_RIC_CallProcessType_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_rc_v3_RIC_CallProcessBreakpoint_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_rc_v3_RIC_CallProcessBreakpoint_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_rc_v3_RIC_ControlAction_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_rc_v3_RIC_ControlAction_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_rc_v3_RIC_EventTriggerCondition_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_rc_v3_RIC_InsertIndication_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_rc_v3_RIC_InsertIndication_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_rc_v3_UE_Group_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_rc_v3_EntityFilter_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, true);

  return offset;
}


static const per_sequence_t RIC_PolicyAction_RANParameter_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RIC_PolicyAction_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RIC_PolicyAction_RANParameter_Item, RIC_PolicyAction_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item_sequence_of[1] = {
  { &hf_rc_v3_ranParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_PolicyAction_RANParameter_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const value_string rc_v3_T_ric_PolicyDecision_vals[] = {
  {   0, "accept" },
  {   1, "reject" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_ric_PolicyDecision(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t RIC_PolicyAction_sequence[] = {
  { &hf_rc_v3_ric_PolicyAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_ControlAction_ID },
  { &hf_rc_v3_ranParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item },
  { &hf_rc_v3_ric_PolicyDecision, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_T_ric_PolicyDecision },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RIC_PolicyAction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RIC_PolicyAction, RIC_PolicyAction_sequence);

  return offset;
}



static int
dissect_rc_v3_UE_Filter_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}


static const per_sequence_t PartialUEID_sequence[] = {
  { &hf_rc_v3_amf_UE_NGAP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_AMF_UE_NGAP_ID },
  { &hf_rc_v3_guami         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_GUAMI },
  { &hf_rc_v3_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_GNB_CU_UE_F1AP_ID },
  { &hf_rc_v3_gNB_CU_CP_UE_E1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_GNB_CU_CP_UE_E1AP_ID },
  { &hf_rc_v3_ran_UEID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANUEID },
  { &hf_rc_v3_m_NG_RAN_UE_XnAP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_NG_RANnodeUEXnAPID },
  { &hf_rc_v3_globalNG_RANNode_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_GlobalNGRANNodeID },
  { &hf_rc_v3_cell_RNTI     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_Cell_RNTI },
  { &hf_rc_v3_ng_eNB_CU_UE_W1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_NGENB_CU_UE_W1AP_ID },
  { &hf_rc_v3_m_eNB_UE_X2AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_ENB_UE_X2AP_ID },
  { &hf_rc_v3_m_eNB_UE_X2AP_ID_Extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_ENB_UE_X2AP_ID_Extension },
  { &hf_rc_v3_globalENB_ID  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_GlobalENB_ID },
  { &hf_rc_v3_mME_UE_S1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_MME_UE_S1AP_ID },
  { &hf_rc_v3_gUMMEI        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_GUMMEI },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_PartialUEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_PartialUEID, PartialUEID_sequence);

  return offset;
}


static const per_sequence_t UEQuery_sequence[] = {
  { &hf_rc_v3_partialUEID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_PartialUEID },
  { &hf_rc_v3_ranParameterTesting, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Testing },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_UEQuery(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_UEQuery, UEQuery_sequence);

  return offset;
}


static const value_string rc_v3_T_ueType_01_vals[] = {
  {   0, "ueType-Choice-Individual" },
  {   1, "ueType-Choice-Group" },
  {   2, "ueQuery" },
  { 0, NULL }
};

static const per_choice_t T_ueType_01_choice[] = {
  {   0, &hf_rc_v3_ueType_Choice_Individual, ASN1_EXTENSION_ROOT    , dissect_rc_v3_EventTrigger_UE_Info_Item_Choice_Individual },
  {   1, &hf_rc_v3_ueType_Choice_Group, ASN1_EXTENSION_ROOT    , dissect_rc_v3_EventTrigger_UE_Info_Item_Choice_Group },
  {   2, &hf_rc_v3_ueQuery       , ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_UEQuery },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ueType_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ueType_01, T_ueType_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Associated_UE_Info_Item_sequence[] = {
  { &hf_rc_v3_ueFilterID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_UE_Filter_ID },
  { &hf_rc_v3_ueType_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ueType_01 },
  { &hf_rc_v3_logicalOR     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_Associated_UE_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_Associated_UE_Info_Item, Associated_UE_Info_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEInfo_OF_Associated_UE_Info_Item_sequence_of[1] = {
  { &hf_rc_v3_associatedUEInfo_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_Associated_UE_Info_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_Associated_UE_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_Associated_UE_Info_Item, SEQUENCE_SIZE_1_maxnoofUEInfo_OF_Associated_UE_Info_Item_sequence_of,
                                                  1, maxnoofUEInfo, false);

  return offset;
}


static const per_sequence_t Associated_UE_Info_sequence[] = {
  { &hf_rc_v3_associatedUEInfo_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_Associated_UE_Info_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_Associated_UE_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_Associated_UE_Info, Associated_UE_Info_sequence);

  return offset;
}


static const value_string rc_v3_InterfaceType_vals[] = {
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
dissect_rc_v3_InterfaceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t InterfaceID_NG_sequence[] = {
  { &hf_rc_v3_guami         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GUAMI },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_InterfaceID_NG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_InterfaceID_NG, InterfaceID_NG_sequence);

  return offset;
}


static const per_sequence_t InterfaceID_Xn_sequence[] = {
  { &hf_rc_v3_global_NG_RAN_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GlobalNGRANNodeID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_InterfaceID_Xn(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_InterfaceID_Xn, InterfaceID_Xn_sequence);

  return offset;
}



static int
dissect_rc_v3_GNB_DU_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(68719476735), NULL, false);

  return offset;
}


static const per_sequence_t InterfaceID_F1_sequence[] = {
  { &hf_rc_v3_globalGNB_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GlobalGNB_ID },
  { &hf_rc_v3_gNB_DU_ID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GNB_DU_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_InterfaceID_F1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_InterfaceID_F1, InterfaceID_F1_sequence);

  return offset;
}



static int
dissect_rc_v3_GNB_CU_UP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(68719476735), NULL, false);

  return offset;
}


static const per_sequence_t InterfaceID_E1_sequence[] = {
  { &hf_rc_v3_globalGNB_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GlobalGNB_ID },
  { &hf_rc_v3_gNB_CU_UP_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GNB_CU_UP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_InterfaceID_E1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_InterfaceID_E1, InterfaceID_E1_sequence);

  return offset;
}


static const per_sequence_t InterfaceID_S1_sequence[] = {
  { &hf_rc_v3_gUMMEI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GUMMEI },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_InterfaceID_S1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_InterfaceID_S1, InterfaceID_S1_sequence);

  return offset;
}


static const value_string rc_v3_EN_GNB_ID_vals[] = {
  {   0, "en-gNB-ID" },
  { 0, NULL }
};

static const per_choice_t EN_GNB_ID_choice[] = {
  {   0, &hf_rc_v3_en_gNB_ID     , ASN1_EXTENSION_ROOT    , dissect_rc_v3_BIT_STRING_SIZE_22_32 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_EN_GNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_EN_GNB_ID, EN_GNB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalenGNB_ID_sequence[] = {
  { &hf_rc_v3_pLMN_Identity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_PLMNIdentity },
  { &hf_rc_v3_en_gNB_ID_choice, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_EN_GNB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_GlobalenGNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_GlobalenGNB_ID, GlobalenGNB_ID_sequence);

  return offset;
}


static const value_string rc_v3_T_nodeType_vals[] = {
  {   0, "global-eNB-ID" },
  {   1, "global-en-gNB-ID" },
  { 0, NULL }
};

static const per_choice_t T_nodeType_choice[] = {
  {   0, &hf_rc_v3_global_eNB_ID , ASN1_EXTENSION_ROOT    , dissect_rc_v3_GlobalENB_ID },
  {   1, &hf_rc_v3_global_en_gNB_ID, ASN1_EXTENSION_ROOT    , dissect_rc_v3_GlobalenGNB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_nodeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_nodeType, T_nodeType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t InterfaceID_X2_sequence[] = {
  { &hf_rc_v3_nodeType      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_nodeType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_InterfaceID_X2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_InterfaceID_X2, InterfaceID_X2_sequence);

  return offset;
}



static int
dissect_rc_v3_NGENB_DU_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(68719476735), NULL, false);

  return offset;
}


static const per_sequence_t InterfaceID_W1_sequence[] = {
  { &hf_rc_v3_global_ng_eNB_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_GlobalNgENB_ID },
  { &hf_rc_v3_ng_eNB_DU_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_NGENB_DU_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_InterfaceID_W1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_InterfaceID_W1, InterfaceID_W1_sequence);

  return offset;
}


static const value_string rc_v3_InterfaceIdentifier_vals[] = {
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
  {   0, &hf_rc_v3_nG            , ASN1_EXTENSION_ROOT    , dissect_rc_v3_InterfaceID_NG },
  {   1, &hf_rc_v3_xN            , ASN1_EXTENSION_ROOT    , dissect_rc_v3_InterfaceID_Xn },
  {   2, &hf_rc_v3_f1            , ASN1_EXTENSION_ROOT    , dissect_rc_v3_InterfaceID_F1 },
  {   3, &hf_rc_v3_e1            , ASN1_EXTENSION_ROOT    , dissect_rc_v3_InterfaceID_E1 },
  {   4, &hf_rc_v3_s1            , ASN1_EXTENSION_ROOT    , dissect_rc_v3_InterfaceID_S1 },
  {   5, &hf_rc_v3_x2            , ASN1_EXTENSION_ROOT    , dissect_rc_v3_InterfaceID_X2 },
  {   6, &hf_rc_v3_w1            , ASN1_EXTENSION_ROOT    , dissect_rc_v3_InterfaceID_W1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_InterfaceIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_InterfaceIdentifier, InterfaceIdentifier_choice,
                                 NULL);

  return offset;
}


static const value_string rc_v3_T_messageType_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_messageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t Interface_MessageID_sequence[] = {
  { &hf_rc_v3_interfaceProcedureID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_INTEGER },
  { &hf_rc_v3_messageType_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_messageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_Interface_MessageID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_Interface_MessageID, Interface_MessageID_sequence);

  return offset;
}


static const per_sequence_t MessageType_Choice_NI_sequence[] = {
  { &hf_rc_v3_nI_Type       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_InterfaceType },
  { &hf_rc_v3_nI_Identifier , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_InterfaceIdentifier },
  { &hf_rc_v3_nI_Message    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_Interface_MessageID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_MessageType_Choice_NI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_MessageType_Choice_NI, MessageType_Choice_NI_sequence);

  return offset;
}


static const value_string rc_v3_RRCclass_LTE_vals[] = {
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
dissect_rc_v3_RRCclass_LTE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     12, NULL, true, 0, NULL);

  return offset;
}


static const value_string rc_v3_RRCclass_NR_vals[] = {
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
dissect_rc_v3_RRCclass_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}


static const value_string rc_v3_T_rrcType_vals[] = {
  {   0, "lTE" },
  {   1, "nR" },
  { 0, NULL }
};

static const per_choice_t T_rrcType_choice[] = {
  {   0, &hf_rc_v3_lTE           , ASN1_EXTENSION_ROOT    , dissect_rc_v3_RRCclass_LTE },
  {   1, &hf_rc_v3_nR            , ASN1_EXTENSION_ROOT    , dissect_rc_v3_RRCclass_NR },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_rrcType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_rrcType, T_rrcType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRC_MessageID_sequence[] = {
  { &hf_rc_v3_rrcType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_rrcType },
  { &hf_rc_v3_messageID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RRC_MessageID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RRC_MessageID, RRC_MessageID_sequence);

  return offset;
}


static const per_sequence_t MessageType_Choice_RRC_sequence[] = {
  { &hf_rc_v3_rRC_Message   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RRC_MessageID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_MessageType_Choice_RRC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_MessageType_Choice_RRC, MessageType_Choice_RRC_sequence);

  return offset;
}


static const value_string rc_v3_MessageType_Choice_vals[] = {
  {   0, "messageType-Choice-NI" },
  {   1, "messageType-Choice-RRC" },
  { 0, NULL }
};

static const per_choice_t MessageType_Choice_choice[] = {
  {   0, &hf_rc_v3_messageType_Choice_NI, ASN1_EXTENSION_ROOT    , dissect_rc_v3_MessageType_Choice_NI },
  {   1, &hf_rc_v3_messageType_Choice_RRC, ASN1_EXTENSION_ROOT    , dissect_rc_v3_MessageType_Choice_RRC },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_MessageType_Choice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_MessageType_Choice, MessageType_Choice_choice,
                                 NULL);

  return offset;
}


static const value_string rc_v3_T_messageDirection_vals[] = {
  {   0, "incoming" },
  {   1, "outgoing" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_messageDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format1_Item_sequence[] = {
  { &hf_rc_v3_ric_eventTriggerCondition_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_EventTriggerCondition_ID },
  { &hf_rc_v3_messageType   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_MessageType_Choice },
  { &hf_rc_v3_messageDirection, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_T_messageDirection },
  { &hf_rc_v3_associatedUEInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_EventTrigger_UE_Info },
  { &hf_rc_v3_associatedUEEvent, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_EventTrigger_UEevent_Info },
  { &hf_rc_v3_logicalOR     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_EventTrigger_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_EventTrigger_Format1_Item, E2SM_RC_EventTrigger_Format1_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item_sequence_of[1] = {
  { &hf_rc_v3_message_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_EventTrigger_Format1_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item, SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item_sequence_of,
                                                  1, maxnoofMessages, false);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format1_sequence[] = {
  { &hf_rc_v3_message_List  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item },
  { &hf_rc_v3_globalAssociatedUEInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_EventTrigger_UE_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_EventTrigger_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_EventTrigger_Format1, E2SM_RC_EventTrigger_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format2_sequence[] = {
  { &hf_rc_v3_ric_callProcessType_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_CallProcessType_ID },
  { &hf_rc_v3_ric_callProcessBreakpoint_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_CallProcessBreakpoint_ID },
  { &hf_rc_v3_associatedE2NodeInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Testing },
  { &hf_rc_v3_associatedUEInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_EventTrigger_UE_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_EventTrigger_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_EventTrigger_Format2, E2SM_RC_EventTrigger_Format2_sequence);

  return offset;
}



static int
dissect_rc_v3_INTEGER_1_512_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 512U, NULL, true);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format3_Item_sequence[] = {
  { &hf_rc_v3_ric_eventTriggerCondition_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_EventTriggerCondition_ID },
  { &hf_rc_v3_e2NodeInfoChange_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_INTEGER_1_512_ },
  { &hf_rc_v3_associatedCellInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_EventTrigger_Cell_Info },
  { &hf_rc_v3_logicalOR     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_EventTrigger_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_EventTrigger_Format3_Item, E2SM_RC_EventTrigger_Format3_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item_sequence_of[1] = {
  { &hf_rc_v3_e2NodeInfoChange_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_EventTrigger_Format3_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item, SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item_sequence_of,
                                                  1, maxnoofE2InfoChanges, false);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format3_sequence[] = {
  { &hf_rc_v3_e2NodeInfoChange_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_EventTrigger_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_EventTrigger_Format3, E2SM_RC_EventTrigger_Format3_sequence);

  return offset;
}


static const per_sequence_t TriggerType_Choice_RRCstate_Item_sequence[] = {
  { &hf_rc_v3_stateChangedTo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RRC_State },
  { &hf_rc_v3_logicalOR     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_TriggerType_Choice_RRCstate_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_TriggerType_Choice_RRCstate_Item, TriggerType_Choice_RRCstate_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item_sequence_of[1] = {
  { &hf_rc_v3_rrcState_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_TriggerType_Choice_RRCstate_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item, SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item_sequence_of,
                                                  1, maxnoofRRCstate, false);

  return offset;
}


static const per_sequence_t TriggerType_Choice_RRCstate_sequence[] = {
  { &hf_rc_v3_rrcState_List , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_TriggerType_Choice_RRCstate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_TriggerType_Choice_RRCstate, TriggerType_Choice_RRCstate_sequence);

  return offset;
}


static const per_sequence_t TriggerType_Choice_UEID_sequence[] = {
  { &hf_rc_v3_ueIDchange_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_INTEGER_1_512_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_TriggerType_Choice_UEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_TriggerType_Choice_UEID, TriggerType_Choice_UEID_sequence);

  return offset;
}


static const per_sequence_t TriggerType_Choice_L2state_sequence[] = {
  { &hf_rc_v3_associatedL2variables, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Testing },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_TriggerType_Choice_L2state(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_TriggerType_Choice_L2state, TriggerType_Choice_L2state_sequence);

  return offset;
}


static const per_sequence_t TriggerType_Choice_UEcontext_sequence[] = {
  { &hf_rc_v3_associatedUECtxtVariables, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Testing },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_TriggerType_Choice_UEcontext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_TriggerType_Choice_UEcontext, TriggerType_Choice_UEcontext_sequence);

  return offset;
}


static const value_string rc_v3_T_mIMOtransModeState_vals[] = {
  {   0, "enabled" },
  {   1, "disabled" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_mIMOtransModeState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TriggerType_Choice_MIMOandBFconfig_sequence[] = {
  { &hf_rc_v3_mIMOtransModeState, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_mIMOtransModeState },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_TriggerType_Choice_MIMOandBFconfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_TriggerType_Choice_MIMOandBFconfig, TriggerType_Choice_MIMOandBFconfig_sequence);

  return offset;
}


static const value_string rc_v3_L2MACschChgType_Choice_vals[] = {
  {   0, "triggerType-Choice-MIMOandBFconfig" },
  { 0, NULL }
};

static const per_choice_t L2MACschChgType_Choice_choice[] = {
  {   0, &hf_rc_v3_triggerType_Choice_MIMOandBFconfig, ASN1_EXTENSION_ROOT    , dissect_rc_v3_TriggerType_Choice_MIMOandBFconfig },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_L2MACschChgType_Choice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_L2MACschChgType_Choice, L2MACschChgType_Choice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TriggerType_Choice_L2MACschChg_sequence[] = {
  { &hf_rc_v3_l2MACschChgType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_L2MACschChgType_Choice },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_TriggerType_Choice_L2MACschChg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_TriggerType_Choice_L2MACschChg, TriggerType_Choice_L2MACschChg_sequence);

  return offset;
}


static const value_string rc_v3_TriggerType_Choice_vals[] = {
  {   0, "triggerType-Choice-RRCstate" },
  {   1, "triggerType-Choice-UEID" },
  {   2, "triggerType-Choice-L2state" },
  {   3, "triggerType-Choice-UEcontext" },
  {   4, "triggerType-Choice-L2MACschChg" },
  { 0, NULL }
};

static const per_choice_t TriggerType_Choice_choice[] = {
  {   0, &hf_rc_v3_triggerType_Choice_RRCstate, ASN1_EXTENSION_ROOT    , dissect_rc_v3_TriggerType_Choice_RRCstate },
  {   1, &hf_rc_v3_triggerType_Choice_UEID, ASN1_EXTENSION_ROOT    , dissect_rc_v3_TriggerType_Choice_UEID },
  {   2, &hf_rc_v3_triggerType_Choice_L2state, ASN1_EXTENSION_ROOT    , dissect_rc_v3_TriggerType_Choice_L2state },
  {   3, &hf_rc_v3_triggerType_Choice_UEcontext, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_TriggerType_Choice_UEcontext },
  {   4, &hf_rc_v3_triggerType_Choice_L2MACschChg, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_TriggerType_Choice_L2MACschChg },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_TriggerType_Choice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_TriggerType_Choice, TriggerType_Choice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format4_Item_sequence[] = {
  { &hf_rc_v3_ric_eventTriggerCondition_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_EventTriggerCondition_ID },
  { &hf_rc_v3_triggerType   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_TriggerType_Choice },
  { &hf_rc_v3_associatedUEInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_EventTrigger_UE_Info },
  { &hf_rc_v3_logicalOR     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_EventTrigger_Format4_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_EventTrigger_Format4_Item, E2SM_RC_EventTrigger_Format4_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item_sequence_of[1] = {
  { &hf_rc_v3_uEInfoChange_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_EventTrigger_Format4_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item, SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item_sequence_of,
                                                  1, maxnoofUEInfoChanges, false);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_Format4_sequence[] = {
  { &hf_rc_v3_uEInfoChange_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_EventTrigger_Format4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_EventTrigger_Format4, E2SM_RC_EventTrigger_Format4_sequence);

  return offset;
}



static int
dissect_rc_v3_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string rc_v3_T_ric_eventTrigger_formats_vals[] = {
  {   0, "eventTrigger-Format1" },
  {   1, "eventTrigger-Format2" },
  {   2, "eventTrigger-Format3" },
  {   3, "eventTrigger-Format4" },
  {   4, "eventTrigger-Format5" },
  { 0, NULL }
};

static const per_choice_t T_ric_eventTrigger_formats_choice[] = {
  {   0, &hf_rc_v3_eventTrigger_Format1, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_EventTrigger_Format1 },
  {   1, &hf_rc_v3_eventTrigger_Format2, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_EventTrigger_Format2 },
  {   2, &hf_rc_v3_eventTrigger_Format3, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_EventTrigger_Format3 },
  {   3, &hf_rc_v3_eventTrigger_Format4, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_EventTrigger_Format4 },
  {   4, &hf_rc_v3_eventTrigger_Format5, ASN1_EXTENSION_ROOT    , dissect_rc_v3_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ric_eventTrigger_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ric_eventTrigger_formats, T_ric_eventTrigger_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_EventTrigger_sequence[] = {
  { &hf_rc_v3_ric_eventTrigger_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ric_eventTrigger_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_EventTrigger(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_EventTrigger, E2SM_RC_EventTrigger_sequence);

  return offset;
}



static int
dissect_rc_v3_RIC_Style_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format1_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ActionDefinition_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ActionDefinition_Format1_Item, E2SM_RC_ActionDefinition_Format1_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item_sequence_of[1] = {
  { &hf_rc_v3_ranP_ToBeReported_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ActionDefinition_Format1_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item, SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item_sequence_of,
                                                  1, maxnoofParametersToReport, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format1_sequence[] = {
  { &hf_rc_v3_ranP_ToBeReported_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ActionDefinition_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ActionDefinition_Format1, E2SM_RC_ActionDefinition_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format2_Item_sequence[] = {
  { &hf_rc_v3_ric_PolicyAction, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_PolicyAction },
  { &hf_rc_v3_ric_PolicyConditionDefinition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Testing },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ActionDefinition_Format2_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ActionDefinition_Format2_Item, E2SM_RC_ActionDefinition_Format2_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_PolicyConditions_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ActionDefinition_Format2_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item, SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item_sequence_of,
                                                  1, maxnoofPolicyConditions, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format2_sequence[] = {
  { &hf_rc_v3_ric_PolicyConditions_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ActionDefinition_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ActionDefinition_Format2, E2SM_RC_ActionDefinition_Format2_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format3_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ActionDefinition_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ActionDefinition_Format3_Item, E2SM_RC_ActionDefinition_Format3_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item_sequence_of[1] = {
  { &hf_rc_v3_ranP_InsertIndication_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ActionDefinition_Format3_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format3_sequence[] = {
  { &hf_rc_v3_ric_InsertIndication_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_InsertIndication_ID },
  { &hf_rc_v3_ranP_InsertIndication_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item },
  { &hf_rc_v3_ueID          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_UEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ActionDefinition_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ActionDefinition_Format3, E2SM_RC_ActionDefinition_Format3_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format4_RANP_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ActionDefinition_Format4_RANP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ActionDefinition_Format4_RANP_Item, E2SM_RC_ActionDefinition_Format4_RANP_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item_sequence_of[1] = {
  { &hf_rc_v3_ranP_InsertIndication_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ActionDefinition_Format4_RANP_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format4_Indication_Item_sequence[] = {
  { &hf_rc_v3_ric_InsertIndication_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_InsertIndication_ID },
  { &hf_rc_v3_ranP_InsertIndication_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ActionDefinition_Format4_Indication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ActionDefinition_Format4_Indication_Item, E2SM_RC_ActionDefinition_Format4_Indication_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_InsertIndication_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ActionDefinition_Format4_Indication_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item, SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item_sequence_of,
                                                  1, maxnoofInsertIndicationActions, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format4_Style_Item_sequence[] = {
  { &hf_rc_v3_requested_Insert_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_InsertIndication_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ActionDefinition_Format4_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ActionDefinition_Format4_Style_Item, E2SM_RC_ActionDefinition_Format4_Style_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_InsertStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ActionDefinition_Format4_Style_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_Format4_sequence[] = {
  { &hf_rc_v3_ric_InsertStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item },
  { &hf_rc_v3_ueID          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_UEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ActionDefinition_Format4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ActionDefinition_Format4, E2SM_RC_ActionDefinition_Format4_sequence);

  return offset;
}


static const value_string rc_v3_T_ric_actionDefinition_formats_vals[] = {
  {   0, "actionDefinition-Format1" },
  {   1, "actionDefinition-Format2" },
  {   2, "actionDefinition-Format3" },
  {   3, "actionDefinition-Format4" },
  { 0, NULL }
};

static const per_choice_t T_ric_actionDefinition_formats_choice[] = {
  {   0, &hf_rc_v3_actionDefinition_Format1, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_ActionDefinition_Format1 },
  {   1, &hf_rc_v3_actionDefinition_Format2, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_ActionDefinition_Format2 },
  {   2, &hf_rc_v3_actionDefinition_Format3, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_ActionDefinition_Format3 },
  {   3, &hf_rc_v3_actionDefinition_Format4, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_E2SM_RC_ActionDefinition_Format4 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ric_actionDefinition_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ric_actionDefinition_formats, T_ric_actionDefinition_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ActionDefinition_sequence[] = {
  { &hf_rc_v3_ric_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_actionDefinition_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ric_actionDefinition_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ActionDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ActionDefinition, E2SM_RC_ActionDefinition_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationHeader_Format1_sequence[] = {
  { &hf_rc_v3_ric_eventTriggerCondition_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RIC_EventTriggerCondition_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationHeader_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationHeader_Format1, E2SM_RC_IndicationHeader_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationHeader_Format2_sequence[] = {
  { &hf_rc_v3_ueID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_UEID },
  { &hf_rc_v3_ric_InsertStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_InsertIndication_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_InsertIndication_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationHeader_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationHeader_Format2, E2SM_RC_IndicationHeader_Format2_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationHeader_Format3_sequence[] = {
  { &hf_rc_v3_ric_eventTriggerCondition_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RIC_EventTriggerCondition_ID },
  { &hf_rc_v3_ueID          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_UEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationHeader_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationHeader_Format3, E2SM_RC_IndicationHeader_Format3_sequence);

  return offset;
}


static const value_string rc_v3_T_ric_indicationHeader_formats_vals[] = {
  {   0, "indicationHeader-Format1" },
  {   1, "indicationHeader-Format2" },
  {   2, "indicationHeader-Format3" },
  { 0, NULL }
};

static const per_choice_t T_ric_indicationHeader_formats_choice[] = {
  {   0, &hf_rc_v3_indicationHeader_Format1, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_IndicationHeader_Format1 },
  {   1, &hf_rc_v3_indicationHeader_Format2, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_IndicationHeader_Format2 },
  {   2, &hf_rc_v3_indicationHeader_Format3, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_E2SM_RC_IndicationHeader_Format3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ric_indicationHeader_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ric_indicationHeader_formats, T_ric_indicationHeader_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationHeader_sequence[] = {
  { &hf_rc_v3_ric_indicationHeader_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ric_indicationHeader_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationHeader, E2SM_RC_IndicationHeader_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format1_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage_Format1_Item, E2SM_RC_IndicationMessage_Format1_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item_sequence_of[1] = {
  { &hf_rc_v3_ranP_Reported_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_IndicationMessage_Format1_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format1_sequence[] = {
  { &hf_rc_v3_ranP_Reported_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage_Format1, E2SM_RC_IndicationMessage_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format2_RANParameter_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage_Format2_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage_Format2_RANParameter_Item, E2SM_RC_IndicationMessage_Format2_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item_sequence_of[1] = {
  { &hf_rc_v3_ranP_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_IndicationMessage_Format2_RANParameter_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format2_Item_sequence[] = {
  { &hf_rc_v3_ueID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_UEID },
  { &hf_rc_v3_ranP_List     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage_Format2_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage_Format2_Item, E2SM_RC_IndicationMessage_Format2_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item_sequence_of[1] = {
  { &hf_rc_v3_ueParameter_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_IndicationMessage_Format2_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item, SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item_sequence_of,
                                                  1, maxnoofUEID, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format2_sequence[] = {
  { &hf_rc_v3_ueParameter_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage_Format2, E2SM_RC_IndicationMessage_Format2_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format3_Item_sequence[] = {
  { &hf_rc_v3_cellGlobal_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_CGI },
  { &hf_rc_v3_cellContextInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_OCTET_STRING },
  { &hf_rc_v3_cellDeleted   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_BOOLEAN },
  { &hf_rc_v3_neighborRelation_Table, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_NeighborRelation_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage_Format3_Item, E2SM_RC_IndicationMessage_Format3_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item_sequence_of[1] = {
  { &hf_rc_v3_cellInfo_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_IndicationMessage_Format3_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item, SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item_sequence_of,
                                                  1, maxnoofCellID, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format3_sequence[] = {
  { &hf_rc_v3_cellInfo_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage_Format3, E2SM_RC_IndicationMessage_Format3_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format5_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage_Format5_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage_Format5_Item, E2SM_RC_IndicationMessage_Format5_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item_sequence_of[1] = {
  { &hf_rc_v3_ranP_Requested_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_IndicationMessage_Format5_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item, SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item_sequence_of,
                                                  0, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format5_sequence[] = {
  { &hf_rc_v3_ranP_Requested_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage_Format5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage_Format5, E2SM_RC_IndicationMessage_Format5_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format6_RANP_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage_Format6_RANP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage_Format6_RANP_Item, E2SM_RC_IndicationMessage_Format6_RANP_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item_sequence_of[1] = {
  { &hf_rc_v3_ranP_InsertIndication_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_IndicationMessage_Format6_RANP_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item, SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item_sequence_of,
                                                  0, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format6_Indication_Item_sequence[] = {
  { &hf_rc_v3_ric_InsertIndication_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_InsertIndication_ID },
  { &hf_rc_v3_ranP_InsertIndication_List_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage_Format6_Indication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage_Format6_Indication_Item, E2SM_RC_IndicationMessage_Format6_Indication_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_InsertIndication_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_IndicationMessage_Format6_Indication_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item, SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item_sequence_of,
                                                  1, maxnoofInsertIndicationActions, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format6_Style_Item_sequence[] = {
  { &hf_rc_v3_indicated_Insert_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_InsertIndication_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage_Format6_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage_Format6_Style_Item, E2SM_RC_IndicationMessage_Format6_Style_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_InsertStyle_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_IndicationMessage_Format6_Style_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_Format6_sequence[] = {
  { &hf_rc_v3_ric_InsertStyle_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage_Format6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage_Format6, E2SM_RC_IndicationMessage_Format6_sequence);

  return offset;
}


static const value_string rc_v3_T_ric_indicationMessage_formats_vals[] = {
  {   0, "indicationMessage-Format1" },
  {   1, "indicationMessage-Format2" },
  {   2, "indicationMessage-Format3" },
  {   3, "indicationMessage-Format4" },
  {   4, "indicationMessage-Format5" },
  {   5, "indicationMessage-Format6" },
  { 0, NULL }
};

static const per_choice_t T_ric_indicationMessage_formats_choice[] = {
  {   0, &hf_rc_v3_indicationMessage_Format1, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_IndicationMessage_Format1 },
  {   1, &hf_rc_v3_indicationMessage_Format2, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_IndicationMessage_Format2 },
  {   2, &hf_rc_v3_indicationMessage_Format3, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_IndicationMessage_Format3 },
  {   3, &hf_rc_v3_indicationMessage_Format4, ASN1_EXTENSION_ROOT    , dissect_rc_v3_NULL },
  {   4, &hf_rc_v3_indicationMessage_Format5, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_IndicationMessage_Format5 },
  {   5, &hf_rc_v3_indicationMessage_Format6, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_E2SM_RC_IndicationMessage_Format6 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ric_indicationMessage_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ric_indicationMessage_formats, T_ric_indicationMessage_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_IndicationMessage_sequence[] = {
  { &hf_rc_v3_ric_indicationMessage_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ric_indicationMessage_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_IndicationMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_IndicationMessage, E2SM_RC_IndicationMessage_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_CallProcessID_Format1_sequence[] = {
  { &hf_rc_v3_ric_callProcess_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RAN_CallProcess_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_CallProcessID_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_CallProcessID_Format1, E2SM_RC_CallProcessID_Format1_sequence);

  return offset;
}


static const value_string rc_v3_T_ric_callProcessID_formats_vals[] = {
  {   0, "callProcessID-Format1" },
  { 0, NULL }
};

static const per_choice_t T_ric_callProcessID_formats_choice[] = {
  {   0, &hf_rc_v3_callProcessID_Format1, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_CallProcessID_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ric_callProcessID_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ric_callProcessID_formats, T_ric_callProcessID_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_CallProcessID_sequence[] = {
  { &hf_rc_v3_ric_callProcessID_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ric_callProcessID_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_CallProcessID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_CallProcessID, E2SM_RC_CallProcessID_sequence);

  return offset;
}


static const value_string rc_v3_T_ric_ControlDecision_vals[] = {
  {   0, "accept" },
  {   1, "reject" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_ric_ControlDecision(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlHeader_Format1_sequence[] = {
  { &hf_rc_v3_ueID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_UEID },
  { &hf_rc_v3_ric_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_ControlAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_ControlAction_ID },
  { &hf_rc_v3_ric_ControlDecision, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_T_ric_ControlDecision },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlHeader_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlHeader_Format1, E2SM_RC_ControlHeader_Format1_sequence);

  return offset;
}


static const value_string rc_v3_T_ric_ControlDecision_01_vals[] = {
  {   0, "accept" },
  {   1, "reject" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_ric_ControlDecision_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlHeader_Format2_sequence[] = {
  { &hf_rc_v3_ueID          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_UEID },
  { &hf_rc_v3_ric_ControlDecision_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_T_ric_ControlDecision_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlHeader_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlHeader_Format2, E2SM_RC_ControlHeader_Format2_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlHeader_Format3_sequence[] = {
  { &hf_rc_v3_ue_Group_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_UE_Group_ID },
  { &hf_rc_v3_ue_Group_Definition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_UE_Group_Definition },
  { &hf_rc_v3_ric_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_ControlAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_ControlAction_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlHeader_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlHeader_Format3, E2SM_RC_ControlHeader_Format3_sequence);

  return offset;
}


static const value_string rc_v3_T_ric_ControlDecision_02_vals[] = {
  {   0, "accept" },
  {   1, "reject" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_ric_ControlDecision_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlHeader_Format4_sequence[] = {
  { &hf_rc_v3_partial_ueID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_PartialUEID },
  { &hf_rc_v3_ric_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_ControlAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_ControlAction_ID },
  { &hf_rc_v3_ric_ControlDecision_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_T_ric_ControlDecision_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlHeader_Format4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlHeader_Format4, E2SM_RC_ControlHeader_Format4_sequence);

  return offset;
}


static const value_string rc_v3_T_ric_controlHeader_formats_vals[] = {
  {   0, "controlHeader-Format1" },
  {   1, "controlHeader-Format2" },
  {   2, "controlHeader-Format3" },
  {   3, "controlHeader-Format4" },
  { 0, NULL }
};

static const per_choice_t T_ric_controlHeader_formats_choice[] = {
  {   0, &hf_rc_v3_controlHeader_Format1, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_ControlHeader_Format1 },
  {   1, &hf_rc_v3_controlHeader_Format2, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_E2SM_RC_ControlHeader_Format2 },
  {   2, &hf_rc_v3_controlHeader_Format3, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_E2SM_RC_ControlHeader_Format3 },
  {   3, &hf_rc_v3_controlHeader_Format4, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_E2SM_RC_ControlHeader_Format4 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ric_controlHeader_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ric_controlHeader_formats, T_ric_controlHeader_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlHeader_sequence[] = {
  { &hf_rc_v3_ric_controlHeader_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ric_controlHeader_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlHeader, E2SM_RC_ControlHeader_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_Format1_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlMessage_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlMessage_Format1_Item, E2SM_RC_ControlMessage_Format1_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item_sequence_of[1] = {
  { &hf_rc_v3_ranP_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ControlMessage_Format1_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item, SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item_sequence_of,
                                                  0, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_Format1_sequence[] = {
  { &hf_rc_v3_ranP_List_01  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlMessage_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlMessage_Format1, E2SM_RC_ControlMessage_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_Format2_ControlAction_Item_sequence[] = {
  { &hf_rc_v3_ric_ControlAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_ControlAction_ID },
  { &hf_rc_v3_ranP_List_02  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ControlMessage_Format1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlMessage_Format2_ControlAction_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlMessage_Format2_ControlAction_Item, E2SM_RC_ControlMessage_Format2_ControlAction_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_ControlAction_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ControlMessage_Format2_ControlAction_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item, SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item_sequence_of,
                                                  1, maxnoofMulCtrlActions, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_Format2_Style_Item_sequence[] = {
  { &hf_rc_v3_indicated_Control_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_ControlAction_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlMessage_Format2_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlMessage_Format2_Style_Item, E2SM_RC_ControlMessage_Format2_Style_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_ControlStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ControlMessage_Format2_Style_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_Format2_sequence[] = {
  { &hf_rc_v3_ric_ControlStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlMessage_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlMessage_Format2, E2SM_RC_ControlMessage_Format2_sequence);

  return offset;
}


static const per_sequence_t EntitySpecific_ranP_ControlParameters_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_EntitySpecific_ranP_ControlParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_EntitySpecific_ranP_ControlParameters, EntitySpecific_ranP_ControlParameters_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_EntitySpecific_ranP_ControlParameters_sequence_of[1] = {
  { &hf_rc_v3_entitySpecificControlRanP_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_EntitySpecific_ranP_ControlParameters },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_EntitySpecific_ranP_ControlParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_EntitySpecific_ranP_ControlParameters, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_EntitySpecific_ranP_ControlParameters_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_EntityFilter_sequence[] = {
  { &hf_rc_v3_entityFilter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_EntityFilter_ID },
  { &hf_rc_v3_entityFilter_Definition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Testing },
  { &hf_rc_v3_entitySpecificControlRanP_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_EntitySpecific_ranP_ControlParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_EntityFilter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_EntityFilter, E2SM_RC_EntityFilter_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofAssociatedEntityFilters_OF_E2SM_RC_EntityFilter_sequence_of[1] = {
  { &hf_rc_v3_listOfEntityFilters_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_EntityFilter },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedEntityFilters_OF_E2SM_RC_EntityFilter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedEntityFilters_OF_E2SM_RC_EntityFilter, SEQUENCE_SIZE_0_maxnoofAssociatedEntityFilters_OF_E2SM_RC_EntityFilter_sequence_of,
                                                  0, maxnoofAssociatedEntityFilters, false);

  return offset;
}


static const per_sequence_t EntityAgnostic_ranP_ControlParameters_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_EntityAgnostic_ranP_ControlParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_EntityAgnostic_ranP_ControlParameters, EntityAgnostic_ranP_ControlParameters_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_EntityAgnostic_ranP_ControlParameters_sequence_of[1] = {
  { &hf_rc_v3_entityAgnosticControlRanP_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_EntityAgnostic_ranP_ControlParameters },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_EntityAgnostic_ranP_ControlParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_EntityAgnostic_ranP_ControlParameters, SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_EntityAgnostic_ranP_ControlParameters_sequence_of,
                                                  0, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_Format3_sequence[] = {
  { &hf_rc_v3_listOfEntityFilters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedEntityFilters_OF_E2SM_RC_EntityFilter },
  { &hf_rc_v3_entityAgnosticControlRanP_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_EntityAgnostic_ranP_ControlParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlMessage_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlMessage_Format3, E2SM_RC_ControlMessage_Format3_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_Format4_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_Definition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlMessage_Format4_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlMessage_Format4_Item, E2SM_RC_ControlMessage_Format4_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format4_Item_sequence_of[1] = {
  { &hf_rc_v3_ranP_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ControlMessage_Format4_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format4_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format4_Item, SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format4_Item_sequence_of,
                                                  0, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_Format4_sequence[] = {
  { &hf_rc_v3_ranP_List_03  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format4_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlMessage_Format4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlMessage_Format4, E2SM_RC_ControlMessage_Format4_sequence);

  return offset;
}



static int
dissect_rc_v3_E2SM_RC_ControlMessage_Format5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string rc_v3_T_ric_controlMessage_formats_vals[] = {
  {   0, "controlMessage-Format1" },
  {   1, "controlMessage-Format2" },
  {   2, "controlMessage-Format3" },
  {   3, "controlMessage-Format4" },
  {   4, "controlMessage-Format5" },
  { 0, NULL }
};

static const per_choice_t T_ric_controlMessage_formats_choice[] = {
  {   0, &hf_rc_v3_controlMessage_Format1, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_ControlMessage_Format1 },
  {   1, &hf_rc_v3_controlMessage_Format2, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_E2SM_RC_ControlMessage_Format2 },
  {   2, &hf_rc_v3_controlMessage_Format3, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_E2SM_RC_ControlMessage_Format3 },
  {   3, &hf_rc_v3_controlMessage_Format4, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_E2SM_RC_ControlMessage_Format4 },
  {   4, &hf_rc_v3_controlMessage_Format5, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_E2SM_RC_ControlMessage_Format5 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ric_controlMessage_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ric_controlMessage_formats, T_ric_controlMessage_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlMessage_sequence[] = {
  { &hf_rc_v3_ric_controlMessage_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ric_controlMessage_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlMessage, E2SM_RC_ControlMessage_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format1_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_value, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlOutcome_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlOutcome_Format1_Item, E2SM_RC_ControlOutcome_Format1_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item_sequence_of[1] = {
  { &hf_rc_v3_ranP_List_item_03, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ControlOutcome_Format1_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item, SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item_sequence_of,
                                                  0, maxnoofRANOutcomeParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format1_sequence[] = {
  { &hf_rc_v3_ranP_List_04  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlOutcome_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlOutcome_Format1, E2SM_RC_ControlOutcome_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format2_RANP_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_value, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlOutcome_Format2_RANP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlOutcome_Format2_RANP_Item, E2SM_RC_ControlOutcome_Format2_RANP_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item_sequence_of[1] = {
  { &hf_rc_v3_ranP_List_item_04, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ControlOutcome_Format2_RANP_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item_sequence[] = {
  { &hf_rc_v3_ric_ControlAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_ControlAction_ID },
  { &hf_rc_v3_ranP_List_05  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item, E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_ControlOutcome_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item, SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item_sequence_of,
                                                  1, maxnoofMulCtrlActions, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format2_Style_Item_sequence[] = {
  { &hf_rc_v3_indicated_Control_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_ControlOutcome_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlOutcome_Format2_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlOutcome_Format2_Style_Item, E2SM_RC_ControlOutcome_Format2_Style_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_ControlStyle_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ControlOutcome_Format2_Style_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format2_sequence[] = {
  { &hf_rc_v3_ric_ControlStyle_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlOutcome_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlOutcome_Format2, E2SM_RC_ControlOutcome_Format2_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format3_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlOutcome_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlOutcome_Format3_Item, E2SM_RC_ControlOutcome_Format3_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item_sequence_of[1] = {
  { &hf_rc_v3_ranP_List_item_05, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_ControlOutcome_Format3_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item, SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item_sequence_of,
                                                  0, maxnoofRANOutcomeParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_Format3_sequence[] = {
  { &hf_rc_v3_ranP_List_06  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlOutcome_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlOutcome_Format3, E2SM_RC_ControlOutcome_Format3_sequence);

  return offset;
}


static const value_string rc_v3_T_ric_controlOutcome_formats_vals[] = {
  {   0, "controlOutcome-Format1" },
  {   1, "controlOutcome-Format2" },
  {   2, "controlOutcome-Format3" },
  { 0, NULL }
};

static const per_choice_t T_ric_controlOutcome_formats_choice[] = {
  {   0, &hf_rc_v3_controlOutcome_Format1, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_ControlOutcome_Format1 },
  {   1, &hf_rc_v3_controlOutcome_Format2, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_E2SM_RC_ControlOutcome_Format2 },
  {   2, &hf_rc_v3_controlOutcome_Format3, ASN1_NOT_EXTENSION_ROOT, dissect_rc_v3_E2SM_RC_ControlOutcome_Format3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ric_controlOutcome_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ric_controlOutcome_formats, T_ric_controlOutcome_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_ControlOutcome_sequence[] = {
  { &hf_rc_v3_ric_controlOutcome_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ric_controlOutcome_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_ControlOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_ControlOutcome, E2SM_RC_ControlOutcome_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_QueryHeader_Format1_sequence[] = {
  { &hf_rc_v3_ric_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_associatedE2NodeInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Testing },
  { &hf_rc_v3_associatedUEInfo_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_Associated_UE_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_QueryHeader_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_QueryHeader_Format1, E2SM_RC_QueryHeader_Format1_sequence);

  return offset;
}


static const value_string rc_v3_T_ric_queryHeader_formats_vals[] = {
  {   0, "queryHeader-Format1" },
  { 0, NULL }
};

static const per_choice_t T_ric_queryHeader_formats_choice[] = {
  {   0, &hf_rc_v3_queryHeader_Format1, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_QueryHeader_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ric_queryHeader_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ric_queryHeader_formats, T_ric_queryHeader_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_QueryHeader_sequence[] = {
  { &hf_rc_v3_ric_queryHeader_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ric_queryHeader_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_QueryHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_QueryHeader, E2SM_RC_QueryHeader_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_QueryDefinition_Format1_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_Definition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_QueryDefinition_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_QueryDefinition_Format1_Item, E2SM_RC_QueryDefinition_Format1_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryDefinition_Format1_Item_sequence_of[1] = {
  { &hf_rc_v3_ranP_List_item_06, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_QueryDefinition_Format1_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryDefinition_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryDefinition_Format1_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryDefinition_Format1_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_QueryDefinition_Format1_sequence[] = {
  { &hf_rc_v3_ranP_List_07  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryDefinition_Format1_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_QueryDefinition_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_QueryDefinition_Format1, E2SM_RC_QueryDefinition_Format1_sequence);

  return offset;
}


static const value_string rc_v3_T_ric_queryDefinition_formats_vals[] = {
  {   0, "queryRequest-Format1" },
  { 0, NULL }
};

static const per_choice_t T_ric_queryDefinition_formats_choice[] = {
  {   0, &hf_rc_v3_queryRequest_Format1, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_QueryDefinition_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ric_queryDefinition_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ric_queryDefinition_formats, T_ric_queryDefinition_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_QueryDefinition_sequence[] = {
  { &hf_rc_v3_ric_queryDefinition_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ric_queryDefinition_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_QueryDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_QueryDefinition, E2SM_RC_QueryDefinition_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_QueryOutcome_Format1_ItemParameters_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_QueryOutcome_Format1_ItemParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_QueryOutcome_Format1_ItemParameters, E2SM_RC_QueryOutcome_Format1_ItemParameters_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format1_ItemParameters_sequence_of[1] = {
  { &hf_rc_v3_ranP_List_item_07, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_QueryOutcome_Format1_ItemParameters },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format1_ItemParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format1_ItemParameters, SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format1_ItemParameters_sequence_of,
                                                  0, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_QueryOutcome_Format1_ItemCell_sequence[] = {
  { &hf_rc_v3_cellGlobal_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_CGI },
  { &hf_rc_v3_ranP_List_08  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format1_ItemParameters },
  { &hf_rc_v3_neighborRelation_Table, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_NeighborRelation_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_QueryOutcome_Format1_ItemCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_QueryOutcome_Format1_ItemCell, E2SM_RC_QueryOutcome_Format1_ItemCell_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_QueryOutcome_Format1_ItemCell_sequence_of[1] = {
  { &hf_rc_v3_cellInfo_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_QueryOutcome_Format1_ItemCell },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_QueryOutcome_Format1_ItemCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_QueryOutcome_Format1_ItemCell, SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_QueryOutcome_Format1_ItemCell_sequence_of,
                                                  1, maxnoofCellID, false);

  return offset;
}


static const per_sequence_t E2SM_RC_QueryOutcome_Format1_sequence[] = {
  { &hf_rc_v3_cellInfo_List_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_QueryOutcome_Format1_ItemCell },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_QueryOutcome_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_QueryOutcome_Format1, E2SM_RC_QueryOutcome_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_QueryOutcome_Format2_ItemParameters_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_valueType, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_ValueType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_QueryOutcome_Format2_ItemParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_QueryOutcome_Format2_ItemParameters, E2SM_RC_QueryOutcome_Format2_ItemParameters_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format2_ItemParameters_sequence_of[1] = {
  { &hf_rc_v3_ranP_List_item_08, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_QueryOutcome_Format2_ItemParameters },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format2_ItemParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format2_ItemParameters, SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format2_ItemParameters_sequence_of,
                                                  0, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t E2SM_RC_QueryOutcome_Format2_ItemUE_sequence[] = {
  { &hf_rc_v3_ueID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_UEID },
  { &hf_rc_v3_ranP_List_09  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format2_ItemParameters },
  { &hf_rc_v3_ueFilterID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_UE_Filter_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_QueryOutcome_Format2_ItemUE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_QueryOutcome_Format2_ItemUE, E2SM_RC_QueryOutcome_Format2_ItemUE_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_QueryOutcome_Format2_ItemUE_sequence_of[1] = {
  { &hf_rc_v3_ueInfo_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_E2SM_RC_QueryOutcome_Format2_ItemUE },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_QueryOutcome_Format2_ItemUE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_QueryOutcome_Format2_ItemUE, SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_QueryOutcome_Format2_ItemUE_sequence_of,
                                                  0, maxnoofUEID, false);

  return offset;
}


static const per_sequence_t E2SM_RC_QueryOutcome_Format2_sequence[] = {
  { &hf_rc_v3_ueInfo_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_QueryOutcome_Format2_ItemUE },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_QueryOutcome_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_QueryOutcome_Format2, E2SM_RC_QueryOutcome_Format2_sequence);

  return offset;
}


static const value_string rc_v3_T_ric_queryOutcome_formats_vals[] = {
  {   0, "queryOutcome-Format1" },
  {   1, "queryOutcome-Format2" },
  { 0, NULL }
};

static const per_choice_t T_ric_queryOutcome_formats_choice[] = {
  {   0, &hf_rc_v3_queryOutcome_Format1, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_QueryOutcome_Format1 },
  {   1, &hf_rc_v3_queryOutcome_Format2, ASN1_EXTENSION_ROOT    , dissect_rc_v3_E2SM_RC_QueryOutcome_Format2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rc_v3_T_ric_queryOutcome_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rc_v3_T_ric_queryOutcome_formats, T_ric_queryOutcome_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_RC_QueryOutcome_sequence[] = {
  { &hf_rc_v3_ric_queryOutcome_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ric_queryOutcome_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_QueryOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_QueryOutcome, E2SM_RC_QueryOutcome_sequence);

  return offset;
}



static int
dissect_rc_v3_T_ranFunction_ShortName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_rc_v3_T_ranFunction_E2SM_OID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 1000, true,
                                          &parameter_tvb);

  e2ap_update_ran_function_mapping(actx->pinfo, tree, parameter_tvb,
                                   tvb_get_string_enc(actx->pinfo->pool, parameter_tvb, 0,
				   tvb_captured_length(parameter_tvb), ENC_ASCII));




  return offset;
}



static int
dissect_rc_v3_PrintableString_SIZE_1_150_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}


static const per_sequence_t RANfunction_Name_sequence[] = {
  { &hf_rc_v3_ranFunction_ShortName, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ranFunction_ShortName },
  { &hf_rc_v3_ranFunction_E2SM_OID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_T_ranFunction_E2SM_OID },
  { &hf_rc_v3_ranFunction_Description, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_PrintableString_SIZE_1_150_ },
  { &hf_rc_v3_ranFunction_Instance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANfunction_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANfunction_Name, RANfunction_Name_sequence);

  return offset;
}



static int
dissect_rc_v3_RIC_Style_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_rc_v3_RIC_Format_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_EventTrigger_Style_Item_sequence[] = {
  { &hf_rc_v3_ric_EventTriggerStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_EventTriggerStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Name },
  { &hf_rc_v3_ric_EventTriggerFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_EventTrigger_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_EventTrigger_Style_Item, RANFunctionDefinition_EventTrigger_Style_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_EventTriggerStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANFunctionDefinition_EventTrigger_Style_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t L2Parameters_RANParameter_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Name },
  { &hf_rc_v3_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_L2Parameters_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_L2Parameters_RANParameter_Item, L2Parameters_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item_sequence_of[1] = {
  { &hf_rc_v3_ran_L2Parameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_L2Parameters_RANParameter_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t CallProcessBreakpoint_RANParameter_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Name },
  { &hf_rc_v3_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_CallProcessBreakpoint_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_CallProcessBreakpoint_RANParameter_Item, CallProcessBreakpoint_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item_sequence_of[1] = {
  { &hf_rc_v3_ran_CallProcessBreakpointParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_CallProcessBreakpoint_RANParameter_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_EventTrigger_Breakpoint_Item_sequence[] = {
  { &hf_rc_v3_callProcessBreakpoint_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_CallProcessBreakpoint_ID },
  { &hf_rc_v3_callProcessBreakpoint_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_CallProcessBreakpoint_Name },
  { &hf_rc_v3_ran_CallProcessBreakpointParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_EventTrigger_Breakpoint_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_EventTrigger_Breakpoint_Item, RANFunctionDefinition_EventTrigger_Breakpoint_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item_sequence_of[1] = {
  { &hf_rc_v3_callProcessBreakpoints_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANFunctionDefinition_EventTrigger_Breakpoint_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item, SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item_sequence_of,
                                                  1, maxnoofCallProcessBreakpoints, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_EventTrigger_CallProcess_Item_sequence[] = {
  { &hf_rc_v3_callProcessType_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_CallProcessType_ID },
  { &hf_rc_v3_callProcessType_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_CallProcessType_Name },
  { &hf_rc_v3_callProcessBreakpoints_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_EventTrigger_CallProcess_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_EventTrigger_CallProcess_Item, RANFunctionDefinition_EventTrigger_CallProcess_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item_sequence_of[1] = {
  { &hf_rc_v3_ran_CallProcessTypes_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANFunctionDefinition_EventTrigger_CallProcess_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item, SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item_sequence_of,
                                                  1, maxnoofCallProcessTypes, false);

  return offset;
}


static const per_sequence_t UEIdentification_RANParameter_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Name },
  { &hf_rc_v3_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_UEIdentification_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_UEIdentification_RANParameter_Item, UEIdentification_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item_sequence_of[1] = {
  { &hf_rc_v3_ran_UEIdentificationParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_UEIdentification_RANParameter_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t CellIdentification_RANParameter_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Name },
  { &hf_rc_v3_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_CellIdentification_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_CellIdentification_RANParameter_Item, CellIdentification_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item_sequence_of[1] = {
  { &hf_rc_v3_ran_CellIdentificationParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_CellIdentification_RANParameter_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_EventTrigger_sequence[] = {
  { &hf_rc_v3_ric_EventTriggerStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item },
  { &hf_rc_v3_ran_L2Parameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item },
  { &hf_rc_v3_ran_CallProcessTypes_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item },
  { &hf_rc_v3_ran_UEIdentificationParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item },
  { &hf_rc_v3_ran_CellIdentificationParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_EventTrigger(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_EventTrigger, RANFunctionDefinition_EventTrigger_sequence);

  return offset;
}


static const per_sequence_t Report_RANParameter_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Name },
  { &hf_rc_v3_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_Report_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_Report_RANParameter_Item, Report_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item_sequence_of[1] = {
  { &hf_rc_v3_ran_ReportParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_Report_RANParameter_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Report_Item_sequence[] = {
  { &hf_rc_v3_ric_ReportStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_ReportStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Name },
  { &hf_rc_v3_ric_SupportedEventTriggerStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_ReportActionFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ric_IndicationHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ric_IndicationMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ran_ReportParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_Report_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_Report_Item, RANFunctionDefinition_Report_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_ReportStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANFunctionDefinition_Report_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Report_sequence[] = {
  { &hf_rc_v3_ric_ReportStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_Report(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_Report, RANFunctionDefinition_Report_sequence);

  return offset;
}


static const per_sequence_t InsertIndication_RANParameter_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Name },
  { &hf_rc_v3_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_InsertIndication_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_InsertIndication_RANParameter_Item, InsertIndication_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item_sequence_of[1] = {
  { &hf_rc_v3_ran_InsertIndicationParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_InsertIndication_RANParameter_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Insert_Indication_Item_sequence[] = {
  { &hf_rc_v3_ric_InsertIndication_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_InsertIndication_ID },
  { &hf_rc_v3_ric_InsertIndication_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_InsertIndication_Name },
  { &hf_rc_v3_ran_InsertIndicationParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_Insert_Indication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_Insert_Indication_Item, RANFunctionDefinition_Insert_Indication_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_InsertIndication_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANFunctionDefinition_Insert_Indication_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item, SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item_sequence_of,
                                                  1, maxnoofInsertIndication, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Insert_Item_sequence[] = {
  { &hf_rc_v3_ric_InsertStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_InsertStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Name },
  { &hf_rc_v3_ric_SupportedEventTriggerStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_ActionDefinitionFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ric_InsertIndication_List_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item },
  { &hf_rc_v3_ric_IndicationHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ric_IndicationMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ric_CallProcessIDFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_Insert_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_Insert_Item, RANFunctionDefinition_Insert_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_InsertStyle_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANFunctionDefinition_Insert_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Insert_sequence[] = {
  { &hf_rc_v3_ric_InsertStyle_List_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_Insert(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_Insert, RANFunctionDefinition_Insert_sequence);

  return offset;
}


static const per_sequence_t ControlAction_RANParameter_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Name },
  { &hf_rc_v3_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_ControlAction_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_ControlAction_RANParameter_Item, ControlAction_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item_sequence_of[1] = {
  { &hf_rc_v3_ran_ControlActionParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_ControlAction_RANParameter_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const value_string rc_v3_T_ueGroup_ControlAction_Supported_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_rc_v3_T_ueGroup_ControlAction_Supported(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Control_Action_Item_sequence[] = {
  { &hf_rc_v3_ric_ControlAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_ControlAction_ID },
  { &hf_rc_v3_ric_ControlAction_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_ControlAction_Name },
  { &hf_rc_v3_ran_ControlActionParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item },
  { &hf_rc_v3_ueGroup_ControlAction_Supported, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_T_ueGroup_ControlAction_Supported },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_Control_Action_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_Control_Action_Item, RANFunctionDefinition_Control_Action_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_ControlAction_List_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANFunctionDefinition_Control_Action_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item, SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item_sequence_of,
                                                  1, maxnoofControlAction, false);

  return offset;
}


static const per_sequence_t ControlOutcome_RANParameter_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Name },
  { &hf_rc_v3_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_ControlOutcome_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_ControlOutcome_RANParameter_Item, ControlOutcome_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item_sequence_of[1] = {
  { &hf_rc_v3_ran_ControlOutcomeParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_ControlOutcome_RANParameter_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item_sequence_of,
                                                  1, maxnoofRANOutcomeParameters, false);

  return offset;
}


static const per_sequence_t AdditionalSupportedFormat_sequence[] = {
  { &hf_rc_v3_ric_ControlHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ric_ControlMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ric_ControlOutcomeFormat_Type, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ric_ControlAction_ID, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RIC_ControlAction_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_AdditionalSupportedFormat(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_AdditionalSupportedFormat, AdditionalSupportedFormat_sequence);

  return offset;
}


static const per_sequence_t ListOfAdditionalSupportedFormats_sequence_of[1] = {
  { &hf_rc_v3_ListOfAdditionalSupportedFormats_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_AdditionalSupportedFormat },
};

static int
dissect_rc_v3_ListOfAdditionalSupportedFormats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_ListOfAdditionalSupportedFormats, ListOfAdditionalSupportedFormats_sequence_of,
                                                  0, maxnoofFormatTypes, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Control_Item_sequence[] = {
  { &hf_rc_v3_ric_ControlStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_ControlStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Name },
  { &hf_rc_v3_ric_ControlAction_List_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item },
  { &hf_rc_v3_ric_ControlHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ric_ControlMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ric_CallProcessIDFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ric_ControlOutcomeFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ran_ControlOutcomeParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item },
  { &hf_rc_v3_listOfAdditionalSupportedFormats, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_ListOfAdditionalSupportedFormats },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_Control_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_Control_Item, RANFunctionDefinition_Control_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_ControlStyle_List_item_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANFunctionDefinition_Control_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Control_sequence[] = {
  { &hf_rc_v3_ric_ControlStyle_List_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_Control(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_Control, RANFunctionDefinition_Control_sequence);

  return offset;
}


static const per_sequence_t PolicyAction_RANParameter_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Name },
  { &hf_rc_v3_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_PolicyAction_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_PolicyAction_RANParameter_Item, PolicyAction_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item_sequence_of[1] = {
  { &hf_rc_v3_ran_PolicyActionParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_PolicyAction_RANParameter_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t PolicyCondition_RANParameter_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Name },
  { &hf_rc_v3_ranParameter_Definition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_PolicyCondition_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_PolicyCondition_RANParameter_Item, PolicyCondition_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item_sequence_of[1] = {
  { &hf_rc_v3_ran_PolicyConditionParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_PolicyCondition_RANParameter_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Policy_Action_Item_sequence[] = {
  { &hf_rc_v3_ric_PolicyAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_ControlAction_ID },
  { &hf_rc_v3_ric_PolicyAction_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_ControlAction_Name },
  { &hf_rc_v3_ric_ActionDefinitionFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ran_PolicyActionParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item },
  { &hf_rc_v3_ran_PolicyConditionParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_Policy_Action_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_Policy_Action_Item, RANFunctionDefinition_Policy_Action_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_PolicyAction_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANFunctionDefinition_Policy_Action_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item, SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item_sequence_of,
                                                  1, maxnoofPolicyAction, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Policy_Item_sequence[] = {
  { &hf_rc_v3_ric_PolicyStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_PolicyStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Name },
  { &hf_rc_v3_ric_SupportedEventTriggerStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_PolicyAction_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_Policy_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_Policy_Item, RANFunctionDefinition_Policy_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_PolicyStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANFunctionDefinition_Policy_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Policy_sequence[] = {
  { &hf_rc_v3_ric_PolicyStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_Policy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_Policy, RANFunctionDefinition_Policy_sequence);

  return offset;
}


static const per_sequence_t Query_RANParameter_Item_sequence[] = {
  { &hf_rc_v3_ranParameter_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_ID },
  { &hf_rc_v3_ranParameter_name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANParameter_Name },
  { &hf_rc_v3_ranParameter_Definition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANParameter_Definition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_Query_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_Query_RANParameter_Item, Query_RANParameter_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Query_RANParameter_Item_sequence_of[1] = {
  { &hf_rc_v3_ran_QueryParameters_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_Query_RANParameter_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Query_RANParameter_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Query_RANParameter_Item, SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Query_RANParameter_Item_sequence_of,
                                                  1, maxnoofAssociatedRANParameters, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Query_Item_sequence[] = {
  { &hf_rc_v3_ric_QueryStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Type },
  { &hf_rc_v3_ric_QueryStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Style_Name },
  { &hf_rc_v3_ric_QueryHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ric_QueryDefinitionFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ric_QueryOutcomeFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RIC_Format_Type },
  { &hf_rc_v3_ran_QueryParameters_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Query_RANParameter_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_Query_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_Query_Item, RANFunctionDefinition_Query_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Query_Item_sequence_of[1] = {
  { &hf_rc_v3_ric_QueryStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANFunctionDefinition_Query_Item },
};

static int
dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Query_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Query_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Query_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Query_sequence[] = {
  { &hf_rc_v3_ric_QueryStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Query_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_RANFunctionDefinition_Query(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_RANFunctionDefinition_Query, RANFunctionDefinition_Query_sequence);

  return offset;
}


static const per_sequence_t E2SM_RC_RANFunctionDefinition_sequence[] = {
  { &hf_rc_v3_ranFunction_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rc_v3_RANfunction_Name },
  { &hf_rc_v3_ranFunctionDefinition_EventTrigger, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANFunctionDefinition_EventTrigger },
  { &hf_rc_v3_ranFunctionDefinition_Report, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANFunctionDefinition_Report },
  { &hf_rc_v3_ranFunctionDefinition_Insert, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANFunctionDefinition_Insert },
  { &hf_rc_v3_ranFunctionDefinition_Control, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANFunctionDefinition_Control },
  { &hf_rc_v3_ranFunctionDefinition_Policy, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rc_v3_RANFunctionDefinition_Policy },
  { &hf_rc_v3_ranFunctionDefinition_Query, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rc_v3_RANFunctionDefinition_Query },
  { NULL, 0, 0, NULL }
};

static int
dissect_rc_v3_E2SM_RC_RANFunctionDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rc_v3_E2SM_RC_RANFunctionDefinition, E2SM_RC_RANFunctionDefinition_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_E2SM_RC_EventTrigger_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_rc_v3_E2SM_RC_EventTrigger(tvb, offset, &asn1_ctx, tree, hf_rc_v3_E2SM_RC_EventTrigger_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_rc_v3_E2SM_RC_ActionDefinition(tvb, offset, &asn1_ctx, tree, hf_rc_v3_E2SM_RC_ActionDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_rc_v3_E2SM_RC_IndicationHeader(tvb, offset, &asn1_ctx, tree, hf_rc_v3_E2SM_RC_IndicationHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_rc_v3_E2SM_RC_IndicationMessage(tvb, offset, &asn1_ctx, tree, hf_rc_v3_E2SM_RC_IndicationMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_CallProcessID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_rc_v3_E2SM_RC_CallProcessID(tvb, offset, &asn1_ctx, tree, hf_rc_v3_E2SM_RC_CallProcessID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_ControlHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_rc_v3_E2SM_RC_ControlHeader(tvb, offset, &asn1_ctx, tree, hf_rc_v3_E2SM_RC_ControlHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_ControlMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_rc_v3_E2SM_RC_ControlMessage(tvb, offset, &asn1_ctx, tree, hf_rc_v3_E2SM_RC_ControlMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_ControlOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_rc_v3_E2SM_RC_ControlOutcome(tvb, offset, &asn1_ctx, tree, hf_rc_v3_E2SM_RC_ControlOutcome_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_QueryHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_rc_v3_E2SM_RC_QueryHeader(tvb, offset, &asn1_ctx, tree, hf_rc_v3_E2SM_RC_QueryHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_QueryDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_rc_v3_E2SM_RC_QueryDefinition(tvb, offset, &asn1_ctx, tree, hf_rc_v3_E2SM_RC_QueryDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_QueryOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_rc_v3_E2SM_RC_QueryOutcome(tvb, offset, &asn1_ctx, tree, hf_rc_v3_E2SM_RC_QueryOutcome_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_RC_RANFunctionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_rc_v3_E2SM_RC_RANFunctionDefinition(tvb, offset, &asn1_ctx, tree, hf_rc_v3_E2SM_RC_RANFunctionDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}



/*--- proto_reg_handoff_rc_v3 ---------------------------------------*/
void
proto_reg_handoff_rc_v3(void)
{
//#include "packet-rc-v3-dis-tab.c"

    static ran_function_dissector_t rc_v3 =
    { "ORAN-E2SM-RC",  "1.3.6.1.4.1.53148.1.1.2.3", 3, 5,
      {  dissect_E2SM_RC_RANFunctionDefinition_PDU,

         dissect_E2SM_RC_ControlHeader_PDU,
         dissect_E2SM_RC_ControlMessage_PDU,
         dissect_E2SM_RC_ControlOutcome_PDU,
         /* new for v3 */
         dissect_E2SM_RC_QueryOutcome_PDU,
         dissect_E2SM_RC_QueryDefinition_PDU,
         dissect_E2SM_RC_QueryHeader_PDU,

         dissect_E2SM_RC_ActionDefinition_PDU,
         dissect_E2SM_RC_IndicationMessage_PDU,
         dissect_E2SM_RC_IndicationHeader_PDU,
         dissect_E2SM_RC_CallProcessID_PDU,
         dissect_E2SM_RC_EventTrigger_PDU
      }
    };

    /* Register dissector with e2ap */
    register_e2ap_ran_function_dissector(RC_RANFUNCTIONS, &rc_v3);
}



/*--- proto_register_rc_v3 -------------------------------------------*/
void proto_register_rc_v3(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_rc_v3_E2SM_RC_EventTrigger_PDU,
      { "E2SM-RC-EventTrigger", "rc-v3.E2SM_RC_EventTrigger_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_E2SM_RC_ActionDefinition_PDU,
      { "E2SM-RC-ActionDefinition", "rc-v3.E2SM_RC_ActionDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_E2SM_RC_IndicationHeader_PDU,
      { "E2SM-RC-IndicationHeader", "rc-v3.E2SM_RC_IndicationHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_E2SM_RC_IndicationMessage_PDU,
      { "E2SM-RC-IndicationMessage", "rc-v3.E2SM_RC_IndicationMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_E2SM_RC_CallProcessID_PDU,
      { "E2SM-RC-CallProcessID", "rc-v3.E2SM_RC_CallProcessID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_E2SM_RC_ControlHeader_PDU,
      { "E2SM-RC-ControlHeader", "rc-v3.E2SM_RC_ControlHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_E2SM_RC_ControlMessage_PDU,
      { "E2SM-RC-ControlMessage", "rc-v3.E2SM_RC_ControlMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_E2SM_RC_ControlOutcome_PDU,
      { "E2SM-RC-ControlOutcome", "rc-v3.E2SM_RC_ControlOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_E2SM_RC_QueryHeader_PDU,
      { "E2SM-RC-QueryHeader", "rc-v3.E2SM_RC_QueryHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_E2SM_RC_QueryDefinition_PDU,
      { "E2SM-RC-QueryDefinition", "rc-v3.E2SM_RC_QueryDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_E2SM_RC_QueryOutcome_PDU,
      { "E2SM-RC-QueryOutcome", "rc-v3.E2SM_RC_QueryOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_E2SM_RC_RANFunctionDefinition_PDU,
      { "E2SM-RC-RANFunctionDefinition", "rc-v3.E2SM_RC_RANFunctionDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_NeighborCell_List_item,
      { "NeighborCell-Item", "rc-v3.NeighborCell_Item",
        FT_UINT32, BASE_DEC, VALS(rc_v3_NeighborCell_Item_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranType_Choice_NR,
      { "ranType-Choice-NR", "rc-v3.ranType_Choice_NR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NeighborCell_Item_Choice_NR", HFILL }},
    { &hf_rc_v3_ranType_Choice_EUTRA,
      { "ranType-Choice-EUTRA", "rc-v3.ranType_Choice_EUTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NeighborCell_Item_Choice_E_UTRA", HFILL }},
    { &hf_rc_v3_nR_CGI,
      { "nR-CGI", "rc-v3.nR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_nR_PCI,
      { "nR-PCI", "rc-v3.nR_PCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_fiveGS_TAC,
      { "fiveGS-TAC", "rc-v3.fiveGS_TAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_nR_mode_info,
      { "nR-mode-info", "rc-v3.nR_mode_info",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_nR_mode_info_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_nR_FreqInfo,
      { "nR-FreqInfo", "rc-v3.nR_FreqInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRFrequencyInfo", HFILL }},
    { &hf_rc_v3_x2_Xn_established,
      { "x2-Xn-established", "rc-v3.x2_Xn_established",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_x2_Xn_established_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_hO_validated,
      { "hO-validated", "rc-v3.hO_validated",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_hO_validated_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_version,
      { "version", "rc-v3.version",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_rc_v3_eUTRA_CGI,
      { "eUTRA-CGI", "rc-v3.eUTRA_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_eUTRA_PCI,
      { "eUTRA-PCI", "rc-v3.eUTRA_PCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRA_PCI", HFILL }},
    { &hf_rc_v3_eUTRA_ARFCN,
      { "eUTRA-ARFCN", "rc-v3.eUTRA_ARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRA_ARFCN", HFILL }},
    { &hf_rc_v3_eUTRA_TAC,
      { "eUTRA-TAC", "rc-v3.eUTRA_TAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "E_UTRA_TAC", HFILL }},
    { &hf_rc_v3_x2_Xn_established_01,
      { "x2-Xn-established", "rc-v3.x2_Xn_established",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_x2_Xn_established_01_vals), 0,
        "T_x2_Xn_established_01", HFILL }},
    { &hf_rc_v3_hO_validated_01,
      { "hO-validated", "rc-v3.hO_validated",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_hO_validated_01_vals), 0,
        "T_hO_validated_01", HFILL }},
    { &hf_rc_v3_servingCellPCI,
      { "servingCellPCI", "rc-v3.servingCellPCI",
        FT_UINT32, BASE_DEC, VALS(rc_v3_ServingCell_PCI_vals), 0,
        "ServingCell_PCI", HFILL }},
    { &hf_rc_v3_servingCellARFCN,
      { "servingCellARFCN", "rc-v3.servingCellARFCN",
        FT_UINT32, BASE_DEC, VALS(rc_v3_ServingCell_ARFCN_vals), 0,
        "ServingCell_ARFCN", HFILL }},
    { &hf_rc_v3_neighborCell_List,
      { "neighborCell-List", "rc-v3.neighborCell_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_cellInfo_List,
      { "cellInfo-List", "rc-v3.cellInfo_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item", HFILL }},
    { &hf_rc_v3_cellInfo_List_item,
      { "EventTrigger-Cell-Info-Item", "rc-v3.EventTrigger_Cell_Info_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_eventTriggerCellID,
      { "eventTriggerCellID", "rc-v3.eventTriggerCellID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RIC_EventTrigger_Cell_ID", HFILL }},
    { &hf_rc_v3_cellType,
      { "cellType", "rc-v3.cellType",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_cellType_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_cellType_Choice_Individual,
      { "cellType-Choice-Individual", "rc-v3.cellType_Choice_Individual_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_Cell_Info_Item_Choice_Individual", HFILL }},
    { &hf_rc_v3_cellType_Choice_Group,
      { "cellType-Choice-Group", "rc-v3.cellType_Choice_Group_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_Cell_Info_Item_Choice_Group", HFILL }},
    { &hf_rc_v3_logicalOR,
      { "logicalOR", "rc-v3.logicalOR",
        FT_UINT32, BASE_DEC, VALS(rc_v3_LogicalOR_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_cellGlobalID,
      { "cellGlobalID", "rc-v3.cellGlobalID",
        FT_UINT32, BASE_DEC, VALS(rc_v3_CGI_vals), 0,
        "CGI", HFILL }},
    { &hf_rc_v3_ranParameterTesting,
      { "ranParameterTesting", "rc-v3.ranParameterTesting",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing", HFILL }},
    { &hf_rc_v3_ueInfo_List,
      { "ueInfo-List", "rc-v3.ueInfo_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item", HFILL }},
    { &hf_rc_v3_ueInfo_List_item,
      { "EventTrigger-UE-Info-Item", "rc-v3.EventTrigger_UE_Info_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_eventTriggerUEID,
      { "eventTriggerUEID", "rc-v3.eventTriggerUEID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RIC_EventTrigger_UE_ID", HFILL }},
    { &hf_rc_v3_ueType,
      { "ueType", "rc-v3.ueType",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ueType_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_ueType_Choice_Individual,
      { "ueType-Choice-Individual", "rc-v3.ueType_Choice_Individual_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UE_Info_Item_Choice_Individual", HFILL }},
    { &hf_rc_v3_ueType_Choice_Group,
      { "ueType-Choice-Group", "rc-v3.ueType_Choice_Group_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UE_Info_Item_Choice_Group", HFILL }},
    { &hf_rc_v3_ueID,
      { "ueID", "rc-v3.ueID",
        FT_UINT32, BASE_DEC, VALS(rc_v3_UEID_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_ueEvent_List,
      { "ueEvent-List", "rc-v3.ueEvent_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item", HFILL }},
    { &hf_rc_v3_ueEvent_List_item,
      { "EventTrigger-UEevent-Info-Item", "rc-v3.EventTrigger_UEevent_Info_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ueEventID,
      { "ueEventID", "rc-v3.ueEventID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RIC_EventTrigger_UEevent_ID", HFILL }},
    { &hf_rc_v3_ranParameter_Definition_Choice,
      { "ranParameter-Definition-Choice", "rc-v3.ranParameter_Definition_Choice",
        FT_UINT32, BASE_DEC, VALS(rc_v3_RANParameter_Definition_Choice_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_choiceLIST,
      { "choiceLIST", "rc-v3.choiceLIST_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_Definition_Choice_LIST", HFILL }},
    { &hf_rc_v3_choiceSTRUCTURE,
      { "choiceSTRUCTURE", "rc-v3.choiceSTRUCTURE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_Definition_Choice_STRUCTURE", HFILL }},
    { &hf_rc_v3_ranParameter_List,
      { "ranParameter-List", "rc-v3.ranParameter_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item", HFILL }},
    { &hf_rc_v3_ranParameter_List_item,
      { "RANParameter-Definition-Choice-LIST-Item", "rc-v3.RANParameter_Definition_Choice_LIST_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranParameter_ID,
      { "ranParameter-ID", "rc-v3.ranParameter_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranParameter_name,
      { "ranParameter-name", "rc-v3.ranParameter_name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranParameter_Definition,
      { "ranParameter-Definition", "rc-v3.ranParameter_Definition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranParameter_STRUCTURE,
      { "ranParameter-STRUCTURE", "rc-v3.ranParameter_STRUCTURE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item", HFILL }},
    { &hf_rc_v3_ranParameter_STRUCTURE_item,
      { "RANParameter-Definition-Choice-STRUCTURE-Item", "rc-v3.RANParameter_Definition_Choice_STRUCTURE_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_valueBoolean,
      { "valueBoolean", "rc-v3.valueBoolean",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_rc_v3_valueInt,
      { "valueInt", "rc-v3.valueInt",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_rc_v3_valueReal,
      { "valueReal", "rc-v3.valueReal",
        FT_DOUBLE, BASE_NONE, NULL, 0,
        "REAL", HFILL }},
    { &hf_rc_v3_valueBitS,
      { "valueBitS", "rc-v3.valueBitS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_rc_v3_valueOctS,
      { "valueOctS", "rc-v3.valueOctS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_rc_v3_valuePrintableString,
      { "valuePrintableString", "rc-v3.valuePrintableString",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_rc_v3_ranP_Choice_ElementTrue,
      { "ranP-Choice-ElementTrue", "rc-v3.ranP_Choice_ElementTrue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_ValueType_Choice_ElementTrue", HFILL }},
    { &hf_rc_v3_ranP_Choice_ElementFalse,
      { "ranP-Choice-ElementFalse", "rc-v3.ranP_Choice_ElementFalse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_ValueType_Choice_ElementFalse", HFILL }},
    { &hf_rc_v3_ranP_Choice_Structure,
      { "ranP-Choice-Structure", "rc-v3.ranP_Choice_Structure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_ValueType_Choice_Structure", HFILL }},
    { &hf_rc_v3_ranP_Choice_List,
      { "ranP-Choice-List", "rc-v3.ranP_Choice_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_ValueType_Choice_List", HFILL }},
    { &hf_rc_v3_ranParameter_value,
      { "ranParameter-value", "rc-v3.ranParameter_value",
        FT_UINT32, BASE_DEC, VALS(rc_v3_RANParameter_Value_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranParameter_Structure,
      { "ranParameter-Structure", "rc-v3.ranParameter_Structure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranParameter_List_01,
      { "ranParameter-List", "rc-v3.ranParameter_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_sequence_of_ranParameters,
      { "sequence-of-ranParameters", "rc-v3.sequence_of_ranParameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item", HFILL }},
    { &hf_rc_v3_sequence_of_ranParameters_item,
      { "RANParameter-STRUCTURE-Item", "rc-v3.RANParameter_STRUCTURE_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranParameter_valueType,
      { "ranParameter-valueType", "rc-v3.ranParameter_valueType",
        FT_UINT32, BASE_DEC, VALS(rc_v3_RANParameter_ValueType_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_list_of_ranParameter,
      { "list-of-ranParameter", "rc-v3.list_of_ranParameter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE", HFILL }},
    { &hf_rc_v3_list_of_ranParameter_item,
      { "RANParameter-STRUCTURE", "rc-v3.RANParameter_STRUCTURE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_RANParameter_Testing_item,
      { "RANParameter-Testing-Item", "rc-v3.RANParameter_Testing_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranP_Choice_comparison,
      { "ranP-Choice-comparison", "rc-v3.ranP_Choice_comparison",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ranP_Choice_comparison_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranP_Choice_presence,
      { "ranP-Choice-presence", "rc-v3.ranP_Choice_presence",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ranP_Choice_presence_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranParameter_Type,
      { "ranParameter-Type", "rc-v3.ranParameter_Type",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ranParameter_Type_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranP_Choice_List_01,
      { "ranP-Choice-List", "rc-v3.ranP_Choice_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_Testing_Item_Choice_List", HFILL }},
    { &hf_rc_v3_ranP_Choice_Structure_01,
      { "ranP-Choice-Structure", "rc-v3.ranP_Choice_Structure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_Testing_Item_Choice_Structure", HFILL }},
    { &hf_rc_v3_ranP_Choice_ElementTrue_01,
      { "ranP-Choice-ElementTrue", "rc-v3.ranP_Choice_ElementTrue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_Testing_Item_Choice_ElementTrue", HFILL }},
    { &hf_rc_v3_ranP_Choice_ElementFalse_01,
      { "ranP-Choice-ElementFalse", "rc-v3.ranP_Choice_ElementFalse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANParameter_Testing_Item_Choice_ElementFalse", HFILL }},
    { &hf_rc_v3_ranParameter_List_02,
      { "ranParameter-List", "rc-v3.ranParameter_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing_LIST", HFILL }},
    { &hf_rc_v3_ranParameter_Structure_01,
      { "ranParameter-Structure", "rc-v3.ranParameter_Structure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing_STRUCTURE", HFILL }},
    { &hf_rc_v3_ranParameter_TestCondition,
      { "ranParameter-TestCondition", "rc-v3.ranParameter_TestCondition",
        FT_UINT32, BASE_DEC, VALS(rc_v3_RANParameter_TestingCondition_vals), 0,
        "RANParameter_TestingCondition", HFILL }},
    { &hf_rc_v3_ranParameter_Value,
      { "ranParameter-Value", "rc-v3.ranParameter_Value",
        FT_UINT32, BASE_DEC, VALS(rc_v3_RANParameter_Value_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_RANParameter_Testing_LIST_item,
      { "RANParameter-Testing-Item", "rc-v3.RANParameter_Testing_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_RANParameter_Testing_STRUCTURE_item,
      { "RANParameter-Testing-Item", "rc-v3.RANParameter_Testing_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ueGroupDefinitionIdentifier_LIST,
      { "ueGroupDefinitionIdentifier-LIST", "rc-v3.ueGroupDefinitionIdentifier_LIST",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxGroupDefinitionIdentifierParameters_OF_UEGroupDefinitionIdentifier_Item", HFILL }},
    { &hf_rc_v3_ueGroupDefinitionIdentifier_LIST_item,
      { "UEGroupDefinitionIdentifier-Item", "rc-v3.UEGroupDefinitionIdentifier_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_PolicyAction_ID,
      { "ric-PolicyAction-ID", "rc-v3.ric_PolicyAction_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RIC_ControlAction_ID", HFILL }},
    { &hf_rc_v3_ranParameters_List,
      { "ranParameters-List", "rc-v3.ranParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item", HFILL }},
    { &hf_rc_v3_ranParameters_List_item,
      { "RIC-PolicyAction-RANParameter-Item", "rc-v3.RIC_PolicyAction_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_PolicyDecision,
      { "ric-PolicyDecision", "rc-v3.ric_PolicyDecision",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_PolicyDecision_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_associatedUEInfo_List,
      { "associatedUEInfo-List", "rc-v3.associatedUEInfo_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEInfo_OF_Associated_UE_Info_Item", HFILL }},
    { &hf_rc_v3_associatedUEInfo_List_item,
      { "Associated-UE-Info-Item", "rc-v3.Associated_UE_Info_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ueFilterID,
      { "ueFilterID", "rc-v3.ueFilterID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UE_Filter_ID", HFILL }},
    { &hf_rc_v3_ueType_01,
      { "ueType", "rc-v3.ueType",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ueType_01_vals), 0,
        "T_ueType_01", HFILL }},
    { &hf_rc_v3_ueQuery,
      { "ueQuery", "rc-v3.ueQuery_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_partialUEID,
      { "partialUEID", "rc-v3.partialUEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_eventTrigger_formats,
      { "ric-eventTrigger-formats", "rc-v3.ric_eventTrigger_formats",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_eventTrigger_formats_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_eventTrigger_Format1,
      { "eventTrigger-Format1", "rc-v3.eventTrigger_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_EventTrigger_Format1", HFILL }},
    { &hf_rc_v3_eventTrigger_Format2,
      { "eventTrigger-Format2", "rc-v3.eventTrigger_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_EventTrigger_Format2", HFILL }},
    { &hf_rc_v3_eventTrigger_Format3,
      { "eventTrigger-Format3", "rc-v3.eventTrigger_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_EventTrigger_Format3", HFILL }},
    { &hf_rc_v3_eventTrigger_Format4,
      { "eventTrigger-Format4", "rc-v3.eventTrigger_Format4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_EventTrigger_Format4", HFILL }},
    { &hf_rc_v3_eventTrigger_Format5,
      { "eventTrigger-Format5", "rc-v3.eventTrigger_Format5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_message_List,
      { "message-List", "rc-v3.message_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item", HFILL }},
    { &hf_rc_v3_message_List_item,
      { "E2SM-RC-EventTrigger-Format1-Item", "rc-v3.E2SM_RC_EventTrigger_Format1_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_globalAssociatedUEInfo,
      { "globalAssociatedUEInfo", "rc-v3.globalAssociatedUEInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UE_Info", HFILL }},
    { &hf_rc_v3_ric_eventTriggerCondition_ID,
      { "ric-eventTriggerCondition-ID", "rc-v3.ric_eventTriggerCondition_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_messageType,
      { "messageType", "rc-v3.messageType",
        FT_UINT32, BASE_DEC, VALS(rc_v3_MessageType_Choice_vals), 0,
        "MessageType_Choice", HFILL }},
    { &hf_rc_v3_messageDirection,
      { "messageDirection", "rc-v3.messageDirection",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_messageDirection_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_associatedUEInfo,
      { "associatedUEInfo", "rc-v3.associatedUEInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UE_Info", HFILL }},
    { &hf_rc_v3_associatedUEEvent,
      { "associatedUEEvent", "rc-v3.associatedUEEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UEevent_Info", HFILL }},
    { &hf_rc_v3_messageType_Choice_NI,
      { "messageType-Choice-NI", "rc-v3.messageType_Choice_NI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_messageType_Choice_RRC,
      { "messageType-Choice-RRC", "rc-v3.messageType_Choice_RRC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_nI_Type,
      { "nI-Type", "rc-v3.nI_Type",
        FT_UINT32, BASE_DEC, VALS(rc_v3_InterfaceType_vals), 0,
        "InterfaceType", HFILL }},
    { &hf_rc_v3_nI_Identifier,
      { "nI-Identifier", "rc-v3.nI_Identifier",
        FT_UINT32, BASE_DEC, VALS(rc_v3_InterfaceIdentifier_vals), 0,
        "InterfaceIdentifier", HFILL }},
    { &hf_rc_v3_nI_Message,
      { "nI-Message", "rc-v3.nI_Message_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Interface_MessageID", HFILL }},
    { &hf_rc_v3_rRC_Message,
      { "rRC-Message", "rc-v3.rRC_Message_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RRC_MessageID", HFILL }},
    { &hf_rc_v3_ric_callProcessType_ID,
      { "ric-callProcessType-ID", "rc-v3.ric_callProcessType_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_callProcessBreakpoint_ID,
      { "ric-callProcessBreakpoint-ID", "rc-v3.ric_callProcessBreakpoint_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_associatedE2NodeInfo,
      { "associatedE2NodeInfo", "rc-v3.associatedE2NodeInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing", HFILL }},
    { &hf_rc_v3_e2NodeInfoChange_List,
      { "e2NodeInfoChange-List", "rc-v3.e2NodeInfoChange_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item", HFILL }},
    { &hf_rc_v3_e2NodeInfoChange_List_item,
      { "E2SM-RC-EventTrigger-Format3-Item", "rc-v3.E2SM_RC_EventTrigger_Format3_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_e2NodeInfoChange_ID,
      { "e2NodeInfoChange-ID", "rc-v3.e2NodeInfoChange_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_512_", HFILL }},
    { &hf_rc_v3_associatedCellInfo,
      { "associatedCellInfo", "rc-v3.associatedCellInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_Cell_Info", HFILL }},
    { &hf_rc_v3_uEInfoChange_List,
      { "uEInfoChange-List", "rc-v3.uEInfoChange_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item", HFILL }},
    { &hf_rc_v3_uEInfoChange_List_item,
      { "E2SM-RC-EventTrigger-Format4-Item", "rc-v3.E2SM_RC_EventTrigger_Format4_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_triggerType,
      { "triggerType", "rc-v3.triggerType",
        FT_UINT32, BASE_DEC, VALS(rc_v3_TriggerType_Choice_vals), 0,
        "TriggerType_Choice", HFILL }},
    { &hf_rc_v3_triggerType_Choice_RRCstate,
      { "triggerType-Choice-RRCstate", "rc-v3.triggerType_Choice_RRCstate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_triggerType_Choice_UEID,
      { "triggerType-Choice-UEID", "rc-v3.triggerType_Choice_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_triggerType_Choice_L2state,
      { "triggerType-Choice-L2state", "rc-v3.triggerType_Choice_L2state_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_triggerType_Choice_UEcontext,
      { "triggerType-Choice-UEcontext", "rc-v3.triggerType_Choice_UEcontext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_triggerType_Choice_L2MACschChg,
      { "triggerType-Choice-L2MACschChg", "rc-v3.triggerType_Choice_L2MACschChg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_rrcState_List,
      { "rrcState-List", "rc-v3.rrcState_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item", HFILL }},
    { &hf_rc_v3_rrcState_List_item,
      { "TriggerType-Choice-RRCstate-Item", "rc-v3.TriggerType_Choice_RRCstate_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_stateChangedTo,
      { "stateChangedTo", "rc-v3.stateChangedTo",
        FT_UINT32, BASE_DEC, VALS(rc_v3_RRC_State_vals), 0,
        "RRC_State", HFILL }},
    { &hf_rc_v3_ueIDchange_ID,
      { "ueIDchange-ID", "rc-v3.ueIDchange_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_512_", HFILL }},
    { &hf_rc_v3_associatedL2variables,
      { "associatedL2variables", "rc-v3.associatedL2variables",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing", HFILL }},
    { &hf_rc_v3_associatedUECtxtVariables,
      { "associatedUECtxtVariables", "rc-v3.associatedUECtxtVariables",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing", HFILL }},
    { &hf_rc_v3_l2MACschChgType,
      { "l2MACschChgType", "rc-v3.l2MACschChgType",
        FT_UINT32, BASE_DEC, VALS(rc_v3_L2MACschChgType_Choice_vals), 0,
        "L2MACschChgType_Choice", HFILL }},
    { &hf_rc_v3_triggerType_Choice_MIMOandBFconfig,
      { "triggerType-Choice-MIMOandBFconfig", "rc-v3.triggerType_Choice_MIMOandBFconfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_mIMOtransModeState,
      { "mIMOtransModeState", "rc-v3.mIMOtransModeState",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_mIMOtransModeState_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_Style_Type,
      { "ric-Style-Type", "rc-v3.ric_Style_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_actionDefinition_formats,
      { "ric-actionDefinition-formats", "rc-v3.ric_actionDefinition_formats",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_actionDefinition_formats_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_actionDefinition_Format1,
      { "actionDefinition-Format1", "rc-v3.actionDefinition_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ActionDefinition_Format1", HFILL }},
    { &hf_rc_v3_actionDefinition_Format2,
      { "actionDefinition-Format2", "rc-v3.actionDefinition_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ActionDefinition_Format2", HFILL }},
    { &hf_rc_v3_actionDefinition_Format3,
      { "actionDefinition-Format3", "rc-v3.actionDefinition_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ActionDefinition_Format3", HFILL }},
    { &hf_rc_v3_actionDefinition_Format4,
      { "actionDefinition-Format4", "rc-v3.actionDefinition_Format4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ActionDefinition_Format4", HFILL }},
    { &hf_rc_v3_ranP_ToBeReported_List,
      { "ranP-ToBeReported-List", "rc-v3.ranP_ToBeReported_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item", HFILL }},
    { &hf_rc_v3_ranP_ToBeReported_List_item,
      { "E2SM-RC-ActionDefinition-Format1-Item", "rc-v3.E2SM_RC_ActionDefinition_Format1_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_PolicyConditions_List,
      { "ric-PolicyConditions-List", "rc-v3.ric_PolicyConditions_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item", HFILL }},
    { &hf_rc_v3_ric_PolicyConditions_List_item,
      { "E2SM-RC-ActionDefinition-Format2-Item", "rc-v3.E2SM_RC_ActionDefinition_Format2_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_PolicyAction,
      { "ric-PolicyAction", "rc-v3.ric_PolicyAction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_PolicyConditionDefinition,
      { "ric-PolicyConditionDefinition", "rc-v3.ric_PolicyConditionDefinition",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing", HFILL }},
    { &hf_rc_v3_ric_InsertIndication_ID,
      { "ric-InsertIndication-ID", "rc-v3.ric_InsertIndication_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranP_InsertIndication_List,
      { "ranP-InsertIndication-List", "rc-v3.ranP_InsertIndication_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item", HFILL }},
    { &hf_rc_v3_ranP_InsertIndication_List_item,
      { "E2SM-RC-ActionDefinition-Format3-Item", "rc-v3.E2SM_RC_ActionDefinition_Format3_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_InsertStyle_List,
      { "ric-InsertStyle-List", "rc-v3.ric_InsertStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item", HFILL }},
    { &hf_rc_v3_ric_InsertStyle_List_item,
      { "E2SM-RC-ActionDefinition-Format4-Style-Item", "rc-v3.E2SM_RC_ActionDefinition_Format4_Style_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_requested_Insert_Style_Type,
      { "requested-Insert-Style-Type", "rc-v3.requested_Insert_Style_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_rc_v3_ric_InsertIndication_List,
      { "ric-InsertIndication-List", "rc-v3.ric_InsertIndication_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item", HFILL }},
    { &hf_rc_v3_ric_InsertIndication_List_item,
      { "E2SM-RC-ActionDefinition-Format4-Indication-Item", "rc-v3.E2SM_RC_ActionDefinition_Format4_Indication_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranP_InsertIndication_List_01,
      { "ranP-InsertIndication-List", "rc-v3.ranP_InsertIndication_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item", HFILL }},
    { &hf_rc_v3_ranP_InsertIndication_List_item_01,
      { "E2SM-RC-ActionDefinition-Format4-RANP-Item", "rc-v3.E2SM_RC_ActionDefinition_Format4_RANP_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_indicationHeader_formats,
      { "ric-indicationHeader-formats", "rc-v3.ric_indicationHeader_formats",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_indicationHeader_formats_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_indicationHeader_Format1,
      { "indicationHeader-Format1", "rc-v3.indicationHeader_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationHeader_Format1", HFILL }},
    { &hf_rc_v3_indicationHeader_Format2,
      { "indicationHeader-Format2", "rc-v3.indicationHeader_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationHeader_Format2", HFILL }},
    { &hf_rc_v3_indicationHeader_Format3,
      { "indicationHeader-Format3", "rc-v3.indicationHeader_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationHeader_Format3", HFILL }},
    { &hf_rc_v3_ric_InsertStyle_Type,
      { "ric-InsertStyle-Type", "rc-v3.ric_InsertStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_rc_v3_ric_indicationMessage_formats,
      { "ric-indicationMessage-formats", "rc-v3.ric_indicationMessage_formats",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_indicationMessage_formats_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_indicationMessage_Format1,
      { "indicationMessage-Format1", "rc-v3.indicationMessage_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationMessage_Format1", HFILL }},
    { &hf_rc_v3_indicationMessage_Format2,
      { "indicationMessage-Format2", "rc-v3.indicationMessage_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationMessage_Format2", HFILL }},
    { &hf_rc_v3_indicationMessage_Format3,
      { "indicationMessage-Format3", "rc-v3.indicationMessage_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationMessage_Format3", HFILL }},
    { &hf_rc_v3_indicationMessage_Format4,
      { "indicationMessage-Format4", "rc-v3.indicationMessage_Format4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_indicationMessage_Format5,
      { "indicationMessage-Format5", "rc-v3.indicationMessage_Format5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationMessage_Format5", HFILL }},
    { &hf_rc_v3_indicationMessage_Format6,
      { "indicationMessage-Format6", "rc-v3.indicationMessage_Format6_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_IndicationMessage_Format6", HFILL }},
    { &hf_rc_v3_ranP_Reported_List,
      { "ranP-Reported-List", "rc-v3.ranP_Reported_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item", HFILL }},
    { &hf_rc_v3_ranP_Reported_List_item,
      { "E2SM-RC-IndicationMessage-Format1-Item", "rc-v3.E2SM_RC_IndicationMessage_Format1_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ueParameter_List,
      { "ueParameter-List", "rc-v3.ueParameter_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item", HFILL }},
    { &hf_rc_v3_ueParameter_List_item,
      { "E2SM-RC-IndicationMessage-Format2-Item", "rc-v3.E2SM_RC_IndicationMessage_Format2_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranP_List,
      { "ranP-List", "rc-v3.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item", HFILL }},
    { &hf_rc_v3_ranP_List_item,
      { "E2SM-RC-IndicationMessage-Format2-RANParameter-Item", "rc-v3.E2SM_RC_IndicationMessage_Format2_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_cellInfo_List_01,
      { "cellInfo-List", "rc-v3.cellInfo_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item", HFILL }},
    { &hf_rc_v3_cellInfo_List_item_01,
      { "E2SM-RC-IndicationMessage-Format3-Item", "rc-v3.E2SM_RC_IndicationMessage_Format3_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_cellGlobal_ID,
      { "cellGlobal-ID", "rc-v3.cellGlobal_ID",
        FT_UINT32, BASE_DEC, VALS(rc_v3_CGI_vals), 0,
        "CGI", HFILL }},
    { &hf_rc_v3_cellContextInfo,
      { "cellContextInfo", "rc-v3.cellContextInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_rc_v3_cellDeleted,
      { "cellDeleted", "rc-v3.cellDeleted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_rc_v3_neighborRelation_Table,
      { "neighborRelation-Table", "rc-v3.neighborRelation_Table_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NeighborRelation_Info", HFILL }},
    { &hf_rc_v3_ranP_Requested_List,
      { "ranP-Requested-List", "rc-v3.ranP_Requested_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item", HFILL }},
    { &hf_rc_v3_ranP_Requested_List_item,
      { "E2SM-RC-IndicationMessage-Format5-Item", "rc-v3.E2SM_RC_IndicationMessage_Format5_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_InsertStyle_List_01,
      { "ric-InsertStyle-List", "rc-v3.ric_InsertStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item", HFILL }},
    { &hf_rc_v3_ric_InsertStyle_List_item_01,
      { "E2SM-RC-IndicationMessage-Format6-Style-Item", "rc-v3.E2SM_RC_IndicationMessage_Format6_Style_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_indicated_Insert_Style_Type,
      { "indicated-Insert-Style-Type", "rc-v3.indicated_Insert_Style_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_rc_v3_ric_InsertIndication_List_01,
      { "ric-InsertIndication-List", "rc-v3.ric_InsertIndication_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item", HFILL }},
    { &hf_rc_v3_ric_InsertIndication_List_item_01,
      { "E2SM-RC-IndicationMessage-Format6-Indication-Item", "rc-v3.E2SM_RC_IndicationMessage_Format6_Indication_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranP_InsertIndication_List_02,
      { "ranP-InsertIndication-List", "rc-v3.ranP_InsertIndication_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item", HFILL }},
    { &hf_rc_v3_ranP_InsertIndication_List_item_02,
      { "E2SM-RC-IndicationMessage-Format6-RANP-Item", "rc-v3.E2SM_RC_IndicationMessage_Format6_RANP_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_callProcessID_formats,
      { "ric-callProcessID-formats", "rc-v3.ric_callProcessID_formats",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_callProcessID_formats_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_callProcessID_Format1,
      { "callProcessID-Format1", "rc-v3.callProcessID_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_CallProcessID_Format1", HFILL }},
    { &hf_rc_v3_ric_callProcess_ID,
      { "ric-callProcess-ID", "rc-v3.ric_callProcess_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAN_CallProcess_ID", HFILL }},
    { &hf_rc_v3_ric_controlHeader_formats,
      { "ric-controlHeader-formats", "rc-v3.ric_controlHeader_formats",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_controlHeader_formats_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_controlHeader_Format1,
      { "controlHeader-Format1", "rc-v3.controlHeader_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlHeader_Format1", HFILL }},
    { &hf_rc_v3_controlHeader_Format2,
      { "controlHeader-Format2", "rc-v3.controlHeader_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlHeader_Format2", HFILL }},
    { &hf_rc_v3_controlHeader_Format3,
      { "controlHeader-Format3", "rc-v3.controlHeader_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlHeader_Format3", HFILL }},
    { &hf_rc_v3_controlHeader_Format4,
      { "controlHeader-Format4", "rc-v3.controlHeader_Format4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlHeader_Format4", HFILL }},
    { &hf_rc_v3_ric_ControlAction_ID,
      { "ric-ControlAction-ID", "rc-v3.ric_ControlAction_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_ControlDecision,
      { "ric-ControlDecision", "rc-v3.ric_ControlDecision",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_ControlDecision_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_ControlDecision_01,
      { "ric-ControlDecision", "rc-v3.ric_ControlDecision",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_ControlDecision_01_vals), 0,
        "T_ric_ControlDecision_01", HFILL }},
    { &hf_rc_v3_ue_Group_ID,
      { "ue-Group-ID", "rc-v3.ue_Group_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ue_Group_Definition,
      { "ue-Group-Definition", "rc-v3.ue_Group_Definition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_partial_ueID,
      { "partial-ueID", "rc-v3.partial_ueID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartialUEID", HFILL }},
    { &hf_rc_v3_ric_ControlDecision_02,
      { "ric-ControlDecision", "rc-v3.ric_ControlDecision",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_ControlDecision_02_vals), 0,
        "T_ric_ControlDecision_02", HFILL }},
    { &hf_rc_v3_ric_controlMessage_formats,
      { "ric-controlMessage-formats", "rc-v3.ric_controlMessage_formats",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_controlMessage_formats_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_controlMessage_Format1,
      { "controlMessage-Format1", "rc-v3.controlMessage_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlMessage_Format1", HFILL }},
    { &hf_rc_v3_controlMessage_Format2,
      { "controlMessage-Format2", "rc-v3.controlMessage_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlMessage_Format2", HFILL }},
    { &hf_rc_v3_controlMessage_Format3,
      { "controlMessage-Format3", "rc-v3.controlMessage_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlMessage_Format3", HFILL }},
    { &hf_rc_v3_controlMessage_Format4,
      { "controlMessage-Format4", "rc-v3.controlMessage_Format4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlMessage_Format4", HFILL }},
    { &hf_rc_v3_controlMessage_Format5,
      { "controlMessage-Format5", "rc-v3.controlMessage_Format5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlMessage_Format5", HFILL }},
    { &hf_rc_v3_ranP_List_01,
      { "ranP-List", "rc-v3.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item", HFILL }},
    { &hf_rc_v3_ranP_List_item_01,
      { "E2SM-RC-ControlMessage-Format1-Item", "rc-v3.E2SM_RC_ControlMessage_Format1_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_ControlStyle_List,
      { "ric-ControlStyle-List", "rc-v3.ric_ControlStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item", HFILL }},
    { &hf_rc_v3_ric_ControlStyle_List_item,
      { "E2SM-RC-ControlMessage-Format2-Style-Item", "rc-v3.E2SM_RC_ControlMessage_Format2_Style_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_indicated_Control_Style_Type,
      { "indicated-Control-Style-Type", "rc-v3.indicated_Control_Style_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_rc_v3_ric_ControlAction_List,
      { "ric-ControlAction-List", "rc-v3.ric_ControlAction_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item", HFILL }},
    { &hf_rc_v3_ric_ControlAction_List_item,
      { "E2SM-RC-ControlMessage-Format2-ControlAction-Item", "rc-v3.E2SM_RC_ControlMessage_Format2_ControlAction_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranP_List_02,
      { "ranP-List", "rc-v3.ranP_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlMessage_Format1", HFILL }},
    { &hf_rc_v3_listOfEntityFilters,
      { "listOfEntityFilters", "rc-v3.listOfEntityFilters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofAssociatedEntityFilters_OF_E2SM_RC_EntityFilter", HFILL }},
    { &hf_rc_v3_listOfEntityFilters_item,
      { "E2SM-RC-EntityFilter", "rc-v3.E2SM_RC_EntityFilter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_entityAgnosticControlRanP_List,
      { "entityAgnosticControlRanP-List", "rc-v3.entityAgnosticControlRanP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_EntityAgnostic_ranP_ControlParameters", HFILL }},
    { &hf_rc_v3_entityAgnosticControlRanP_List_item,
      { "EntityAgnostic-ranP-ControlParameters", "rc-v3.EntityAgnostic_ranP_ControlParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_entityFilter_ID,
      { "entityFilter-ID", "rc-v3.entityFilter_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_entityFilter_Definition,
      { "entityFilter-Definition", "rc-v3.entityFilter_Definition",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RANParameter_Testing", HFILL }},
    { &hf_rc_v3_entitySpecificControlRanP_List,
      { "entitySpecificControlRanP-List", "rc-v3.entitySpecificControlRanP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_EntitySpecific_ranP_ControlParameters", HFILL }},
    { &hf_rc_v3_entitySpecificControlRanP_List_item,
      { "EntitySpecific-ranP-ControlParameters", "rc-v3.EntitySpecific_ranP_ControlParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranP_List_03,
      { "ranP-List", "rc-v3.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format4_Item", HFILL }},
    { &hf_rc_v3_ranP_List_item_02,
      { "E2SM-RC-ControlMessage-Format4-Item", "rc-v3.E2SM_RC_ControlMessage_Format4_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_controlOutcome_formats,
      { "ric-controlOutcome-formats", "rc-v3.ric_controlOutcome_formats",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_controlOutcome_formats_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_controlOutcome_Format1,
      { "controlOutcome-Format1", "rc-v3.controlOutcome_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlOutcome_Format1", HFILL }},
    { &hf_rc_v3_controlOutcome_Format2,
      { "controlOutcome-Format2", "rc-v3.controlOutcome_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlOutcome_Format2", HFILL }},
    { &hf_rc_v3_controlOutcome_Format3,
      { "controlOutcome-Format3", "rc-v3.controlOutcome_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_ControlOutcome_Format3", HFILL }},
    { &hf_rc_v3_ranP_List_04,
      { "ranP-List", "rc-v3.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item", HFILL }},
    { &hf_rc_v3_ranP_List_item_03,
      { "E2SM-RC-ControlOutcome-Format1-Item", "rc-v3.E2SM_RC_ControlOutcome_Format1_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_ControlStyle_List_01,
      { "ric-ControlStyle-List", "rc-v3.ric_ControlStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item", HFILL }},
    { &hf_rc_v3_ric_ControlStyle_List_item_01,
      { "E2SM-RC-ControlOutcome-Format2-Style-Item", "rc-v3.E2SM_RC_ControlOutcome_Format2_Style_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_ControlOutcome_List,
      { "ric-ControlOutcome-List", "rc-v3.ric_ControlOutcome_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item", HFILL }},
    { &hf_rc_v3_ric_ControlOutcome_List_item,
      { "E2SM-RC-ControlOutcome-Format2-ControlOutcome-Item", "rc-v3.E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranP_List_05,
      { "ranP-List", "rc-v3.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item", HFILL }},
    { &hf_rc_v3_ranP_List_item_04,
      { "E2SM-RC-ControlOutcome-Format2-RANP-Item", "rc-v3.E2SM_RC_ControlOutcome_Format2_RANP_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranP_List_06,
      { "ranP-List", "rc-v3.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item", HFILL }},
    { &hf_rc_v3_ranP_List_item_05,
      { "E2SM-RC-ControlOutcome-Format3-Item", "rc-v3.E2SM_RC_ControlOutcome_Format3_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_queryHeader_formats,
      { "ric-queryHeader-formats", "rc-v3.ric_queryHeader_formats",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_queryHeader_formats_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_queryHeader_Format1,
      { "queryHeader-Format1", "rc-v3.queryHeader_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_QueryHeader_Format1", HFILL }},
    { &hf_rc_v3_associatedUEInfo_01,
      { "associatedUEInfo", "rc-v3.associatedUEInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Associated_UE_Info", HFILL }},
    { &hf_rc_v3_ric_queryDefinition_formats,
      { "ric-queryDefinition-formats", "rc-v3.ric_queryDefinition_formats",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_queryDefinition_formats_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_queryRequest_Format1,
      { "queryRequest-Format1", "rc-v3.queryRequest_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_QueryDefinition_Format1", HFILL }},
    { &hf_rc_v3_ranP_List_07,
      { "ranP-List", "rc-v3.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryDefinition_Format1_Item", HFILL }},
    { &hf_rc_v3_ranP_List_item_06,
      { "E2SM-RC-QueryDefinition-Format1-Item", "rc-v3.E2SM_RC_QueryDefinition_Format1_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_queryOutcome_formats,
      { "ric-queryOutcome-formats", "rc-v3.ric_queryOutcome_formats",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ric_queryOutcome_formats_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_queryOutcome_Format1,
      { "queryOutcome-Format1", "rc-v3.queryOutcome_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_QueryOutcome_Format1", HFILL }},
    { &hf_rc_v3_queryOutcome_Format2,
      { "queryOutcome-Format2", "rc-v3.queryOutcome_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_RC_QueryOutcome_Format2", HFILL }},
    { &hf_rc_v3_cellInfo_List_02,
      { "cellInfo-List", "rc-v3.cellInfo_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_QueryOutcome_Format1_ItemCell", HFILL }},
    { &hf_rc_v3_cellInfo_List_item_02,
      { "E2SM-RC-QueryOutcome-Format1-ItemCell", "rc-v3.E2SM_RC_QueryOutcome_Format1_ItemCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranP_List_08,
      { "ranP-List", "rc-v3.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format1_ItemParameters", HFILL }},
    { &hf_rc_v3_ranP_List_item_07,
      { "E2SM-RC-QueryOutcome-Format1-ItemParameters", "rc-v3.E2SM_RC_QueryOutcome_Format1_ItemParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ueInfo_List_01,
      { "ueInfo-List", "rc-v3.ueInfo_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_QueryOutcome_Format2_ItemUE", HFILL }},
    { &hf_rc_v3_ueInfo_List_item_01,
      { "E2SM-RC-QueryOutcome-Format2-ItemUE", "rc-v3.E2SM_RC_QueryOutcome_Format2_ItemUE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranP_List_09,
      { "ranP-List", "rc-v3.ranP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format2_ItemParameters", HFILL }},
    { &hf_rc_v3_ranP_List_item_08,
      { "E2SM-RC-QueryOutcome-Format2-ItemParameters", "rc-v3.E2SM_RC_QueryOutcome_Format2_ItemParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranFunction_Name,
      { "ranFunction-Name", "rc-v3.ranFunction_Name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranFunctionDefinition_EventTrigger,
      { "ranFunctionDefinition-EventTrigger", "rc-v3.ranFunctionDefinition_EventTrigger_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranFunctionDefinition_Report,
      { "ranFunctionDefinition-Report", "rc-v3.ranFunctionDefinition_Report_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranFunctionDefinition_Insert,
      { "ranFunctionDefinition-Insert", "rc-v3.ranFunctionDefinition_Insert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranFunctionDefinition_Control,
      { "ranFunctionDefinition-Control", "rc-v3.ranFunctionDefinition_Control_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranFunctionDefinition_Policy,
      { "ranFunctionDefinition-Policy", "rc-v3.ranFunctionDefinition_Policy_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranFunctionDefinition_Query,
      { "ranFunctionDefinition-Query", "rc-v3.ranFunctionDefinition_Query_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_EventTriggerStyle_List,
      { "ric-EventTriggerStyle-List", "rc-v3.ric_EventTriggerStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item", HFILL }},
    { &hf_rc_v3_ric_EventTriggerStyle_List_item,
      { "RANFunctionDefinition-EventTrigger-Style-Item", "rc-v3.RANFunctionDefinition_EventTrigger_Style_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ran_L2Parameters_List,
      { "ran-L2Parameters-List", "rc-v3.ran_L2Parameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item", HFILL }},
    { &hf_rc_v3_ran_L2Parameters_List_item,
      { "L2Parameters-RANParameter-Item", "rc-v3.L2Parameters_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ran_CallProcessTypes_List,
      { "ran-CallProcessTypes-List", "rc-v3.ran_CallProcessTypes_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item", HFILL }},
    { &hf_rc_v3_ran_CallProcessTypes_List_item,
      { "RANFunctionDefinition-EventTrigger-CallProcess-Item", "rc-v3.RANFunctionDefinition_EventTrigger_CallProcess_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ran_UEIdentificationParameters_List,
      { "ran-UEIdentificationParameters-List", "rc-v3.ran_UEIdentificationParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item", HFILL }},
    { &hf_rc_v3_ran_UEIdentificationParameters_List_item,
      { "UEIdentification-RANParameter-Item", "rc-v3.UEIdentification_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ran_CellIdentificationParameters_List,
      { "ran-CellIdentificationParameters-List", "rc-v3.ran_CellIdentificationParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item", HFILL }},
    { &hf_rc_v3_ran_CellIdentificationParameters_List_item,
      { "CellIdentification-RANParameter-Item", "rc-v3.CellIdentification_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_EventTriggerStyle_Type,
      { "ric-EventTriggerStyle-Type", "rc-v3.ric_EventTriggerStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_rc_v3_ric_EventTriggerStyle_Name,
      { "ric-EventTriggerStyle-Name", "rc-v3.ric_EventTriggerStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_rc_v3_ric_EventTriggerFormat_Type,
      { "ric-EventTriggerFormat-Type", "rc-v3.ric_EventTriggerFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_rc_v3_callProcessType_ID,
      { "callProcessType-ID", "rc-v3.callProcessType_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RIC_CallProcessType_ID", HFILL }},
    { &hf_rc_v3_callProcessType_Name,
      { "callProcessType-Name", "rc-v3.callProcessType_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_CallProcessType_Name", HFILL }},
    { &hf_rc_v3_callProcessBreakpoints_List,
      { "callProcessBreakpoints-List", "rc-v3.callProcessBreakpoints_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item", HFILL }},
    { &hf_rc_v3_callProcessBreakpoints_List_item,
      { "RANFunctionDefinition-EventTrigger-Breakpoint-Item", "rc-v3.RANFunctionDefinition_EventTrigger_Breakpoint_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_callProcessBreakpoint_ID,
      { "callProcessBreakpoint-ID", "rc-v3.callProcessBreakpoint_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RIC_CallProcessBreakpoint_ID", HFILL }},
    { &hf_rc_v3_callProcessBreakpoint_Name,
      { "callProcessBreakpoint-Name", "rc-v3.callProcessBreakpoint_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_CallProcessBreakpoint_Name", HFILL }},
    { &hf_rc_v3_ran_CallProcessBreakpointParameters_List,
      { "ran-CallProcessBreakpointParameters-List", "rc-v3.ran_CallProcessBreakpointParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item", HFILL }},
    { &hf_rc_v3_ran_CallProcessBreakpointParameters_List_item,
      { "CallProcessBreakpoint-RANParameter-Item", "rc-v3.CallProcessBreakpoint_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_ReportStyle_List,
      { "ric-ReportStyle-List", "rc-v3.ric_ReportStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item", HFILL }},
    { &hf_rc_v3_ric_ReportStyle_List_item,
      { "RANFunctionDefinition-Report-Item", "rc-v3.RANFunctionDefinition_Report_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_ReportStyle_Type,
      { "ric-ReportStyle-Type", "rc-v3.ric_ReportStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_rc_v3_ric_ReportStyle_Name,
      { "ric-ReportStyle-Name", "rc-v3.ric_ReportStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_rc_v3_ric_SupportedEventTriggerStyle_Type,
      { "ric-SupportedEventTriggerStyle-Type", "rc-v3.ric_SupportedEventTriggerStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_rc_v3_ric_ReportActionFormat_Type,
      { "ric-ReportActionFormat-Type", "rc-v3.ric_ReportActionFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_rc_v3_ric_IndicationHeaderFormat_Type,
      { "ric-IndicationHeaderFormat-Type", "rc-v3.ric_IndicationHeaderFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_rc_v3_ric_IndicationMessageFormat_Type,
      { "ric-IndicationMessageFormat-Type", "rc-v3.ric_IndicationMessageFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_rc_v3_ran_ReportParameters_List,
      { "ran-ReportParameters-List", "rc-v3.ran_ReportParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item", HFILL }},
    { &hf_rc_v3_ran_ReportParameters_List_item,
      { "Report-RANParameter-Item", "rc-v3.Report_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_InsertStyle_List_02,
      { "ric-InsertStyle-List", "rc-v3.ric_InsertStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item", HFILL }},
    { &hf_rc_v3_ric_InsertStyle_List_item_02,
      { "RANFunctionDefinition-Insert-Item", "rc-v3.RANFunctionDefinition_Insert_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_InsertStyle_Name,
      { "ric-InsertStyle-Name", "rc-v3.ric_InsertStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_rc_v3_ric_ActionDefinitionFormat_Type,
      { "ric-ActionDefinitionFormat-Type", "rc-v3.ric_ActionDefinitionFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_rc_v3_ric_InsertIndication_List_02,
      { "ric-InsertIndication-List", "rc-v3.ric_InsertIndication_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item", HFILL }},
    { &hf_rc_v3_ric_InsertIndication_List_item_02,
      { "RANFunctionDefinition-Insert-Indication-Item", "rc-v3.RANFunctionDefinition_Insert_Indication_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_CallProcessIDFormat_Type,
      { "ric-CallProcessIDFormat-Type", "rc-v3.ric_CallProcessIDFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_rc_v3_ric_InsertIndication_Name,
      { "ric-InsertIndication-Name", "rc-v3.ric_InsertIndication_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ran_InsertIndicationParameters_List,
      { "ran-InsertIndicationParameters-List", "rc-v3.ran_InsertIndicationParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item", HFILL }},
    { &hf_rc_v3_ran_InsertIndicationParameters_List_item,
      { "InsertIndication-RANParameter-Item", "rc-v3.InsertIndication_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_ControlStyle_List_02,
      { "ric-ControlStyle-List", "rc-v3.ric_ControlStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item", HFILL }},
    { &hf_rc_v3_ric_ControlStyle_List_item_02,
      { "RANFunctionDefinition-Control-Item", "rc-v3.RANFunctionDefinition_Control_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_ControlStyle_Type,
      { "ric-ControlStyle-Type", "rc-v3.ric_ControlStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_rc_v3_ric_ControlStyle_Name,
      { "ric-ControlStyle-Name", "rc-v3.ric_ControlStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_rc_v3_ric_ControlAction_List_01,
      { "ric-ControlAction-List", "rc-v3.ric_ControlAction_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item", HFILL }},
    { &hf_rc_v3_ric_ControlAction_List_item_01,
      { "RANFunctionDefinition-Control-Action-Item", "rc-v3.RANFunctionDefinition_Control_Action_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_ControlHeaderFormat_Type,
      { "ric-ControlHeaderFormat-Type", "rc-v3.ric_ControlHeaderFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_rc_v3_ric_ControlMessageFormat_Type,
      { "ric-ControlMessageFormat-Type", "rc-v3.ric_ControlMessageFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_rc_v3_ric_ControlOutcomeFormat_Type,
      { "ric-ControlOutcomeFormat-Type", "rc-v3.ric_ControlOutcomeFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_rc_v3_ran_ControlOutcomeParameters_List,
      { "ran-ControlOutcomeParameters-List", "rc-v3.ran_ControlOutcomeParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item", HFILL }},
    { &hf_rc_v3_ran_ControlOutcomeParameters_List_item,
      { "ControlOutcome-RANParameter-Item", "rc-v3.ControlOutcome_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_listOfAdditionalSupportedFormats,
      { "listOfAdditionalSupportedFormats", "rc-v3.listOfAdditionalSupportedFormats",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_ControlAction_Name,
      { "ric-ControlAction-Name", "rc-v3.ric_ControlAction_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ran_ControlActionParameters_List,
      { "ran-ControlActionParameters-List", "rc-v3.ran_ControlActionParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item", HFILL }},
    { &hf_rc_v3_ran_ControlActionParameters_List_item,
      { "ControlAction-RANParameter-Item", "rc-v3.ControlAction_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ueGroup_ControlAction_Supported,
      { "ueGroup-ControlAction-Supported", "rc-v3.ueGroup_ControlAction_Supported",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_ueGroup_ControlAction_Supported_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_ListOfAdditionalSupportedFormats_item,
      { "AdditionalSupportedFormat", "rc-v3.AdditionalSupportedFormat_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_PolicyStyle_List,
      { "ric-PolicyStyle-List", "rc-v3.ric_PolicyStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item", HFILL }},
    { &hf_rc_v3_ric_PolicyStyle_List_item,
      { "RANFunctionDefinition-Policy-Item", "rc-v3.RANFunctionDefinition_Policy_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_PolicyStyle_Type,
      { "ric-PolicyStyle-Type", "rc-v3.ric_PolicyStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_rc_v3_ric_PolicyStyle_Name,
      { "ric-PolicyStyle-Name", "rc-v3.ric_PolicyStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_rc_v3_ric_PolicyAction_List,
      { "ric-PolicyAction-List", "rc-v3.ric_PolicyAction_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item", HFILL }},
    { &hf_rc_v3_ric_PolicyAction_List_item,
      { "RANFunctionDefinition-Policy-Action-Item", "rc-v3.RANFunctionDefinition_Policy_Action_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_PolicyAction_Name,
      { "ric-PolicyAction-Name", "rc-v3.ric_PolicyAction_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_ControlAction_Name", HFILL }},
    { &hf_rc_v3_ran_PolicyActionParameters_List,
      { "ran-PolicyActionParameters-List", "rc-v3.ran_PolicyActionParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item", HFILL }},
    { &hf_rc_v3_ran_PolicyActionParameters_List_item,
      { "PolicyAction-RANParameter-Item", "rc-v3.PolicyAction_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ran_PolicyConditionParameters_List,
      { "ran-PolicyConditionParameters-List", "rc-v3.ran_PolicyConditionParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item", HFILL }},
    { &hf_rc_v3_ran_PolicyConditionParameters_List_item,
      { "PolicyCondition-RANParameter-Item", "rc-v3.PolicyCondition_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_QueryStyle_List,
      { "ric-QueryStyle-List", "rc-v3.ric_QueryStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Query_Item", HFILL }},
    { &hf_rc_v3_ric_QueryStyle_List_item,
      { "RANFunctionDefinition-Query-Item", "rc-v3.RANFunctionDefinition_Query_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ric_QueryStyle_Type,
      { "ric-QueryStyle-Type", "rc-v3.ric_QueryStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_rc_v3_ric_QueryStyle_Name,
      { "ric-QueryStyle-Name", "rc-v3.ric_QueryStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_rc_v3_ric_QueryHeaderFormat_Type,
      { "ric-QueryHeaderFormat-Type", "rc-v3.ric_QueryHeaderFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_rc_v3_ric_QueryDefinitionFormat_Type,
      { "ric-QueryDefinitionFormat-Type", "rc-v3.ric_QueryDefinitionFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_rc_v3_ric_QueryOutcomeFormat_Type,
      { "ric-QueryOutcomeFormat-Type", "rc-v3.ric_QueryOutcomeFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_rc_v3_ran_QueryParameters_List,
      { "ran-QueryParameters-List", "rc-v3.ran_QueryParameters_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Query_RANParameter_Item", HFILL }},
    { &hf_rc_v3_ran_QueryParameters_List_item,
      { "Query-RANParameter-Item", "rc-v3.Query_RANParameter_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_c_RNTI,
      { "c-RNTI", "rc-v3.c_RNTI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RNTI_Value", HFILL }},
    { &hf_rc_v3_cell_Global_ID,
      { "cell-Global-ID", "rc-v3.cell_Global_ID",
        FT_UINT32, BASE_DEC, VALS(rc_v3_CGI_vals), 0,
        "CGI", HFILL }},
    { &hf_rc_v3_nG,
      { "nG", "rc-v3.nG_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_NG", HFILL }},
    { &hf_rc_v3_xN,
      { "xN", "rc-v3.xN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_Xn", HFILL }},
    { &hf_rc_v3_f1,
      { "f1", "rc-v3.f1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_F1", HFILL }},
    { &hf_rc_v3_e1,
      { "e1", "rc-v3.e1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_E1", HFILL }},
    { &hf_rc_v3_s1,
      { "s1", "rc-v3.s1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_S1", HFILL }},
    { &hf_rc_v3_x2,
      { "x2", "rc-v3.x2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_X2", HFILL }},
    { &hf_rc_v3_w1,
      { "w1", "rc-v3.w1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterfaceID_W1", HFILL }},
    { &hf_rc_v3_guami,
      { "guami", "rc-v3.guami_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_global_NG_RAN_ID,
      { "global-NG-RAN-ID", "rc-v3.global_NG_RAN_ID",
        FT_UINT32, BASE_DEC, VALS(rc_v3_GlobalNGRANNodeID_vals), 0,
        "GlobalNGRANNodeID", HFILL }},
    { &hf_rc_v3_globalGNB_ID,
      { "globalGNB-ID", "rc-v3.globalGNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_gNB_DU_ID,
      { "gNB-DU-ID", "rc-v3.gNB_DU_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_gNB_CU_UP_ID,
      { "gNB-CU-UP-ID", "rc-v3.gNB_CU_UP_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_gUMMEI,
      { "gUMMEI", "rc-v3.gUMMEI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_nodeType,
      { "nodeType", "rc-v3.nodeType",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_nodeType_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_global_eNB_ID,
      { "global-eNB-ID", "rc-v3.global_eNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalENB_ID", HFILL }},
    { &hf_rc_v3_global_en_gNB_ID,
      { "global-en-gNB-ID", "rc-v3.global_en_gNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalenGNB_ID", HFILL }},
    { &hf_rc_v3_global_ng_eNB_ID,
      { "global-ng-eNB-ID", "rc-v3.global_ng_eNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalNgENB_ID", HFILL }},
    { &hf_rc_v3_ng_eNB_DU_ID,
      { "ng-eNB-DU-ID", "rc-v3.ng_eNB_DU_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        "NGENB_DU_ID", HFILL }},
    { &hf_rc_v3_interfaceProcedureID,
      { "interfaceProcedureID", "rc-v3.interfaceProcedureID",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_rc_v3_messageType_01,
      { "messageType", "rc-v3.messageType",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_messageType_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_amf_UE_NGAP_ID,
      { "amf-UE-NGAP-ID", "rc-v3.amf_UE_NGAP_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_gNB_CU_UE_F1AP_ID,
      { "gNB-CU-UE-F1AP-ID", "rc-v3.gNB_CU_UE_F1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_gNB_CU_CP_UE_E1AP_ID,
      { "gNB-CU-CP-UE-E1AP-ID", "rc-v3.gNB_CU_CP_UE_E1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ran_UEID,
      { "ran-UEID", "rc-v3.ran_UEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RANUEID", HFILL }},
    { &hf_rc_v3_m_NG_RAN_UE_XnAP_ID,
      { "m-NG-RAN-UE-XnAP-ID", "rc-v3.m_NG_RAN_UE_XnAP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NG_RANnodeUEXnAPID", HFILL }},
    { &hf_rc_v3_globalNG_RANNode_ID,
      { "globalNG-RANNode-ID", "rc-v3.globalNG_RANNode_ID",
        FT_UINT32, BASE_DEC, VALS(rc_v3_GlobalNGRANNodeID_vals), 0,
        "GlobalNGRANNodeID", HFILL }},
    { &hf_rc_v3_cell_RNTI,
      { "cell-RNTI", "rc-v3.cell_RNTI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ng_eNB_CU_UE_W1AP_ID,
      { "ng-eNB-CU-UE-W1AP-ID", "rc-v3.ng_eNB_CU_UE_W1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NGENB_CU_UE_W1AP_ID", HFILL }},
    { &hf_rc_v3_m_eNB_UE_X2AP_ID,
      { "m-eNB-UE-X2AP-ID", "rc-v3.m_eNB_UE_X2AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ENB_UE_X2AP_ID", HFILL }},
    { &hf_rc_v3_m_eNB_UE_X2AP_ID_Extension,
      { "m-eNB-UE-X2AP-ID-Extension", "rc-v3.m_eNB_UE_X2AP_ID_Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ENB_UE_X2AP_ID_Extension", HFILL }},
    { &hf_rc_v3_globalENB_ID,
      { "globalENB-ID", "rc-v3.globalENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_mME_UE_S1AP_ID,
      { "mME-UE-S1AP-ID", "rc-v3.mME_UE_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranFunction_ShortName,
      { "ranFunction-ShortName", "rc-v3.ranFunction_ShortName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranFunction_E2SM_OID,
      { "ranFunction-E2SM-OID", "rc-v3.ranFunction_E2SM_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_ranFunction_Description,
      { "ranFunction-Description", "rc-v3.ranFunction_Description",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_150_", HFILL }},
    { &hf_rc_v3_ranFunction_Instance,
      { "ranFunction-Instance", "rc-v3.ranFunction_Instance",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_rc_v3_rrcType,
      { "rrcType", "rc-v3.rrcType",
        FT_UINT32, BASE_DEC, VALS(rc_v3_T_rrcType_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_lTE,
      { "lTE", "rc-v3.lTE",
        FT_UINT32, BASE_DEC, VALS(rc_v3_RRCclass_LTE_vals), 0,
        "RRCclass_LTE", HFILL }},
    { &hf_rc_v3_nR,
      { "nR", "rc-v3.nR",
        FT_UINT32, BASE_DEC, VALS(rc_v3_RRCclass_NR_vals), 0,
        "RRCclass_NR", HFILL }},
    { &hf_rc_v3_messageID,
      { "messageID", "rc-v3.messageID",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_rc_v3_nR_01,
      { "nR", "rc-v3.nR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_ARFCN", HFILL }},
    { &hf_rc_v3_eUTRA,
      { "eUTRA", "rc-v3.eUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRA_ARFCN", HFILL }},
    { &hf_rc_v3_nR_02,
      { "nR", "rc-v3.nR",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NR_PCI", HFILL }},
    { &hf_rc_v3_eUTRA_01,
      { "eUTRA", "rc-v3.eUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRA_PCI", HFILL }},
    { &hf_rc_v3_gNB_UEID,
      { "gNB-UEID", "rc-v3.gNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_GNB", HFILL }},
    { &hf_rc_v3_gNB_DU_UEID,
      { "gNB-DU-UEID", "rc-v3.gNB_DU_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_GNB_DU", HFILL }},
    { &hf_rc_v3_gNB_CU_UP_UEID,
      { "gNB-CU-UP-UEID", "rc-v3.gNB_CU_UP_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_GNB_CU_UP", HFILL }},
    { &hf_rc_v3_ng_eNB_UEID,
      { "ng-eNB-UEID", "rc-v3.ng_eNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_NG_ENB", HFILL }},
    { &hf_rc_v3_ng_eNB_DU_UEID,
      { "ng-eNB-DU-UEID", "rc-v3.ng_eNB_DU_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_NG_ENB_DU", HFILL }},
    { &hf_rc_v3_en_gNB_UEID,
      { "en-gNB-UEID", "rc-v3.en_gNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_EN_GNB", HFILL }},
    { &hf_rc_v3_eNB_UEID,
      { "eNB-UEID", "rc-v3.eNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_ENB", HFILL }},
    { &hf_rc_v3_gNB_CU_UE_F1AP_ID_List,
      { "gNB-CU-UE-F1AP-ID-List", "rc-v3.gNB_CU_UE_F1AP_ID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UEID_GNB_CU_F1AP_ID_List", HFILL }},
    { &hf_rc_v3_gNB_CU_CP_UE_E1AP_ID_List,
      { "gNB-CU-CP-UE-E1AP-ID-List", "rc-v3.gNB_CU_CP_UE_E1AP_ID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UEID_GNB_CU_CP_E1AP_ID_List", HFILL }},
    { &hf_rc_v3_UEID_GNB_CU_CP_E1AP_ID_List_item,
      { "UEID-GNB-CU-CP-E1AP-ID-Item", "rc-v3.UEID_GNB_CU_CP_E1AP_ID_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_UEID_GNB_CU_F1AP_ID_List_item,
      { "UEID-GNB-CU-CP-F1AP-ID-Item", "rc-v3.UEID_GNB_CU_CP_F1AP_ID_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_globalNgENB_ID,
      { "globalNgENB-ID", "rc-v3.globalNgENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_macro_eNB_ID,
      { "macro-eNB-ID", "rc-v3.macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_rc_v3_home_eNB_ID,
      { "home-eNB-ID", "rc-v3.home_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_28", HFILL }},
    { &hf_rc_v3_short_Macro_eNB_ID,
      { "short-Macro-eNB-ID", "rc-v3.short_Macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_rc_v3_long_Macro_eNB_ID,
      { "long-Macro-eNB-ID", "rc-v3.long_Macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_rc_v3_pLMNIdentity,
      { "pLMNIdentity", "rc-v3.pLMNIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_eNB_ID,
      { "eNB-ID", "rc-v3.eNB_ID",
        FT_UINT32, BASE_DEC, VALS(rc_v3_ENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_pLMN_Identity,
      { "pLMN-Identity", "rc-v3.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMNIdentity", HFILL }},
    { &hf_rc_v3_mME_Group_ID,
      { "mME-Group-ID", "rc-v3.mME_Group_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_mME_Code,
      { "mME-Code", "rc-v3.mME_Code",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_en_gNB_ID,
      { "en-gNB-ID", "rc-v3.en_gNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22_32", HFILL }},
    { &hf_rc_v3_en_gNB_ID_choice,
      { "en-gNB-ID", "rc-v3.en_gNB_ID_choice",
        FT_UINT32, BASE_DEC, VALS(rc_v3_EN_GNB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_eUTRACellIdentity,
      { "eUTRACellIdentity", "rc-v3.eUTRACellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_gNB_ID_choice,
      { "gNB-ID", "rc-v3.gNB_ID_choice",
        FT_UINT32, BASE_DEC, VALS(rc_v3_GNB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_ngENB_ID,
      { "ngENB-ID", "rc-v3.ngENB_ID",
        FT_UINT32, BASE_DEC, VALS(rc_v3_NgENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_rc_v3_gNB_ID,
      { "gNB-ID", "rc-v3.gNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22_32", HFILL }},
    { &hf_rc_v3_aMFRegionID,
      { "aMFRegionID", "rc-v3.aMFRegionID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_aMFSetID,
      { "aMFSetID", "rc-v3.aMFSetID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_aMFPointer,
      { "aMFPointer", "rc-v3.aMFPointer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_macroNgENB_ID,
      { "macroNgENB-ID", "rc-v3.macroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_rc_v3_shortMacroNgENB_ID,
      { "shortMacroNgENB-ID", "rc-v3.shortMacroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_rc_v3_longMacroNgENB_ID,
      { "longMacroNgENB-ID", "rc-v3.longMacroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_rc_v3_nRCellIdentity,
      { "nRCellIdentity", "rc-v3.nRCellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_gNB,
      { "gNB", "rc-v3.gNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalGNB_ID", HFILL }},
    { &hf_rc_v3_ng_eNB,
      { "ng-eNB", "rc-v3.ng_eNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalNgENB_ID", HFILL }},
    { &hf_rc_v3_nRARFCN,
      { "nRARFCN", "rc-v3.nRARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxNRARFCN", HFILL }},
    { &hf_rc_v3_NRFrequencyBand_List_item,
      { "NRFrequencyBandItem", "rc-v3.NRFrequencyBandItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_freqBandIndicatorNr,
      { "freqBandIndicatorNr", "rc-v3.freqBandIndicatorNr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1024_", HFILL }},
    { &hf_rc_v3_supportedSULBandList,
      { "supportedSULBandList", "rc-v3.supportedSULBandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rc_v3_nrARFCN,
      { "nrARFCN", "rc-v3.nrARFCN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_ARFCN", HFILL }},
    { &hf_rc_v3_frequencyBand_List,
      { "frequencyBand-List", "rc-v3.frequencyBand_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NRFrequencyBand_List", HFILL }},
    { &hf_rc_v3_frequencyShift7p5khz,
      { "frequencyShift7p5khz", "rc-v3.frequencyShift7p5khz",
        FT_UINT32, BASE_DEC, VALS(rc_v3_NRFrequencyShift7p5khz_vals), 0,
        "NRFrequencyShift7p5khz", HFILL }},
    { &hf_rc_v3_SupportedSULBandList_item,
      { "SupportedSULFreqBandItem", "rc-v3.SupportedSULFreqBandItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
      { &hf_rc_v3_timestamp_string,
          { "Timestamp string", "rc-v3.timestamp-string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_rc_v3_NeighborCell_List,
    &ett_rc_v3_NeighborCell_Item,
    &ett_rc_v3_NeighborCell_Item_Choice_NR,
    &ett_rc_v3_NeighborCell_Item_Choice_E_UTRA,
    &ett_rc_v3_NeighborRelation_Info,
    &ett_rc_v3_EventTrigger_Cell_Info,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCellInfo_OF_EventTrigger_Cell_Info_Item,
    &ett_rc_v3_EventTrigger_Cell_Info_Item,
    &ett_rc_v3_T_cellType,
    &ett_rc_v3_EventTrigger_Cell_Info_Item_Choice_Individual,
    &ett_rc_v3_EventTrigger_Cell_Info_Item_Choice_Group,
    &ett_rc_v3_EventTrigger_UE_Info,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item,
    &ett_rc_v3_EventTrigger_UE_Info_Item,
    &ett_rc_v3_T_ueType,
    &ett_rc_v3_EventTrigger_UE_Info_Item_Choice_Individual,
    &ett_rc_v3_EventTrigger_UE_Info_Item_Choice_Group,
    &ett_rc_v3_EventTrigger_UEevent_Info,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEeventInfo_OF_EventTrigger_UEevent_Info_Item,
    &ett_rc_v3_EventTrigger_UEevent_Info_Item,
    &ett_rc_v3_RANParameter_Definition,
    &ett_rc_v3_RANParameter_Definition_Choice,
    &ett_rc_v3_RANParameter_Definition_Choice_LIST,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_Definition_Choice_LIST_Item,
    &ett_rc_v3_RANParameter_Definition_Choice_LIST_Item,
    &ett_rc_v3_RANParameter_Definition_Choice_STRUCTURE,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_Definition_Choice_STRUCTURE_Item,
    &ett_rc_v3_RANParameter_Definition_Choice_STRUCTURE_Item,
    &ett_rc_v3_RANParameter_Value,
    &ett_rc_v3_RANParameter_ValueType,
    &ett_rc_v3_RANParameter_ValueType_Choice_ElementTrue,
    &ett_rc_v3_RANParameter_ValueType_Choice_ElementFalse,
    &ett_rc_v3_RANParameter_ValueType_Choice_Structure,
    &ett_rc_v3_RANParameter_ValueType_Choice_List,
    &ett_rc_v3_RANParameter_STRUCTURE,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersinStructure_OF_RANParameter_STRUCTURE_Item,
    &ett_rc_v3_RANParameter_STRUCTURE_Item,
    &ett_rc_v3_RANParameter_LIST,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofItemsinList_OF_RANParameter_STRUCTURE,
    &ett_rc_v3_RANParameter_Testing,
    &ett_rc_v3_RANParameter_TestingCondition,
    &ett_rc_v3_RANParameter_Testing_Item,
    &ett_rc_v3_T_ranParameter_Type,
    &ett_rc_v3_RANParameter_Testing_Item_Choice_List,
    &ett_rc_v3_RANParameter_Testing_Item_Choice_Structure,
    &ett_rc_v3_RANParameter_Testing_Item_Choice_ElementTrue,
    &ett_rc_v3_RANParameter_Testing_Item_Choice_ElementFalse,
    &ett_rc_v3_RANParameter_Testing_LIST,
    &ett_rc_v3_RANParameter_Testing_STRUCTURE,
    &ett_rc_v3_UE_Group_Definition,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxGroupDefinitionIdentifierParameters_OF_UEGroupDefinitionIdentifier_Item,
    &ett_rc_v3_UEGroupDefinitionIdentifier_Item,
    &ett_rc_v3_RIC_PolicyAction,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_RIC_PolicyAction_RANParameter_Item,
    &ett_rc_v3_RIC_PolicyAction_RANParameter_Item,
    &ett_rc_v3_Associated_UE_Info,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_Associated_UE_Info_Item,
    &ett_rc_v3_Associated_UE_Info_Item,
    &ett_rc_v3_T_ueType_01,
    &ett_rc_v3_UEQuery,
    &ett_rc_v3_E2SM_RC_EventTrigger,
    &ett_rc_v3_T_ric_eventTrigger_formats,
    &ett_rc_v3_E2SM_RC_EventTrigger_Format1,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofMessages_OF_E2SM_RC_EventTrigger_Format1_Item,
    &ett_rc_v3_E2SM_RC_EventTrigger_Format1_Item,
    &ett_rc_v3_MessageType_Choice,
    &ett_rc_v3_MessageType_Choice_NI,
    &ett_rc_v3_MessageType_Choice_RRC,
    &ett_rc_v3_E2SM_RC_EventTrigger_Format2,
    &ett_rc_v3_E2SM_RC_EventTrigger_Format3,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofE2InfoChanges_OF_E2SM_RC_EventTrigger_Format3_Item,
    &ett_rc_v3_E2SM_RC_EventTrigger_Format3_Item,
    &ett_rc_v3_E2SM_RC_EventTrigger_Format4,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEInfoChanges_OF_E2SM_RC_EventTrigger_Format4_Item,
    &ett_rc_v3_E2SM_RC_EventTrigger_Format4_Item,
    &ett_rc_v3_TriggerType_Choice,
    &ett_rc_v3_TriggerType_Choice_RRCstate,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRRCstate_OF_TriggerType_Choice_RRCstate_Item,
    &ett_rc_v3_TriggerType_Choice_RRCstate_Item,
    &ett_rc_v3_TriggerType_Choice_UEID,
    &ett_rc_v3_TriggerType_Choice_L2state,
    &ett_rc_v3_TriggerType_Choice_UEcontext,
    &ett_rc_v3_TriggerType_Choice_L2MACschChg,
    &ett_rc_v3_L2MACschChgType_Choice,
    &ett_rc_v3_TriggerType_Choice_MIMOandBFconfig,
    &ett_rc_v3_E2SM_RC_ActionDefinition,
    &ett_rc_v3_T_ric_actionDefinition_formats,
    &ett_rc_v3_E2SM_RC_ActionDefinition_Format1,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofParametersToReport_OF_E2SM_RC_ActionDefinition_Format1_Item,
    &ett_rc_v3_E2SM_RC_ActionDefinition_Format1_Item,
    &ett_rc_v3_E2SM_RC_ActionDefinition_Format2,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofPolicyConditions_OF_E2SM_RC_ActionDefinition_Format2_Item,
    &ett_rc_v3_E2SM_RC_ActionDefinition_Format2_Item,
    &ett_rc_v3_E2SM_RC_ActionDefinition_Format3,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format3_Item,
    &ett_rc_v3_E2SM_RC_ActionDefinition_Format3_Item,
    &ett_rc_v3_E2SM_RC_ActionDefinition_Format4,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ActionDefinition_Format4_Style_Item,
    &ett_rc_v3_E2SM_RC_ActionDefinition_Format4_Style_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_ActionDefinition_Format4_Indication_Item,
    &ett_rc_v3_E2SM_RC_ActionDefinition_Format4_Indication_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ActionDefinition_Format4_RANP_Item,
    &ett_rc_v3_E2SM_RC_ActionDefinition_Format4_RANP_Item,
    &ett_rc_v3_E2SM_RC_IndicationHeader,
    &ett_rc_v3_T_ric_indicationHeader_formats,
    &ett_rc_v3_E2SM_RC_IndicationHeader_Format1,
    &ett_rc_v3_E2SM_RC_IndicationHeader_Format2,
    &ett_rc_v3_E2SM_RC_IndicationHeader_Format3,
    &ett_rc_v3_E2SM_RC_IndicationMessage,
    &ett_rc_v3_T_ric_indicationMessage_formats,
    &ett_rc_v3_E2SM_RC_IndicationMessage_Format1,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format1_Item,
    &ett_rc_v3_E2SM_RC_IndicationMessage_Format1_Item,
    &ett_rc_v3_E2SM_RC_IndicationMessage_Format2,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofUEID_OF_E2SM_RC_IndicationMessage_Format2_Item,
    &ett_rc_v3_E2SM_RC_IndicationMessage_Format2_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format2_RANParameter_Item,
    &ett_rc_v3_E2SM_RC_IndicationMessage_Format2_RANParameter_Item,
    &ett_rc_v3_E2SM_RC_IndicationMessage_Format3,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_IndicationMessage_Format3_Item,
    &ett_rc_v3_E2SM_RC_IndicationMessage_Format3_Item,
    &ett_rc_v3_E2SM_RC_IndicationMessage_Format5,
    &ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format5_Item,
    &ett_rc_v3_E2SM_RC_IndicationMessage_Format5_Item,
    &ett_rc_v3_E2SM_RC_IndicationMessage_Format6,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_IndicationMessage_Format6_Style_Item,
    &ett_rc_v3_E2SM_RC_IndicationMessage_Format6_Style_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndicationActions_OF_E2SM_RC_IndicationMessage_Format6_Indication_Item,
    &ett_rc_v3_E2SM_RC_IndicationMessage_Format6_Indication_Item,
    &ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_IndicationMessage_Format6_RANP_Item,
    &ett_rc_v3_E2SM_RC_IndicationMessage_Format6_RANP_Item,
    &ett_rc_v3_E2SM_RC_CallProcessID,
    &ett_rc_v3_T_ric_callProcessID_formats,
    &ett_rc_v3_E2SM_RC_CallProcessID_Format1,
    &ett_rc_v3_E2SM_RC_ControlHeader,
    &ett_rc_v3_T_ric_controlHeader_formats,
    &ett_rc_v3_E2SM_RC_ControlHeader_Format1,
    &ett_rc_v3_E2SM_RC_ControlHeader_Format2,
    &ett_rc_v3_E2SM_RC_ControlHeader_Format3,
    &ett_rc_v3_E2SM_RC_ControlHeader_Format4,
    &ett_rc_v3_E2SM_RC_ControlMessage,
    &ett_rc_v3_T_ric_controlMessage_formats,
    &ett_rc_v3_E2SM_RC_ControlMessage_Format1,
    &ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format1_Item,
    &ett_rc_v3_E2SM_RC_ControlMessage_Format1_Item,
    &ett_rc_v3_E2SM_RC_ControlMessage_Format2,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlMessage_Format2_Style_Item,
    &ett_rc_v3_E2SM_RC_ControlMessage_Format2_Style_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlMessage_Format2_ControlAction_Item,
    &ett_rc_v3_E2SM_RC_ControlMessage_Format2_ControlAction_Item,
    &ett_rc_v3_E2SM_RC_ControlMessage_Format3,
    &ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedEntityFilters_OF_E2SM_RC_EntityFilter,
    &ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_EntityAgnostic_ranP_ControlParameters,
    &ett_rc_v3_E2SM_RC_EntityFilter,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_EntitySpecific_ranP_ControlParameters,
    &ett_rc_v3_EntityAgnostic_ranP_ControlParameters,
    &ett_rc_v3_EntitySpecific_ranP_ControlParameters,
    &ett_rc_v3_E2SM_RC_ControlMessage_Format4,
    &ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlMessage_Format4_Item,
    &ett_rc_v3_E2SM_RC_ControlMessage_Format4_Item,
    &ett_rc_v3_E2SM_RC_ControlOutcome,
    &ett_rc_v3_T_ric_controlOutcome_formats,
    &ett_rc_v3_E2SM_RC_ControlOutcome_Format1,
    &ett_rc_v3_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format1_Item,
    &ett_rc_v3_E2SM_RC_ControlOutcome_Format1_Item,
    &ett_rc_v3_E2SM_RC_ControlOutcome_Format2,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_E2SM_RC_ControlOutcome_Format2_Style_Item,
    &ett_rc_v3_E2SM_RC_ControlOutcome_Format2_Style_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofMulCtrlActions_OF_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item,
    &ett_rc_v3_E2SM_RC_ControlOutcome_Format2_ControlOutcome_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_ControlOutcome_Format2_RANP_Item,
    &ett_rc_v3_E2SM_RC_ControlOutcome_Format2_RANP_Item,
    &ett_rc_v3_E2SM_RC_ControlOutcome_Format3,
    &ett_rc_v3_SEQUENCE_SIZE_0_maxnoofRANOutcomeParameters_OF_E2SM_RC_ControlOutcome_Format3_Item,
    &ett_rc_v3_E2SM_RC_ControlOutcome_Format3_Item,
    &ett_rc_v3_E2SM_RC_QueryHeader,
    &ett_rc_v3_T_ric_queryHeader_formats,
    &ett_rc_v3_E2SM_RC_QueryHeader_Format1,
    &ett_rc_v3_E2SM_RC_QueryDefinition,
    &ett_rc_v3_T_ric_queryDefinition_formats,
    &ett_rc_v3_E2SM_RC_QueryDefinition_Format1,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryDefinition_Format1_Item,
    &ett_rc_v3_E2SM_RC_QueryDefinition_Format1_Item,
    &ett_rc_v3_E2SM_RC_QueryOutcome,
    &ett_rc_v3_T_ric_queryOutcome_formats,
    &ett_rc_v3_E2SM_RC_QueryOutcome_Format1,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCellID_OF_E2SM_RC_QueryOutcome_Format1_ItemCell,
    &ett_rc_v3_E2SM_RC_QueryOutcome_Format1_ItemCell,
    &ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format1_ItemParameters,
    &ett_rc_v3_E2SM_RC_QueryOutcome_Format1_ItemParameters,
    &ett_rc_v3_E2SM_RC_QueryOutcome_Format2,
    &ett_rc_v3_SEQUENCE_SIZE_0_maxnoofUEID_OF_E2SM_RC_QueryOutcome_Format2_ItemUE,
    &ett_rc_v3_E2SM_RC_QueryOutcome_Format2_ItemUE,
    &ett_rc_v3_SEQUENCE_SIZE_0_maxnoofAssociatedRANParameters_OF_E2SM_RC_QueryOutcome_Format2_ItemParameters,
    &ett_rc_v3_E2SM_RC_QueryOutcome_Format2_ItemParameters,
    &ett_rc_v3_E2SM_RC_RANFunctionDefinition,
    &ett_rc_v3_RANFunctionDefinition_EventTrigger,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_L2Parameters_RANParameter_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCallProcessTypes_OF_RANFunctionDefinition_EventTrigger_CallProcess_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_UEIdentification_RANParameter_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CellIdentification_RANParameter_Item,
    &ett_rc_v3_RANFunctionDefinition_EventTrigger_Style_Item,
    &ett_rc_v3_L2Parameters_RANParameter_Item,
    &ett_rc_v3_UEIdentification_RANParameter_Item,
    &ett_rc_v3_CellIdentification_RANParameter_Item,
    &ett_rc_v3_RANFunctionDefinition_EventTrigger_CallProcess_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofCallProcessBreakpoints_OF_RANFunctionDefinition_EventTrigger_Breakpoint_Item,
    &ett_rc_v3_RANFunctionDefinition_EventTrigger_Breakpoint_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_CallProcessBreakpoint_RANParameter_Item,
    &ett_rc_v3_CallProcessBreakpoint_RANParameter_Item,
    &ett_rc_v3_RANFunctionDefinition_Report,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item,
    &ett_rc_v3_RANFunctionDefinition_Report_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Report_RANParameter_Item,
    &ett_rc_v3_Report_RANParameter_Item,
    &ett_rc_v3_RANFunctionDefinition_Insert,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Insert_Item,
    &ett_rc_v3_RANFunctionDefinition_Insert_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofInsertIndication_OF_RANFunctionDefinition_Insert_Indication_Item,
    &ett_rc_v3_RANFunctionDefinition_Insert_Indication_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_InsertIndication_RANParameter_Item,
    &ett_rc_v3_InsertIndication_RANParameter_Item,
    &ett_rc_v3_RANFunctionDefinition_Control,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item,
    &ett_rc_v3_RANFunctionDefinition_Control_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRANOutcomeParameters_OF_ControlOutcome_RANParameter_Item,
    &ett_rc_v3_ControlOutcome_RANParameter_Item,
    &ett_rc_v3_RANFunctionDefinition_Control_Action_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_ControlAction_RANParameter_Item,
    &ett_rc_v3_ControlAction_RANParameter_Item,
    &ett_rc_v3_ListOfAdditionalSupportedFormats,
    &ett_rc_v3_AdditionalSupportedFormat,
    &ett_rc_v3_RANFunctionDefinition_Policy,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Policy_Item,
    &ett_rc_v3_RANFunctionDefinition_Policy_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofPolicyAction_OF_RANFunctionDefinition_Policy_Action_Item,
    &ett_rc_v3_RANFunctionDefinition_Policy_Action_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyAction_RANParameter_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_PolicyCondition_RANParameter_Item,
    &ett_rc_v3_PolicyAction_RANParameter_Item,
    &ett_rc_v3_PolicyCondition_RANParameter_Item,
    &ett_rc_v3_RANFunctionDefinition_Query,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Query_Item,
    &ett_rc_v3_RANFunctionDefinition_Query_Item,
    &ett_rc_v3_SEQUENCE_SIZE_1_maxnoofAssociatedRANParameters_OF_Query_RANParameter_Item,
    &ett_rc_v3_Query_RANParameter_Item,
    &ett_rc_v3_Cell_RNTI,
    &ett_rc_v3_CGI,
    &ett_rc_v3_InterfaceIdentifier,
    &ett_rc_v3_InterfaceID_NG,
    &ett_rc_v3_InterfaceID_Xn,
    &ett_rc_v3_InterfaceID_F1,
    &ett_rc_v3_InterfaceID_E1,
    &ett_rc_v3_InterfaceID_S1,
    &ett_rc_v3_InterfaceID_X2,
    &ett_rc_v3_T_nodeType,
    &ett_rc_v3_InterfaceID_W1,
    &ett_rc_v3_Interface_MessageID,
    &ett_rc_v3_PartialUEID,
    &ett_rc_v3_RANfunction_Name,
    &ett_rc_v3_RRC_MessageID,
    &ett_rc_v3_T_rrcType,
    &ett_rc_v3_ServingCell_ARFCN,
    &ett_rc_v3_ServingCell_PCI,
    &ett_rc_v3_UEID,
    &ett_rc_v3_UEID_GNB,
    &ett_rc_v3_UEID_GNB_CU_CP_E1AP_ID_List,
    &ett_rc_v3_UEID_GNB_CU_CP_E1AP_ID_Item,
    &ett_rc_v3_UEID_GNB_CU_F1AP_ID_List,
    &ett_rc_v3_UEID_GNB_CU_CP_F1AP_ID_Item,
    &ett_rc_v3_UEID_GNB_DU,
    &ett_rc_v3_UEID_GNB_CU_UP,
    &ett_rc_v3_UEID_NG_ENB,
    &ett_rc_v3_UEID_NG_ENB_DU,
    &ett_rc_v3_UEID_EN_GNB,
    &ett_rc_v3_UEID_ENB,
    &ett_rc_v3_ENB_ID,
    &ett_rc_v3_GlobalENB_ID,
    &ett_rc_v3_GUMMEI,
    &ett_rc_v3_EN_GNB_ID,
    &ett_rc_v3_GlobalenGNB_ID,
    &ett_rc_v3_EUTRA_CGI,
    &ett_rc_v3_GlobalGNB_ID,
    &ett_rc_v3_GlobalNgENB_ID,
    &ett_rc_v3_GNB_ID,
    &ett_rc_v3_GUAMI,
    &ett_rc_v3_NgENB_ID,
    &ett_rc_v3_NR_CGI,
    &ett_rc_v3_GlobalNGRANNodeID,
    &ett_rc_v3_NR_ARFCN,
    &ett_rc_v3_NRFrequencyBand_List,
    &ett_rc_v3_NRFrequencyBandItem,
    &ett_rc_v3_NRFrequencyInfo,
    &ett_rc_v3_SupportedSULBandList,
    &ett_rc_v3_SupportedSULFreqBandItem,
  };


  /* Register protocol */
  proto_rc_v3 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rc_v3, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
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
