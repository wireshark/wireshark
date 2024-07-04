/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-kpm-v2.c                                                            */
/* asn2wrs.py -q -L -p kpm-v2 -c ./kpm-v2.cnf -s ./packet-kpm-v2-template -D . -O ../.. e2sm-kpm-v2.02.asn e2sm-v3.01.asn */

/* packet-kpm-v2-template.c
 * Copyright 2021, Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: ORAN-WG3.E2SM-KPM-v02.02
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>

#include "packet-e2ap.h"
#include "packet-per.h"
#include "packet-ntp.h"

#define PNAME  "KPM V2"
#define PSNAME "KPMv2"
#define PFNAME "kpm-v2"


void proto_register_kpm_v2(void);
void proto_reg_handoff_kpm_v2(void);


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
#define maxE1APid                      65535
#define maxF1APid                      4
#define maxEARFCN                      65535
#define maxNRARFCN                     3279165
#define maxnoofNrCellBands             32

/* Initialize the protocol and registered fields */
static int proto_kpm_v2;
static int hf_kpm_v2_E2SM_KPM_EventTriggerDefinition_PDU;  /* E2SM_KPM_EventTriggerDefinition */
static int hf_kpm_v2_E2SM_KPM_ActionDefinition_PDU;  /* E2SM_KPM_ActionDefinition */
static int hf_kpm_v2_E2SM_KPM_IndicationHeader_PDU;  /* E2SM_KPM_IndicationHeader */
static int hf_kpm_v2_E2SM_KPM_IndicationMessage_PDU;  /* E2SM_KPM_IndicationMessage */
static int hf_kpm_v2_E2SM_KPM_RANfunction_Description_PDU;  /* E2SM_KPM_RANfunction_Description */
static int hf_kpm_v2_measName;                    /* MeasurementTypeName */
static int hf_kpm_v2_measID;                      /* MeasurementTypeID */
static int hf_kpm_v2_noLabel;                     /* T_noLabel */
static int hf_kpm_v2_plmnID;                      /* PLMNIdentity */
static int hf_kpm_v2_sliceID;                     /* S_NSSAI */
static int hf_kpm_v2_fiveQI;                      /* FiveQI */
static int hf_kpm_v2_qFI;                         /* QosFlowIdentifier */
static int hf_kpm_v2_qCI;                         /* QCI */
static int hf_kpm_v2_qCImax;                      /* QCI */
static int hf_kpm_v2_qCImin;                      /* QCI */
static int hf_kpm_v2_aRPmax;                      /* INTEGER_1_15_ */
static int hf_kpm_v2_aRPmin;                      /* INTEGER_1_15_ */
static int hf_kpm_v2_bitrateRange;                /* INTEGER_1_65535_ */
static int hf_kpm_v2_layerMU_MIMO;                /* INTEGER_1_65535_ */
static int hf_kpm_v2_sUM;                         /* T_sUM */
static int hf_kpm_v2_distBinX;                    /* INTEGER_1_65535_ */
static int hf_kpm_v2_distBinY;                    /* INTEGER_1_65535_ */
static int hf_kpm_v2_distBinZ;                    /* INTEGER_1_65535_ */
static int hf_kpm_v2_preLabelOverride;            /* T_preLabelOverride */
static int hf_kpm_v2_startEndInd;                 /* T_startEndInd */
static int hf_kpm_v2_min;                         /* T_min */
static int hf_kpm_v2_max;                         /* T_max */
static int hf_kpm_v2_avg;                         /* T_avg */
static int hf_kpm_v2_testType;                    /* TestCond_Type */
static int hf_kpm_v2_testExpr;                    /* TestCond_Expression */
static int hf_kpm_v2_testValue;                   /* TestCond_Value */
static int hf_kpm_v2_gBR;                         /* T_gBR */
static int hf_kpm_v2_aMBR;                        /* T_aMBR */
static int hf_kpm_v2_isStat;                      /* T_isStat */
static int hf_kpm_v2_isCatM;                      /* T_isCatM */
static int hf_kpm_v2_rSRP;                        /* T_rSRP */
static int hf_kpm_v2_rSRQ;                        /* T_rSRQ */
static int hf_kpm_v2_ul_rSRP;                     /* T_ul_rSRP */
static int hf_kpm_v2_cQI;                         /* T_cQI */
static int hf_kpm_v2_fiveQI_01;                   /* T_fiveQI */
static int hf_kpm_v2_qCI_01;                      /* T_qCI */
static int hf_kpm_v2_sNSSAI;                      /* T_sNSSAI */
static int hf_kpm_v2_valueInt;                    /* INTEGER */
static int hf_kpm_v2_valueEnum;                   /* INTEGER */
static int hf_kpm_v2_valueBool;                   /* BOOLEAN */
static int hf_kpm_v2_valueBitS;                   /* BIT_STRING */
static int hf_kpm_v2_valueOctS;                   /* OCTET_STRING */
static int hf_kpm_v2_valuePrtS;                   /* PrintableString */
static int hf_kpm_v2_valueReal;                   /* REAL */
static int hf_kpm_v2_MeasurementInfoList_item;    /* MeasurementInfoItem */
static int hf_kpm_v2_measType;                    /* MeasurementType */
static int hf_kpm_v2_labelInfoList;               /* LabelInfoList */
static int hf_kpm_v2_LabelInfoList_item;          /* LabelInfoItem */
static int hf_kpm_v2_measLabel;                   /* MeasurementLabel */
static int hf_kpm_v2_MeasurementData_item;        /* MeasurementDataItem */
static int hf_kpm_v2_measRecord;                  /* MeasurementRecord */
static int hf_kpm_v2_incompleteFlag;              /* T_incompleteFlag */
static int hf_kpm_v2_MeasurementRecord_item;      /* MeasurementRecordItem */
static int hf_kpm_v2_integer;                     /* INTEGER_0_4294967295 */
static int hf_kpm_v2_real;                        /* REAL */
static int hf_kpm_v2_noValue;                     /* NULL */
static int hf_kpm_v2_MeasurementInfo_Action_List_item;  /* MeasurementInfo_Action_Item */
static int hf_kpm_v2_MeasurementCondList_item;    /* MeasurementCondItem */
static int hf_kpm_v2_matchingCond;                /* MatchingCondList */
static int hf_kpm_v2_MeasurementCondUEidList_item;  /* MeasurementCondUEidItem */
static int hf_kpm_v2_matchingUEidList;            /* MatchingUEidList */
static int hf_kpm_v2_MatchingCondList_item;       /* MatchingCondItem */
static int hf_kpm_v2_testCondInfo;                /* TestCondInfo */
static int hf_kpm_v2_MatchingUEidList_item;       /* MatchingUEidItem */
static int hf_kpm_v2_ueID;                        /* UEID */
static int hf_kpm_v2_MatchingUeCondPerSubList_item;  /* MatchingUeCondPerSubItem */
static int hf_kpm_v2_MatchingUEidPerSubList_item;  /* MatchingUEidPerSubItem */
static int hf_kpm_v2_UEMeasurementReportList_item;  /* UEMeasurementReportItem */
static int hf_kpm_v2_measReport;                  /* E2SM_KPM_IndicationMessage_Format1 */
static int hf_kpm_v2_eventDefinition_formats;     /* T_eventDefinition_formats */
static int hf_kpm_v2_eventDefinition_Format1;     /* E2SM_KPM_EventTriggerDefinition_Format1 */
static int hf_kpm_v2_reportingPeriod;             /* INTEGER_1_4294967295 */
static int hf_kpm_v2_ric_Style_Type;              /* RIC_Style_Type */
static int hf_kpm_v2_actionDefinition_formats;    /* T_actionDefinition_formats */
static int hf_kpm_v2_actionDefinition_Format1;    /* E2SM_KPM_ActionDefinition_Format1 */
static int hf_kpm_v2_actionDefinition_Format2;    /* E2SM_KPM_ActionDefinition_Format2 */
static int hf_kpm_v2_actionDefinition_Format3;    /* E2SM_KPM_ActionDefinition_Format3 */
static int hf_kpm_v2_actionDefinition_Format4;    /* E2SM_KPM_ActionDefinition_Format4 */
static int hf_kpm_v2_actionDefinition_Format5;    /* E2SM_KPM_ActionDefinition_Format5 */
static int hf_kpm_v2_measInfoList;                /* MeasurementInfoList */
static int hf_kpm_v2_granulPeriod;                /* GranularityPeriod */
static int hf_kpm_v2_cellGlobalID;                /* CGI */
static int hf_kpm_v2_subscriptInfo;               /* E2SM_KPM_ActionDefinition_Format1 */
static int hf_kpm_v2_measCondList;                /* MeasurementCondList */
static int hf_kpm_v2_matchingUeCondList;          /* MatchingUeCondPerSubList */
static int hf_kpm_v2_subscriptionInfo;            /* E2SM_KPM_ActionDefinition_Format1 */
static int hf_kpm_v2_matchingUEidList_01;         /* MatchingUEidPerSubList */
static int hf_kpm_v2_indicationHeader_formats;    /* T_indicationHeader_formats */
static int hf_kpm_v2_indicationHeader_Format1;    /* E2SM_KPM_IndicationHeader_Format1 */
static int hf_kpm_v2_colletStartTime;             /* T_colletStartTime */
static int hf_kpm_v2_fileFormatversion;           /* PrintableString_SIZE_0_15_ */
static int hf_kpm_v2_senderName;                  /* PrintableString_SIZE_0_400_ */
static int hf_kpm_v2_senderType;                  /* PrintableString_SIZE_0_8_ */
static int hf_kpm_v2_vendorName;                  /* PrintableString_SIZE_0_32_ */
static int hf_kpm_v2_indicationMessage_formats;   /* T_indicationMessage_formats */
static int hf_kpm_v2_indicationMessage_Format1;   /* E2SM_KPM_IndicationMessage_Format1 */
static int hf_kpm_v2_indicationMessage_Format2;   /* E2SM_KPM_IndicationMessage_Format2 */
static int hf_kpm_v2_indicationMessage_Format3;   /* E2SM_KPM_IndicationMessage_Format3 */
static int hf_kpm_v2_measData;                    /* MeasurementData */
static int hf_kpm_v2_measCondUEidList;            /* MeasurementCondUEidList */
static int hf_kpm_v2_ueMeasReportList;            /* UEMeasurementReportList */
static int hf_kpm_v2_ranFunction_Name;            /* RANfunction_Name */
static int hf_kpm_v2_ric_EventTriggerStyle_List;  /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item */
static int hf_kpm_v2_ric_EventTriggerStyle_List_item;  /* RIC_EventTriggerStyle_Item */
static int hf_kpm_v2_ric_ReportStyle_List;        /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item */
static int hf_kpm_v2_ric_ReportStyle_List_item;   /* RIC_ReportStyle_Item */
static int hf_kpm_v2_ric_EventTriggerStyle_Type;  /* RIC_Style_Type */
static int hf_kpm_v2_ric_EventTriggerStyle_Name;  /* RIC_Style_Name */
static int hf_kpm_v2_ric_EventTriggerFormat_Type;  /* RIC_Format_Type */
static int hf_kpm_v2_ric_ReportStyle_Type;        /* RIC_Style_Type */
static int hf_kpm_v2_ric_ReportStyle_Name;        /* RIC_Style_Name */
static int hf_kpm_v2_ric_ActionFormat_Type;       /* RIC_Format_Type */
static int hf_kpm_v2_measInfo_Action_List;        /* MeasurementInfo_Action_List */
static int hf_kpm_v2_ric_IndicationHeaderFormat_Type;  /* RIC_Format_Type */
static int hf_kpm_v2_ric_IndicationMessageFormat_Type;  /* RIC_Format_Type */
static int hf_kpm_v2_nR_CGI;                      /* NR_CGI */
static int hf_kpm_v2_eUTRA_CGI;                   /* EUTRA_CGI */
static int hf_kpm_v2_ranFunction_ShortName;       /* T_ranFunction_ShortName */
static int hf_kpm_v2_ranFunction_E2SM_OID;        /* T_ranFunction_E2SM_OID */
static int hf_kpm_v2_ranFunction_Description;     /* PrintableString_SIZE_1_150_ */
static int hf_kpm_v2_ranFunction_Instance;        /* INTEGER */
static int hf_kpm_v2_gNB_UEID;                    /* UEID_GNB */
static int hf_kpm_v2_gNB_DU_UEID;                 /* UEID_GNB_DU */
static int hf_kpm_v2_gNB_CU_UP_UEID;              /* UEID_GNB_CU_UP */
static int hf_kpm_v2_ng_eNB_UEID;                 /* UEID_NG_ENB */
static int hf_kpm_v2_ng_eNB_DU_UEID;              /* UEID_NG_ENB_DU */
static int hf_kpm_v2_en_gNB_UEID;                 /* UEID_EN_GNB */
static int hf_kpm_v2_eNB_UEID;                    /* UEID_ENB */
static int hf_kpm_v2_amf_UE_NGAP_ID;              /* AMF_UE_NGAP_ID */
static int hf_kpm_v2_guami;                       /* GUAMI */
static int hf_kpm_v2_gNB_CU_UE_F1AP_ID_List;      /* UEID_GNB_CU_F1AP_ID_List */
static int hf_kpm_v2_gNB_CU_CP_UE_E1AP_ID_List;   /* UEID_GNB_CU_CP_E1AP_ID_List */
static int hf_kpm_v2_ran_UEID;                    /* RANUEID */
static int hf_kpm_v2_m_NG_RAN_UE_XnAP_ID;         /* NG_RANnodeUEXnAPID */
static int hf_kpm_v2_globalGNB_ID;                /* GlobalGNB_ID */
static int hf_kpm_v2_globalNG_RANNode_ID;         /* GlobalNGRANNodeID */
static int hf_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_List_item;  /* UEID_GNB_CU_CP_E1AP_ID_Item */
static int hf_kpm_v2_gNB_CU_CP_UE_E1AP_ID;        /* GNB_CU_CP_UE_E1AP_ID */
static int hf_kpm_v2_UEID_GNB_CU_F1AP_ID_List_item;  /* UEID_GNB_CU_CP_F1AP_ID_Item */
static int hf_kpm_v2_gNB_CU_UE_F1AP_ID;           /* GNB_CU_UE_F1AP_ID */
static int hf_kpm_v2_ng_eNB_CU_UE_W1AP_ID;        /* NGENB_CU_UE_W1AP_ID */
static int hf_kpm_v2_globalNgENB_ID;              /* GlobalNgENB_ID */
static int hf_kpm_v2_m_eNB_UE_X2AP_ID;            /* ENB_UE_X2AP_ID */
static int hf_kpm_v2_m_eNB_UE_X2AP_ID_Extension;  /* ENB_UE_X2AP_ID_Extension */
static int hf_kpm_v2_globalENB_ID;                /* GlobalENB_ID */
static int hf_kpm_v2_mME_UE_S1AP_ID;              /* MME_UE_S1AP_ID */
static int hf_kpm_v2_gUMMEI;                      /* GUMMEI */
static int hf_kpm_v2_macro_eNB_ID;                /* BIT_STRING_SIZE_20 */
static int hf_kpm_v2_home_eNB_ID;                 /* BIT_STRING_SIZE_28 */
static int hf_kpm_v2_short_Macro_eNB_ID;          /* BIT_STRING_SIZE_18 */
static int hf_kpm_v2_long_Macro_eNB_ID;           /* BIT_STRING_SIZE_21 */
static int hf_kpm_v2_pLMNIdentity;                /* PLMNIdentity */
static int hf_kpm_v2_eNB_ID;                      /* ENB_ID */
static int hf_kpm_v2_pLMN_Identity;               /* PLMNIdentity */
static int hf_kpm_v2_mME_Group_ID;                /* MME_Group_ID */
static int hf_kpm_v2_mME_Code;                    /* MME_Code */
static int hf_kpm_v2_eUTRACellIdentity;           /* EUTRACellIdentity */
static int hf_kpm_v2_gNB_ID;                      /* GNB_ID */
static int hf_kpm_v2_ngENB_ID;                    /* NgENB_ID */
static int hf_kpm_v2_gNB_ID_01;                   /* BIT_STRING_SIZE_22_32 */
static int hf_kpm_v2_aMFRegionID;                 /* AMFRegionID */
static int hf_kpm_v2_aMFSetID;                    /* AMFSetID */
static int hf_kpm_v2_aMFPointer;                  /* AMFPointer */
static int hf_kpm_v2_macroNgENB_ID;               /* BIT_STRING_SIZE_20 */
static int hf_kpm_v2_shortMacroNgENB_ID;          /* BIT_STRING_SIZE_18 */
static int hf_kpm_v2_longMacroNgENB_ID;           /* BIT_STRING_SIZE_21 */
static int hf_kpm_v2_nRCellIdentity;              /* NRCellIdentity */
static int hf_kpm_v2_sST;                         /* SST */
static int hf_kpm_v2_sD;                          /* SD */
static int hf_kpm_v2_gNB;                         /* GlobalGNB_ID */
static int hf_kpm_v2_ng_eNB;                      /* GlobalNgENB_ID */

static int hf_kpm_v2_timestamp_string;


static int ett_kpm_v2_MeasurementType;
static int ett_kpm_v2_MeasurementLabel;
static int ett_kpm_v2_TestCondInfo;
static int ett_kpm_v2_TestCond_Type;
static int ett_kpm_v2_TestCond_Value;
static int ett_kpm_v2_MeasurementInfoList;
static int ett_kpm_v2_MeasurementInfoItem;
static int ett_kpm_v2_LabelInfoList;
static int ett_kpm_v2_LabelInfoItem;
static int ett_kpm_v2_MeasurementData;
static int ett_kpm_v2_MeasurementDataItem;
static int ett_kpm_v2_MeasurementRecord;
static int ett_kpm_v2_MeasurementRecordItem;
static int ett_kpm_v2_MeasurementInfo_Action_List;
static int ett_kpm_v2_MeasurementInfo_Action_Item;
static int ett_kpm_v2_MeasurementCondList;
static int ett_kpm_v2_MeasurementCondItem;
static int ett_kpm_v2_MeasurementCondUEidList;
static int ett_kpm_v2_MeasurementCondUEidItem;
static int ett_kpm_v2_MatchingCondList;
static int ett_kpm_v2_MatchingCondItem;
static int ett_kpm_v2_MatchingUEidList;
static int ett_kpm_v2_MatchingUEidItem;
static int ett_kpm_v2_MatchingUeCondPerSubList;
static int ett_kpm_v2_MatchingUeCondPerSubItem;
static int ett_kpm_v2_MatchingUEidPerSubList;
static int ett_kpm_v2_MatchingUEidPerSubItem;
static int ett_kpm_v2_UEMeasurementReportList;
static int ett_kpm_v2_UEMeasurementReportItem;
static int ett_kpm_v2_E2SM_KPM_EventTriggerDefinition;
static int ett_kpm_v2_T_eventDefinition_formats;
static int ett_kpm_v2_E2SM_KPM_EventTriggerDefinition_Format1;
static int ett_kpm_v2_E2SM_KPM_ActionDefinition;
static int ett_kpm_v2_T_actionDefinition_formats;
static int ett_kpm_v2_E2SM_KPM_ActionDefinition_Format1;
static int ett_kpm_v2_E2SM_KPM_ActionDefinition_Format2;
static int ett_kpm_v2_E2SM_KPM_ActionDefinition_Format3;
static int ett_kpm_v2_E2SM_KPM_ActionDefinition_Format4;
static int ett_kpm_v2_E2SM_KPM_ActionDefinition_Format5;
static int ett_kpm_v2_E2SM_KPM_IndicationHeader;
static int ett_kpm_v2_T_indicationHeader_formats;
static int ett_kpm_v2_E2SM_KPM_IndicationHeader_Format1;
static int ett_kpm_v2_E2SM_KPM_IndicationMessage;
static int ett_kpm_v2_T_indicationMessage_formats;
static int ett_kpm_v2_E2SM_KPM_IndicationMessage_Format1;
static int ett_kpm_v2_E2SM_KPM_IndicationMessage_Format2;
static int ett_kpm_v2_E2SM_KPM_IndicationMessage_Format3;
static int ett_kpm_v2_E2SM_KPM_RANfunction_Description;
static int ett_kpm_v2_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item;
static int ett_kpm_v2_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item;
static int ett_kpm_v2_RIC_EventTriggerStyle_Item;
static int ett_kpm_v2_RIC_ReportStyle_Item;
static int ett_kpm_v2_CGI;
static int ett_kpm_v2_RANfunction_Name;
static int ett_kpm_v2_UEID;
static int ett_kpm_v2_UEID_GNB;
static int ett_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_List;
static int ett_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_Item;
static int ett_kpm_v2_UEID_GNB_CU_F1AP_ID_List;
static int ett_kpm_v2_UEID_GNB_CU_CP_F1AP_ID_Item;
static int ett_kpm_v2_UEID_GNB_DU;
static int ett_kpm_v2_UEID_GNB_CU_UP;
static int ett_kpm_v2_UEID_NG_ENB;
static int ett_kpm_v2_UEID_NG_ENB_DU;
static int ett_kpm_v2_UEID_EN_GNB;
static int ett_kpm_v2_UEID_ENB;
static int ett_kpm_v2_ENB_ID;
static int ett_kpm_v2_GlobalENB_ID;
static int ett_kpm_v2_GUMMEI;
static int ett_kpm_v2_EUTRA_CGI;
static int ett_kpm_v2_GlobalGNB_ID;
static int ett_kpm_v2_GlobalNgENB_ID;
static int ett_kpm_v2_GNB_ID;
static int ett_kpm_v2_GUAMI;
static int ett_kpm_v2_NgENB_ID;
static int ett_kpm_v2_NR_CGI;
static int ett_kpm_v2_S_NSSAI;
static int ett_kpm_v2_GlobalNGRANNodeID;


/* Forward declarations */
static int dissect_E2SM_KPM_EventTriggerDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_KPM_RANfunction_Description_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);



static int
dissect_kpm_v2_TimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}



static int
dissect_kpm_v2_GranularityPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_kpm_v2_MeasurementTypeName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_kpm_v2_MeasurementTypeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65536U, NULL, true);

  return offset;
}


static const value_string kpm_v2_MeasurementType_vals[] = {
  {   0, "measName" },
  {   1, "measID" },
  { 0, NULL }
};

static const per_choice_t MeasurementType_choice[] = {
  {   0, &hf_kpm_v2_measName     , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_MeasurementTypeName },
  {   1, &hf_kpm_v2_measID       , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_MeasurementTypeID },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_MeasurementType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_MeasurementType, MeasurementType_choice,
                                 NULL);

  return offset;
}


static const value_string kpm_v2_T_noLabel_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_noLabel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_kpm_v2_PLMNIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}



static int
dissect_kpm_v2_SST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}



static int
dissect_kpm_v2_SD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}


static const per_sequence_t S_NSSAI_sequence[] = {
  { &hf_kpm_v2_sST          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_SST },
  { &hf_kpm_v2_sD           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_SD },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_S_NSSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_S_NSSAI, S_NSSAI_sequence);

  return offset;
}



static int
dissect_kpm_v2_FiveQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, true);

  return offset;
}



static int
dissect_kpm_v2_QosFlowIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, true);

  return offset;
}



static int
dissect_kpm_v2_QCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_kpm_v2_INTEGER_1_15_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 15U, NULL, true);

  return offset;
}



static int
dissect_kpm_v2_INTEGER_1_65535_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}


static const value_string kpm_v2_T_sUM_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_sUM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_preLabelOverride_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_preLabelOverride(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_startEndInd_vals[] = {
  {   0, "start" },
  {   1, "end" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_startEndInd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_min_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_min(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_max_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_max(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_avg_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_avg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MeasurementLabel_sequence[] = {
  { &hf_kpm_v2_noLabel      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_T_noLabel },
  { &hf_kpm_v2_plmnID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_PLMNIdentity },
  { &hf_kpm_v2_sliceID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_S_NSSAI },
  { &hf_kpm_v2_fiveQI       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_FiveQI },
  { &hf_kpm_v2_qFI          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_QosFlowIdentifier },
  { &hf_kpm_v2_qCI          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_QCI },
  { &hf_kpm_v2_qCImax       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_QCI },
  { &hf_kpm_v2_qCImin       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_QCI },
  { &hf_kpm_v2_aRPmax       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_INTEGER_1_15_ },
  { &hf_kpm_v2_aRPmin       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_INTEGER_1_15_ },
  { &hf_kpm_v2_bitrateRange , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_INTEGER_1_65535_ },
  { &hf_kpm_v2_layerMU_MIMO , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_INTEGER_1_65535_ },
  { &hf_kpm_v2_sUM          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_T_sUM },
  { &hf_kpm_v2_distBinX     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_INTEGER_1_65535_ },
  { &hf_kpm_v2_distBinY     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_INTEGER_1_65535_ },
  { &hf_kpm_v2_distBinZ     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_INTEGER_1_65535_ },
  { &hf_kpm_v2_preLabelOverride, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_T_preLabelOverride },
  { &hf_kpm_v2_startEndInd  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_T_startEndInd },
  { &hf_kpm_v2_min          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_T_min },
  { &hf_kpm_v2_max          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_T_max },
  { &hf_kpm_v2_avg          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_T_avg },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_MeasurementLabel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_MeasurementLabel, MeasurementLabel_sequence);

  return offset;
}


static const value_string kpm_v2_T_gBR_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_gBR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_aMBR_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_aMBR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_isStat_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_isStat(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_isCatM_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_isCatM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_rSRP_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_rSRP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_rSRQ_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_rSRQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_ul_rSRP_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_ul_rSRP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_cQI_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_cQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_fiveQI_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_fiveQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_qCI_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_qCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_T_sNSSAI_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_sNSSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string kpm_v2_TestCond_Type_vals[] = {
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
  {   0, &hf_kpm_v2_gBR          , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_T_gBR },
  {   1, &hf_kpm_v2_aMBR         , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_T_aMBR },
  {   2, &hf_kpm_v2_isStat       , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_T_isStat },
  {   3, &hf_kpm_v2_isCatM       , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_T_isCatM },
  {   4, &hf_kpm_v2_rSRP         , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_T_rSRP },
  {   5, &hf_kpm_v2_rSRQ         , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_T_rSRQ },
  {   6, &hf_kpm_v2_ul_rSRP      , ASN1_NOT_EXTENSION_ROOT, dissect_kpm_v2_T_ul_rSRP },
  {   7, &hf_kpm_v2_cQI          , ASN1_NOT_EXTENSION_ROOT, dissect_kpm_v2_T_cQI },
  {   8, &hf_kpm_v2_fiveQI_01    , ASN1_NOT_EXTENSION_ROOT, dissect_kpm_v2_T_fiveQI },
  {   9, &hf_kpm_v2_qCI_01       , ASN1_NOT_EXTENSION_ROOT, dissect_kpm_v2_T_qCI },
  {  10, &hf_kpm_v2_sNSSAI       , ASN1_NOT_EXTENSION_ROOT, dissect_kpm_v2_T_sNSSAI },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_TestCond_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_TestCond_Type, TestCond_Type_choice,
                                 NULL);

  return offset;
}


static const value_string kpm_v2_TestCond_Expression_vals[] = {
  {   0, "equal" },
  {   1, "greaterthan" },
  {   2, "lessthan" },
  {   3, "contains" },
  {   4, "present" },
  { 0, NULL }
};


static int
dissect_kpm_v2_TestCond_Expression(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_kpm_v2_INTEGER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_kpm_v2_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_kpm_v2_BIT_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_kpm_v2_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}



static int
dissect_kpm_v2_PrintableString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND, false,
                                          NULL);

  return offset;
}



static int
dissect_kpm_v2_REAL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_real(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string kpm_v2_TestCond_Value_vals[] = {
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
  {   0, &hf_kpm_v2_valueInt     , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_INTEGER },
  {   1, &hf_kpm_v2_valueEnum    , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_INTEGER },
  {   2, &hf_kpm_v2_valueBool    , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_BOOLEAN },
  {   3, &hf_kpm_v2_valueBitS    , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_BIT_STRING },
  {   4, &hf_kpm_v2_valueOctS    , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_OCTET_STRING },
  {   5, &hf_kpm_v2_valuePrtS    , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_PrintableString },
  {   6, &hf_kpm_v2_valueReal    , ASN1_NOT_EXTENSION_ROOT, dissect_kpm_v2_REAL },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_TestCond_Value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_TestCond_Value, TestCond_Value_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TestCondInfo_sequence[] = {
  { &hf_kpm_v2_testType     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_TestCond_Type },
  { &hf_kpm_v2_testExpr     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_TestCond_Expression },
  { &hf_kpm_v2_testValue    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_TestCond_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_TestCondInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_TestCondInfo, TestCondInfo_sequence);

  return offset;
}


static const per_sequence_t LabelInfoItem_sequence[] = {
  { &hf_kpm_v2_measLabel    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementLabel },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_LabelInfoItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_LabelInfoItem, LabelInfoItem_sequence);

  return offset;
}


static const per_sequence_t LabelInfoList_sequence_of[1] = {
  { &hf_kpm_v2_LabelInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_LabelInfoItem },
};

static int
dissect_kpm_v2_LabelInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_LabelInfoList, LabelInfoList_sequence_of,
                                                  1, maxnoofLabelInfo, false);

  return offset;
}


static const per_sequence_t MeasurementInfoItem_sequence[] = {
  { &hf_kpm_v2_measType     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementType },
  { &hf_kpm_v2_labelInfoList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_LabelInfoList },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_MeasurementInfoItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_MeasurementInfoItem, MeasurementInfoItem_sequence);

  return offset;
}


static const per_sequence_t MeasurementInfoList_sequence_of[1] = {
  { &hf_kpm_v2_MeasurementInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementInfoItem },
};

static int
dissect_kpm_v2_MeasurementInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_MeasurementInfoList, MeasurementInfoList_sequence_of,
                                                  1, maxnoofMeasurementInfo, false);

  return offset;
}



static int
dissect_kpm_v2_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_kpm_v2_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string kpm_v2_MeasurementRecordItem_vals[] = {
  {   0, "integer" },
  {   1, "real" },
  {   2, "noValue" },
  { 0, NULL }
};

static const per_choice_t MeasurementRecordItem_choice[] = {
  {   0, &hf_kpm_v2_integer      , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_INTEGER_0_4294967295 },
  {   1, &hf_kpm_v2_real         , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_REAL },
  {   2, &hf_kpm_v2_noValue      , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_MeasurementRecordItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_MeasurementRecordItem, MeasurementRecordItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MeasurementRecord_sequence_of[1] = {
  { &hf_kpm_v2_MeasurementRecord_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementRecordItem },
};

static int
dissect_kpm_v2_MeasurementRecord(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_MeasurementRecord, MeasurementRecord_sequence_of,
                                                  1, maxnoofMeasurementValue, false);

  return offset;
}


static const value_string kpm_v2_T_incompleteFlag_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_kpm_v2_T_incompleteFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MeasurementDataItem_sequence[] = {
  { &hf_kpm_v2_measRecord   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementRecord },
  { &hf_kpm_v2_incompleteFlag, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_T_incompleteFlag },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_MeasurementDataItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_MeasurementDataItem, MeasurementDataItem_sequence);

  return offset;
}


static const per_sequence_t MeasurementData_sequence_of[1] = {
  { &hf_kpm_v2_MeasurementData_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementDataItem },
};

static int
dissect_kpm_v2_MeasurementData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_MeasurementData, MeasurementData_sequence_of,
                                                  1, maxnoofMeasurementRecord, false);

  return offset;
}


static const per_sequence_t MeasurementInfo_Action_Item_sequence[] = {
  { &hf_kpm_v2_measName     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementTypeName },
  { &hf_kpm_v2_measID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_MeasurementTypeID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_MeasurementInfo_Action_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_MeasurementInfo_Action_Item, MeasurementInfo_Action_Item_sequence);

  return offset;
}


static const per_sequence_t MeasurementInfo_Action_List_sequence_of[1] = {
  { &hf_kpm_v2_MeasurementInfo_Action_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementInfo_Action_Item },
};

static int
dissect_kpm_v2_MeasurementInfo_Action_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_MeasurementInfo_Action_List, MeasurementInfo_Action_List_sequence_of,
                                                  1, maxnoofMeasurementInfo, false);

  return offset;
}


static const value_string kpm_v2_MatchingCondItem_vals[] = {
  {   0, "measLabel" },
  {   1, "testCondInfo" },
  { 0, NULL }
};

static const per_choice_t MatchingCondItem_choice[] = {
  {   0, &hf_kpm_v2_measLabel    , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_MeasurementLabel },
  {   1, &hf_kpm_v2_testCondInfo , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_TestCondInfo },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_MatchingCondItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_MatchingCondItem, MatchingCondItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MatchingCondList_sequence_of[1] = {
  { &hf_kpm_v2_MatchingCondList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MatchingCondItem },
};

static int
dissect_kpm_v2_MatchingCondList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_MatchingCondList, MatchingCondList_sequence_of,
                                                  1, maxnoofConditionInfo, false);

  return offset;
}


static const per_sequence_t MeasurementCondItem_sequence[] = {
  { &hf_kpm_v2_measType     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementType },
  { &hf_kpm_v2_matchingCond , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MatchingCondList },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_MeasurementCondItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_MeasurementCondItem, MeasurementCondItem_sequence);

  return offset;
}


static const per_sequence_t MeasurementCondList_sequence_of[1] = {
  { &hf_kpm_v2_MeasurementCondList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementCondItem },
};

static int
dissect_kpm_v2_MeasurementCondList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_MeasurementCondList, MeasurementCondList_sequence_of,
                                                  1, maxnoofMeasurementInfo, false);

  return offset;
}



static int
dissect_kpm_v2_AMF_UE_NGAP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(1099511627775), NULL, false);

  return offset;
}



static int
dissect_kpm_v2_AMFRegionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_kpm_v2_AMFSetID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_kpm_v2_AMFPointer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GUAMI_sequence[] = {
  { &hf_kpm_v2_pLMNIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_PLMNIdentity },
  { &hf_kpm_v2_aMFRegionID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_AMFRegionID },
  { &hf_kpm_v2_aMFSetID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_AMFSetID },
  { &hf_kpm_v2_aMFPointer   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_AMFPointer },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_GUAMI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_GUAMI, GUAMI_sequence);

  return offset;
}



static int
dissect_kpm_v2_GNB_CU_UE_F1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_CP_F1AP_ID_Item_sequence[] = {
  { &hf_kpm_v2_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_GNB_CU_UE_F1AP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_UEID_GNB_CU_CP_F1AP_ID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_UEID_GNB_CU_CP_F1AP_ID_Item, UEID_GNB_CU_CP_F1AP_ID_Item_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_F1AP_ID_List_sequence_of[1] = {
  { &hf_kpm_v2_UEID_GNB_CU_F1AP_ID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_UEID_GNB_CU_CP_F1AP_ID_Item },
};

static int
dissect_kpm_v2_UEID_GNB_CU_F1AP_ID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_UEID_GNB_CU_F1AP_ID_List, UEID_GNB_CU_F1AP_ID_List_sequence_of,
                                                  1, maxF1APid, false);

  return offset;
}



static int
dissect_kpm_v2_GNB_CU_CP_UE_E1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_CP_E1AP_ID_Item_sequence[] = {
  { &hf_kpm_v2_gNB_CU_CP_UE_E1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_GNB_CU_CP_UE_E1AP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_Item, UEID_GNB_CU_CP_E1AP_ID_Item_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_CP_E1AP_ID_List_sequence_of[1] = {
  { &hf_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_Item },
};

static int
dissect_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_List, UEID_GNB_CU_CP_E1AP_ID_List_sequence_of,
                                                  1, maxE1APid, false);

  return offset;
}



static int
dissect_kpm_v2_RANUEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}



static int
dissect_kpm_v2_NG_RANnodeUEXnAPID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_kpm_v2_BIT_STRING_SIZE_22_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     22, 32, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string kpm_v2_GNB_ID_vals[] = {
  {   0, "gNB-ID" },
  { 0, NULL }
};

static const per_choice_t GNB_ID_choice[] = {
  {   0, &hf_kpm_v2_gNB_ID_01    , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_BIT_STRING_SIZE_22_32 },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_GNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_GNB_ID, GNB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalGNB_ID_sequence[] = {
  { &hf_kpm_v2_pLMNIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_PLMNIdentity },
  { &hf_kpm_v2_gNB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_GNB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_GlobalGNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_GlobalGNB_ID, GlobalGNB_ID_sequence);

  return offset;
}



static int
dissect_kpm_v2_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_kpm_v2_BIT_STRING_SIZE_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     18, 18, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_kpm_v2_BIT_STRING_SIZE_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     21, 21, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string kpm_v2_NgENB_ID_vals[] = {
  {   0, "macroNgENB-ID" },
  {   1, "shortMacroNgENB-ID" },
  {   2, "longMacroNgENB-ID" },
  { 0, NULL }
};

static const per_choice_t NgENB_ID_choice[] = {
  {   0, &hf_kpm_v2_macroNgENB_ID, ASN1_EXTENSION_ROOT    , dissect_kpm_v2_BIT_STRING_SIZE_20 },
  {   1, &hf_kpm_v2_shortMacroNgENB_ID, ASN1_EXTENSION_ROOT    , dissect_kpm_v2_BIT_STRING_SIZE_18 },
  {   2, &hf_kpm_v2_longMacroNgENB_ID, ASN1_EXTENSION_ROOT    , dissect_kpm_v2_BIT_STRING_SIZE_21 },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_NgENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_NgENB_ID, NgENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalNgENB_ID_sequence[] = {
  { &hf_kpm_v2_pLMNIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_PLMNIdentity },
  { &hf_kpm_v2_ngENB_ID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_NgENB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_GlobalNgENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_GlobalNgENB_ID, GlobalNgENB_ID_sequence);

  return offset;
}


static const value_string kpm_v2_GlobalNGRANNodeID_vals[] = {
  {   0, "gNB" },
  {   1, "ng-eNB" },
  { 0, NULL }
};

static const per_choice_t GlobalNGRANNodeID_choice[] = {
  {   0, &hf_kpm_v2_gNB          , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_GlobalGNB_ID },
  {   1, &hf_kpm_v2_ng_eNB       , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_GlobalNgENB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_GlobalNGRANNodeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_GlobalNGRANNodeID, GlobalNGRANNodeID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UEID_GNB_sequence[] = {
  { &hf_kpm_v2_amf_UE_NGAP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_AMF_UE_NGAP_ID },
  { &hf_kpm_v2_guami        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_GUAMI },
  { &hf_kpm_v2_gNB_CU_UE_F1AP_ID_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_UEID_GNB_CU_F1AP_ID_List },
  { &hf_kpm_v2_gNB_CU_CP_UE_E1AP_ID_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_List },
  { &hf_kpm_v2_ran_UEID     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_RANUEID },
  { &hf_kpm_v2_m_NG_RAN_UE_XnAP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_NG_RANnodeUEXnAPID },
  { &hf_kpm_v2_globalGNB_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_GlobalGNB_ID },
  { &hf_kpm_v2_globalNG_RANNode_ID, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_kpm_v2_GlobalNGRANNodeID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_UEID_GNB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_UEID_GNB, UEID_GNB_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_DU_sequence[] = {
  { &hf_kpm_v2_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_GNB_CU_UE_F1AP_ID },
  { &hf_kpm_v2_ran_UEID     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_RANUEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_UEID_GNB_DU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_UEID_GNB_DU, UEID_GNB_DU_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_UP_sequence[] = {
  { &hf_kpm_v2_gNB_CU_CP_UE_E1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_GNB_CU_CP_UE_E1AP_ID },
  { &hf_kpm_v2_ran_UEID     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_RANUEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_UEID_GNB_CU_UP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_UEID_GNB_CU_UP, UEID_GNB_CU_UP_sequence);

  return offset;
}



static int
dissect_kpm_v2_NGENB_CU_UE_W1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_NG_ENB_sequence[] = {
  { &hf_kpm_v2_amf_UE_NGAP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_AMF_UE_NGAP_ID },
  { &hf_kpm_v2_guami        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_GUAMI },
  { &hf_kpm_v2_ng_eNB_CU_UE_W1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_NGENB_CU_UE_W1AP_ID },
  { &hf_kpm_v2_m_NG_RAN_UE_XnAP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_NG_RANnodeUEXnAPID },
  { &hf_kpm_v2_globalNgENB_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_GlobalNgENB_ID },
  { &hf_kpm_v2_globalNG_RANNode_ID, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_kpm_v2_GlobalNGRANNodeID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_UEID_NG_ENB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_UEID_NG_ENB, UEID_NG_ENB_sequence);

  return offset;
}


static const per_sequence_t UEID_NG_ENB_DU_sequence[] = {
  { &hf_kpm_v2_ng_eNB_CU_UE_W1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_NGENB_CU_UE_W1AP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_UEID_NG_ENB_DU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_UEID_NG_ENB_DU, UEID_NG_ENB_DU_sequence);

  return offset;
}



static int
dissect_kpm_v2_ENB_UE_X2AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}



static int
dissect_kpm_v2_ENB_UE_X2AP_ID_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, true);

  return offset;
}



static int
dissect_kpm_v2_BIT_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string kpm_v2_ENB_ID_vals[] = {
  {   0, "macro-eNB-ID" },
  {   1, "home-eNB-ID" },
  {   2, "short-Macro-eNB-ID" },
  {   3, "long-Macro-eNB-ID" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_choice[] = {
  {   0, &hf_kpm_v2_macro_eNB_ID , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_BIT_STRING_SIZE_20 },
  {   1, &hf_kpm_v2_home_eNB_ID  , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_BIT_STRING_SIZE_28 },
  {   2, &hf_kpm_v2_short_Macro_eNB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_kpm_v2_BIT_STRING_SIZE_18 },
  {   3, &hf_kpm_v2_long_Macro_eNB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_kpm_v2_BIT_STRING_SIZE_21 },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_ENB_ID, ENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalENB_ID_sequence[] = {
  { &hf_kpm_v2_pLMNIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_PLMNIdentity },
  { &hf_kpm_v2_eNB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_ENB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_GlobalENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_GlobalENB_ID, GlobalENB_ID_sequence);

  return offset;
}


static const per_sequence_t UEID_EN_GNB_sequence[] = {
  { &hf_kpm_v2_m_eNB_UE_X2AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_ENB_UE_X2AP_ID },
  { &hf_kpm_v2_m_eNB_UE_X2AP_ID_Extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_ENB_UE_X2AP_ID_Extension },
  { &hf_kpm_v2_globalENB_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_GlobalENB_ID },
  { &hf_kpm_v2_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_GNB_CU_UE_F1AP_ID },
  { &hf_kpm_v2_gNB_CU_CP_UE_E1AP_ID_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_List },
  { &hf_kpm_v2_ran_UEID     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_RANUEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_UEID_EN_GNB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_UEID_EN_GNB, UEID_EN_GNB_sequence);

  return offset;
}



static int
dissect_kpm_v2_MME_UE_S1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_kpm_v2_MME_Group_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, NULL);

  return offset;
}



static int
dissect_kpm_v2_MME_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const per_sequence_t GUMMEI_sequence[] = {
  { &hf_kpm_v2_pLMN_Identity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_PLMNIdentity },
  { &hf_kpm_v2_mME_Group_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MME_Group_ID },
  { &hf_kpm_v2_mME_Code     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MME_Code },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_GUMMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_GUMMEI, GUMMEI_sequence);

  return offset;
}


static const per_sequence_t UEID_ENB_sequence[] = {
  { &hf_kpm_v2_mME_UE_S1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MME_UE_S1AP_ID },
  { &hf_kpm_v2_gUMMEI       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_GUMMEI },
  { &hf_kpm_v2_m_eNB_UE_X2AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_ENB_UE_X2AP_ID },
  { &hf_kpm_v2_m_eNB_UE_X2AP_ID_Extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_ENB_UE_X2AP_ID_Extension },
  { &hf_kpm_v2_globalENB_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_GlobalENB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_UEID_ENB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_UEID_ENB, UEID_ENB_sequence);

  return offset;
}


static const value_string kpm_v2_UEID_vals[] = {
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
  {   0, &hf_kpm_v2_gNB_UEID     , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_UEID_GNB },
  {   1, &hf_kpm_v2_gNB_DU_UEID  , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_UEID_GNB_DU },
  {   2, &hf_kpm_v2_gNB_CU_UP_UEID, ASN1_EXTENSION_ROOT    , dissect_kpm_v2_UEID_GNB_CU_UP },
  {   3, &hf_kpm_v2_ng_eNB_UEID  , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_UEID_NG_ENB },
  {   4, &hf_kpm_v2_ng_eNB_DU_UEID, ASN1_EXTENSION_ROOT    , dissect_kpm_v2_UEID_NG_ENB_DU },
  {   5, &hf_kpm_v2_en_gNB_UEID  , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_UEID_EN_GNB },
  {   6, &hf_kpm_v2_eNB_UEID     , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_UEID_ENB },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_UEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_UEID, UEID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MatchingUEidItem_sequence[] = {
  { &hf_kpm_v2_ueID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_UEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_MatchingUEidItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_MatchingUEidItem, MatchingUEidItem_sequence);

  return offset;
}


static const per_sequence_t MatchingUEidList_sequence_of[1] = {
  { &hf_kpm_v2_MatchingUEidList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MatchingUEidItem },
};

static int
dissect_kpm_v2_MatchingUEidList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_MatchingUEidList, MatchingUEidList_sequence_of,
                                                  1, maxnoofUEID, false);

  return offset;
}


static const per_sequence_t MeasurementCondUEidItem_sequence[] = {
  { &hf_kpm_v2_measType     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementType },
  { &hf_kpm_v2_matchingCond , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MatchingCondList },
  { &hf_kpm_v2_matchingUEidList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_MatchingUEidList },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_MeasurementCondUEidItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_MeasurementCondUEidItem, MeasurementCondUEidItem_sequence);

  return offset;
}


static const per_sequence_t MeasurementCondUEidList_sequence_of[1] = {
  { &hf_kpm_v2_MeasurementCondUEidList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementCondUEidItem },
};

static int
dissect_kpm_v2_MeasurementCondUEidList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_MeasurementCondUEidList, MeasurementCondUEidList_sequence_of,
                                                  1, maxnoofMeasurementInfo, false);

  return offset;
}


static const per_sequence_t MatchingUeCondPerSubItem_sequence[] = {
  { &hf_kpm_v2_testCondInfo , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_TestCondInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_MatchingUeCondPerSubItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_MatchingUeCondPerSubItem, MatchingUeCondPerSubItem_sequence);

  return offset;
}


static const per_sequence_t MatchingUeCondPerSubList_sequence_of[1] = {
  { &hf_kpm_v2_MatchingUeCondPerSubList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MatchingUeCondPerSubItem },
};

static int
dissect_kpm_v2_MatchingUeCondPerSubList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_MatchingUeCondPerSubList, MatchingUeCondPerSubList_sequence_of,
                                                  1, maxnoofConditionInfoPerSub, false);

  return offset;
}


static const per_sequence_t MatchingUEidPerSubItem_sequence[] = {
  { &hf_kpm_v2_ueID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_UEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_MatchingUEidPerSubItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_MatchingUEidPerSubItem, MatchingUEidPerSubItem_sequence);

  return offset;
}


static const per_sequence_t MatchingUEidPerSubList_sequence_of[1] = {
  { &hf_kpm_v2_MatchingUEidPerSubList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MatchingUEidPerSubItem },
};

static int
dissect_kpm_v2_MatchingUEidPerSubList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_MatchingUEidPerSubList, MatchingUEidPerSubList_sequence_of,
                                                  2, maxnoofUEIDPerSub, false);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationMessage_Format1_sequence[] = {
  { &hf_kpm_v2_measData     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementData },
  { &hf_kpm_v2_measInfoList , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_MeasurementInfoList },
  { &hf_kpm_v2_granulPeriod , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_GranularityPeriod },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_IndicationMessage_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_IndicationMessage_Format1, E2SM_KPM_IndicationMessage_Format1_sequence);

  return offset;
}


static const per_sequence_t UEMeasurementReportItem_sequence[] = {
  { &hf_kpm_v2_ueID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_UEID },
  { &hf_kpm_v2_measReport   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_E2SM_KPM_IndicationMessage_Format1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_UEMeasurementReportItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_UEMeasurementReportItem, UEMeasurementReportItem_sequence);

  return offset;
}


static const per_sequence_t UEMeasurementReportList_sequence_of[1] = {
  { &hf_kpm_v2_UEMeasurementReportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_UEMeasurementReportItem },
};

static int
dissect_kpm_v2_UEMeasurementReportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_UEMeasurementReportList, UEMeasurementReportList_sequence_of,
                                                  1, maxnoofUEMeasReport, false);

  return offset;
}



static int
dissect_kpm_v2_INTEGER_1_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t E2SM_KPM_EventTriggerDefinition_Format1_sequence[] = {
  { &hf_kpm_v2_reportingPeriod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_INTEGER_1_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_EventTriggerDefinition_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_EventTriggerDefinition_Format1, E2SM_KPM_EventTriggerDefinition_Format1_sequence);

  return offset;
}


static const value_string kpm_v2_T_eventDefinition_formats_vals[] = {
  {   0, "eventDefinition-Format1" },
  { 0, NULL }
};

static const per_choice_t T_eventDefinition_formats_choice[] = {
  {   0, &hf_kpm_v2_eventDefinition_Format1, ASN1_EXTENSION_ROOT    , dissect_kpm_v2_E2SM_KPM_EventTriggerDefinition_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_T_eventDefinition_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_T_eventDefinition_formats, T_eventDefinition_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_KPM_EventTriggerDefinition_sequence[] = {
  { &hf_kpm_v2_eventDefinition_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_T_eventDefinition_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_EventTriggerDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_EventTriggerDefinition, E2SM_KPM_EventTriggerDefinition_sequence);

  return offset;
}



static int
dissect_kpm_v2_RIC_Style_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_kpm_v2_NRCellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NR_CGI_sequence[] = {
  { &hf_kpm_v2_pLMNIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_PLMNIdentity },
  { &hf_kpm_v2_nRCellIdentity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_NRCellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_NR_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_NR_CGI, NR_CGI_sequence);

  return offset;
}



static int
dissect_kpm_v2_EUTRACellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t EUTRA_CGI_sequence[] = {
  { &hf_kpm_v2_pLMNIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_PLMNIdentity },
  { &hf_kpm_v2_eUTRACellIdentity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_EUTRACellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_EUTRA_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_EUTRA_CGI, EUTRA_CGI_sequence);

  return offset;
}


static const value_string kpm_v2_CGI_vals[] = {
  {   0, "nR-CGI" },
  {   1, "eUTRA-CGI" },
  { 0, NULL }
};

static const per_choice_t CGI_choice[] = {
  {   0, &hf_kpm_v2_nR_CGI       , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_NR_CGI },
  {   1, &hf_kpm_v2_eUTRA_CGI    , ASN1_EXTENSION_ROOT    , dissect_kpm_v2_EUTRA_CGI },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_CGI, CGI_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_KPM_ActionDefinition_Format1_sequence[] = {
  { &hf_kpm_v2_measInfoList , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementInfoList },
  { &hf_kpm_v2_granulPeriod , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_GranularityPeriod },
  { &hf_kpm_v2_cellGlobalID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_CGI },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_ActionDefinition_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_ActionDefinition_Format1, E2SM_KPM_ActionDefinition_Format1_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_ActionDefinition_Format2_sequence[] = {
  { &hf_kpm_v2_ueID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_UEID },
  { &hf_kpm_v2_subscriptInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_E2SM_KPM_ActionDefinition_Format1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_ActionDefinition_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_ActionDefinition_Format2, E2SM_KPM_ActionDefinition_Format2_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_ActionDefinition_Format3_sequence[] = {
  { &hf_kpm_v2_measCondList , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementCondList },
  { &hf_kpm_v2_granulPeriod , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_GranularityPeriod },
  { &hf_kpm_v2_cellGlobalID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_CGI },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_ActionDefinition_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_ActionDefinition_Format3, E2SM_KPM_ActionDefinition_Format3_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_ActionDefinition_Format4_sequence[] = {
  { &hf_kpm_v2_matchingUeCondList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MatchingUeCondPerSubList },
  { &hf_kpm_v2_subscriptionInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_E2SM_KPM_ActionDefinition_Format1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_ActionDefinition_Format4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_ActionDefinition_Format4, E2SM_KPM_ActionDefinition_Format4_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_ActionDefinition_Format5_sequence[] = {
  { &hf_kpm_v2_matchingUEidList_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MatchingUEidPerSubList },
  { &hf_kpm_v2_subscriptionInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_E2SM_KPM_ActionDefinition_Format1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_ActionDefinition_Format5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_ActionDefinition_Format5, E2SM_KPM_ActionDefinition_Format5_sequence);

  return offset;
}


static const value_string kpm_v2_T_actionDefinition_formats_vals[] = {
  {   0, "actionDefinition-Format1" },
  {   1, "actionDefinition-Format2" },
  {   2, "actionDefinition-Format3" },
  {   3, "actionDefinition-Format4" },
  {   4, "actionDefinition-Format5" },
  { 0, NULL }
};

static const per_choice_t T_actionDefinition_formats_choice[] = {
  {   0, &hf_kpm_v2_actionDefinition_Format1, ASN1_EXTENSION_ROOT    , dissect_kpm_v2_E2SM_KPM_ActionDefinition_Format1 },
  {   1, &hf_kpm_v2_actionDefinition_Format2, ASN1_EXTENSION_ROOT    , dissect_kpm_v2_E2SM_KPM_ActionDefinition_Format2 },
  {   2, &hf_kpm_v2_actionDefinition_Format3, ASN1_EXTENSION_ROOT    , dissect_kpm_v2_E2SM_KPM_ActionDefinition_Format3 },
  {   3, &hf_kpm_v2_actionDefinition_Format4, ASN1_NOT_EXTENSION_ROOT, dissect_kpm_v2_E2SM_KPM_ActionDefinition_Format4 },
  {   4, &hf_kpm_v2_actionDefinition_Format5, ASN1_NOT_EXTENSION_ROOT, dissect_kpm_v2_E2SM_KPM_ActionDefinition_Format5 },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_T_actionDefinition_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_T_actionDefinition_formats, T_actionDefinition_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_KPM_ActionDefinition_sequence[] = {
  { &hf_kpm_v2_ric_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_RIC_Style_Type },
  { &hf_kpm_v2_actionDefinition_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_T_actionDefinition_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_ActionDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_ActionDefinition, E2SM_KPM_ActionDefinition_sequence);

  return offset;
}



static int
dissect_kpm_v2_T_colletStartTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int ts_offset = offset;
    offset = dissect_kpm_v2_TimeStamp(tvb, offset, actx, tree, hf_index);

  /* Add as a generated field the timestamp decoded */
  const char *time_str = tvb_ntp_fmt_ts_sec(tvb, (ts_offset+7)/8);
  proto_item *ti = proto_tree_add_string(tree, hf_kpm_v2_timestamp_string, tvb, (ts_offset+7)/8, 4, time_str);
  proto_item_set_generated(ti);


  return offset;
}



static int
dissect_kpm_v2_PrintableString_SIZE_0_15_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          0, 15, true,
                                          NULL);

  return offset;
}



static int
dissect_kpm_v2_PrintableString_SIZE_0_400_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          0, 400, true,
                                          NULL);

  return offset;
}



static int
dissect_kpm_v2_PrintableString_SIZE_0_8_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          0, 8, true,
                                          NULL);

  return offset;
}



static int
dissect_kpm_v2_PrintableString_SIZE_0_32_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          0, 32, true,
                                          NULL);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationHeader_Format1_sequence[] = {
  { &hf_kpm_v2_colletStartTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_T_colletStartTime },
  { &hf_kpm_v2_fileFormatversion, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_PrintableString_SIZE_0_15_ },
  { &hf_kpm_v2_senderName   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_PrintableString_SIZE_0_400_ },
  { &hf_kpm_v2_senderType   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_PrintableString_SIZE_0_8_ },
  { &hf_kpm_v2_vendorName   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_PrintableString_SIZE_0_32_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_IndicationHeader_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_IndicationHeader_Format1, E2SM_KPM_IndicationHeader_Format1_sequence);

  return offset;
}


static const value_string kpm_v2_T_indicationHeader_formats_vals[] = {
  {   0, "indicationHeader-Format1" },
  { 0, NULL }
};

static const per_choice_t T_indicationHeader_formats_choice[] = {
  {   0, &hf_kpm_v2_indicationHeader_Format1, ASN1_EXTENSION_ROOT    , dissect_kpm_v2_E2SM_KPM_IndicationHeader_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_T_indicationHeader_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_T_indicationHeader_formats, T_indicationHeader_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationHeader_sequence[] = {
  { &hf_kpm_v2_indicationHeader_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_T_indicationHeader_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_IndicationHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_IndicationHeader, E2SM_KPM_IndicationHeader_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationMessage_Format2_sequence[] = {
  { &hf_kpm_v2_measData     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementData },
  { &hf_kpm_v2_measCondUEidList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementCondUEidList },
  { &hf_kpm_v2_granulPeriod , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_GranularityPeriod },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_IndicationMessage_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_IndicationMessage_Format2, E2SM_KPM_IndicationMessage_Format2_sequence);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationMessage_Format3_sequence[] = {
  { &hf_kpm_v2_ueMeasReportList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_UEMeasurementReportList },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_IndicationMessage_Format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_IndicationMessage_Format3, E2SM_KPM_IndicationMessage_Format3_sequence);

  return offset;
}


static const value_string kpm_v2_T_indicationMessage_formats_vals[] = {
  {   0, "indicationMessage-Format1" },
  {   1, "indicationMessage-Format2" },
  {   2, "indicationMessage-Format3" },
  { 0, NULL }
};

static const per_choice_t T_indicationMessage_formats_choice[] = {
  {   0, &hf_kpm_v2_indicationMessage_Format1, ASN1_EXTENSION_ROOT    , dissect_kpm_v2_E2SM_KPM_IndicationMessage_Format1 },
  {   1, &hf_kpm_v2_indicationMessage_Format2, ASN1_EXTENSION_ROOT    , dissect_kpm_v2_E2SM_KPM_IndicationMessage_Format2 },
  {   2, &hf_kpm_v2_indicationMessage_Format3, ASN1_NOT_EXTENSION_ROOT, dissect_kpm_v2_E2SM_KPM_IndicationMessage_Format3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_kpm_v2_T_indicationMessage_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_kpm_v2_T_indicationMessage_formats, T_indicationMessage_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_KPM_IndicationMessage_sequence[] = {
  { &hf_kpm_v2_indicationMessage_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_T_indicationMessage_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_IndicationMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_IndicationMessage, E2SM_KPM_IndicationMessage_sequence);

  return offset;
}



static int
dissect_kpm_v2_T_ranFunction_ShortName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_kpm_v2_T_ranFunction_E2SM_OID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_kpm_v2_PrintableString_SIZE_1_150_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}


static const per_sequence_t RANfunction_Name_sequence[] = {
  { &hf_kpm_v2_ranFunction_ShortName, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_T_ranFunction_ShortName },
  { &hf_kpm_v2_ranFunction_E2SM_OID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_T_ranFunction_E2SM_OID },
  { &hf_kpm_v2_ranFunction_Description, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_PrintableString_SIZE_1_150_ },
  { &hf_kpm_v2_ranFunction_Instance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_RANfunction_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_RANfunction_Name, RANfunction_Name_sequence);

  return offset;
}



static int
dissect_kpm_v2_RIC_Style_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_kpm_v2_RIC_Format_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t RIC_EventTriggerStyle_Item_sequence[] = {
  { &hf_kpm_v2_ric_EventTriggerStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_RIC_Style_Type },
  { &hf_kpm_v2_ric_EventTriggerStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_RIC_Style_Name },
  { &hf_kpm_v2_ric_EventTriggerFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_RIC_EventTriggerStyle_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_RIC_EventTriggerStyle_Item, RIC_EventTriggerStyle_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item_sequence_of[1] = {
  { &hf_kpm_v2_ric_EventTriggerStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_RIC_EventTriggerStyle_Item },
};

static int
dissect_kpm_v2_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RIC_ReportStyle_Item_sequence[] = {
  { &hf_kpm_v2_ric_ReportStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_RIC_Style_Type },
  { &hf_kpm_v2_ric_ReportStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_RIC_Style_Name },
  { &hf_kpm_v2_ric_ActionFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_RIC_Format_Type },
  { &hf_kpm_v2_measInfo_Action_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_MeasurementInfo_Action_List },
  { &hf_kpm_v2_ric_IndicationHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_RIC_Format_Type },
  { &hf_kpm_v2_ric_IndicationMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_RIC_ReportStyle_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_RIC_ReportStyle_Item, RIC_ReportStyle_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item_sequence_of[1] = {
  { &hf_kpm_v2_ric_ReportStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_kpm_v2_RIC_ReportStyle_Item },
};

static int
dissect_kpm_v2_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_kpm_v2_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t E2SM_KPM_RANfunction_Description_sequence[] = {
  { &hf_kpm_v2_ranFunction_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_kpm_v2_RANfunction_Name },
  { &hf_kpm_v2_ric_EventTriggerStyle_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item },
  { &hf_kpm_v2_ric_ReportStyle_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_kpm_v2_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_kpm_v2_E2SM_KPM_RANfunction_Description(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_kpm_v2_E2SM_KPM_RANfunction_Description, E2SM_KPM_RANfunction_Description_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_E2SM_KPM_EventTriggerDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_kpm_v2_E2SM_KPM_EventTriggerDefinition(tvb, offset, &asn1_ctx, tree, hf_kpm_v2_E2SM_KPM_EventTriggerDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_kpm_v2_E2SM_KPM_ActionDefinition(tvb, offset, &asn1_ctx, tree, hf_kpm_v2_E2SM_KPM_ActionDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_kpm_v2_E2SM_KPM_IndicationHeader(tvb, offset, &asn1_ctx, tree, hf_kpm_v2_E2SM_KPM_IndicationHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_kpm_v2_E2SM_KPM_IndicationMessage(tvb, offset, &asn1_ctx, tree, hf_kpm_v2_E2SM_KPM_IndicationMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_KPM_RANfunction_Description_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_kpm_v2_E2SM_KPM_RANfunction_Description(tvb, offset, &asn1_ctx, tree, hf_kpm_v2_E2SM_KPM_RANfunction_Description_PDU);
  offset += 7; offset >>= 3;
  return offset;
}



/*--- proto_reg_handoff_kpm_v2 ---------------------------------------*/
void
proto_reg_handoff_kpm_v2(void)
{
//#include "packet-kpm-v2-dis-tab.c"

    static ran_function_dissector_t kpm_v2 =
    { "ORAN-E2SM-KPM", "1.3.6.1.4.1.53148.1.2.2.2", 2, 2,
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

    /* Register dissector with e2ap */
    register_e2ap_ran_function_dissector(KPM_RANFUNCTIONS, &kpm_v2);
}



/*--- proto_register_kpm_v2 -------------------------------------------*/
void proto_register_kpm_v2(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_kpm_v2_E2SM_KPM_EventTriggerDefinition_PDU,
      { "E2SM-KPM-EventTriggerDefinition", "kpm-v2.E2SM_KPM_EventTriggerDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_E2SM_KPM_ActionDefinition_PDU,
      { "E2SM-KPM-ActionDefinition", "kpm-v2.E2SM_KPM_ActionDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_E2SM_KPM_IndicationHeader_PDU,
      { "E2SM-KPM-IndicationHeader", "kpm-v2.E2SM_KPM_IndicationHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_E2SM_KPM_IndicationMessage_PDU,
      { "E2SM-KPM-IndicationMessage", "kpm-v2.E2SM_KPM_IndicationMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_E2SM_KPM_RANfunction_Description_PDU,
      { "E2SM-KPM-RANfunction-Description", "kpm-v2.E2SM_KPM_RANfunction_Description_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_measName,
      { "measName", "kpm-v2.measName",
        FT_STRING, BASE_NONE, NULL, 0,
        "MeasurementTypeName", HFILL }},
    { &hf_kpm_v2_measID,
      { "measID", "kpm-v2.measID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementTypeID", HFILL }},
    { &hf_kpm_v2_noLabel,
      { "noLabel", "kpm-v2.noLabel",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_noLabel_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_plmnID,
      { "plmnID", "kpm-v2.plmnID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMNIdentity", HFILL }},
    { &hf_kpm_v2_sliceID,
      { "sliceID", "kpm-v2.sliceID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "S_NSSAI", HFILL }},
    { &hf_kpm_v2_fiveQI,
      { "fiveQI", "kpm-v2.fiveQI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_qFI,
      { "qFI", "kpm-v2.qFI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QosFlowIdentifier", HFILL }},
    { &hf_kpm_v2_qCI,
      { "qCI", "kpm-v2.qCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_qCImax,
      { "qCImax", "kpm-v2.qCImax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QCI", HFILL }},
    { &hf_kpm_v2_qCImin,
      { "qCImin", "kpm-v2.qCImin",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QCI", HFILL }},
    { &hf_kpm_v2_aRPmax,
      { "aRPmax", "kpm-v2.aRPmax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_15_", HFILL }},
    { &hf_kpm_v2_aRPmin,
      { "aRPmin", "kpm-v2.aRPmin",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_15_", HFILL }},
    { &hf_kpm_v2_bitrateRange,
      { "bitrateRange", "kpm-v2.bitrateRange",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_kpm_v2_layerMU_MIMO,
      { "layerMU-MIMO", "kpm-v2.layerMU_MIMO",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_kpm_v2_sUM,
      { "sUM", "kpm-v2.sUM",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_sUM_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_distBinX,
      { "distBinX", "kpm-v2.distBinX",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_kpm_v2_distBinY,
      { "distBinY", "kpm-v2.distBinY",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_kpm_v2_distBinZ,
      { "distBinZ", "kpm-v2.distBinZ",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535_", HFILL }},
    { &hf_kpm_v2_preLabelOverride,
      { "preLabelOverride", "kpm-v2.preLabelOverride",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_preLabelOverride_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_startEndInd,
      { "startEndInd", "kpm-v2.startEndInd",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_startEndInd_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_min,
      { "min", "kpm-v2.min",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_min_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_max,
      { "max", "kpm-v2.max",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_max_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_avg,
      { "avg", "kpm-v2.avg",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_avg_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_testType,
      { "testType", "kpm-v2.testType",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_TestCond_Type_vals), 0,
        "TestCond_Type", HFILL }},
    { &hf_kpm_v2_testExpr,
      { "testExpr", "kpm-v2.testExpr",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_TestCond_Expression_vals), 0,
        "TestCond_Expression", HFILL }},
    { &hf_kpm_v2_testValue,
      { "testValue", "kpm-v2.testValue",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_TestCond_Value_vals), 0,
        "TestCond_Value", HFILL }},
    { &hf_kpm_v2_gBR,
      { "gBR", "kpm-v2.gBR",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_gBR_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_aMBR,
      { "aMBR", "kpm-v2.aMBR",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_aMBR_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_isStat,
      { "isStat", "kpm-v2.isStat",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_isStat_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_isCatM,
      { "isCatM", "kpm-v2.isCatM",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_isCatM_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_rSRP,
      { "rSRP", "kpm-v2.rSRP",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_rSRP_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_rSRQ,
      { "rSRQ", "kpm-v2.rSRQ",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_rSRQ_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_ul_rSRP,
      { "ul-rSRP", "kpm-v2.ul_rSRP",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_ul_rSRP_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_cQI,
      { "cQI", "kpm-v2.cQI",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_cQI_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_fiveQI_01,
      { "fiveQI", "kpm-v2.fiveQI",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_fiveQI_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_qCI_01,
      { "qCI", "kpm-v2.qCI",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_qCI_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_sNSSAI,
      { "sNSSAI", "kpm-v2.sNSSAI",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_sNSSAI_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_valueInt,
      { "valueInt", "kpm-v2.valueInt",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_kpm_v2_valueEnum,
      { "valueEnum", "kpm-v2.valueEnum",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_kpm_v2_valueBool,
      { "valueBool", "kpm-v2.valueBool",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_kpm_v2_valueBitS,
      { "valueBitS", "kpm-v2.valueBitS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_kpm_v2_valueOctS,
      { "valueOctS", "kpm-v2.valueOctS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_kpm_v2_valuePrtS,
      { "valuePrtS", "kpm-v2.valuePrtS",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_kpm_v2_valueReal,
      { "valueReal", "kpm-v2.valueReal",
        FT_DOUBLE, BASE_NONE, NULL, 0,
        "REAL", HFILL }},
    { &hf_kpm_v2_MeasurementInfoList_item,
      { "MeasurementInfoItem", "kpm-v2.MeasurementInfoItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_measType,
      { "measType", "kpm-v2.measType",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_MeasurementType_vals), 0,
        "MeasurementType", HFILL }},
    { &hf_kpm_v2_labelInfoList,
      { "labelInfoList", "kpm-v2.labelInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_LabelInfoList_item,
      { "LabelInfoItem", "kpm-v2.LabelInfoItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_measLabel,
      { "measLabel", "kpm-v2.measLabel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MeasurementLabel", HFILL }},
    { &hf_kpm_v2_MeasurementData_item,
      { "MeasurementDataItem", "kpm-v2.MeasurementDataItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_measRecord,
      { "measRecord", "kpm-v2.measRecord",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementRecord", HFILL }},
    { &hf_kpm_v2_incompleteFlag,
      { "incompleteFlag", "kpm-v2.incompleteFlag",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_incompleteFlag_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_MeasurementRecord_item,
      { "MeasurementRecordItem", "kpm-v2.MeasurementRecordItem",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_MeasurementRecordItem_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_integer,
      { "integer", "kpm-v2.integer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_kpm_v2_real,
      { "real", "kpm-v2.real",
        FT_DOUBLE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_noValue,
      { "noValue", "kpm-v2.noValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_MeasurementInfo_Action_List_item,
      { "MeasurementInfo-Action-Item", "kpm-v2.MeasurementInfo_Action_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_MeasurementCondList_item,
      { "MeasurementCondItem", "kpm-v2.MeasurementCondItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_matchingCond,
      { "matchingCond", "kpm-v2.matchingCond",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MatchingCondList", HFILL }},
    { &hf_kpm_v2_MeasurementCondUEidList_item,
      { "MeasurementCondUEidItem", "kpm-v2.MeasurementCondUEidItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_matchingUEidList,
      { "matchingUEidList", "kpm-v2.matchingUEidList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_MatchingCondList_item,
      { "MatchingCondItem", "kpm-v2.MatchingCondItem",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_MatchingCondItem_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_testCondInfo,
      { "testCondInfo", "kpm-v2.testCondInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_MatchingUEidList_item,
      { "MatchingUEidItem", "kpm-v2.MatchingUEidItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_ueID,
      { "ueID", "kpm-v2.ueID",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_UEID_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_MatchingUeCondPerSubList_item,
      { "MatchingUeCondPerSubItem", "kpm-v2.MatchingUeCondPerSubItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_MatchingUEidPerSubList_item,
      { "MatchingUEidPerSubItem", "kpm-v2.MatchingUEidPerSubItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_UEMeasurementReportList_item,
      { "UEMeasurementReportItem", "kpm-v2.UEMeasurementReportItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_measReport,
      { "measReport", "kpm-v2.measReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_IndicationMessage_Format1", HFILL }},
    { &hf_kpm_v2_eventDefinition_formats,
      { "eventDefinition-formats", "kpm-v2.eventDefinition_formats",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_eventDefinition_formats_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_eventDefinition_Format1,
      { "eventDefinition-Format1", "kpm-v2.eventDefinition_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_EventTriggerDefinition_Format1", HFILL }},
    { &hf_kpm_v2_reportingPeriod,
      { "reportingPeriod", "kpm-v2.reportingPeriod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4294967295", HFILL }},
    { &hf_kpm_v2_ric_Style_Type,
      { "ric-Style-Type", "kpm-v2.ric_Style_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_actionDefinition_formats,
      { "actionDefinition-formats", "kpm-v2.actionDefinition_formats",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_actionDefinition_formats_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_actionDefinition_Format1,
      { "actionDefinition-Format1", "kpm-v2.actionDefinition_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format1", HFILL }},
    { &hf_kpm_v2_actionDefinition_Format2,
      { "actionDefinition-Format2", "kpm-v2.actionDefinition_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format2", HFILL }},
    { &hf_kpm_v2_actionDefinition_Format3,
      { "actionDefinition-Format3", "kpm-v2.actionDefinition_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format3", HFILL }},
    { &hf_kpm_v2_actionDefinition_Format4,
      { "actionDefinition-Format4", "kpm-v2.actionDefinition_Format4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format4", HFILL }},
    { &hf_kpm_v2_actionDefinition_Format5,
      { "actionDefinition-Format5", "kpm-v2.actionDefinition_Format5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format5", HFILL }},
    { &hf_kpm_v2_measInfoList,
      { "measInfoList", "kpm-v2.measInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementInfoList", HFILL }},
    { &hf_kpm_v2_granulPeriod,
      { "granulPeriod", "kpm-v2.granulPeriod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GranularityPeriod", HFILL }},
    { &hf_kpm_v2_cellGlobalID,
      { "cellGlobalID", "kpm-v2.cellGlobalID",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_CGI_vals), 0,
        "CGI", HFILL }},
    { &hf_kpm_v2_subscriptInfo,
      { "subscriptInfo", "kpm-v2.subscriptInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format1", HFILL }},
    { &hf_kpm_v2_measCondList,
      { "measCondList", "kpm-v2.measCondList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementCondList", HFILL }},
    { &hf_kpm_v2_matchingUeCondList,
      { "matchingUeCondList", "kpm-v2.matchingUeCondList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MatchingUeCondPerSubList", HFILL }},
    { &hf_kpm_v2_subscriptionInfo,
      { "subscriptionInfo", "kpm-v2.subscriptionInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_ActionDefinition_Format1", HFILL }},
    { &hf_kpm_v2_matchingUEidList_01,
      { "matchingUEidList", "kpm-v2.matchingUEidList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MatchingUEidPerSubList", HFILL }},
    { &hf_kpm_v2_indicationHeader_formats,
      { "indicationHeader-formats", "kpm-v2.indicationHeader_formats",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_indicationHeader_formats_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_indicationHeader_Format1,
      { "indicationHeader-Format1", "kpm-v2.indicationHeader_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_IndicationHeader_Format1", HFILL }},
    { &hf_kpm_v2_colletStartTime,
      { "colletStartTime", "kpm-v2.colletStartTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_fileFormatversion,
      { "fileFormatversion", "kpm-v2.fileFormatversion",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_0_15_", HFILL }},
    { &hf_kpm_v2_senderName,
      { "senderName", "kpm-v2.senderName",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_0_400_", HFILL }},
    { &hf_kpm_v2_senderType,
      { "senderType", "kpm-v2.senderType",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_0_8_", HFILL }},
    { &hf_kpm_v2_vendorName,
      { "vendorName", "kpm-v2.vendorName",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_0_32_", HFILL }},
    { &hf_kpm_v2_indicationMessage_formats,
      { "indicationMessage-formats", "kpm-v2.indicationMessage_formats",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_T_indicationMessage_formats_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_indicationMessage_Format1,
      { "indicationMessage-Format1", "kpm-v2.indicationMessage_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_IndicationMessage_Format1", HFILL }},
    { &hf_kpm_v2_indicationMessage_Format2,
      { "indicationMessage-Format2", "kpm-v2.indicationMessage_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_IndicationMessage_Format2", HFILL }},
    { &hf_kpm_v2_indicationMessage_Format3,
      { "indicationMessage-Format3", "kpm-v2.indicationMessage_Format3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_KPM_IndicationMessage_Format3", HFILL }},
    { &hf_kpm_v2_measData,
      { "measData", "kpm-v2.measData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementData", HFILL }},
    { &hf_kpm_v2_measCondUEidList,
      { "measCondUEidList", "kpm-v2.measCondUEidList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementCondUEidList", HFILL }},
    { &hf_kpm_v2_ueMeasReportList,
      { "ueMeasReportList", "kpm-v2.ueMeasReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UEMeasurementReportList", HFILL }},
    { &hf_kpm_v2_ranFunction_Name,
      { "ranFunction-Name", "kpm-v2.ranFunction_Name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_ric_EventTriggerStyle_List,
      { "ric-EventTriggerStyle-List", "kpm-v2.ric_EventTriggerStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item", HFILL }},
    { &hf_kpm_v2_ric_EventTriggerStyle_List_item,
      { "RIC-EventTriggerStyle-Item", "kpm-v2.RIC_EventTriggerStyle_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_ric_ReportStyle_List,
      { "ric-ReportStyle-List", "kpm-v2.ric_ReportStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item", HFILL }},
    { &hf_kpm_v2_ric_ReportStyle_List_item,
      { "RIC-ReportStyle-Item", "kpm-v2.RIC_ReportStyle_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_ric_EventTriggerStyle_Type,
      { "ric-EventTriggerStyle-Type", "kpm-v2.ric_EventTriggerStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_kpm_v2_ric_EventTriggerStyle_Name,
      { "ric-EventTriggerStyle-Name", "kpm-v2.ric_EventTriggerStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_kpm_v2_ric_EventTriggerFormat_Type,
      { "ric-EventTriggerFormat-Type", "kpm-v2.ric_EventTriggerFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_kpm_v2_ric_ReportStyle_Type,
      { "ric-ReportStyle-Type", "kpm-v2.ric_ReportStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_kpm_v2_ric_ReportStyle_Name,
      { "ric-ReportStyle-Name", "kpm-v2.ric_ReportStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_kpm_v2_ric_ActionFormat_Type,
      { "ric-ActionFormat-Type", "kpm-v2.ric_ActionFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_kpm_v2_measInfo_Action_List,
      { "measInfo-Action-List", "kpm-v2.measInfo_Action_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasurementInfo_Action_List", HFILL }},
    { &hf_kpm_v2_ric_IndicationHeaderFormat_Type,
      { "ric-IndicationHeaderFormat-Type", "kpm-v2.ric_IndicationHeaderFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_kpm_v2_ric_IndicationMessageFormat_Type,
      { "ric-IndicationMessageFormat-Type", "kpm-v2.ric_IndicationMessageFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_kpm_v2_nR_CGI,
      { "nR-CGI", "kpm-v2.nR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_eUTRA_CGI,
      { "eUTRA-CGI", "kpm-v2.eUTRA_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_ranFunction_ShortName,
      { "ranFunction-ShortName", "kpm-v2.ranFunction_ShortName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_ranFunction_E2SM_OID,
      { "ranFunction-E2SM-OID", "kpm-v2.ranFunction_E2SM_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_ranFunction_Description,
      { "ranFunction-Description", "kpm-v2.ranFunction_Description",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_150_", HFILL }},
    { &hf_kpm_v2_ranFunction_Instance,
      { "ranFunction-Instance", "kpm-v2.ranFunction_Instance",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_kpm_v2_gNB_UEID,
      { "gNB-UEID", "kpm-v2.gNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_GNB", HFILL }},
    { &hf_kpm_v2_gNB_DU_UEID,
      { "gNB-DU-UEID", "kpm-v2.gNB_DU_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_GNB_DU", HFILL }},
    { &hf_kpm_v2_gNB_CU_UP_UEID,
      { "gNB-CU-UP-UEID", "kpm-v2.gNB_CU_UP_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_GNB_CU_UP", HFILL }},
    { &hf_kpm_v2_ng_eNB_UEID,
      { "ng-eNB-UEID", "kpm-v2.ng_eNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_NG_ENB", HFILL }},
    { &hf_kpm_v2_ng_eNB_DU_UEID,
      { "ng-eNB-DU-UEID", "kpm-v2.ng_eNB_DU_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_NG_ENB_DU", HFILL }},
    { &hf_kpm_v2_en_gNB_UEID,
      { "en-gNB-UEID", "kpm-v2.en_gNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_EN_GNB", HFILL }},
    { &hf_kpm_v2_eNB_UEID,
      { "eNB-UEID", "kpm-v2.eNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_ENB", HFILL }},
    { &hf_kpm_v2_amf_UE_NGAP_ID,
      { "amf-UE-NGAP-ID", "kpm-v2.amf_UE_NGAP_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_guami,
      { "guami", "kpm-v2.guami_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_gNB_CU_UE_F1AP_ID_List,
      { "gNB-CU-UE-F1AP-ID-List", "kpm-v2.gNB_CU_UE_F1AP_ID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UEID_GNB_CU_F1AP_ID_List", HFILL }},
    { &hf_kpm_v2_gNB_CU_CP_UE_E1AP_ID_List,
      { "gNB-CU-CP-UE-E1AP-ID-List", "kpm-v2.gNB_CU_CP_UE_E1AP_ID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UEID_GNB_CU_CP_E1AP_ID_List", HFILL }},
    { &hf_kpm_v2_ran_UEID,
      { "ran-UEID", "kpm-v2.ran_UEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RANUEID", HFILL }},
    { &hf_kpm_v2_m_NG_RAN_UE_XnAP_ID,
      { "m-NG-RAN-UE-XnAP-ID", "kpm-v2.m_NG_RAN_UE_XnAP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NG_RANnodeUEXnAPID", HFILL }},
    { &hf_kpm_v2_globalGNB_ID,
      { "globalGNB-ID", "kpm-v2.globalGNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_globalNG_RANNode_ID,
      { "globalNG-RANNode-ID", "kpm-v2.globalNG_RANNode_ID",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_GlobalNGRANNodeID_vals), 0,
        "GlobalNGRANNodeID", HFILL }},
    { &hf_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_List_item,
      { "UEID-GNB-CU-CP-E1AP-ID-Item", "kpm-v2.UEID_GNB_CU_CP_E1AP_ID_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_gNB_CU_CP_UE_E1AP_ID,
      { "gNB-CU-CP-UE-E1AP-ID", "kpm-v2.gNB_CU_CP_UE_E1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_UEID_GNB_CU_F1AP_ID_List_item,
      { "UEID-GNB-CU-CP-F1AP-ID-Item", "kpm-v2.UEID_GNB_CU_CP_F1AP_ID_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_gNB_CU_UE_F1AP_ID,
      { "gNB-CU-UE-F1AP-ID", "kpm-v2.gNB_CU_UE_F1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_ng_eNB_CU_UE_W1AP_ID,
      { "ng-eNB-CU-UE-W1AP-ID", "kpm-v2.ng_eNB_CU_UE_W1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NGENB_CU_UE_W1AP_ID", HFILL }},
    { &hf_kpm_v2_globalNgENB_ID,
      { "globalNgENB-ID", "kpm-v2.globalNgENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_m_eNB_UE_X2AP_ID,
      { "m-eNB-UE-X2AP-ID", "kpm-v2.m_eNB_UE_X2AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ENB_UE_X2AP_ID", HFILL }},
    { &hf_kpm_v2_m_eNB_UE_X2AP_ID_Extension,
      { "m-eNB-UE-X2AP-ID-Extension", "kpm-v2.m_eNB_UE_X2AP_ID_Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ENB_UE_X2AP_ID_Extension", HFILL }},
    { &hf_kpm_v2_globalENB_ID,
      { "globalENB-ID", "kpm-v2.globalENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_mME_UE_S1AP_ID,
      { "mME-UE-S1AP-ID", "kpm-v2.mME_UE_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_gUMMEI,
      { "gUMMEI", "kpm-v2.gUMMEI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_macro_eNB_ID,
      { "macro-eNB-ID", "kpm-v2.macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_kpm_v2_home_eNB_ID,
      { "home-eNB-ID", "kpm-v2.home_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_28", HFILL }},
    { &hf_kpm_v2_short_Macro_eNB_ID,
      { "short-Macro-eNB-ID", "kpm-v2.short_Macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_kpm_v2_long_Macro_eNB_ID,
      { "long-Macro-eNB-ID", "kpm-v2.long_Macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_kpm_v2_pLMNIdentity,
      { "pLMNIdentity", "kpm-v2.pLMNIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_eNB_ID,
      { "eNB-ID", "kpm-v2.eNB_ID",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_ENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_pLMN_Identity,
      { "pLMN-Identity", "kpm-v2.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMNIdentity", HFILL }},
    { &hf_kpm_v2_mME_Group_ID,
      { "mME-Group-ID", "kpm-v2.mME_Group_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_mME_Code,
      { "mME-Code", "kpm-v2.mME_Code",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_eUTRACellIdentity,
      { "eUTRACellIdentity", "kpm-v2.eUTRACellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_gNB_ID,
      { "gNB-ID", "kpm-v2.gNB_ID",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_GNB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_ngENB_ID,
      { "ngENB-ID", "kpm-v2.ngENB_ID",
        FT_UINT32, BASE_DEC, VALS(kpm_v2_NgENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_kpm_v2_gNB_ID_01,
      { "gNB-ID", "kpm-v2.gNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22_32", HFILL }},
    { &hf_kpm_v2_aMFRegionID,
      { "aMFRegionID", "kpm-v2.aMFRegionID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_aMFSetID,
      { "aMFSetID", "kpm-v2.aMFSetID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_aMFPointer,
      { "aMFPointer", "kpm-v2.aMFPointer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_macroNgENB_ID,
      { "macroNgENB-ID", "kpm-v2.macroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_kpm_v2_shortMacroNgENB_ID,
      { "shortMacroNgENB-ID", "kpm-v2.shortMacroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_kpm_v2_longMacroNgENB_ID,
      { "longMacroNgENB-ID", "kpm-v2.longMacroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_kpm_v2_nRCellIdentity,
      { "nRCellIdentity", "kpm-v2.nRCellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_sST,
      { "sST", "kpm-v2.sST",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_sD,
      { "sD", "kpm-v2.sD",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kpm_v2_gNB,
      { "gNB", "kpm-v2.gNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalGNB_ID", HFILL }},
    { &hf_kpm_v2_ng_eNB,
      { "ng-eNB", "kpm-v2.ng_eNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalNgENB_ID", HFILL }},
      { &hf_kpm_v2_timestamp_string,
          { "Timestamp string", "kpm-v2.timestamp-string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_kpm_v2_MeasurementType,
    &ett_kpm_v2_MeasurementLabel,
    &ett_kpm_v2_TestCondInfo,
    &ett_kpm_v2_TestCond_Type,
    &ett_kpm_v2_TestCond_Value,
    &ett_kpm_v2_MeasurementInfoList,
    &ett_kpm_v2_MeasurementInfoItem,
    &ett_kpm_v2_LabelInfoList,
    &ett_kpm_v2_LabelInfoItem,
    &ett_kpm_v2_MeasurementData,
    &ett_kpm_v2_MeasurementDataItem,
    &ett_kpm_v2_MeasurementRecord,
    &ett_kpm_v2_MeasurementRecordItem,
    &ett_kpm_v2_MeasurementInfo_Action_List,
    &ett_kpm_v2_MeasurementInfo_Action_Item,
    &ett_kpm_v2_MeasurementCondList,
    &ett_kpm_v2_MeasurementCondItem,
    &ett_kpm_v2_MeasurementCondUEidList,
    &ett_kpm_v2_MeasurementCondUEidItem,
    &ett_kpm_v2_MatchingCondList,
    &ett_kpm_v2_MatchingCondItem,
    &ett_kpm_v2_MatchingUEidList,
    &ett_kpm_v2_MatchingUEidItem,
    &ett_kpm_v2_MatchingUeCondPerSubList,
    &ett_kpm_v2_MatchingUeCondPerSubItem,
    &ett_kpm_v2_MatchingUEidPerSubList,
    &ett_kpm_v2_MatchingUEidPerSubItem,
    &ett_kpm_v2_UEMeasurementReportList,
    &ett_kpm_v2_UEMeasurementReportItem,
    &ett_kpm_v2_E2SM_KPM_EventTriggerDefinition,
    &ett_kpm_v2_T_eventDefinition_formats,
    &ett_kpm_v2_E2SM_KPM_EventTriggerDefinition_Format1,
    &ett_kpm_v2_E2SM_KPM_ActionDefinition,
    &ett_kpm_v2_T_actionDefinition_formats,
    &ett_kpm_v2_E2SM_KPM_ActionDefinition_Format1,
    &ett_kpm_v2_E2SM_KPM_ActionDefinition_Format2,
    &ett_kpm_v2_E2SM_KPM_ActionDefinition_Format3,
    &ett_kpm_v2_E2SM_KPM_ActionDefinition_Format4,
    &ett_kpm_v2_E2SM_KPM_ActionDefinition_Format5,
    &ett_kpm_v2_E2SM_KPM_IndicationHeader,
    &ett_kpm_v2_T_indicationHeader_formats,
    &ett_kpm_v2_E2SM_KPM_IndicationHeader_Format1,
    &ett_kpm_v2_E2SM_KPM_IndicationMessage,
    &ett_kpm_v2_T_indicationMessage_formats,
    &ett_kpm_v2_E2SM_KPM_IndicationMessage_Format1,
    &ett_kpm_v2_E2SM_KPM_IndicationMessage_Format2,
    &ett_kpm_v2_E2SM_KPM_IndicationMessage_Format3,
    &ett_kpm_v2_E2SM_KPM_RANfunction_Description,
    &ett_kpm_v2_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_EventTriggerStyle_Item,
    &ett_kpm_v2_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RIC_ReportStyle_Item,
    &ett_kpm_v2_RIC_EventTriggerStyle_Item,
    &ett_kpm_v2_RIC_ReportStyle_Item,
    &ett_kpm_v2_CGI,
    &ett_kpm_v2_RANfunction_Name,
    &ett_kpm_v2_UEID,
    &ett_kpm_v2_UEID_GNB,
    &ett_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_List,
    &ett_kpm_v2_UEID_GNB_CU_CP_E1AP_ID_Item,
    &ett_kpm_v2_UEID_GNB_CU_F1AP_ID_List,
    &ett_kpm_v2_UEID_GNB_CU_CP_F1AP_ID_Item,
    &ett_kpm_v2_UEID_GNB_DU,
    &ett_kpm_v2_UEID_GNB_CU_UP,
    &ett_kpm_v2_UEID_NG_ENB,
    &ett_kpm_v2_UEID_NG_ENB_DU,
    &ett_kpm_v2_UEID_EN_GNB,
    &ett_kpm_v2_UEID_ENB,
    &ett_kpm_v2_ENB_ID,
    &ett_kpm_v2_GlobalENB_ID,
    &ett_kpm_v2_GUMMEI,
    &ett_kpm_v2_EUTRA_CGI,
    &ett_kpm_v2_GlobalGNB_ID,
    &ett_kpm_v2_GlobalNgENB_ID,
    &ett_kpm_v2_GNB_ID,
    &ett_kpm_v2_GUAMI,
    &ett_kpm_v2_NgENB_ID,
    &ett_kpm_v2_NR_CGI,
    &ett_kpm_v2_S_NSSAI,
    &ett_kpm_v2_GlobalNGRANNodeID,
  };


  /* Register protocol */
  proto_kpm_v2 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_kpm_v2, hf, array_length(hf));
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
