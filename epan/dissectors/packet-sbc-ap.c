/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-sbc-ap.c                                                            */
/* asn2wrs.py -q -L -p sbc-ap -c ./sbc-ap.cnf -s ./packet-sbc-ap-template -D . -O ../.. SBC-AP-CommonDataTypes.asn SBC-AP-Constants.asn SBC-AP-Containers.asn SBC-AP-IEs.asn SBC-AP-PDU-Contents.asn SBC-AP-PDU-Descriptions.asn */

/* packet-sbc-ap.c
 * Routines for SBc Application Part (SBc-AP) packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref 3GPP TS 29.168
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/sctpppids.h>
#include <epan/proto_data.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-gsm_map.h"
#include "packet-s1ap.h"
#include "packet-lte-rrc.h"

#define PNAME  "SBc Application Part"
#define PSNAME "SBcAP"
#define PFNAME "sbcap"

void proto_register_sbc_ap(void);
void proto_reg_handoff_sbc_ap(void);

/* The registered port number for SBc-AP is 29168.
 * The registered payload protocol identifier for SBc-AP is 24.
 */
#define SBC_AP_PORT 29168
static dissector_handle_t sbc_ap_handle;


#define maxNrOfErrors                  256
#define maxnoofCellID                  65535
#define maxnoofCellinEAI               65535
#define maxnoofCellinTAI               65535
#define maxNrOfTAIs                    65535
#define maxnoofEmergencyAreaID         65535
#define maxnoofTAIforWarning           65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxnoofeNBIds                  256
#define maxnoofRestartedCells          256
#define maxnoofRestartTAIs             2048
#define maxnoofRestartEAIs             256
#define maxnoofFailedCells             256
#define maxnoof5GSTAIs                 2048
#define maxnoofCellsingNB              16384
#define maxnoofCellsin5GS              16776960
#define maxnoofCellsin5GSTAI           65535
#define maxnoofRANNodes                65535
#define maxnoofRestart5GSTAIs          2048
#define maxnoofCellsforRestartNR       16384

typedef enum _ProcedureCode_enum {
  id_Write_Replace_Warning =   0,
  id_Stop_Warning =   1,
  id_Error_Indication =   2,
  id_Write_Replace_Warning_Indication =   3,
  id_Stop_Warning_Indication =   4,
  id_PWS_Restart_Indication =   5,
  id_PWS_Failure_Indication =   6
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_Broadcast_Message_Content =   0,
  id_Cause     =   1,
  id_Criticality_Diagnostics =   2,
  id_Data_Coding_Scheme =   3,
  id_Failure_List =   4,
  id_Message_Identifier =   5,
  id_Number_of_Broadcasts_Completed_List =   6,
  id_Number_of_Broadcasts_Requested =   7,
  id_Radio_Resource_Loading_List =   8,
  id_Recovery_Indication =   9,
  id_Repetition_Period =  10,
  id_Serial_Number =  11,
  id_Service_Areas_List =  12,
  id_TypeOfError =  13,
  id_List_of_TAIs =  14,
  id_Warning_Area_List =  15,
  id_Warning_Message_Content =  16,
  id_Warning_Security_Information =  17,
  id_Warning_Type =  18,
  id_Omc_Id    =  19,
  id_Concurrent_Warning_Message_Indicator =  20,
  id_Extended_Repetition_Period =  21,
  id_Unknown_Tracking_Area_List =  22,
  id_Broadcast_Scheduled_Area_List =  23,
  id_Send_Write_Replace_Warning_Indication =  24,
  id_Broadcast_Cancelled_Area_List =  25,
  id_Send_Stop_Warning_Indication =  26,
  id_Stop_All_Indicator =  27,
  id_Global_ENB_ID =  28,
  id_Broadcast_Empty_Area_List =  29,
  id_Restarted_Cell_List =  30,
  id_List_of_TAIs_Restart =  31,
  id_List_of_EAIs_Restart =  32,
  id_Failed_Cell_List =  33,
  id_List_of_5GS_TAIs =  34,
  id_Warning_Area_List_5GS =  35,
  id_Global_RAN_Node_ID =  36,
  id_Global_GNB_ID =  37,
  id_RAT_Selector_5GS =  38,
  id_Unknown_5GS_Tracking_Area_List =  39,
  id_Broadcast_Scheduled_Area_List_5GS =  40,
  id_Broadcast_Cancelled_Area_List_5GS =  41,
  id_Broadcast_Empty_Area_List_5GS =  42,
  id_Restarted_Cell_List_NR =  43,
  id_Failed_Cell_List_NR =  44,
  id_List_of_5GS_TAI_for_Restart =  45,
  id_Warning_Area_Coordinates =  46
} ProtocolIE_ID_enum;

/* Initialize the protocol and registered fields */
static int proto_sbc_ap;

static int hf_sbc_ap_Serial_Number_gs;
static int hf_sbc_ap_Serial_Number_msg_code;
static int hf_sbc_ap_Serial_Number_upd_nb;
static int hf_sbc_ap_Warning_Type_value;
static int hf_sbc_ap_Warning_Type_emergency_user_alert;
static int hf_sbc_ap_Warning_Type_popup;
static int hf_sbc_ap_Warning_Message_Contents_nb_pages;
static int hf_sbc_ap_Warning_Message_Contents_decoded_page;
static int hf_sbc_ap_Broadcast_Scheduled_Area_List_PDU;  /* Broadcast_Scheduled_Area_List */
static int hf_sbc_ap_Broadcast_Scheduled_Area_List_5GS_PDU;  /* Broadcast_Scheduled_Area_List_5GS */
static int hf_sbc_ap_Broadcast_Cancelled_Area_List_PDU;  /* Broadcast_Cancelled_Area_List */
static int hf_sbc_ap_Broadcast_Cancelled_Area_List_5GS_PDU;  /* Broadcast_Cancelled_Area_List_5GS */
static int hf_sbc_ap_Broadcast_Empty_Area_List_PDU;  /* Broadcast_Empty_Area_List */
static int hf_sbc_ap_Broadcast_Empty_Area_List_5GS_PDU;  /* Broadcast_Empty_Area_List_5GS */
static int hf_sbc_ap_Cause_PDU;                   /* Cause */
static int hf_sbc_ap_Concurrent_Warning_Message_Indicator_PDU;  /* Concurrent_Warning_Message_Indicator */
static int hf_sbc_ap_Criticality_Diagnostics_PDU;  /* Criticality_Diagnostics */
static int hf_sbc_ap_Data_Coding_Scheme_PDU;      /* Data_Coding_Scheme */
static int hf_sbc_ap_Extended_Repetition_Period_PDU;  /* Extended_Repetition_Period */
static int hf_sbc_ap_Failed_Cell_List_PDU;        /* Failed_Cell_List */
static int hf_sbc_ap_Failed_Cell_List_NR_PDU;     /* Failed_Cell_List_NR */
static int hf_sbc_ap_Global_ENB_ID_PDU;           /* Global_ENB_ID */
static int hf_sbc_ap_Global_RAN_Node_ID_PDU;      /* Global_RAN_Node_ID */
static int hf_sbc_ap_Global_GNB_ID_PDU;           /* Global_GNB_ID */
static int hf_sbc_ap_List_of_TAIs_PDU;            /* List_of_TAIs */
static int hf_sbc_ap_List_of_TAIs_Restart_PDU;    /* List_of_TAIs_Restart */
static int hf_sbc_ap_List_of_EAIs_Restart_PDU;    /* List_of_EAIs_Restart */
static int hf_sbc_ap_List_of_5GS_TAIs_PDU;        /* List_of_5GS_TAIs */
static int hf_sbc_ap_List_of_5GS_TAI_for_Restart_PDU;  /* List_of_5GS_TAI_for_Restart */
static int hf_sbc_ap_Message_Identifier_PDU;      /* Message_Identifier */
static int hf_sbc_ap_Number_of_Broadcasts_Requested_PDU;  /* Number_of_Broadcasts_Requested */
static int hf_sbc_ap_Omc_Id_PDU;                  /* Omc_Id */
static int hf_sbc_ap_Repetition_Period_PDU;       /* Repetition_Period */
static int hf_sbc_ap_Restarted_Cell_List_PDU;     /* Restarted_Cell_List */
static int hf_sbc_ap_RAT_Selector_5GS_PDU;        /* RAT_Selector_5GS */
static int hf_sbc_ap_Restarted_Cell_List_NR_PDU;  /* Restarted_Cell_List_NR */
static int hf_sbc_ap_Send_Write_Replace_Warning_Indication_PDU;  /* Send_Write_Replace_Warning_Indication */
static int hf_sbc_ap_Send_Stop_Warning_Indication_PDU;  /* Send_Stop_Warning_Indication */
static int hf_sbc_ap_Serial_Number_PDU;           /* Serial_Number */
static int hf_sbc_ap_Stop_All_Indicator_PDU;      /* Stop_All_Indicator */
static int hf_sbc_ap_Unknown_5GS_Tracking_Area_List_PDU;  /* Unknown_5GS_Tracking_Area_List */
static int hf_sbc_ap_Warning_Area_List_PDU;       /* Warning_Area_List */
static int hf_sbc_ap_Warning_Message_Content_PDU;  /* Warning_Message_Content */
static int hf_sbc_ap_Warning_Area_Coordinates_PDU;  /* Warning_Area_Coordinates */
static int hf_sbc_ap_Warning_Security_Information_PDU;  /* Warning_Security_Information */
static int hf_sbc_ap_Warning_Type_PDU;            /* Warning_Type */
static int hf_sbc_ap_Warning_Area_List_5GS_PDU;   /* Warning_Area_List_5GS */
static int hf_sbc_ap_Write_Replace_Warning_Request_PDU;  /* Write_Replace_Warning_Request */
static int hf_sbc_ap_Write_Replace_Warning_Response_PDU;  /* Write_Replace_Warning_Response */
static int hf_sbc_ap_Stop_Warning_Request_PDU;    /* Stop_Warning_Request */
static int hf_sbc_ap_Stop_Warning_Response_PDU;   /* Stop_Warning_Response */
static int hf_sbc_ap_Write_Replace_Warning_Indication_PDU;  /* Write_Replace_Warning_Indication */
static int hf_sbc_ap_Stop_Warning_Indication_PDU;  /* Stop_Warning_Indication */
static int hf_sbc_ap_PWS_Restart_Indication_PDU;  /* PWS_Restart_Indication */
static int hf_sbc_ap_PWS_Failure_Indication_PDU;  /* PWS_Failure_Indication */
static int hf_sbc_ap_Error_Indication_PDU;        /* Error_Indication */
static int hf_sbc_ap_SBC_AP_PDU_PDU;              /* SBC_AP_PDU */
static int hf_sbc_ap_ProtocolIE_Container_item;   /* ProtocolIE_Field */
static int hf_sbc_ap_id;                          /* ProtocolIE_ID */
static int hf_sbc_ap_criticality;                 /* Criticality */
static int hf_sbc_ap_ie_field_value;              /* T_ie_field_value */
static int hf_sbc_ap_ProtocolExtensionContainer_item;  /* ProtocolExtensionField */
static int hf_sbc_ap_ext_id;                      /* ProtocolExtensionID */
static int hf_sbc_ap_extensionValue;              /* T_extensionValue */
static int hf_sbc_ap_cellId_Broadcast_List;       /* CellId_Broadcast_List */
static int hf_sbc_ap_tAI_Broadcast_List;          /* TAI_Broadcast_List */
static int hf_sbc_ap_emergencyAreaID_Broadcast_List;  /* EmergencyAreaID_Broadcast_List */
static int hf_sbc_ap_iE_Extensions;               /* ProtocolExtensionContainer */
static int hf_sbc_ap_cellId_Broadcast_List_5GS;   /* CellId_Broadcast_List_5GS */
static int hf_sbc_ap_tAI_Broadcast_List_5GS;      /* TAI_Broadcast_List_5GS */
static int hf_sbc_ap_cellID_Cancelled_List;       /* CellID_Cancelled_List */
static int hf_sbc_ap_tAI_Cancelled_List;          /* TAI_Cancelled_List */
static int hf_sbc_ap_emergencyAreaID_Cancelled_List;  /* EmergencyAreaID_Cancelled_List */
static int hf_sbc_ap_cellID_Cancelled_List_5GS;   /* CellID_Cancelled_List_5GS */
static int hf_sbc_ap_tAI_Cancelled_List_5GS;      /* TAI_Cancelled_List_5GS */
static int hf_sbc_ap_Broadcast_Empty_Area_List_item;  /* Global_ENB_ID */
static int hf_sbc_ap_Broadcast_Empty_Area_List_5GS_item;  /* Global_RAN_Node_ID */
static int hf_sbc_ap_CancelledCellinEAI_item;     /* CancelledCellinEAI_Item */
static int hf_sbc_ap_eCGI;                        /* EUTRAN_CGI */
static int hf_sbc_ap_numberOfBroadcasts;          /* NumberOfBroadcasts */
static int hf_sbc_ap_CancelledCellinTAI_item;     /* CancelledCellinTAI_Item */
static int hf_sbc_ap_CancelledCellinTAI_5GS_item;  /* CancelledCellinTAI_5GS_item */
static int hf_sbc_ap_nR_CGI;                      /* NR_CGI */
static int hf_sbc_ap_CellId_Broadcast_List_item;  /* CellId_Broadcast_List_Item */
static int hf_sbc_ap_CellId_Broadcast_List_5GS_item;  /* CellId_Broadcast_List_5GS_item */
static int hf_sbc_ap_CellID_Cancelled_List_item;  /* CellID_Cancelled_Item */
static int hf_sbc_ap_CellID_Cancelled_List_5GS_item;  /* CellID_Cancelled_List_5GS_item */
static int hf_sbc_ap_procedureCode;               /* ProcedureCode */
static int hf_sbc_ap_triggeringMessage;           /* TriggeringMessage */
static int hf_sbc_ap_procedureCriticality;        /* Criticality */
static int hf_sbc_ap_iE_CriticalityDiagnostics;   /* CriticalityDiagnostics_IE_List */
static int hf_sbc_ap_CriticalityDiagnostics_IE_List_item;  /* CriticalityDiagnostics_IE_List_item */
static int hf_sbc_ap_iECriticality;               /* Criticality */
static int hf_sbc_ap_iE_ID;                       /* ProtocolIE_ID */
static int hf_sbc_ap_typeOfError;                 /* TypeOfError */
static int hf_sbc_ap_ECGIList_item;               /* EUTRAN_CGI */
static int hf_sbc_ap_Emergency_Area_ID_List_item;  /* Emergency_Area_ID */
static int hf_sbc_ap_EmergencyAreaID_Broadcast_List_item;  /* EmergencyAreaID_Broadcast_List_Item */
static int hf_sbc_ap_emergencyAreaID;             /* Emergency_Area_ID */
static int hf_sbc_ap_scheduledCellinEAI;          /* ScheduledCellinEAI */
static int hf_sbc_ap_EmergencyAreaID_Cancelled_List_item;  /* EmergencyAreaID_Cancelled_Item */
static int hf_sbc_ap_cancelledCellinEAI;          /* CancelledCellinEAI */
static int hf_sbc_ap_pLMNidentity;                /* PLMNidentity */
static int hf_sbc_ap_cell_ID;                     /* CellIdentity */
static int hf_sbc_ap_macroENB_ID;                 /* BIT_STRING_SIZE_20 */
static int hf_sbc_ap_homeENB_ID;                  /* BIT_STRING_SIZE_28 */
static int hf_sbc_ap_short_macroENB_ID;           /* BIT_STRING_SIZE_18 */
static int hf_sbc_ap_long_macroENB_ID;            /* BIT_STRING_SIZE_21 */
static int hf_sbc_ap_Failed_Cell_List_item;       /* EUTRAN_CGI */
static int hf_sbc_ap_Failed_Cell_List_NR_item;    /* NR_CGI */
static int hf_sbc_ap_eNB_ID;                      /* ENB_ID */
static int hf_sbc_ap_global_GNB_ID;               /* Global_GNB_ID */
static int hf_sbc_ap_global_NgENB_ID;             /* Global_NgENB_ID */
static int hf_sbc_ap_gNB_ID;                      /* GNB_ID */
static int hf_sbc_ap_gNB_ID_01;                   /* BIT_STRING_SIZE_22_32 */
static int hf_sbc_ap_ngENB_ID;                    /* ENB_ID */
static int hf_sbc_ap_List_of_TAIs_item;           /* List_of_TAIs_item */
static int hf_sbc_ap_tai;                         /* TAI */
static int hf_sbc_ap_List_of_TAIs_Restart_item;   /* List_of_TAIs_Restart_item */
static int hf_sbc_ap_List_of_EAIs_Restart_item;   /* Emergency_Area_ID */
static int hf_sbc_ap_List_of_5GS_TAIs_item;       /* TAI_5GS */
static int hf_sbc_ap_List_of_5GS_TAI_for_Restart_item;  /* TAI_5GS */
static int hf_sbc_ap_NR_CGIList_item;             /* NR_CGI */
static int hf_sbc_ap_nRCellIdentity;              /* NRCellIdentity */
static int hf_sbc_ap_Restarted_Cell_List_item;    /* EUTRAN_CGI */
static int hf_sbc_ap_Restarted_Cell_List_NR_item;  /* NR_CGI */
static int hf_sbc_ap_ScheduledCellinEAI_item;     /* ScheduledCellinEAI_Item */
static int hf_sbc_ap_ScheduledCellinTAI_item;     /* ScheduledCellinTAI_Item */
static int hf_sbc_ap_ScheduledCellinTAI_5GS_item;  /* ScheduledCellinTAI_5GS_item */
static int hf_sbc_ap_TAI_Broadcast_List_item;     /* TAI_Broadcast_List_Item */
static int hf_sbc_ap_tAI;                         /* TAI */
static int hf_sbc_ap_scheduledCellinTAI;          /* ScheduledCellinTAI */
static int hf_sbc_ap_TAI_Broadcast_List_5GS_item;  /* TAI_Broadcast_List_5GS_item */
static int hf_sbc_ap_tAI_5GS;                     /* TAI_5GS */
static int hf_sbc_ap_scheduledCellinTAI_5GS;      /* ScheduledCellinTAI_5GS */
static int hf_sbc_ap_TAI_Cancelled_List_item;     /* TAI_Cancelled_List_Item */
static int hf_sbc_ap_cancelledCellinTAI;          /* CancelledCellinTAI */
static int hf_sbc_ap_TAI_Cancelled_List_5GS_item;  /* TAI_Cancelled_List_5GS_item */
static int hf_sbc_ap_cancelledCellinTAI_5GS;      /* CancelledCellinTAI_5GS */
static int hf_sbc_ap_TAI_List_for_Warning_item;   /* TAI */
static int hf_sbc_ap_tAC;                         /* TAC */
static int hf_sbc_ap_tAC_5GS;                     /* TAC_5GS */
static int hf_sbc_ap_Unknown_5GS_Tracking_Area_List_item;  /* TAI_5GS */
static int hf_sbc_ap_cell_ID_List;                /* ECGIList */
static int hf_sbc_ap_tracking_Area_List_for_Warning;  /* TAI_List_for_Warning */
static int hf_sbc_ap_emergency_Area_ID_List;      /* Emergency_Area_ID_List */
static int hf_sbc_ap_nR_CGIList;                  /* NR_CGIList */
static int hf_sbc_ap_tAIList_5GS;                 /* TAI_5GS */
static int hf_sbc_ap_emergencyAreaIDList;         /* Emergency_Area_ID_List */
static int hf_sbc_ap_protocolIEs;                 /* ProtocolIE_Container */
static int hf_sbc_ap_protocolExtensions;          /* ProtocolExtensionContainer */
static int hf_sbc_ap_initiatingMessage;           /* InitiatingMessage */
static int hf_sbc_ap_successfulOutcome;           /* SuccessfulOutcome */
static int hf_sbc_ap_unsuccessfulOutcome;         /* UnsuccessfulOutcome */
static int hf_sbc_ap_initiatingMessagevalue;      /* InitiatingMessage_value */
static int hf_sbc_ap_successfulOutcome_value;     /* SuccessfulOutcome_value */
static int hf_sbc_ap_unsuccessfulOutcome_value;   /* UnsuccessfulOutcome_value */

/* Initialize the subtree pointers */
static int ett_sbc_ap;
static int ett_sbc_ap_Serial_Number;
static int ett_sbc_ap_Warning_Type;
static int ett_sbc_ap_Data_Coding_Scheme;
static int ett_sbc_ap_Warning_Message_Contents;

static int ett_sbc_ap_ProtocolIE_Container;
static int ett_sbc_ap_ProtocolIE_Field;
static int ett_sbc_ap_ProtocolExtensionContainer;
static int ett_sbc_ap_ProtocolExtensionField;
static int ett_sbc_ap_Broadcast_Scheduled_Area_List;
static int ett_sbc_ap_Broadcast_Scheduled_Area_List_5GS;
static int ett_sbc_ap_Broadcast_Cancelled_Area_List;
static int ett_sbc_ap_Broadcast_Cancelled_Area_List_5GS;
static int ett_sbc_ap_Broadcast_Empty_Area_List;
static int ett_sbc_ap_Broadcast_Empty_Area_List_5GS;
static int ett_sbc_ap_CancelledCellinEAI;
static int ett_sbc_ap_CancelledCellinEAI_Item;
static int ett_sbc_ap_CancelledCellinTAI;
static int ett_sbc_ap_CancelledCellinTAI_Item;
static int ett_sbc_ap_CancelledCellinTAI_5GS;
static int ett_sbc_ap_CancelledCellinTAI_5GS_item;
static int ett_sbc_ap_CellId_Broadcast_List;
static int ett_sbc_ap_CellId_Broadcast_List_Item;
static int ett_sbc_ap_CellId_Broadcast_List_5GS;
static int ett_sbc_ap_CellId_Broadcast_List_5GS_item;
static int ett_sbc_ap_CellID_Cancelled_List;
static int ett_sbc_ap_CellID_Cancelled_Item;
static int ett_sbc_ap_CellID_Cancelled_List_5GS;
static int ett_sbc_ap_CellID_Cancelled_List_5GS_item;
static int ett_sbc_ap_Criticality_Diagnostics;
static int ett_sbc_ap_CriticalityDiagnostics_IE_List;
static int ett_sbc_ap_CriticalityDiagnostics_IE_List_item;
static int ett_sbc_ap_ECGIList;
static int ett_sbc_ap_Emergency_Area_ID_List;
static int ett_sbc_ap_EmergencyAreaID_Broadcast_List;
static int ett_sbc_ap_EmergencyAreaID_Broadcast_List_Item;
static int ett_sbc_ap_EmergencyAreaID_Cancelled_List;
static int ett_sbc_ap_EmergencyAreaID_Cancelled_Item;
static int ett_sbc_ap_EUTRAN_CGI;
static int ett_sbc_ap_ENB_ID;
static int ett_sbc_ap_Failed_Cell_List;
static int ett_sbc_ap_Failed_Cell_List_NR;
static int ett_sbc_ap_Global_ENB_ID;
static int ett_sbc_ap_Global_RAN_Node_ID;
static int ett_sbc_ap_Global_GNB_ID;
static int ett_sbc_ap_GNB_ID;
static int ett_sbc_ap_Global_NgENB_ID;
static int ett_sbc_ap_List_of_TAIs;
static int ett_sbc_ap_List_of_TAIs_item;
static int ett_sbc_ap_List_of_TAIs_Restart;
static int ett_sbc_ap_List_of_TAIs_Restart_item;
static int ett_sbc_ap_List_of_EAIs_Restart;
static int ett_sbc_ap_List_of_5GS_TAIs;
static int ett_sbc_ap_List_of_5GS_TAI_for_Restart;
static int ett_sbc_ap_NR_CGIList;
static int ett_sbc_ap_NR_CGI;
static int ett_sbc_ap_Restarted_Cell_List;
static int ett_sbc_ap_Restarted_Cell_List_NR;
static int ett_sbc_ap_ScheduledCellinEAI;
static int ett_sbc_ap_ScheduledCellinEAI_Item;
static int ett_sbc_ap_ScheduledCellinTAI;
static int ett_sbc_ap_ScheduledCellinTAI_Item;
static int ett_sbc_ap_ScheduledCellinTAI_5GS;
static int ett_sbc_ap_ScheduledCellinTAI_5GS_item;
static int ett_sbc_ap_TAI_Broadcast_List;
static int ett_sbc_ap_TAI_Broadcast_List_Item;
static int ett_sbc_ap_TAI_Broadcast_List_5GS;
static int ett_sbc_ap_TAI_Broadcast_List_5GS_item;
static int ett_sbc_ap_TAI_Cancelled_List;
static int ett_sbc_ap_TAI_Cancelled_List_Item;
static int ett_sbc_ap_TAI_Cancelled_List_5GS;
static int ett_sbc_ap_TAI_Cancelled_List_5GS_item;
static int ett_sbc_ap_TAI_List_for_Warning;
static int ett_sbc_ap_TAI;
static int ett_sbc_ap_TAI_5GS;
static int ett_sbc_ap_Unknown_5GS_Tracking_Area_List;
static int ett_sbc_ap_Warning_Area_List;
static int ett_sbc_ap_Warning_Area_List_5GS;
static int ett_sbc_ap_Write_Replace_Warning_Request;
static int ett_sbc_ap_Write_Replace_Warning_Response;
static int ett_sbc_ap_Stop_Warning_Request;
static int ett_sbc_ap_Stop_Warning_Response;
static int ett_sbc_ap_Write_Replace_Warning_Indication;
static int ett_sbc_ap_Stop_Warning_Indication;
static int ett_sbc_ap_PWS_Restart_Indication;
static int ett_sbc_ap_PWS_Failure_Indication;
static int ett_sbc_ap_Error_Indication;
static int ett_sbc_ap_SBC_AP_PDU;
static int ett_sbc_ap_InitiatingMessage;
static int ett_sbc_ap_SuccessfulOutcome;
static int ett_sbc_ap_UnsuccessfulOutcome;

enum{
	INITIATING_MESSAGE,
	SUCCESSFUL_OUTCOME,
	UNSUCCESSFUL_OUTCOME
};

struct sbc_ap_private_data {
  uint8_t data_coding_scheme;
  e212_number_type_t number_type;
};

/* Global variables */
static uint32_t ProcedureCode;
static uint32_t ProtocolIE_ID;
static uint32_t ProtocolExtensionID;
static int global_sbc_ap_port = SBC_AP_PORT;

/* Dissector tables */
static dissector_table_t sbc_ap_ies_dissector_table;
static dissector_table_t sbc_ap_extension_dissector_table;
static dissector_table_t sbc_ap_proc_imsg_dissector_table;
static dissector_table_t sbc_ap_proc_sout_dissector_table;
static dissector_table_t sbc_ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);


static struct sbc_ap_private_data*
sbc_ap_get_private_data(packet_info *pinfo)
{
  struct sbc_ap_private_data *sbc_ap_data = (struct sbc_ap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_sbc_ap, 0);
  if (!sbc_ap_data) {
    sbc_ap_data = wmem_new0(pinfo->pool, struct sbc_ap_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_sbc_ap, 0, sbc_ap_data);
  }
  return sbc_ap_data;
}


static const value_string sbc_ap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_sbc_ap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}


static const value_string sbc_ap_ProcedureCode_vals[] = {
  { id_Write_Replace_Warning, "id-Write-Replace-Warning" },
  { id_Stop_Warning, "id-Stop-Warning" },
  { id_Error_Indication, "id-Error-Indication" },
  { id_Write_Replace_Warning_Indication, "id-Write-Replace-Warning-Indication" },
  { id_Stop_Warning_Indication, "id-Stop-Warning-Indication" },
  { id_PWS_Restart_Indication, "id-PWS-Restart-Indication" },
  { id_PWS_Failure_Indication, "id-PWS-Failure-Indication" },
  { 0, NULL }
};


static int
dissect_sbc_ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, false);

  return offset;
}



static int
dissect_sbc_ap_ProtocolExtensionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolExtensionID, false);

  return offset;
}


static const value_string sbc_ap_ProtocolIE_ID_vals[] = {
  { id_Broadcast_Message_Content, "id-Broadcast-Message-Content" },
  { id_Cause, "id-Cause" },
  { id_Criticality_Diagnostics, "id-Criticality-Diagnostics" },
  { id_Data_Coding_Scheme, "id-Data-Coding-Scheme" },
  { id_Failure_List, "id-Failure-List" },
  { id_Message_Identifier, "id-Message-Identifier" },
  { id_Number_of_Broadcasts_Completed_List, "id-Number-of-Broadcasts-Completed-List" },
  { id_Number_of_Broadcasts_Requested, "id-Number-of-Broadcasts-Requested" },
  { id_Radio_Resource_Loading_List, "id-Radio-Resource-Loading-List" },
  { id_Recovery_Indication, "id-Recovery-Indication" },
  { id_Repetition_Period, "id-Repetition-Period" },
  { id_Serial_Number, "id-Serial-Number" },
  { id_Service_Areas_List, "id-Service-Areas-List" },
  { id_TypeOfError, "id-TypeOfError" },
  { id_List_of_TAIs, "id-List-of-TAIs" },
  { id_Warning_Area_List, "id-Warning-Area-List" },
  { id_Warning_Message_Content, "id-Warning-Message-Content" },
  { id_Warning_Security_Information, "id-Warning-Security-Information" },
  { id_Warning_Type, "id-Warning-Type" },
  { id_Omc_Id, "id-Omc-Id" },
  { id_Concurrent_Warning_Message_Indicator, "id-Concurrent-Warning-Message-Indicator" },
  { id_Extended_Repetition_Period, "id-Extended-Repetition-Period" },
  { id_Unknown_Tracking_Area_List, "id-Unknown-Tracking-Area-List" },
  { id_Broadcast_Scheduled_Area_List, "id-Broadcast-Scheduled-Area-List" },
  { id_Send_Write_Replace_Warning_Indication, "id-Send-Write-Replace-Warning-Indication" },
  { id_Broadcast_Cancelled_Area_List, "id-Broadcast-Cancelled-Area-List" },
  { id_Send_Stop_Warning_Indication, "id-Send-Stop-Warning-Indication" },
  { id_Stop_All_Indicator, "id-Stop-All-Indicator" },
  { id_Global_ENB_ID, "id-Global-ENB-ID" },
  { id_Broadcast_Empty_Area_List, "id-Broadcast-Empty-Area-List" },
  { id_Restarted_Cell_List, "id-Restarted-Cell-List" },
  { id_List_of_TAIs_Restart, "id-List-of-TAIs-Restart" },
  { id_List_of_EAIs_Restart, "id-List-of-EAIs-Restart" },
  { id_Failed_Cell_List, "id-Failed-Cell-List" },
  { id_List_of_5GS_TAIs, "id-List-of-5GS-TAIs" },
  { id_Warning_Area_List_5GS, "id-Warning-Area-List-5GS" },
  { id_Global_RAN_Node_ID, "id-Global-RAN-Node-ID" },
  { id_Global_GNB_ID, "id-Global-GNB-ID" },
  { id_RAT_Selector_5GS, "id-RAT-Selector-5GS" },
  { id_Unknown_5GS_Tracking_Area_List, "id-Unknown-5GS-Tracking-Area-List" },
  { id_Broadcast_Scheduled_Area_List_5GS, "id-Broadcast-Scheduled-Area-List-5GS" },
  { id_Broadcast_Cancelled_Area_List_5GS, "id-Broadcast-Cancelled-Area-List-5GS" },
  { id_Broadcast_Empty_Area_List_5GS, "id-Broadcast-Empty-Area-List-5GS" },
  { id_Restarted_Cell_List_NR, "id-Restarted-Cell-List-NR" },
  { id_Failed_Cell_List_NR, "id-Failed-Cell-List-NR" },
  { id_List_of_5GS_TAI_for_Restart, "id-List-of-5GS-TAI-for-Restart" },
  { id_Warning_Area_Coordinates, "id-Warning-Area-Coordinates" },
  { 0, NULL }
};


static int
dissect_sbc_ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolIE_ID, false);

  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str(ProtocolIE_ID, VALS(sbc_ap_ProtocolIE_ID_vals), "unknown (%d)"));
  }
  return offset;
}


static const value_string sbc_ap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessful-outcome" },
  {   3, "outcome" },
  { 0, NULL }
};


static int
dissect_sbc_ap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_sbc_ap_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_sbc_ap_id           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolIE_ID },
  { &hf_sbc_ap_criticality  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_Criticality },
  { &hf_sbc_ap_ie_field_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_T_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_sbc_ap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolIE_Field },
};

static int
dissect_sbc_ap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, false);

  return offset;
}



static int
dissect_sbc_ap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_sbc_ap_ext_id       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolExtensionID },
  { &hf_sbc_ap_criticality  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_Criticality },
  { &hf_sbc_ap_extensionValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_sbc_ap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolExtensionField },
};

static int
dissect_sbc_ap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, false);

  return offset;
}




static int
dissect_sbc_ap_PLMNidentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb=NULL;
  struct sbc_ap_private_data *sbc_ap_data = sbc_ap_get_private_data(actx->pinfo);
  e212_number_type_t number_type = sbc_ap_data->number_type;
  sbc_ap_data->number_type = E212_NONE;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, &parameter_tvb);
    if(tvb_reported_length(tvb)==0)
        return offset;

    if (!parameter_tvb)
        return offset;
    dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, tree, 0, number_type, false);

  return offset;
}



static int
dissect_sbc_ap_CellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t EUTRAN_CGI_sequence[] = {
  { &hf_sbc_ap_pLMNidentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_PLMNidentity },
  { &hf_sbc_ap_cell_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_CellIdentity },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_EUTRAN_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct sbc_ap_private_data *sbc_ap_data = sbc_ap_get_private_data(actx->pinfo);
  sbc_ap_data->number_type = E212_ECGI;
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_EUTRAN_CGI, EUTRAN_CGI_sequence);



  return offset;
}


static const per_sequence_t CellId_Broadcast_List_Item_sequence[] = {
  { &hf_sbc_ap_eCGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_EUTRAN_CGI },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_CellId_Broadcast_List_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_CellId_Broadcast_List_Item, CellId_Broadcast_List_Item_sequence);

  return offset;
}


static const per_sequence_t CellId_Broadcast_List_sequence_of[1] = {
  { &hf_sbc_ap_CellId_Broadcast_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_CellId_Broadcast_List_Item },
};

static int
dissect_sbc_ap_CellId_Broadcast_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_CellId_Broadcast_List, CellId_Broadcast_List_sequence_of,
                                                  1, maxnoofCellID, false);

  return offset;
}



static int
dissect_sbc_ap_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, false, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const per_sequence_t TAI_sequence[] = {
  { &hf_sbc_ap_pLMNidentity , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_PLMNidentity },
  { &hf_sbc_ap_tAC          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAC },
  { &hf_sbc_ap_iE_Extensions, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_TAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct sbc_ap_private_data *sbc_ap_data = sbc_ap_get_private_data(actx->pinfo);
  sbc_ap_data->number_type = E212_TAI;
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_TAI, TAI_sequence);



  return offset;
}


static const per_sequence_t ScheduledCellinTAI_Item_sequence[] = {
  { &hf_sbc_ap_eCGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_EUTRAN_CGI },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_ScheduledCellinTAI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_ScheduledCellinTAI_Item, ScheduledCellinTAI_Item_sequence);

  return offset;
}


static const per_sequence_t ScheduledCellinTAI_sequence_of[1] = {
  { &hf_sbc_ap_ScheduledCellinTAI_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ScheduledCellinTAI_Item },
};

static int
dissect_sbc_ap_ScheduledCellinTAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_ScheduledCellinTAI, ScheduledCellinTAI_sequence_of,
                                                  1, maxnoofCellinTAI, false);

  return offset;
}


static const per_sequence_t TAI_Broadcast_List_Item_sequence[] = {
  { &hf_sbc_ap_tAI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI },
  { &hf_sbc_ap_scheduledCellinTAI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ScheduledCellinTAI },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_TAI_Broadcast_List_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_TAI_Broadcast_List_Item, TAI_Broadcast_List_Item_sequence);

  return offset;
}


static const per_sequence_t TAI_Broadcast_List_sequence_of[1] = {
  { &hf_sbc_ap_TAI_Broadcast_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI_Broadcast_List_Item },
};

static int
dissect_sbc_ap_TAI_Broadcast_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_TAI_Broadcast_List, TAI_Broadcast_List_sequence_of,
                                                  1, maxnoofTAIforWarning, false);

  return offset;
}



static int
dissect_sbc_ap_Emergency_Area_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}


static const per_sequence_t ScheduledCellinEAI_Item_sequence[] = {
  { &hf_sbc_ap_eCGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_EUTRAN_CGI },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_ScheduledCellinEAI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_ScheduledCellinEAI_Item, ScheduledCellinEAI_Item_sequence);

  return offset;
}


static const per_sequence_t ScheduledCellinEAI_sequence_of[1] = {
  { &hf_sbc_ap_ScheduledCellinEAI_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ScheduledCellinEAI_Item },
};

static int
dissect_sbc_ap_ScheduledCellinEAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_ScheduledCellinEAI, ScheduledCellinEAI_sequence_of,
                                                  1, maxnoofCellinEAI, false);

  return offset;
}


static const per_sequence_t EmergencyAreaID_Broadcast_List_Item_sequence[] = {
  { &hf_sbc_ap_emergencyAreaID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_Emergency_Area_ID },
  { &hf_sbc_ap_scheduledCellinEAI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ScheduledCellinEAI },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_EmergencyAreaID_Broadcast_List_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_EmergencyAreaID_Broadcast_List_Item, EmergencyAreaID_Broadcast_List_Item_sequence);

  return offset;
}


static const per_sequence_t EmergencyAreaID_Broadcast_List_sequence_of[1] = {
  { &hf_sbc_ap_EmergencyAreaID_Broadcast_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_EmergencyAreaID_Broadcast_List_Item },
};

static int
dissect_sbc_ap_EmergencyAreaID_Broadcast_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_EmergencyAreaID_Broadcast_List, EmergencyAreaID_Broadcast_List_sequence_of,
                                                  1, maxnoofEmergencyAreaID, false);

  return offset;
}


static const per_sequence_t Broadcast_Scheduled_Area_List_sequence[] = {
  { &hf_sbc_ap_cellId_Broadcast_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_CellId_Broadcast_List },
  { &hf_sbc_ap_tAI_Broadcast_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_TAI_Broadcast_List },
  { &hf_sbc_ap_emergencyAreaID_Broadcast_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_EmergencyAreaID_Broadcast_List },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Broadcast_Scheduled_Area_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Broadcast_Scheduled_Area_List, Broadcast_Scheduled_Area_List_sequence);

  return offset;
}



static int
dissect_sbc_ap_NRCellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NR_CGI_sequence[] = {
  { &hf_sbc_ap_pLMNidentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_PLMNidentity },
  { &hf_sbc_ap_nRCellIdentity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_NRCellIdentity },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_NR_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct sbc_ap_private_data *sbc_ap_data = sbc_ap_get_private_data(actx->pinfo);
  sbc_ap_data->number_type = E212_NRCGI;
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_NR_CGI, NR_CGI_sequence);



  return offset;
}


static const per_sequence_t CellId_Broadcast_List_5GS_item_sequence[] = {
  { &hf_sbc_ap_nR_CGI       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_NR_CGI },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_CellId_Broadcast_List_5GS_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_CellId_Broadcast_List_5GS_item, CellId_Broadcast_List_5GS_item_sequence);

  return offset;
}


static const per_sequence_t CellId_Broadcast_List_5GS_sequence_of[1] = {
  { &hf_sbc_ap_CellId_Broadcast_List_5GS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_CellId_Broadcast_List_5GS_item },
};

static int
dissect_sbc_ap_CellId_Broadcast_List_5GS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_CellId_Broadcast_List_5GS, CellId_Broadcast_List_5GS_sequence_of,
                                                  1, maxnoofCellsin5GS, false);

  return offset;
}



static int
dissect_sbc_ap_TAC_5GS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       3, 3, false, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 3, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t TAI_5GS_sequence[] = {
  { &hf_sbc_ap_pLMNidentity , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_PLMNidentity },
  { &hf_sbc_ap_tAC_5GS      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAC_5GS },
  { &hf_sbc_ap_iE_Extensions, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_TAI_5GS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct sbc_ap_private_data *sbc_ap_data = sbc_ap_get_private_data(actx->pinfo);
  sbc_ap_data->number_type = E212_5GSTAI;
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_TAI_5GS, TAI_5GS_sequence);



  return offset;
}


static const per_sequence_t ScheduledCellinTAI_5GS_item_sequence[] = {
  { &hf_sbc_ap_nR_CGI       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_NR_CGI },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_ScheduledCellinTAI_5GS_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_ScheduledCellinTAI_5GS_item, ScheduledCellinTAI_5GS_item_sequence);

  return offset;
}


static const per_sequence_t ScheduledCellinTAI_5GS_sequence_of[1] = {
  { &hf_sbc_ap_ScheduledCellinTAI_5GS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ScheduledCellinTAI_5GS_item },
};

static int
dissect_sbc_ap_ScheduledCellinTAI_5GS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_ScheduledCellinTAI_5GS, ScheduledCellinTAI_5GS_sequence_of,
                                                  1, maxnoofCellsin5GSTAI, false);

  return offset;
}


static const per_sequence_t TAI_Broadcast_List_5GS_item_sequence[] = {
  { &hf_sbc_ap_tAI_5GS      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI_5GS },
  { &hf_sbc_ap_scheduledCellinTAI_5GS, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ScheduledCellinTAI_5GS },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_TAI_Broadcast_List_5GS_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_TAI_Broadcast_List_5GS_item, TAI_Broadcast_List_5GS_item_sequence);

  return offset;
}


static const per_sequence_t TAI_Broadcast_List_5GS_sequence_of[1] = {
  { &hf_sbc_ap_TAI_Broadcast_List_5GS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI_Broadcast_List_5GS_item },
};

static int
dissect_sbc_ap_TAI_Broadcast_List_5GS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_TAI_Broadcast_List_5GS, TAI_Broadcast_List_5GS_sequence_of,
                                                  1, maxnoof5GSTAIs, false);

  return offset;
}


static const per_sequence_t Broadcast_Scheduled_Area_List_5GS_sequence[] = {
  { &hf_sbc_ap_cellId_Broadcast_List_5GS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_CellId_Broadcast_List_5GS },
  { &hf_sbc_ap_tAI_Broadcast_List_5GS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_TAI_Broadcast_List_5GS },
  { &hf_sbc_ap_emergencyAreaID_Broadcast_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_EmergencyAreaID_Broadcast_List },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Broadcast_Scheduled_Area_List_5GS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Broadcast_Scheduled_Area_List_5GS, Broadcast_Scheduled_Area_List_5GS_sequence);

  return offset;
}



static int
dissect_sbc_ap_NumberOfBroadcasts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const per_sequence_t CellID_Cancelled_Item_sequence[] = {
  { &hf_sbc_ap_eCGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_EUTRAN_CGI },
  { &hf_sbc_ap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_NumberOfBroadcasts },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_CellID_Cancelled_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_CellID_Cancelled_Item, CellID_Cancelled_Item_sequence);

  return offset;
}


static const per_sequence_t CellID_Cancelled_List_sequence_of[1] = {
  { &hf_sbc_ap_CellID_Cancelled_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_CellID_Cancelled_Item },
};

static int
dissect_sbc_ap_CellID_Cancelled_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_CellID_Cancelled_List, CellID_Cancelled_List_sequence_of,
                                                  1, maxnoofCellID, false);

  return offset;
}


static const per_sequence_t CancelledCellinTAI_Item_sequence[] = {
  { &hf_sbc_ap_eCGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_EUTRAN_CGI },
  { &hf_sbc_ap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_NumberOfBroadcasts },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_CancelledCellinTAI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_CancelledCellinTAI_Item, CancelledCellinTAI_Item_sequence);

  return offset;
}


static const per_sequence_t CancelledCellinTAI_sequence_of[1] = {
  { &hf_sbc_ap_CancelledCellinTAI_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_CancelledCellinTAI_Item },
};

static int
dissect_sbc_ap_CancelledCellinTAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_CancelledCellinTAI, CancelledCellinTAI_sequence_of,
                                                  1, maxnoofCellinTAI, false);

  return offset;
}


static const per_sequence_t TAI_Cancelled_List_Item_sequence[] = {
  { &hf_sbc_ap_tAI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI },
  { &hf_sbc_ap_cancelledCellinTAI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_CancelledCellinTAI },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_TAI_Cancelled_List_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_TAI_Cancelled_List_Item, TAI_Cancelled_List_Item_sequence);

  return offset;
}


static const per_sequence_t TAI_Cancelled_List_sequence_of[1] = {
  { &hf_sbc_ap_TAI_Cancelled_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI_Cancelled_List_Item },
};

static int
dissect_sbc_ap_TAI_Cancelled_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_TAI_Cancelled_List, TAI_Cancelled_List_sequence_of,
                                                  1, maxnoofTAIforWarning, false);

  return offset;
}


static const per_sequence_t CancelledCellinEAI_Item_sequence[] = {
  { &hf_sbc_ap_eCGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_EUTRAN_CGI },
  { &hf_sbc_ap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_NumberOfBroadcasts },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_CancelledCellinEAI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_CancelledCellinEAI_Item, CancelledCellinEAI_Item_sequence);

  return offset;
}


static const per_sequence_t CancelledCellinEAI_sequence_of[1] = {
  { &hf_sbc_ap_CancelledCellinEAI_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_CancelledCellinEAI_Item },
};

static int
dissect_sbc_ap_CancelledCellinEAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_CancelledCellinEAI, CancelledCellinEAI_sequence_of,
                                                  1, maxnoofCellinEAI, false);

  return offset;
}


static const per_sequence_t EmergencyAreaID_Cancelled_Item_sequence[] = {
  { &hf_sbc_ap_emergencyAreaID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_Emergency_Area_ID },
  { &hf_sbc_ap_cancelledCellinEAI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_CancelledCellinEAI },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_EmergencyAreaID_Cancelled_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_EmergencyAreaID_Cancelled_Item, EmergencyAreaID_Cancelled_Item_sequence);

  return offset;
}


static const per_sequence_t EmergencyAreaID_Cancelled_List_sequence_of[1] = {
  { &hf_sbc_ap_EmergencyAreaID_Cancelled_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_EmergencyAreaID_Cancelled_Item },
};

static int
dissect_sbc_ap_EmergencyAreaID_Cancelled_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_EmergencyAreaID_Cancelled_List, EmergencyAreaID_Cancelled_List_sequence_of,
                                                  1, maxnoofEmergencyAreaID, false);

  return offset;
}


static const per_sequence_t Broadcast_Cancelled_Area_List_sequence[] = {
  { &hf_sbc_ap_cellID_Cancelled_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_CellID_Cancelled_List },
  { &hf_sbc_ap_tAI_Cancelled_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_TAI_Cancelled_List },
  { &hf_sbc_ap_emergencyAreaID_Cancelled_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_EmergencyAreaID_Cancelled_List },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Broadcast_Cancelled_Area_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Broadcast_Cancelled_Area_List, Broadcast_Cancelled_Area_List_sequence);

  return offset;
}


static const per_sequence_t CellID_Cancelled_List_5GS_item_sequence[] = {
  { &hf_sbc_ap_nR_CGI       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_NR_CGI },
  { &hf_sbc_ap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_NumberOfBroadcasts },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_CellID_Cancelled_List_5GS_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_CellID_Cancelled_List_5GS_item, CellID_Cancelled_List_5GS_item_sequence);

  return offset;
}


static const per_sequence_t CellID_Cancelled_List_5GS_sequence_of[1] = {
  { &hf_sbc_ap_CellID_Cancelled_List_5GS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_CellID_Cancelled_List_5GS_item },
};

static int
dissect_sbc_ap_CellID_Cancelled_List_5GS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_CellID_Cancelled_List_5GS, CellID_Cancelled_List_5GS_sequence_of,
                                                  1, maxnoofCellsin5GS, false);

  return offset;
}


static const per_sequence_t CancelledCellinTAI_5GS_item_sequence[] = {
  { &hf_sbc_ap_nR_CGI       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_NR_CGI },
  { &hf_sbc_ap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_NumberOfBroadcasts },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_CancelledCellinTAI_5GS_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_CancelledCellinTAI_5GS_item, CancelledCellinTAI_5GS_item_sequence);

  return offset;
}


static const per_sequence_t CancelledCellinTAI_5GS_sequence_of[1] = {
  { &hf_sbc_ap_CancelledCellinTAI_5GS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_CancelledCellinTAI_5GS_item },
};

static int
dissect_sbc_ap_CancelledCellinTAI_5GS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_CancelledCellinTAI_5GS, CancelledCellinTAI_5GS_sequence_of,
                                                  1, maxnoofCellsin5GSTAI, false);

  return offset;
}


static const per_sequence_t TAI_Cancelled_List_5GS_item_sequence[] = {
  { &hf_sbc_ap_tAI_5GS      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI_5GS },
  { &hf_sbc_ap_cancelledCellinTAI_5GS, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_CancelledCellinTAI_5GS },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_TAI_Cancelled_List_5GS_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_TAI_Cancelled_List_5GS_item, TAI_Cancelled_List_5GS_item_sequence);

  return offset;
}


static const per_sequence_t TAI_Cancelled_List_5GS_sequence_of[1] = {
  { &hf_sbc_ap_TAI_Cancelled_List_5GS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI_Cancelled_List_5GS_item },
};

static int
dissect_sbc_ap_TAI_Cancelled_List_5GS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_TAI_Cancelled_List_5GS, TAI_Cancelled_List_5GS_sequence_of,
                                                  1, maxnoof5GSTAIs, false);

  return offset;
}


static const per_sequence_t Broadcast_Cancelled_Area_List_5GS_sequence[] = {
  { &hf_sbc_ap_cellID_Cancelled_List_5GS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_CellID_Cancelled_List_5GS },
  { &hf_sbc_ap_tAI_Cancelled_List_5GS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_TAI_Cancelled_List_5GS },
  { &hf_sbc_ap_emergencyAreaID_Cancelled_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_EmergencyAreaID_Cancelled_List },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Broadcast_Cancelled_Area_List_5GS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Broadcast_Cancelled_Area_List_5GS, Broadcast_Cancelled_Area_List_5GS_sequence);

  return offset;
}



static int
dissect_sbc_ap_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_sbc_ap_BIT_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_sbc_ap_BIT_STRING_SIZE_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     18, 18, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_sbc_ap_BIT_STRING_SIZE_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     21, 21, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string sbc_ap_ENB_ID_vals[] = {
  {   0, "macroENB-ID" },
  {   1, "homeENB-ID" },
  {   2, "short-macroENB-ID" },
  {   3, "long-macroENB-ID" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_choice[] = {
  {   0, &hf_sbc_ap_macroENB_ID  , ASN1_EXTENSION_ROOT    , dissect_sbc_ap_BIT_STRING_SIZE_20 },
  {   1, &hf_sbc_ap_homeENB_ID   , ASN1_EXTENSION_ROOT    , dissect_sbc_ap_BIT_STRING_SIZE_28 },
  {   2, &hf_sbc_ap_short_macroENB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_sbc_ap_BIT_STRING_SIZE_18 },
  {   3, &hf_sbc_ap_long_macroENB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_sbc_ap_BIT_STRING_SIZE_21 },
  { 0, NULL, 0, NULL }
};

static int
dissect_sbc_ap_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_sbc_ap_ENB_ID, ENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Global_ENB_ID_sequence[] = {
  { &hf_sbc_ap_pLMNidentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_PLMNidentity },
  { &hf_sbc_ap_eNB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ENB_ID },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Global_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Global_ENB_ID, Global_ENB_ID_sequence);

  return offset;
}


static const per_sequence_t Broadcast_Empty_Area_List_sequence_of[1] = {
  { &hf_sbc_ap_Broadcast_Empty_Area_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_Global_ENB_ID },
};

static int
dissect_sbc_ap_Broadcast_Empty_Area_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_Broadcast_Empty_Area_List, Broadcast_Empty_Area_List_sequence_of,
                                                  1, maxnoofeNBIds, false);

  return offset;
}



static int
dissect_sbc_ap_BIT_STRING_SIZE_22_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     22, 32, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string sbc_ap_GNB_ID_vals[] = {
  {   0, "gNB-ID" },
  { 0, NULL }
};

static const per_choice_t GNB_ID_choice[] = {
  {   0, &hf_sbc_ap_gNB_ID_01    , ASN1_EXTENSION_ROOT    , dissect_sbc_ap_BIT_STRING_SIZE_22_32 },
  { 0, NULL, 0, NULL }
};

static int
dissect_sbc_ap_GNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_sbc_ap_GNB_ID, GNB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Global_GNB_ID_sequence[] = {
  { &hf_sbc_ap_pLMNidentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_PLMNidentity },
  { &hf_sbc_ap_gNB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_GNB_ID },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Global_GNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Global_GNB_ID, Global_GNB_ID_sequence);

  return offset;
}


static const per_sequence_t Global_NgENB_ID_sequence[] = {
  { &hf_sbc_ap_pLMNidentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_PLMNidentity },
  { &hf_sbc_ap_ngENB_ID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ENB_ID },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Global_NgENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Global_NgENB_ID, Global_NgENB_ID_sequence);

  return offset;
}


static const value_string sbc_ap_Global_RAN_Node_ID_vals[] = {
  {   0, "global-GNB-ID" },
  {   1, "global-NgENB-ID" },
  { 0, NULL }
};

static const per_choice_t Global_RAN_Node_ID_choice[] = {
  {   0, &hf_sbc_ap_global_GNB_ID, ASN1_EXTENSION_ROOT    , dissect_sbc_ap_Global_GNB_ID },
  {   1, &hf_sbc_ap_global_NgENB_ID, ASN1_EXTENSION_ROOT    , dissect_sbc_ap_Global_NgENB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_sbc_ap_Global_RAN_Node_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_sbc_ap_Global_RAN_Node_ID, Global_RAN_Node_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Broadcast_Empty_Area_List_5GS_sequence_of[1] = {
  { &hf_sbc_ap_Broadcast_Empty_Area_List_5GS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_Global_RAN_Node_ID },
};

static int
dissect_sbc_ap_Broadcast_Empty_Area_List_5GS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_Broadcast_Empty_Area_List_5GS, Broadcast_Empty_Area_List_5GS_sequence_of,
                                                  1, maxnoofRANNodes, false);

  return offset;
}


static const value_string sbc_ap_Cause_vals[] = {
  {   0, "message-accepted" },
  {   1, "parameter-not-recognised" },
  {   2, "parameter-value-invalid" },
  {   3, "valid-message-not-identified" },
  {   4, "tracking-area-not-valid" },
  {   5, "unrecognised-message" },
  {   6, "missing-mandatory-element" },
  {   7, "mME-capacity-exceeded" },
  {   8, "mME-memory-exceeded" },
  {   9, "warning-broadcast-not-supported" },
  {  10, "warning-broadcast-not-operational" },
  {  11, "message-reference-already-used" },
  {  12, "unspecifed-error" },
  {  13, "transfer-syntax-error" },
  {  14, "semantic-error" },
  {  15, "message-not-compatible-with-receiver-state" },
  {  16, "abstract-syntax-error-reject" },
  {  17, "abstract-syntax-error-ignore-and-notify" },
  {  18, "abstract-syntax-error-falsely-constructed-message" },
  { 0, NULL }
};


static int
dissect_sbc_ap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const value_string sbc_ap_Concurrent_Warning_Message_Indicator_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_sbc_ap_Concurrent_Warning_Message_Indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, false, 0, NULL);

  return offset;
}


static const value_string sbc_ap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_sbc_ap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_sbc_ap_iECriticality, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_Criticality },
  { &hf_sbc_ap_iE_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolIE_ID },
  { &hf_sbc_ap_typeOfError  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TypeOfError },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_sbc_ap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_sbc_ap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxNrOfErrors, false);

  return offset;
}


static const per_sequence_t Criticality_Diagnostics_sequence[] = {
  { &hf_sbc_ap_procedureCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProcedureCode },
  { &hf_sbc_ap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_TriggeringMessage },
  { &hf_sbc_ap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_Criticality },
  { &hf_sbc_ap_iE_CriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_CriticalityDiagnostics_IE_List },
  { &hf_sbc_ap_iE_Extensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Criticality_Diagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Criticality_Diagnostics, Criticality_Diagnostics_sequence);

  return offset;
}



static int
dissect_sbc_ap_Data_Coding_Scheme(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    struct sbc_ap_private_data *sbc_ap_data = sbc_ap_get_private_data(actx->pinfo);
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_sbc_ap_Data_Coding_Scheme);
    sbc_ap_data->data_coding_scheme = dissect_cbs_data_coding_scheme(parameter_tvb, actx->pinfo, subtree, 0);
  }


  return offset;
}


static const per_sequence_t ECGIList_sequence_of[1] = {
  { &hf_sbc_ap_ECGIList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_EUTRAN_CGI },
};

static int
dissect_sbc_ap_ECGIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_ECGIList, ECGIList_sequence_of,
                                                  1, maxnoofCellID, false);

  return offset;
}


static const per_sequence_t Emergency_Area_ID_List_sequence_of[1] = {
  { &hf_sbc_ap_Emergency_Area_ID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_Emergency_Area_ID },
};

static int
dissect_sbc_ap_Emergency_Area_ID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_Emergency_Area_ID_List, Emergency_Area_ID_List_sequence_of,
                                                  1, maxnoofEmergencyAreaID, false);

  return offset;
}



static int
dissect_sbc_ap_Extended_Repetition_Period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            4096U, 131071U, NULL, false);

  return offset;
}


static const per_sequence_t Failed_Cell_List_sequence_of[1] = {
  { &hf_sbc_ap_Failed_Cell_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_EUTRAN_CGI },
};

static int
dissect_sbc_ap_Failed_Cell_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_Failed_Cell_List, Failed_Cell_List_sequence_of,
                                                  1, maxnoofFailedCells, false);

  return offset;
}


static const per_sequence_t Failed_Cell_List_NR_sequence_of[1] = {
  { &hf_sbc_ap_Failed_Cell_List_NR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_NR_CGI },
};

static int
dissect_sbc_ap_Failed_Cell_List_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_Failed_Cell_List_NR, Failed_Cell_List_NR_sequence_of,
                                                  1, maxnoofCellsingNB, false);

  return offset;
}


static const per_sequence_t List_of_TAIs_item_sequence[] = {
  { &hf_sbc_ap_tai          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_List_of_TAIs_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_List_of_TAIs_item, List_of_TAIs_item_sequence);

  return offset;
}


static const per_sequence_t List_of_TAIs_sequence_of[1] = {
  { &hf_sbc_ap_List_of_TAIs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_List_of_TAIs_item },
};

static int
dissect_sbc_ap_List_of_TAIs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_List_of_TAIs, List_of_TAIs_sequence_of,
                                                  1, maxNrOfTAIs, false);

  return offset;
}


static const per_sequence_t List_of_TAIs_Restart_item_sequence[] = {
  { &hf_sbc_ap_tai          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_List_of_TAIs_Restart_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_List_of_TAIs_Restart_item, List_of_TAIs_Restart_item_sequence);

  return offset;
}


static const per_sequence_t List_of_TAIs_Restart_sequence_of[1] = {
  { &hf_sbc_ap_List_of_TAIs_Restart_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_List_of_TAIs_Restart_item },
};

static int
dissect_sbc_ap_List_of_TAIs_Restart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_List_of_TAIs_Restart, List_of_TAIs_Restart_sequence_of,
                                                  1, maxnoofRestartTAIs, false);

  return offset;
}


static const per_sequence_t List_of_EAIs_Restart_sequence_of[1] = {
  { &hf_sbc_ap_List_of_EAIs_Restart_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_Emergency_Area_ID },
};

static int
dissect_sbc_ap_List_of_EAIs_Restart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_List_of_EAIs_Restart, List_of_EAIs_Restart_sequence_of,
                                                  1, maxnoofRestartEAIs, false);

  return offset;
}


static const per_sequence_t List_of_5GS_TAIs_sequence_of[1] = {
  { &hf_sbc_ap_List_of_5GS_TAIs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI_5GS },
};

static int
dissect_sbc_ap_List_of_5GS_TAIs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_List_of_5GS_TAIs, List_of_5GS_TAIs_sequence_of,
                                                  1, maxnoof5GSTAIs, false);

  return offset;
}


static const per_sequence_t List_of_5GS_TAI_for_Restart_sequence_of[1] = {
  { &hf_sbc_ap_List_of_5GS_TAI_for_Restart_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI_5GS },
};

static int
dissect_sbc_ap_List_of_5GS_TAI_for_Restart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_List_of_5GS_TAI_for_Restart, List_of_5GS_TAI_for_Restart_sequence_of,
                                                  1, maxnoofRestart5GSTAIs, false);

  return offset;
}



static int
dissect_sbc_ap_Message_Identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     16, 16, false, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_sbc_ap_Number_of_Broadcasts_Requested(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const per_sequence_t NR_CGIList_sequence_of[1] = {
  { &hf_sbc_ap_NR_CGIList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_NR_CGI },
};

static int
dissect_sbc_ap_NR_CGIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_NR_CGIList, NR_CGIList_sequence_of,
                                                  1, maxnoofCellsingNB, false);

  return offset;
}



static int
dissect_sbc_ap_Omc_Id(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, false, NULL);

  return offset;
}



static int
dissect_sbc_ap_Repetition_Period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4096U, NULL, false);

  return offset;
}


static const per_sequence_t Restarted_Cell_List_sequence_of[1] = {
  { &hf_sbc_ap_Restarted_Cell_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_EUTRAN_CGI },
};

static int
dissect_sbc_ap_Restarted_Cell_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_Restarted_Cell_List, Restarted_Cell_List_sequence_of,
                                                  1, maxnoofRestartedCells, false);

  return offset;
}


static const value_string sbc_ap_RAT_Selector_5GS_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_sbc_ap_RAT_Selector_5GS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t Restarted_Cell_List_NR_sequence_of[1] = {
  { &hf_sbc_ap_Restarted_Cell_List_NR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_NR_CGI },
};

static int
dissect_sbc_ap_Restarted_Cell_List_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_Restarted_Cell_List_NR, Restarted_Cell_List_NR_sequence_of,
                                                  1, maxnoofCellsforRestartNR, false);

  return offset;
}


static const value_string sbc_ap_Send_Write_Replace_Warning_Indication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_sbc_ap_Send_Write_Replace_Warning_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, false, 0, NULL);

  return offset;
}


static const value_string sbc_ap_Send_Stop_Warning_Indication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_sbc_ap_Send_Stop_Warning_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_sbc_ap_Serial_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_sbc_ap_Serial_Number);
    proto_tree_add_item(subtree, hf_sbc_ap_Serial_Number_gs, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_sbc_ap_Serial_Number_msg_code, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_sbc_ap_Serial_Number_upd_nb, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const value_string sbc_ap_Stop_All_Indicator_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_sbc_ap_Stop_All_Indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t TAI_List_for_Warning_sequence_of[1] = {
  { &hf_sbc_ap_TAI_List_for_Warning_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI },
};

static int
dissect_sbc_ap_TAI_List_for_Warning(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_TAI_List_for_Warning, TAI_List_for_Warning_sequence_of,
                                                  1, maxnoofTAIforWarning, false);

  return offset;
}


static const per_sequence_t Unknown_5GS_Tracking_Area_List_sequence_of[1] = {
  { &hf_sbc_ap_Unknown_5GS_Tracking_Area_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI_5GS },
};

static int
dissect_sbc_ap_Unknown_5GS_Tracking_Area_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_Unknown_5GS_Tracking_Area_List, Unknown_5GS_Tracking_Area_List_sequence_of,
                                                  1, maxnoof5GSTAIs, false);

  return offset;
}


static const value_string sbc_ap_Warning_Area_List_vals[] = {
  {   0, "cell-ID-List" },
  {   1, "tracking-Area-List-for-Warning" },
  {   2, "emergency-Area-ID-List" },
  { 0, NULL }
};

static const per_choice_t Warning_Area_List_choice[] = {
  {   0, &hf_sbc_ap_cell_ID_List , ASN1_EXTENSION_ROOT    , dissect_sbc_ap_ECGIList },
  {   1, &hf_sbc_ap_tracking_Area_List_for_Warning, ASN1_EXTENSION_ROOT    , dissect_sbc_ap_TAI_List_for_Warning },
  {   2, &hf_sbc_ap_emergency_Area_ID_List, ASN1_EXTENSION_ROOT    , dissect_sbc_ap_Emergency_Area_ID_List },
  { 0, NULL, 0, NULL }
};

static int
dissect_sbc_ap_Warning_Area_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_sbc_ap_Warning_Area_List, Warning_Area_List_choice,
                                 NULL);

  return offset;
}



static int
dissect_sbc_ap_Warning_Message_Content(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 9600, false, &parameter_tvb);

  if (parameter_tvb) {
    struct sbc_ap_private_data *sbc_ap_data = sbc_ap_get_private_data(actx->pinfo);
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_sbc_ap_Warning_Message_Contents);
    dissect_s1ap_warningMessageContents(parameter_tvb, subtree, actx->pinfo, sbc_ap_data->data_coding_scheme, hf_sbc_ap_Warning_Message_Contents_nb_pages, hf_sbc_ap_Warning_Message_Contents_decoded_page);
  }



  return offset;
}



static int
dissect_sbc_ap_Warning_Area_Coordinates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1024, false, NULL);

  return offset;
}



static int
dissect_sbc_ap_Warning_Security_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       50, 50, false, NULL);

  return offset;
}



static int
dissect_sbc_ap_Warning_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_sbc_ap_Warning_Type);
    proto_tree_add_item(subtree, hf_sbc_ap_Warning_Type_value, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_sbc_ap_Warning_Type_emergency_user_alert, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_sbc_ap_Warning_Type_popup, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const value_string sbc_ap_Warning_Area_List_5GS_vals[] = {
  {   0, "cell-ID-List" },
  {   1, "nR-CGIList" },
  {   2, "tAIList-5GS" },
  {   3, "emergencyAreaIDList" },
  { 0, NULL }
};

static const per_choice_t Warning_Area_List_5GS_choice[] = {
  {   0, &hf_sbc_ap_cell_ID_List , ASN1_EXTENSION_ROOT    , dissect_sbc_ap_ECGIList },
  {   1, &hf_sbc_ap_nR_CGIList   , ASN1_EXTENSION_ROOT    , dissect_sbc_ap_NR_CGIList },
  {   2, &hf_sbc_ap_tAIList_5GS  , ASN1_EXTENSION_ROOT    , dissect_sbc_ap_TAI_5GS },
  {   3, &hf_sbc_ap_emergencyAreaIDList, ASN1_EXTENSION_ROOT    , dissect_sbc_ap_Emergency_Area_ID_List },
  { 0, NULL, 0, NULL }
};

static int
dissect_sbc_ap_Warning_Area_List_5GS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_sbc_ap_Warning_Area_List_5GS, Warning_Area_List_5GS_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Write_Replace_Warning_Request_sequence[] = {
  { &hf_sbc_ap_protocolIEs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolIE_Container },
  { &hf_sbc_ap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Write_Replace_Warning_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Write-Replace-Warning-Request");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Write_Replace_Warning_Request, Write_Replace_Warning_Request_sequence);

  return offset;
}


static const per_sequence_t Write_Replace_Warning_Response_sequence[] = {
  { &hf_sbc_ap_protocolIEs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolIE_Container },
  { &hf_sbc_ap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Write_Replace_Warning_Response(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Write-Replace-Warning-Response");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Write_Replace_Warning_Response, Write_Replace_Warning_Response_sequence);

  return offset;
}


static const per_sequence_t Stop_Warning_Request_sequence[] = {
  { &hf_sbc_ap_protocolIEs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolIE_Container },
  { &hf_sbc_ap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Stop_Warning_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Stop-Warning-Request");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Stop_Warning_Request, Stop_Warning_Request_sequence);

  return offset;
}


static const per_sequence_t Stop_Warning_Response_sequence[] = {
  { &hf_sbc_ap_protocolIEs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolIE_Container },
  { &hf_sbc_ap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Stop_Warning_Response(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Stop-Warning-Response");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Stop_Warning_Response, Stop_Warning_Response_sequence);

  return offset;
}


static const per_sequence_t Write_Replace_Warning_Indication_sequence[] = {
  { &hf_sbc_ap_protocolIEs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolIE_Container },
  { &hf_sbc_ap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Write_Replace_Warning_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Write-Replace-Warning-Indication");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Write_Replace_Warning_Indication, Write_Replace_Warning_Indication_sequence);

  return offset;
}


static const per_sequence_t Stop_Warning_Indication_sequence[] = {
  { &hf_sbc_ap_protocolIEs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolIE_Container },
  { &hf_sbc_ap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Stop_Warning_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Stop-Warning-Indication");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Stop_Warning_Indication, Stop_Warning_Indication_sequence);

  return offset;
}


static const per_sequence_t PWS_Restart_Indication_sequence[] = {
  { &hf_sbc_ap_protocolIEs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolIE_Container },
  { &hf_sbc_ap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_PWS_Restart_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PWS-Restart-Indication");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_PWS_Restart_Indication, PWS_Restart_Indication_sequence);

  return offset;
}


static const per_sequence_t PWS_Failure_Indication_sequence[] = {
  { &hf_sbc_ap_protocolIEs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolIE_Container },
  { &hf_sbc_ap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_PWS_Failure_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PWS-Failure-Indication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_PWS_Failure_Indication, PWS_Failure_Indication_sequence);

  return offset;
}


static const per_sequence_t Error_Indication_sequence[] = {
  { &hf_sbc_ap_protocolIEs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Error_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Error-Indication");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Error_Indication, Error_Indication_sequence);

  return offset;
}



static int
dissect_sbc_ap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_sbc_ap_procedureCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProcedureCode },
  { &hf_sbc_ap_criticality  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_Criticality },
  { &hf_sbc_ap_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_sbc_ap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_sbc_ap_procedureCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProcedureCode },
  { &hf_sbc_ap_criticality  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_Criticality },
  { &hf_sbc_ap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_sbc_ap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_sbc_ap_procedureCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProcedureCode },
  { &hf_sbc_ap_criticality  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_Criticality },
  { &hf_sbc_ap_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string sbc_ap_SBC_AP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t SBC_AP_PDU_choice[] = {
  {   0, &hf_sbc_ap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_sbc_ap_InitiatingMessage },
  {   1, &hf_sbc_ap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_sbc_ap_SuccessfulOutcome },
  {   2, &hf_sbc_ap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_sbc_ap_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_sbc_ap_SBC_AP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_sbc_ap_SBC_AP_PDU, SBC_AP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Broadcast_Scheduled_Area_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Broadcast_Scheduled_Area_List(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Broadcast_Scheduled_Area_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Broadcast_Scheduled_Area_List_5GS_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Broadcast_Scheduled_Area_List_5GS(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Broadcast_Scheduled_Area_List_5GS_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Broadcast_Cancelled_Area_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Broadcast_Cancelled_Area_List(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Broadcast_Cancelled_Area_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Broadcast_Cancelled_Area_List_5GS_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Broadcast_Cancelled_Area_List_5GS(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Broadcast_Cancelled_Area_List_5GS_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Broadcast_Empty_Area_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Broadcast_Empty_Area_List(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Broadcast_Empty_Area_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Broadcast_Empty_Area_List_5GS_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Broadcast_Empty_Area_List_5GS(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Broadcast_Empty_Area_List_5GS_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Cause(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Concurrent_Warning_Message_Indicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Concurrent_Warning_Message_Indicator(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Concurrent_Warning_Message_Indicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Criticality_Diagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Criticality_Diagnostics(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Criticality_Diagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Data_Coding_Scheme_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Data_Coding_Scheme(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Data_Coding_Scheme_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Extended_Repetition_Period_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Extended_Repetition_Period(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Extended_Repetition_Period_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Failed_Cell_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Failed_Cell_List(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Failed_Cell_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Failed_Cell_List_NR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Failed_Cell_List_NR(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Failed_Cell_List_NR_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Global_ENB_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Global_ENB_ID(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Global_ENB_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Global_RAN_Node_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Global_RAN_Node_ID(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Global_RAN_Node_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Global_GNB_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Global_GNB_ID(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Global_GNB_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_List_of_TAIs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_List_of_TAIs(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_List_of_TAIs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_List_of_TAIs_Restart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_List_of_TAIs_Restart(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_List_of_TAIs_Restart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_List_of_EAIs_Restart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_List_of_EAIs_Restart(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_List_of_EAIs_Restart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_List_of_5GS_TAIs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_List_of_5GS_TAIs(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_List_of_5GS_TAIs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_List_of_5GS_TAI_for_Restart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_List_of_5GS_TAI_for_Restart(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_List_of_5GS_TAI_for_Restart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Message_Identifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Message_Identifier(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Message_Identifier_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Number_of_Broadcasts_Requested_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Number_of_Broadcasts_Requested(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Number_of_Broadcasts_Requested_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Omc_Id_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Omc_Id(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Omc_Id_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Repetition_Period_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Repetition_Period(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Repetition_Period_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Restarted_Cell_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Restarted_Cell_List(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Restarted_Cell_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAT_Selector_5GS_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_RAT_Selector_5GS(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_RAT_Selector_5GS_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Restarted_Cell_List_NR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Restarted_Cell_List_NR(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Restarted_Cell_List_NR_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Send_Write_Replace_Warning_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Send_Write_Replace_Warning_Indication(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Send_Write_Replace_Warning_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Send_Stop_Warning_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Send_Stop_Warning_Indication(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Send_Stop_Warning_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Serial_Number_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Serial_Number(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Serial_Number_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Stop_All_Indicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Stop_All_Indicator(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Stop_All_Indicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Unknown_5GS_Tracking_Area_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Unknown_5GS_Tracking_Area_List(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Unknown_5GS_Tracking_Area_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Warning_Area_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Warning_Area_List(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Warning_Area_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Warning_Message_Content_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Warning_Message_Content(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Warning_Message_Content_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Warning_Area_Coordinates_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Warning_Area_Coordinates(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Warning_Area_Coordinates_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Warning_Security_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Warning_Security_Information(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Warning_Security_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Warning_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Warning_Type(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Warning_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Warning_Area_List_5GS_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Warning_Area_List_5GS(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Warning_Area_List_5GS_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Write_Replace_Warning_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Write_Replace_Warning_Request(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Write_Replace_Warning_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Write_Replace_Warning_Response_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Write_Replace_Warning_Response(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Write_Replace_Warning_Response_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Stop_Warning_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Stop_Warning_Request(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Stop_Warning_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Stop_Warning_Response_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Stop_Warning_Response(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Stop_Warning_Response_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Write_Replace_Warning_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Write_Replace_Warning_Indication(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Write_Replace_Warning_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Stop_Warning_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Stop_Warning_Indication(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Stop_Warning_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWS_Restart_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_PWS_Restart_Indication(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_PWS_Restart_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWS_Failure_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_PWS_Failure_Indication(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_PWS_Failure_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Error_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_Error_Indication(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Error_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SBC_AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sbc_ap_SBC_AP_PDU(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_SBC_AP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}
/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_ies_p1_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_ies_p2_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}
*/

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_extension_dissector_table, ProtocolExtensionID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sbc_ap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_sbc_ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item      *sbc_ap_item = NULL;
    proto_tree      *sbc_ap_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
    col_clear(pinfo->cinfo, COL_INFO);

    /* create the sbc_ap protocol tree */
    sbc_ap_item = proto_tree_add_item(tree, proto_sbc_ap, tvb, 0, -1, ENC_NA);
    sbc_ap_tree = proto_item_add_subtree(sbc_ap_item, ett_sbc_ap);

    dissect_SBC_AP_PDU_PDU(tvb, pinfo, sbc_ap_tree, NULL);

    return tvb_captured_length(tvb);
}
/*--- proto_register_sbc_ap -------------------------------------------*/
void proto_register_sbc_ap(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_sbc_ap_Serial_Number_gs,
      { "Geographical Scope", "sbc_ap.SerialNumber.gs",
        FT_UINT16, BASE_DEC, VALS(s1ap_serialNumber_gs_vals), 0xc000,
        NULL, HFILL }},
    { &hf_sbc_ap_Serial_Number_msg_code,
      { "Message Code", "sbc_ap.SerialNumber.msg_code",
        FT_UINT16, BASE_DEC, NULL, 0x3ff0,
        NULL, HFILL }},
    { &hf_sbc_ap_Serial_Number_upd_nb,
      { "Update Number", "sbc_ap.SerialNumber.upd_nb",
        FT_UINT16, BASE_DEC, NULL, 0x000f,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Type_value,
      { "Warning Type Value", "sbc-ap.WarningType.value",
        FT_UINT16, BASE_DEC, VALS(s1ap_warningType_vals), 0xfe00,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Type_emergency_user_alert,
      { "Emergency User Alert", "sbc-ap.WarningType.emergency_user_alert",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Type_popup,
      { "Popup", "sbc-ap.WarningType.popup",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Message_Contents_nb_pages,
      { "Number of Pages", "sbc-ap.WarningMessageContents.nb_pages",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Message_Contents_decoded_page,
      { "Decoded Page", "sbc-ap.WarningMessageContents.decoded_page",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Broadcast_Scheduled_Area_List_PDU,
      { "Broadcast-Scheduled-Area-List", "sbc-ap.Broadcast_Scheduled_Area_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Broadcast_Scheduled_Area_List_5GS_PDU,
      { "Broadcast-Scheduled-Area-List-5GS", "sbc-ap.Broadcast_Scheduled_Area_List_5GS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Broadcast_Cancelled_Area_List_PDU,
      { "Broadcast-Cancelled-Area-List", "sbc-ap.Broadcast_Cancelled_Area_List_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Broadcast_Cancelled_Area_List_5GS_PDU,
      { "Broadcast-Cancelled-Area-List-5GS", "sbc-ap.Broadcast_Cancelled_Area_List_5GS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Broadcast_Empty_Area_List_PDU,
      { "Broadcast-Empty-Area-List", "sbc-ap.Broadcast_Empty_Area_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Broadcast_Empty_Area_List_5GS_PDU,
      { "Broadcast-Empty-Area-List-5GS", "sbc-ap.Broadcast_Empty_Area_List_5GS",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Cause_PDU,
      { "Cause", "sbc-ap.Cause",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Concurrent_Warning_Message_Indicator_PDU,
      { "Concurrent-Warning-Message-Indicator", "sbc-ap.Concurrent_Warning_Message_Indicator",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_Concurrent_Warning_Message_Indicator_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Criticality_Diagnostics_PDU,
      { "Criticality-Diagnostics", "sbc-ap.Criticality_Diagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Data_Coding_Scheme_PDU,
      { "Data-Coding-Scheme", "sbc-ap.Data_Coding_Scheme",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Extended_Repetition_Period_PDU,
      { "Extended-Repetition-Period", "sbc-ap.Extended_Repetition_Period",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Failed_Cell_List_PDU,
      { "Failed-Cell-List", "sbc-ap.Failed_Cell_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Failed_Cell_List_NR_PDU,
      { "Failed-Cell-List-NR", "sbc-ap.Failed_Cell_List_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Global_ENB_ID_PDU,
      { "Global-ENB-ID", "sbc-ap.Global_ENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Global_RAN_Node_ID_PDU,
      { "Global-RAN-Node-ID", "sbc-ap.Global_RAN_Node_ID",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_Global_RAN_Node_ID_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Global_GNB_ID_PDU,
      { "Global-GNB-ID", "sbc-ap.Global_GNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_List_of_TAIs_PDU,
      { "List-of-TAIs", "sbc-ap.List_of_TAIs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_List_of_TAIs_Restart_PDU,
      { "List-of-TAIs-Restart", "sbc-ap.List_of_TAIs_Restart",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_List_of_EAIs_Restart_PDU,
      { "List-of-EAIs-Restart", "sbc-ap.List_of_EAIs_Restart",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_List_of_5GS_TAIs_PDU,
      { "List-of-5GS-TAIs", "sbc-ap.List_of_5GS_TAIs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_List_of_5GS_TAI_for_Restart_PDU,
      { "List-of-5GS-TAI-for-Restart", "sbc-ap.List_of_5GS_TAI_for_Restart",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Message_Identifier_PDU,
      { "Message-Identifier", "sbc-ap.Message_Identifier",
        FT_UINT16, BASE_DEC|BASE_EXT_STRING, &lte_rrc_messageIdentifier_vals_ext, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Number_of_Broadcasts_Requested_PDU,
      { "Number-of-Broadcasts-Requested", "sbc-ap.Number_of_Broadcasts_Requested",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Omc_Id_PDU,
      { "Omc-Id", "sbc-ap.Omc_Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Repetition_Period_PDU,
      { "Repetition-Period", "sbc-ap.Repetition_Period",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Restarted_Cell_List_PDU,
      { "Restarted-Cell-List", "sbc-ap.Restarted_Cell_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_RAT_Selector_5GS_PDU,
      { "RAT-Selector-5GS", "sbc-ap.RAT_Selector_5GS",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_RAT_Selector_5GS_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Restarted_Cell_List_NR_PDU,
      { "Restarted-Cell-List-NR", "sbc-ap.Restarted_Cell_List_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Send_Write_Replace_Warning_Indication_PDU,
      { "Send-Write-Replace-Warning-Indication", "sbc-ap.Send_Write_Replace_Warning_Indication",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_Send_Write_Replace_Warning_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Send_Stop_Warning_Indication_PDU,
      { "Send-Stop-Warning-Indication", "sbc-ap.Send_Stop_Warning_Indication",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_Send_Stop_Warning_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Serial_Number_PDU,
      { "Serial-Number", "sbc-ap.Serial_Number",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Stop_All_Indicator_PDU,
      { "Stop-All-Indicator", "sbc-ap.Stop_All_Indicator",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_Stop_All_Indicator_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Unknown_5GS_Tracking_Area_List_PDU,
      { "Unknown-5GS-Tracking-Area-List", "sbc-ap.Unknown_5GS_Tracking_Area_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Area_List_PDU,
      { "Warning-Area-List", "sbc-ap.Warning_Area_List",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_Warning_Area_List_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Message_Content_PDU,
      { "Warning-Message-Content", "sbc-ap.Warning_Message_Content",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Area_Coordinates_PDU,
      { "Warning-Area-Coordinates", "sbc-ap.Warning_Area_Coordinates",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Security_Information_PDU,
      { "Warning-Security-Information", "sbc-ap.Warning_Security_Information",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Type_PDU,
      { "Warning-Type", "sbc-ap.Warning_Type",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Area_List_5GS_PDU,
      { "Warning-Area-List-5GS", "sbc-ap.Warning_Area_List_5GS",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_Warning_Area_List_5GS_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Write_Replace_Warning_Request_PDU,
      { "Write-Replace-Warning-Request", "sbc-ap.Write_Replace_Warning_Request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Write_Replace_Warning_Response_PDU,
      { "Write-Replace-Warning-Response", "sbc-ap.Write_Replace_Warning_Response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Stop_Warning_Request_PDU,
      { "Stop-Warning-Request", "sbc-ap.Stop_Warning_Request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Stop_Warning_Response_PDU,
      { "Stop-Warning-Response", "sbc-ap.Stop_Warning_Response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Write_Replace_Warning_Indication_PDU,
      { "Write-Replace-Warning-Indication", "sbc-ap.Write_Replace_Warning_Indication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Stop_Warning_Indication_PDU,
      { "Stop-Warning-Indication", "sbc-ap.Stop_Warning_Indication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_PWS_Restart_Indication_PDU,
      { "PWS-Restart-Indication", "sbc-ap.PWS_Restart_Indication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_PWS_Failure_Indication_PDU,
      { "PWS-Failure-Indication", "sbc-ap.PWS_Failure_Indication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Error_Indication_PDU,
      { "Error-Indication", "sbc-ap.Error_Indication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_SBC_AP_PDU_PDU,
      { "SBC-AP-PDU", "sbc-ap.SBC_AP_PDU",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_SBC_AP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "sbc-ap.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_id,
      { "id", "sbc-ap.id",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_sbc_ap_criticality,
      { "criticality", "sbc-ap.criticality",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_ie_field_value,
      { "value", "sbc-ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_sbc_ap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "sbc-ap.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_ext_id,
      { "id", "sbc-ap.id",
        FT_UINT8, BASE_DEC, VALS(sbc_ap_ProtocolIE_ID_vals), 0,
        "ProtocolExtensionID", HFILL }},
    { &hf_sbc_ap_extensionValue,
      { "extensionValue", "sbc-ap.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_cellId_Broadcast_List,
      { "cellId-Broadcast-List", "sbc-ap.cellId_Broadcast_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_tAI_Broadcast_List,
      { "tAI-Broadcast-List", "sbc-ap.tAI_Broadcast_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_emergencyAreaID_Broadcast_List,
      { "emergencyAreaID-Broadcast-List", "sbc-ap.emergencyAreaID_Broadcast_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_iE_Extensions,
      { "iE-Extensions", "sbc-ap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_sbc_ap_cellId_Broadcast_List_5GS,
      { "cellId-Broadcast-List-5GS", "sbc-ap.cellId_Broadcast_List_5GS",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_tAI_Broadcast_List_5GS,
      { "tAI-Broadcast-List-5GS", "sbc-ap.tAI_Broadcast_List_5GS",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_cellID_Cancelled_List,
      { "cellID-Cancelled-List", "sbc-ap.cellID_Cancelled_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_tAI_Cancelled_List,
      { "tAI-Cancelled-List", "sbc-ap.tAI_Cancelled_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_emergencyAreaID_Cancelled_List,
      { "emergencyAreaID-Cancelled-List", "sbc-ap.emergencyAreaID_Cancelled_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_cellID_Cancelled_List_5GS,
      { "cellID-Cancelled-List-5GS", "sbc-ap.cellID_Cancelled_List_5GS",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_tAI_Cancelled_List_5GS,
      { "tAI-Cancelled-List-5GS", "sbc-ap.tAI_Cancelled_List_5GS",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Broadcast_Empty_Area_List_item,
      { "Global-ENB-ID", "sbc-ap.Global_ENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Broadcast_Empty_Area_List_5GS_item,
      { "Global-RAN-Node-ID", "sbc-ap.Global_RAN_Node_ID",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_Global_RAN_Node_ID_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_CancelledCellinEAI_item,
      { "CancelledCellinEAI-Item", "sbc-ap.CancelledCellinEAI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_eCGI,
      { "eCGI", "sbc-ap.eCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EUTRAN_CGI", HFILL }},
    { &hf_sbc_ap_numberOfBroadcasts,
      { "numberOfBroadcasts", "sbc-ap.numberOfBroadcasts",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_CancelledCellinTAI_item,
      { "CancelledCellinTAI-Item", "sbc-ap.CancelledCellinTAI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_CancelledCellinTAI_5GS_item,
      { "CancelledCellinTAI-5GS item", "sbc-ap.CancelledCellinTAI_5GS_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_nR_CGI,
      { "nR-CGI", "sbc-ap.nR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_CellId_Broadcast_List_item,
      { "CellId-Broadcast-List-Item", "sbc-ap.CellId_Broadcast_List_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_CellId_Broadcast_List_5GS_item,
      { "CellId-Broadcast-List-5GS item", "sbc-ap.CellId_Broadcast_List_5GS_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_CellID_Cancelled_List_item,
      { "CellID-Cancelled-Item", "sbc-ap.CellID_Cancelled_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_CellID_Cancelled_List_5GS_item,
      { "CellID-Cancelled-List-5GS item", "sbc-ap.CellID_Cancelled_List_5GS_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_procedureCode,
      { "procedureCode", "sbc-ap.procedureCode",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_ProcedureCode_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_triggeringMessage,
      { "triggeringMessage", "sbc-ap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_procedureCriticality,
      { "procedureCriticality", "sbc-ap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_sbc_ap_iE_CriticalityDiagnostics,
      { "iE-CriticalityDiagnostics", "sbc-ap.iE_CriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_sbc_ap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "sbc-ap.CriticalityDiagnostics_IE_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_iECriticality,
      { "iECriticality", "sbc-ap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_sbc_ap_iE_ID,
      { "iE-ID", "sbc-ap.iE_ID",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_sbc_ap_typeOfError,
      { "typeOfError", "sbc-ap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_ECGIList_item,
      { "EUTRAN-CGI", "sbc-ap.EUTRAN_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Emergency_Area_ID_List_item,
      { "Emergency-Area-ID", "sbc-ap.Emergency_Area_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_EmergencyAreaID_Broadcast_List_item,
      { "EmergencyAreaID-Broadcast-List-Item", "sbc-ap.EmergencyAreaID_Broadcast_List_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_emergencyAreaID,
      { "emergencyAreaID", "sbc-ap.emergencyAreaID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Emergency_Area_ID", HFILL }},
    { &hf_sbc_ap_scheduledCellinEAI,
      { "scheduledCellinEAI", "sbc-ap.scheduledCellinEAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_EmergencyAreaID_Cancelled_List_item,
      { "EmergencyAreaID-Cancelled-Item", "sbc-ap.EmergencyAreaID_Cancelled_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_cancelledCellinEAI,
      { "cancelledCellinEAI", "sbc-ap.cancelledCellinEAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_pLMNidentity,
      { "pLMNidentity", "sbc-ap.pLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_cell_ID,
      { "cell-ID", "sbc-ap.cell_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CellIdentity", HFILL }},
    { &hf_sbc_ap_macroENB_ID,
      { "macroENB-ID", "sbc-ap.macroENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_sbc_ap_homeENB_ID,
      { "homeENB-ID", "sbc-ap.homeENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_28", HFILL }},
    { &hf_sbc_ap_short_macroENB_ID,
      { "short-macroENB-ID", "sbc-ap.short_macroENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_sbc_ap_long_macroENB_ID,
      { "long-macroENB-ID", "sbc-ap.long_macroENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_sbc_ap_Failed_Cell_List_item,
      { "EUTRAN-CGI", "sbc-ap.EUTRAN_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Failed_Cell_List_NR_item,
      { "NR-CGI", "sbc-ap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_eNB_ID,
      { "eNB-ID", "sbc-ap.eNB_ID",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_ENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_global_GNB_ID,
      { "global-GNB-ID", "sbc-ap.global_GNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_global_NgENB_ID,
      { "global-NgENB-ID", "sbc-ap.global_NgENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_gNB_ID,
      { "gNB-ID", "sbc-ap.gNB_ID",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_GNB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_gNB_ID_01,
      { "gNB-ID", "sbc-ap.gNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22_32", HFILL }},
    { &hf_sbc_ap_ngENB_ID,
      { "ngENB-ID", "sbc-ap.ngENB_ID",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_ENB_ID_vals), 0,
        "ENB_ID", HFILL }},
    { &hf_sbc_ap_List_of_TAIs_item,
      { "List-of-TAIs item", "sbc-ap.List_of_TAIs_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_tai,
      { "tai", "sbc-ap.tai_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_List_of_TAIs_Restart_item,
      { "List-of-TAIs-Restart item", "sbc-ap.List_of_TAIs_Restart_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_List_of_EAIs_Restart_item,
      { "Emergency-Area-ID", "sbc-ap.Emergency_Area_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_List_of_5GS_TAIs_item,
      { "TAI-5GS", "sbc-ap.TAI_5GS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_List_of_5GS_TAI_for_Restart_item,
      { "TAI-5GS", "sbc-ap.TAI_5GS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_NR_CGIList_item,
      { "NR-CGI", "sbc-ap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_nRCellIdentity,
      { "nRCellIdentity", "sbc-ap.nRCellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Restarted_Cell_List_item,
      { "EUTRAN-CGI", "sbc-ap.EUTRAN_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Restarted_Cell_List_NR_item,
      { "NR-CGI", "sbc-ap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_ScheduledCellinEAI_item,
      { "ScheduledCellinEAI-Item", "sbc-ap.ScheduledCellinEAI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_ScheduledCellinTAI_item,
      { "ScheduledCellinTAI-Item", "sbc-ap.ScheduledCellinTAI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_ScheduledCellinTAI_5GS_item,
      { "ScheduledCellinTAI-5GS item", "sbc-ap.ScheduledCellinTAI_5GS_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_TAI_Broadcast_List_item,
      { "TAI-Broadcast-List-Item", "sbc-ap.TAI_Broadcast_List_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_tAI,
      { "tAI", "sbc-ap.tAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_scheduledCellinTAI,
      { "scheduledCellinTAI", "sbc-ap.scheduledCellinTAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_TAI_Broadcast_List_5GS_item,
      { "TAI-Broadcast-List-5GS item", "sbc-ap.TAI_Broadcast_List_5GS_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_tAI_5GS,
      { "tAI-5GS", "sbc-ap.tAI_5GS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_scheduledCellinTAI_5GS,
      { "scheduledCellinTAI-5GS", "sbc-ap.scheduledCellinTAI_5GS",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_TAI_Cancelled_List_item,
      { "TAI-Cancelled-List-Item", "sbc-ap.TAI_Cancelled_List_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_cancelledCellinTAI,
      { "cancelledCellinTAI", "sbc-ap.cancelledCellinTAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_TAI_Cancelled_List_5GS_item,
      { "TAI-Cancelled-List-5GS item", "sbc-ap.TAI_Cancelled_List_5GS_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_cancelledCellinTAI_5GS,
      { "cancelledCellinTAI-5GS", "sbc-ap.cancelledCellinTAI_5GS",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_TAI_List_for_Warning_item,
      { "TAI", "sbc-ap.TAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_tAC,
      { "tAC", "sbc-ap.tAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_tAC_5GS,
      { "tAC-5GS", "sbc-ap.tAC_5GS",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Unknown_5GS_Tracking_Area_List_item,
      { "TAI-5GS", "sbc-ap.TAI_5GS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_cell_ID_List,
      { "cell-ID-List", "sbc-ap.cell_ID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ECGIList", HFILL }},
    { &hf_sbc_ap_tracking_Area_List_for_Warning,
      { "tracking-Area-List-for-Warning", "sbc-ap.tracking_Area_List_for_Warning",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TAI_List_for_Warning", HFILL }},
    { &hf_sbc_ap_emergency_Area_ID_List,
      { "emergency-Area-ID-List", "sbc-ap.emergency_Area_ID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_nR_CGIList,
      { "nR-CGIList", "sbc-ap.nR_CGIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_tAIList_5GS,
      { "tAIList-5GS", "sbc-ap.tAIList_5GS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TAI_5GS", HFILL }},
    { &hf_sbc_ap_emergencyAreaIDList,
      { "emergencyAreaIDList", "sbc-ap.emergencyAreaIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Emergency_Area_ID_List", HFILL }},
    { &hf_sbc_ap_protocolIEs,
      { "protocolIEs", "sbc-ap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_sbc_ap_protocolExtensions,
      { "protocolExtensions", "sbc-ap.protocolExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_sbc_ap_initiatingMessage,
      { "initiatingMessage", "sbc-ap.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_successfulOutcome,
      { "successfulOutcome", "sbc-ap.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "sbc-ap.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_initiatingMessagevalue,
      { "value", "sbc-ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_sbc_ap_successfulOutcome_value,
      { "value", "sbc-ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_sbc_ap_unsuccessfulOutcome_value,
      { "value", "sbc-ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
                  &ett_sbc_ap,
                  &ett_sbc_ap_Serial_Number,
                  &ett_sbc_ap_Warning_Type,
                  &ett_sbc_ap_Data_Coding_Scheme,
                  &ett_sbc_ap_Warning_Message_Contents,
    &ett_sbc_ap_ProtocolIE_Container,
    &ett_sbc_ap_ProtocolIE_Field,
    &ett_sbc_ap_ProtocolExtensionContainer,
    &ett_sbc_ap_ProtocolExtensionField,
    &ett_sbc_ap_Broadcast_Scheduled_Area_List,
    &ett_sbc_ap_Broadcast_Scheduled_Area_List_5GS,
    &ett_sbc_ap_Broadcast_Cancelled_Area_List,
    &ett_sbc_ap_Broadcast_Cancelled_Area_List_5GS,
    &ett_sbc_ap_Broadcast_Empty_Area_List,
    &ett_sbc_ap_Broadcast_Empty_Area_List_5GS,
    &ett_sbc_ap_CancelledCellinEAI,
    &ett_sbc_ap_CancelledCellinEAI_Item,
    &ett_sbc_ap_CancelledCellinTAI,
    &ett_sbc_ap_CancelledCellinTAI_Item,
    &ett_sbc_ap_CancelledCellinTAI_5GS,
    &ett_sbc_ap_CancelledCellinTAI_5GS_item,
    &ett_sbc_ap_CellId_Broadcast_List,
    &ett_sbc_ap_CellId_Broadcast_List_Item,
    &ett_sbc_ap_CellId_Broadcast_List_5GS,
    &ett_sbc_ap_CellId_Broadcast_List_5GS_item,
    &ett_sbc_ap_CellID_Cancelled_List,
    &ett_sbc_ap_CellID_Cancelled_Item,
    &ett_sbc_ap_CellID_Cancelled_List_5GS,
    &ett_sbc_ap_CellID_Cancelled_List_5GS_item,
    &ett_sbc_ap_Criticality_Diagnostics,
    &ett_sbc_ap_CriticalityDiagnostics_IE_List,
    &ett_sbc_ap_CriticalityDiagnostics_IE_List_item,
    &ett_sbc_ap_ECGIList,
    &ett_sbc_ap_Emergency_Area_ID_List,
    &ett_sbc_ap_EmergencyAreaID_Broadcast_List,
    &ett_sbc_ap_EmergencyAreaID_Broadcast_List_Item,
    &ett_sbc_ap_EmergencyAreaID_Cancelled_List,
    &ett_sbc_ap_EmergencyAreaID_Cancelled_Item,
    &ett_sbc_ap_EUTRAN_CGI,
    &ett_sbc_ap_ENB_ID,
    &ett_sbc_ap_Failed_Cell_List,
    &ett_sbc_ap_Failed_Cell_List_NR,
    &ett_sbc_ap_Global_ENB_ID,
    &ett_sbc_ap_Global_RAN_Node_ID,
    &ett_sbc_ap_Global_GNB_ID,
    &ett_sbc_ap_GNB_ID,
    &ett_sbc_ap_Global_NgENB_ID,
    &ett_sbc_ap_List_of_TAIs,
    &ett_sbc_ap_List_of_TAIs_item,
    &ett_sbc_ap_List_of_TAIs_Restart,
    &ett_sbc_ap_List_of_TAIs_Restart_item,
    &ett_sbc_ap_List_of_EAIs_Restart,
    &ett_sbc_ap_List_of_5GS_TAIs,
    &ett_sbc_ap_List_of_5GS_TAI_for_Restart,
    &ett_sbc_ap_NR_CGIList,
    &ett_sbc_ap_NR_CGI,
    &ett_sbc_ap_Restarted_Cell_List,
    &ett_sbc_ap_Restarted_Cell_List_NR,
    &ett_sbc_ap_ScheduledCellinEAI,
    &ett_sbc_ap_ScheduledCellinEAI_Item,
    &ett_sbc_ap_ScheduledCellinTAI,
    &ett_sbc_ap_ScheduledCellinTAI_Item,
    &ett_sbc_ap_ScheduledCellinTAI_5GS,
    &ett_sbc_ap_ScheduledCellinTAI_5GS_item,
    &ett_sbc_ap_TAI_Broadcast_List,
    &ett_sbc_ap_TAI_Broadcast_List_Item,
    &ett_sbc_ap_TAI_Broadcast_List_5GS,
    &ett_sbc_ap_TAI_Broadcast_List_5GS_item,
    &ett_sbc_ap_TAI_Cancelled_List,
    &ett_sbc_ap_TAI_Cancelled_List_Item,
    &ett_sbc_ap_TAI_Cancelled_List_5GS,
    &ett_sbc_ap_TAI_Cancelled_List_5GS_item,
    &ett_sbc_ap_TAI_List_for_Warning,
    &ett_sbc_ap_TAI,
    &ett_sbc_ap_TAI_5GS,
    &ett_sbc_ap_Unknown_5GS_Tracking_Area_List,
    &ett_sbc_ap_Warning_Area_List,
    &ett_sbc_ap_Warning_Area_List_5GS,
    &ett_sbc_ap_Write_Replace_Warning_Request,
    &ett_sbc_ap_Write_Replace_Warning_Response,
    &ett_sbc_ap_Stop_Warning_Request,
    &ett_sbc_ap_Stop_Warning_Response,
    &ett_sbc_ap_Write_Replace_Warning_Indication,
    &ett_sbc_ap_Stop_Warning_Indication,
    &ett_sbc_ap_PWS_Restart_Indication,
    &ett_sbc_ap_PWS_Failure_Indication,
    &ett_sbc_ap_Error_Indication,
    &ett_sbc_ap_SBC_AP_PDU,
    &ett_sbc_ap_InitiatingMessage,
    &ett_sbc_ap_SuccessfulOutcome,
    &ett_sbc_ap_UnsuccessfulOutcome,
  };


  /* Register protocol */
  proto_sbc_ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_sbc_ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  sbc_ap_handle = register_dissector(PFNAME, dissect_sbc_ap, proto_sbc_ap);

  /* Register dissector tables */
  sbc_ap_ies_dissector_table = register_dissector_table("sbc_ap.ies", "SBC-AP-PROTOCOL-IES", proto_sbc_ap, FT_UINT32, BASE_DEC);
  sbc_ap_extension_dissector_table = register_dissector_table("sbc_ap.extension", "SBC-AP-PROTOCOL-EXTENSION", proto_sbc_ap, FT_UINT32, BASE_DEC);
  sbc_ap_proc_imsg_dissector_table = register_dissector_table("sbc_ap.proc.imsg", "SBC-AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_sbc_ap, FT_UINT32, BASE_DEC);
  sbc_ap_proc_sout_dissector_table = register_dissector_table("sbc_ap.proc.sout", "SBC-AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_sbc_ap, FT_UINT32, BASE_DEC);
  sbc_ap_proc_uout_dissector_table = register_dissector_table("sbc_ap.proc.uout", "SBC-AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_sbc_ap, FT_UINT32, BASE_DEC);


}


/*--- proto_reg_handoff_sbc_ap ---------------------------------------*/
void
proto_reg_handoff_sbc_ap(void)
{
    static bool inited = false;
	static unsigned SctpPort;

    if( !inited ) {
        dissector_add_uint("sctp.ppi", SBC_AP_PAYLOAD_PROTOCOL_ID,   sbc_ap_handle);
        inited = true;
  dissector_add_uint("sbc_ap.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Criticality_Diagnostics, create_dissector_handle(dissect_Criticality_Diagnostics_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Data_Coding_Scheme, create_dissector_handle(dissect_Data_Coding_Scheme_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Message_Identifier, create_dissector_handle(dissect_Message_Identifier_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Number_of_Broadcasts_Requested, create_dissector_handle(dissect_Number_of_Broadcasts_Requested_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Repetition_Period, create_dissector_handle(dissect_Repetition_Period_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Serial_Number, create_dissector_handle(dissect_Serial_Number_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_List_of_TAIs, create_dissector_handle(dissect_List_of_TAIs_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Warning_Area_List, create_dissector_handle(dissect_Warning_Area_List_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Warning_Message_Content, create_dissector_handle(dissect_Warning_Message_Content_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Warning_Security_Information, create_dissector_handle(dissect_Warning_Security_Information_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Warning_Type, create_dissector_handle(dissect_Warning_Type_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Omc_Id, create_dissector_handle(dissect_Omc_Id_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Concurrent_Warning_Message_Indicator, create_dissector_handle(dissect_Concurrent_Warning_Message_Indicator_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Extended_Repetition_Period, create_dissector_handle(dissect_Extended_Repetition_Period_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Unknown_Tracking_Area_List, create_dissector_handle(dissect_List_of_TAIs_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Broadcast_Scheduled_Area_List, create_dissector_handle(dissect_Broadcast_Scheduled_Area_List_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Send_Write_Replace_Warning_Indication, create_dissector_handle(dissect_Send_Write_Replace_Warning_Indication_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Broadcast_Cancelled_Area_List, create_dissector_handle(dissect_Broadcast_Cancelled_Area_List_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Send_Stop_Warning_Indication, create_dissector_handle(dissect_Send_Stop_Warning_Indication_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Stop_All_Indicator, create_dissector_handle(dissect_Stop_All_Indicator_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Global_ENB_ID, create_dissector_handle(dissect_Global_ENB_ID_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Broadcast_Empty_Area_List, create_dissector_handle(dissect_Broadcast_Empty_Area_List_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Restarted_Cell_List, create_dissector_handle(dissect_Restarted_Cell_List_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_List_of_TAIs_Restart, create_dissector_handle(dissect_List_of_TAIs_Restart_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_List_of_EAIs_Restart, create_dissector_handle(dissect_List_of_EAIs_Restart_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Failed_Cell_List, create_dissector_handle(dissect_Failed_Cell_List_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.extension", id_List_of_5GS_TAIs, create_dissector_handle(dissect_List_of_5GS_TAIs_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.extension", id_Warning_Area_List_5GS, create_dissector_handle(dissect_Warning_Area_List_5GS_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.extension", id_Global_RAN_Node_ID, create_dissector_handle(dissect_Global_RAN_Node_ID_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.extension", id_Global_GNB_ID, create_dissector_handle(dissect_Global_GNB_ID_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.extension", id_RAT_Selector_5GS, create_dissector_handle(dissect_RAT_Selector_5GS_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.extension", id_Unknown_5GS_Tracking_Area_List, create_dissector_handle(dissect_Unknown_5GS_Tracking_Area_List_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.extension", id_Broadcast_Scheduled_Area_List_5GS, create_dissector_handle(dissect_Broadcast_Scheduled_Area_List_5GS_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.extension", id_Broadcast_Cancelled_Area_List_5GS, create_dissector_handle(dissect_Broadcast_Cancelled_Area_List_5GS_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.extension", id_Broadcast_Empty_Area_List_5GS, create_dissector_handle(dissect_Broadcast_Empty_Area_List_5GS_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.extension", id_Restarted_Cell_List_NR, create_dissector_handle(dissect_Restarted_Cell_List_NR_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.extension", id_Failed_Cell_List_NR, create_dissector_handle(dissect_Failed_Cell_List_NR_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.extension", id_List_of_5GS_TAI_for_Restart, create_dissector_handle(dissect_List_of_5GS_TAI_for_Restart_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Warning_Area_Coordinates, create_dissector_handle(dissect_Warning_Area_Coordinates_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.proc.imsg", id_Write_Replace_Warning, create_dissector_handle(dissect_Write_Replace_Warning_Request_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.proc.sout", id_Write_Replace_Warning, create_dissector_handle(dissect_Write_Replace_Warning_Response_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.proc.imsg", id_Stop_Warning, create_dissector_handle(dissect_Stop_Warning_Request_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.proc.sout", id_Stop_Warning, create_dissector_handle(dissect_Stop_Warning_Response_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.proc.imsg", id_Error_Indication, create_dissector_handle(dissect_Error_Indication_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.proc.imsg", id_Write_Replace_Warning_Indication, create_dissector_handle(dissect_Write_Replace_Warning_Indication_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.proc.imsg", id_Stop_Warning_Indication, create_dissector_handle(dissect_Stop_Warning_Indication_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.proc.imsg", id_PWS_Restart_Indication, create_dissector_handle(dissect_PWS_Restart_Indication_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.proc.imsg", id_PWS_Failure_Indication, create_dissector_handle(dissect_PWS_Failure_Indication_PDU, proto_sbc_ap));

	} else {
		if (SctpPort != 0) {
			dissector_delete_uint("sctp.port", SctpPort, sbc_ap_handle);
		}
	}

	SctpPort = global_sbc_ap_port;
	if (SctpPort != 0) {
		dissector_add_uint("sctp.port", SctpPort, sbc_ap_handle);
	}

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
