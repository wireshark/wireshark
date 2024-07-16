/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-sabp.c                                                              */
/* asn2wrs.py -q -L -p sabp -c ./sabp.cnf -s ./packet-sabp-template -D . -O ../.. SABP-CommonDataTypes.asn SABP-Constants.asn SABP-Containers.asn SABP-IEs.asn SABP-PDU-Contents.asn SABP-PDU-Descriptions.asn */

/* packet-sabp-template.c
 * Routines for UTRAN Iu-BC Interface: Service Area Broadcast Protocol (SABP) packet dissection
 * Copyright 2007, Tomas Kukosa <tomas.kukosa@siemens.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: 3GPP TS 25.419 version  V9.0.0 (2009-12)
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/asn1.h>

#include "packet-tcp.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-gsm_map.h"
#include "packet-gsm_sms.h"
#include <epan/sctpppids.h>
#include "packet-cell_broadcast.h"

#define PNAME  "UTRAN IuBC interface SABP signaling"
#define PSNAME "SABP"
#define PFNAME "sabp"

#define maxNrOfErrors                  256
#define maxnoofSAI                     65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxNrOfLevels                  256

typedef enum _ProcedureCode_enum {
  id_Write_Replace =   0,
  id_Kill      =   1,
  id_Load_Status_Enquiry =   2,
  id_Message_Status_Query =   3,
  id_Restart_Indication =   4,
  id_Reset     =   5,
  id_Failure_Indication =   6,
  id_Error_Indication =   7
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_Broadcast_Message_Content =   0,
  id_Category  =   1,
  id_Cause     =   2,
  id_Criticality_Diagnostics =   3,
  id_Data_Coding_Scheme =   4,
  id_Failure_List =   5,
  id_Message_Identifier =   6,
  id_New_Serial_Number =   7,
  id_Number_of_Broadcasts_Completed_List =   8,
  id_Number_of_Broadcasts_Requested =   9,
  id_Old_Serial_Number =  10,
  id_Radio_Resource_Loading_List =  11,
  id_Recovery_Indication =  12,
  id_Repetition_Period =  13,
  id_Serial_Number =  14,
  id_Service_Areas_List =  15,
  id_MessageStructure =  16,
  id_TypeOfError =  17,
  id_Paging_ETWS_Indicator =  18,
  id_Warning_Type =  19,
  id_WarningSecurityInfo =  20,
  id_Broadcast_Message_Content_Validity_Indicator =  21
} ProtocolIE_ID_enum;

void proto_register_sabp(void);
void proto_reg_handoff_sabp(void);

/* Initialize the protocol and registered fields */
static int proto_sabp;

static int hf_sabp_no_of_pages;
static int hf_sabp_cb_inf_len;
static int hf_sabp_cb_msg_inf_page;
static int hf_sabp_cbs_page_content;
static int hf_sabp_Broadcast_Message_Content_PDU;  /* Broadcast_Message_Content */
static int hf_sabp_Broadcast_Message_Content_Validity_Indicator_PDU;  /* Broadcast_Message_Content_Validity_Indicator */
static int hf_sabp_Category_PDU;                  /* Category */
static int hf_sabp_Cause_PDU;                     /* Cause */
static int hf_sabp_Criticality_Diagnostics_PDU;   /* Criticality_Diagnostics */
static int hf_sabp_MessageStructure_PDU;          /* MessageStructure */
static int hf_sabp_Data_Coding_Scheme_PDU;        /* Data_Coding_Scheme */
static int hf_sabp_Failure_List_PDU;              /* Failure_List */
static int hf_sabp_Message_Identifier_PDU;        /* Message_Identifier */
static int hf_sabp_New_Serial_Number_PDU;         /* New_Serial_Number */
static int hf_sabp_Number_of_Broadcasts_Completed_List_PDU;  /* Number_of_Broadcasts_Completed_List */
static int hf_sabp_Number_of_Broadcasts_Requested_PDU;  /* Number_of_Broadcasts_Requested */
static int hf_sabp_Old_Serial_Number_PDU;         /* Old_Serial_Number */
static int hf_sabp_Paging_ETWS_Indicator_PDU;     /* Paging_ETWS_Indicator */
static int hf_sabp_Radio_Resource_Loading_List_PDU;  /* Radio_Resource_Loading_List */
static int hf_sabp_Recovery_Indication_PDU;       /* Recovery_Indication */
static int hf_sabp_Repetition_Period_PDU;         /* Repetition_Period */
static int hf_sabp_Serial_Number_PDU;             /* Serial_Number */
static int hf_sabp_Service_Areas_List_PDU;        /* Service_Areas_List */
static int hf_sabp_TypeOfError_PDU;               /* TypeOfError */
static int hf_sabp_WarningSecurityInfo_PDU;       /* WarningSecurityInfo */
static int hf_sabp_Warning_Type_PDU;              /* Warning_Type */
static int hf_sabp_Write_Replace_PDU;             /* Write_Replace */
static int hf_sabp_Write_Replace_Complete_PDU;    /* Write_Replace_Complete */
static int hf_sabp_Write_Replace_Failure_PDU;     /* Write_Replace_Failure */
static int hf_sabp_Kill_PDU;                      /* Kill */
static int hf_sabp_Kill_Complete_PDU;             /* Kill_Complete */
static int hf_sabp_Kill_Failure_PDU;              /* Kill_Failure */
static int hf_sabp_Load_Query_PDU;                /* Load_Query */
static int hf_sabp_Load_Query_Complete_PDU;       /* Load_Query_Complete */
static int hf_sabp_Load_Query_Failure_PDU;        /* Load_Query_Failure */
static int hf_sabp_Message_Status_Query_PDU;      /* Message_Status_Query */
static int hf_sabp_Message_Status_Query_Complete_PDU;  /* Message_Status_Query_Complete */
static int hf_sabp_Message_Status_Query_Failure_PDU;  /* Message_Status_Query_Failure */
static int hf_sabp_Reset_PDU;                     /* Reset */
static int hf_sabp_Reset_Complete_PDU;            /* Reset_Complete */
static int hf_sabp_Reset_Failure_PDU;             /* Reset_Failure */
static int hf_sabp_Restart_PDU;                   /* Restart */
static int hf_sabp_Failure_PDU;                   /* Failure */
static int hf_sabp_Error_Indication_PDU;          /* Error_Indication */
static int hf_sabp_SABP_PDU_PDU;                  /* SABP_PDU */
static int hf_sabp_ProtocolIE_Container_item;     /* ProtocolIE_Field */
static int hf_sabp_id;                            /* ProtocolIE_ID */
static int hf_sabp_criticality;                   /* Criticality */
static int hf_sabp_protocolIE_Field_value;        /* ProtocolIE_Field_value */
static int hf_sabp_ProtocolExtensionContainer_item;  /* ProtocolExtensionField */
static int hf_sabp_ext_id;                        /* ProtocolExtensionID */
static int hf_sabp_extensionValue;                /* T_extensionValue */
static int hf_sabp_procedureCode;                 /* ProcedureCode */
static int hf_sabp_triggeringMessage;             /* TriggeringMessage */
static int hf_sabp_procedureCriticality;          /* Criticality */
static int hf_sabp_iEsCriticalityDiagnostics;     /* CriticalityDiagnostics_IE_List */
static int hf_sabp_iE_Extensions;                 /* ProtocolExtensionContainer */
static int hf_sabp_CriticalityDiagnostics_IE_List_item;  /* CriticalityDiagnostics_IE_List_item */
static int hf_sabp_iECriticality;                 /* Criticality */
static int hf_sabp_iE_ID;                         /* ProtocolIE_ID */
static int hf_sabp_repetitionNumber;              /* RepetitionNumber0 */
static int hf_sabp_MessageStructure_item;         /* MessageStructure_item */
static int hf_sabp_repetitionNumber1;             /* RepetitionNumber1 */
static int hf_sabp_Failure_List_item;             /* Failure_List_Item */
static int hf_sabp_service_area_identifier;       /* Service_Area_Identifier */
static int hf_sabp_cause;                         /* Cause */
static int hf_sabp_Number_of_Broadcasts_Completed_List_item;  /* Number_of_Broadcasts_Completed_List_Item */
static int hf_sabp_number_of_broadcasts_completed;  /* INTEGER_0_65535 */
static int hf_sabp_number_of_broadcasts_completed_info;  /* Number_Of_Broadcasts_Completed_Info */
static int hf_sabp_Radio_Resource_Loading_List_item;  /* Radio_Resource_Loading_List_Item */
static int hf_sabp_available_bandwidth;           /* Available_Bandwidth */
static int hf_sabp_pLMNidentity;                  /* T_pLMNidentity */
static int hf_sabp_lac;                           /* OCTET_STRING_SIZE_2 */
static int hf_sabp_sac;                           /* OCTET_STRING_SIZE_2 */
static int hf_sabp_Service_Areas_List_item;       /* Service_Area_Identifier */
static int hf_sabp_protocolIEs;                   /* ProtocolIE_Container */
static int hf_sabp_protocolExtensions;            /* ProtocolExtensionContainer */
static int hf_sabp_initiatingMessage;             /* InitiatingMessage */
static int hf_sabp_successfulOutcome;             /* SuccessfulOutcome */
static int hf_sabp_unsuccessfulOutcome;           /* UnsuccessfulOutcome */
static int hf_sabp_initiatingMessage_value;       /* InitiatingMessage_value */
static int hf_sabp_successfulOutcome_value;       /* SuccessfulOutcome_value */
static int hf_sabp_unsuccessfulOutcome_value;     /* UnsuccessfulOutcome_value */

/* Initialize the subtree pointers */
static int ett_sabp;
static int ett_sabp_e212;
static int ett_sabp_cbs_data_coding;
static int ett_sabp_bcast_msg;
static int ett_sabp_cbs_serial_number;
static int ett_sabp_cbs_new_serial_number;
static int ett_sabp_cbs_page;
static int ett_sabp_cbs_page_content;

static int ett_sabp_ProtocolIE_Container;
static int ett_sabp_ProtocolIE_Field;
static int ett_sabp_ProtocolExtensionContainer;
static int ett_sabp_ProtocolExtensionField;
static int ett_sabp_Criticality_Diagnostics;
static int ett_sabp_CriticalityDiagnostics_IE_List;
static int ett_sabp_CriticalityDiagnostics_IE_List_item;
static int ett_sabp_MessageStructure;
static int ett_sabp_MessageStructure_item;
static int ett_sabp_Failure_List;
static int ett_sabp_Failure_List_Item;
static int ett_sabp_Number_of_Broadcasts_Completed_List;
static int ett_sabp_Number_of_Broadcasts_Completed_List_Item;
static int ett_sabp_Radio_Resource_Loading_List;
static int ett_sabp_Radio_Resource_Loading_List_Item;
static int ett_sabp_Service_Area_Identifier;
static int ett_sabp_Service_Areas_List;
static int ett_sabp_Write_Replace;
static int ett_sabp_Write_Replace_Complete;
static int ett_sabp_Write_Replace_Failure;
static int ett_sabp_Kill;
static int ett_sabp_Kill_Complete;
static int ett_sabp_Kill_Failure;
static int ett_sabp_Load_Query;
static int ett_sabp_Load_Query_Complete;
static int ett_sabp_Load_Query_Failure;
static int ett_sabp_Message_Status_Query;
static int ett_sabp_Message_Status_Query_Complete;
static int ett_sabp_Message_Status_Query_Failure;
static int ett_sabp_Reset;
static int ett_sabp_Reset_Complete;
static int ett_sabp_Reset_Failure;
static int ett_sabp_Restart;
static int ett_sabp_Failure;
static int ett_sabp_Error_Indication;
static int ett_sabp_SABP_PDU;
static int ett_sabp_InitiatingMessage;
static int ett_sabp_SuccessfulOutcome;
static int ett_sabp_UnsuccessfulOutcome;

/* Global variables */
static uint32_t ProcedureCode;
static uint32_t ProtocolIE_ID;
static uint32_t ProtocolExtensionID;
static uint8_t sms_encoding;

#define SABP_PORT 3452

/* Dissector tables */
static dissector_table_t sabp_ies_dissector_table;
static dissector_table_t sabp_extension_dissector_table;
static dissector_table_t sabp_proc_imsg_dissector_table;
static dissector_table_t sabp_proc_sout_dissector_table;
static dissector_table_t sabp_proc_uout_dissector_table;

static dissector_handle_t sabp_handle;
static dissector_handle_t sabp_tcp_handle;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static void dissect_sabp_cb_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


static const value_string sabp_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_sabp_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}


static const value_string sabp_ProcedureCode_vals[] = {
  { id_Write_Replace, "id-Write-Replace" },
  { id_Kill, "id-Kill" },
  { id_Load_Status_Enquiry, "id-Load-Status-Enquiry" },
  { id_Message_Status_Query, "id-Message-Status-Query" },
  { id_Restart_Indication, "id-Restart-Indication" },
  { id_Reset, "id-Reset" },
  { id_Failure_Indication, "id-Failure-Indication" },
  { id_Error_Indication, "id-Error-Indication" },
  { 0, NULL }
};

static value_string_ext sabp_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(sabp_ProcedureCode_vals);


static int
dissect_sabp_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, false);

       col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
                   val_to_str_ext_const(ProcedureCode, &sabp_ProcedureCode_vals_ext,
                                        "unknown message"));
  return offset;
}



static int
dissect_sabp_ProtocolExtensionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolExtensionID, false);

  return offset;
}


static const value_string sabp_ProtocolIE_ID_vals[] = {
  { id_Broadcast_Message_Content, "id-Broadcast-Message-Content" },
  { id_Category, "id-Category" },
  { id_Cause, "id-Cause" },
  { id_Criticality_Diagnostics, "id-Criticality-Diagnostics" },
  { id_Data_Coding_Scheme, "id-Data-Coding-Scheme" },
  { id_Failure_List, "id-Failure-List" },
  { id_Message_Identifier, "id-Message-Identifier" },
  { id_New_Serial_Number, "id-New-Serial-Number" },
  { id_Number_of_Broadcasts_Completed_List, "id-Number-of-Broadcasts-Completed-List" },
  { id_Number_of_Broadcasts_Requested, "id-Number-of-Broadcasts-Requested" },
  { id_Old_Serial_Number, "id-Old-Serial-Number" },
  { id_Radio_Resource_Loading_List, "id-Radio-Resource-Loading-List" },
  { id_Recovery_Indication, "id-Recovery-Indication" },
  { id_Repetition_Period, "id-Repetition-Period" },
  { id_Serial_Number, "id-Serial-Number" },
  { id_Service_Areas_List, "id-Service-Areas-List" },
  { id_MessageStructure, "id-MessageStructure" },
  { id_TypeOfError, "id-TypeOfError" },
  { id_Paging_ETWS_Indicator, "id-Paging-ETWS-Indicator" },
  { id_Warning_Type, "id-Warning-Type" },
  { id_WarningSecurityInfo, "id-WarningSecurityInfo" },
  { id_Broadcast_Message_Content_Validity_Indicator, "id-Broadcast-Message-Content-Validity-Indicator" },
  { 0, NULL }
};

static value_string_ext sabp_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(sabp_ProtocolIE_ID_vals);


static int
dissect_sabp_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolIE_ID, false);

  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s",
                           val_to_str_ext(ProtocolIE_ID, &sabp_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }
  return offset;
}


static const value_string sabp_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessful-outcome" },
  {   3, "outcome" },
  { 0, NULL }
};


static int
dissect_sabp_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_sabp_ProtocolIE_Field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_sabp_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_ID },
  { &hf_sabp_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_Criticality },
  { &hf_sabp_protocolIE_Field_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_sabp_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Field },
};

static int
dissect_sabp_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sabp_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, false);

  return offset;
}



static int
dissect_sabp_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_sabp_ext_id         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolExtensionID },
  { &hf_sabp_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_Criticality },
  { &hf_sabp_extensionValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_sabp_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolExtensionField },
};

static int
dissect_sabp_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sabp_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, false);

  return offset;
}



static int
dissect_sabp_Available_Bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 20480U, NULL, false);

  return offset;
}



static int
dissect_sabp_Broadcast_Message_Content(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
 tvbuff_t *parameter_tvb=NULL;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 9968, false, NULL, 0, &parameter_tvb, NULL);

	if (!parameter_tvb)
		return offset;
    dissect_sabp_cb_data(parameter_tvb, actx->pinfo, tree);

  return offset;
}


static const value_string sabp_Broadcast_Message_Content_Validity_Indicator_vals[] = {
  {   0, "broadcast-Message-Content-not-valid" },
  { 0, NULL }
};


static int
dissect_sabp_Broadcast_Message_Content_Validity_Indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string sabp_Category_vals[] = {
  {   0, "high-priority" },
  {   1, "background-priority" },
  {   2, "normal-priority" },
  {   3, "default-priority" },
  { 0, NULL }
};


static int
dissect_sabp_Category(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const value_string sabp_Cause_vals[] = {
  {   0, "parameter-not-recognised" },
  {   1, "parameter-value-invalid" },
  {   2, "valid-CN-message-not-identified" },
  {   3, "service-area-identity-not-valid" },
  {   4, "unrecognised-message" },
  {   5, "missing-mandatory-element" },
  {   6, "rNC-capacity-exceeded" },
  {   7, "rNC-memory-exceeded" },
  {   8, "service-area-broadcast-not-supported" },
  {   9, "service-area-broadcast-not-operational" },
  {  10, "message-reference-already-used" },
  {  11, "unspecifed-error" },
  {  12, "transfer-syntax-error" },
  {  13, "semantic-error" },
  {  14, "message-not-compatible-with-receiver-state" },
  {  15, "abstract-syntax-error-reject" },
  {  16, "abstract-syntax-error-ignore-and-notify" },
  {  17, "abstract-syntax-error-falsely-constructed-message" },
  { 0, NULL }
};

static value_string_ext sabp_Cause_vals_ext = VALUE_STRING_EXT_INIT(sabp_Cause_vals);


static int
dissect_sabp_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_sabp_RepetitionNumber0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_sabp_iECriticality  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_Criticality },
  { &hf_sabp_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_ID },
  { &hf_sabp_repetitionNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_RepetitionNumber0 },
  { &hf_sabp_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_sabp_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_sabp_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sabp_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxNrOfErrors, false);

  return offset;
}


static const per_sequence_t Criticality_Diagnostics_sequence[] = {
  { &hf_sabp_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProcedureCode },
  { &hf_sabp_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_TriggeringMessage },
  { &hf_sabp_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_Criticality },
  { &hf_sabp_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_CriticalityDiagnostics_IE_List },
  { &hf_sabp_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Criticality_Diagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Criticality_Diagnostics, Criticality_Diagnostics_sequence);

  return offset;
}



static int
dissect_sabp_RepetitionNumber1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, false);

  return offset;
}


static const per_sequence_t MessageStructure_item_sequence[] = {
  { &hf_sabp_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_ID },
  { &hf_sabp_repetitionNumber1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_RepetitionNumber1 },
  { &hf_sabp_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_MessageStructure_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_MessageStructure_item, MessageStructure_item_sequence);

  return offset;
}


static const per_sequence_t MessageStructure_sequence_of[1] = {
  { &hf_sabp_MessageStructure_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_MessageStructure_item },
};

static int
dissect_sabp_MessageStructure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sabp_MessageStructure, MessageStructure_sequence_of,
                                                  1, maxNrOfLevels, false);

  return offset;
}



static int
dissect_sabp_Data_Coding_Scheme(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
 tvbuff_t *parameter_tvb=NULL;
 proto_tree *subtree;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, &parameter_tvb, NULL);


	if (!parameter_tvb)
		return offset;
	subtree = proto_item_add_subtree(actx->created_item, ett_sabp_cbs_data_coding);
	sms_encoding = dissect_cbs_data_coding_scheme(parameter_tvb, actx->pinfo, subtree, 0);


  return offset;
}



static int
dissect_sabp_T_pLMNidentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb=NULL;
 proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, &parameter_tvb);

	 if (!parameter_tvb)
		return offset;
	subtree = proto_item_add_subtree(actx->created_item, ett_sabp_e212);
	dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, subtree, 0, E212_SAI, false);


  return offset;
}



static int
dissect_sabp_OCTET_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, NULL);

  return offset;
}


static const per_sequence_t Service_Area_Identifier_sequence[] = {
  { &hf_sabp_pLMNidentity   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_T_pLMNidentity },
  { &hf_sabp_lac            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_OCTET_STRING_SIZE_2 },
  { &hf_sabp_sac            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_OCTET_STRING_SIZE_2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Service_Area_Identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Service_Area_Identifier, Service_Area_Identifier_sequence);

  return offset;
}


static const per_sequence_t Failure_List_Item_sequence[] = {
  { &hf_sabp_service_area_identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_Service_Area_Identifier },
  { &hf_sabp_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_Cause },
  { &hf_sabp_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Failure_List_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Failure_List_Item, Failure_List_Item_sequence);

  return offset;
}


static const per_sequence_t Failure_List_sequence_of[1] = {
  { &hf_sabp_Failure_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_Failure_List_Item },
};

static int
dissect_sabp_Failure_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sabp_Failure_List, Failure_List_sequence_of,
                                                  1, maxnoofSAI, false);

  return offset;
}



static int
dissect_sabp_Message_Identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
 tvbuff_t *parameter_tvb=NULL;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, &parameter_tvb, NULL);

	if (!parameter_tvb)
		return offset;
        dissect_cbs_message_identifier(parameter_tvb, tree, 0);


  return offset;
}



static int
dissect_sabp_Serial_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
 tvbuff_t *parameter_tvb=NULL;
 proto_tree *subtree;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, &parameter_tvb, NULL);

	if (!parameter_tvb)
		return offset;
	subtree = proto_item_add_subtree(actx->created_item, ett_sabp_cbs_serial_number);
        dissect_cbs_serial_number(parameter_tvb, subtree, 0);


  return offset;
}



static int
dissect_sabp_New_Serial_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
 tvbuff_t *parameter_tvb=NULL;
 proto_tree *subtree;

  offset = dissect_sabp_Serial_Number(tvb, offset, actx, tree, hf_index);

	if (!parameter_tvb)
		return offset;
	subtree = proto_item_add_subtree(actx->created_item, ett_sabp_cbs_new_serial_number);
        dissect_cbs_serial_number(parameter_tvb, subtree, 0);


  return offset;
}



static int
dissect_sabp_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const value_string sabp_Number_Of_Broadcasts_Completed_Info_vals[] = {
  {   0, "overflow" },
  {   1, "unknown" },
  { 0, NULL }
};


static int
dissect_sabp_Number_Of_Broadcasts_Completed_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t Number_of_Broadcasts_Completed_List_Item_sequence[] = {
  { &hf_sabp_service_area_identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_Service_Area_Identifier },
  { &hf_sabp_number_of_broadcasts_completed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_INTEGER_0_65535 },
  { &hf_sabp_number_of_broadcasts_completed_info, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_Number_Of_Broadcasts_Completed_Info },
  { &hf_sabp_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Number_of_Broadcasts_Completed_List_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Number_of_Broadcasts_Completed_List_Item, Number_of_Broadcasts_Completed_List_Item_sequence);

  return offset;
}


static const per_sequence_t Number_of_Broadcasts_Completed_List_sequence_of[1] = {
  { &hf_sabp_Number_of_Broadcasts_Completed_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_Number_of_Broadcasts_Completed_List_Item },
};

static int
dissect_sabp_Number_of_Broadcasts_Completed_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sabp_Number_of_Broadcasts_Completed_List, Number_of_Broadcasts_Completed_List_sequence_of,
                                                  1, maxnoofSAI, false);

  return offset;
}


static const value_string sabp_Number_of_Broadcasts_Requested_vals[] = {
  {   0, "broadcast-indefinitely" },
  { 0, NULL }
};


static int
dissect_sabp_Number_of_Broadcasts_Requested(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_sabp_Old_Serial_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_sabp_Serial_Number(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string sabp_Paging_ETWS_Indicator_vals[] = {
  {   0, "paging" },
  { 0, NULL }
};


static int
dissect_sabp_Paging_ETWS_Indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t Radio_Resource_Loading_List_Item_sequence[] = {
  { &hf_sabp_service_area_identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_Service_Area_Identifier },
  { &hf_sabp_available_bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_Available_Bandwidth },
  { &hf_sabp_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Radio_Resource_Loading_List_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Radio_Resource_Loading_List_Item, Radio_Resource_Loading_List_Item_sequence);

  return offset;
}


static const per_sequence_t Radio_Resource_Loading_List_sequence_of[1] = {
  { &hf_sabp_Radio_Resource_Loading_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_Radio_Resource_Loading_List_Item },
};

static int
dissect_sabp_Radio_Resource_Loading_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sabp_Radio_Resource_Loading_List, Radio_Resource_Loading_List_sequence_of,
                                                  1, maxnoofSAI, false);

  return offset;
}


static const value_string sabp_Recovery_Indication_vals[] = {
  {   0, "data-lost" },
  {   1, "data-available" },
  { 0, NULL }
};


static int
dissect_sabp_Recovery_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_sabp_Repetition_Period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4096U, NULL, false);

  return offset;
}


static const per_sequence_t Service_Areas_List_sequence_of[1] = {
  { &hf_sabp_Service_Areas_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_Service_Area_Identifier },
};

static int
dissect_sabp_Service_Areas_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sabp_Service_Areas_List, Service_Areas_List_sequence_of,
                                                  1, maxnoofSAI, false);

  return offset;
}


static const value_string sabp_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_sabp_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_sabp_WarningSecurityInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       50, 50, false, NULL);

  return offset;
}



static int
dissect_sabp_Warning_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, NULL);

  return offset;
}


static const per_sequence_t Write_Replace_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Write_Replace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Write_Replace, Write_Replace_sequence);

  return offset;
}


static const per_sequence_t Write_Replace_Complete_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Write_Replace_Complete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Write_Replace_Complete, Write_Replace_Complete_sequence);

  return offset;
}


static const per_sequence_t Write_Replace_Failure_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Write_Replace_Failure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Write_Replace_Failure, Write_Replace_Failure_sequence);

  return offset;
}


static const per_sequence_t Kill_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Kill(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Kill, Kill_sequence);

  return offset;
}


static const per_sequence_t Kill_Complete_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Kill_Complete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Kill_Complete, Kill_Complete_sequence);

  return offset;
}


static const per_sequence_t Kill_Failure_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Kill_Failure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Kill_Failure, Kill_Failure_sequence);

  return offset;
}


static const per_sequence_t Load_Query_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Load_Query(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Load_Query, Load_Query_sequence);

  return offset;
}


static const per_sequence_t Load_Query_Complete_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Load_Query_Complete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Load_Query_Complete, Load_Query_Complete_sequence);

  return offset;
}


static const per_sequence_t Load_Query_Failure_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Load_Query_Failure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Load_Query_Failure, Load_Query_Failure_sequence);

  return offset;
}


static const per_sequence_t Message_Status_Query_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Message_Status_Query(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Message_Status_Query, Message_Status_Query_sequence);

  return offset;
}


static const per_sequence_t Message_Status_Query_Complete_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Message_Status_Query_Complete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Message_Status_Query_Complete, Message_Status_Query_Complete_sequence);

  return offset;
}


static const per_sequence_t Message_Status_Query_Failure_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Message_Status_Query_Failure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Message_Status_Query_Failure, Message_Status_Query_Failure_sequence);

  return offset;
}


static const per_sequence_t Reset_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Reset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Reset, Reset_sequence);

  return offset;
}


static const per_sequence_t Reset_Complete_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Reset_Complete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Reset_Complete, Reset_Complete_sequence);

  return offset;
}


static const per_sequence_t Reset_Failure_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Reset_Failure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Reset_Failure, Reset_Failure_sequence);

  return offset;
}


static const per_sequence_t Restart_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Restart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Restart, Restart_sequence);

  return offset;
}


static const per_sequence_t Failure_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Failure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Failure, Failure_sequence);

  return offset;
}


static const per_sequence_t Error_Indication_sequence[] = {
  { &hf_sabp_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sabp_ProtocolIE_Container },
  { &hf_sabp_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sabp_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_Error_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_Error_Indication, Error_Indication_sequence);

  return offset;
}



static int
dissect_sabp_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_sabp_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_ProcedureCode },
  { &hf_sabp_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_Criticality },
  { &hf_sabp_initiatingMessage_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_sabp_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_sabp_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_ProcedureCode },
  { &hf_sabp_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_Criticality },
  { &hf_sabp_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_sabp_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_sabp_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_ProcedureCode },
  { &hf_sabp_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_Criticality },
  { &hf_sabp_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_sabp_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sabp_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string sabp_SABP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t SABP_PDU_choice[] = {
  {   0, &hf_sabp_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_sabp_InitiatingMessage },
  {   1, &hf_sabp_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_sabp_SuccessfulOutcome },
  {   2, &hf_sabp_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_sabp_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_sabp_SABP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_sabp_SABP_PDU, SABP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Broadcast_Message_Content_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Broadcast_Message_Content(tvb, offset, &asn1_ctx, tree, hf_sabp_Broadcast_Message_Content_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Broadcast_Message_Content_Validity_Indicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Broadcast_Message_Content_Validity_Indicator(tvb, offset, &asn1_ctx, tree, hf_sabp_Broadcast_Message_Content_Validity_Indicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Category_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Category(tvb, offset, &asn1_ctx, tree, hf_sabp_Category_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Cause(tvb, offset, &asn1_ctx, tree, hf_sabp_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Criticality_Diagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Criticality_Diagnostics(tvb, offset, &asn1_ctx, tree, hf_sabp_Criticality_Diagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MessageStructure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_MessageStructure(tvb, offset, &asn1_ctx, tree, hf_sabp_MessageStructure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Data_Coding_Scheme_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Data_Coding_Scheme(tvb, offset, &asn1_ctx, tree, hf_sabp_Data_Coding_Scheme_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Failure_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Failure_List(tvb, offset, &asn1_ctx, tree, hf_sabp_Failure_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Message_Identifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Message_Identifier(tvb, offset, &asn1_ctx, tree, hf_sabp_Message_Identifier_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_New_Serial_Number_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_New_Serial_Number(tvb, offset, &asn1_ctx, tree, hf_sabp_New_Serial_Number_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Number_of_Broadcasts_Completed_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Number_of_Broadcasts_Completed_List(tvb, offset, &asn1_ctx, tree, hf_sabp_Number_of_Broadcasts_Completed_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Number_of_Broadcasts_Requested_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Number_of_Broadcasts_Requested(tvb, offset, &asn1_ctx, tree, hf_sabp_Number_of_Broadcasts_Requested_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Old_Serial_Number_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Old_Serial_Number(tvb, offset, &asn1_ctx, tree, hf_sabp_Old_Serial_Number_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Paging_ETWS_Indicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Paging_ETWS_Indicator(tvb, offset, &asn1_ctx, tree, hf_sabp_Paging_ETWS_Indicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Radio_Resource_Loading_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Radio_Resource_Loading_List(tvb, offset, &asn1_ctx, tree, hf_sabp_Radio_Resource_Loading_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Recovery_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Recovery_Indication(tvb, offset, &asn1_ctx, tree, hf_sabp_Recovery_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Repetition_Period_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Repetition_Period(tvb, offset, &asn1_ctx, tree, hf_sabp_Repetition_Period_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Serial_Number_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Serial_Number(tvb, offset, &asn1_ctx, tree, hf_sabp_Serial_Number_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Service_Areas_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Service_Areas_List(tvb, offset, &asn1_ctx, tree, hf_sabp_Service_Areas_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TypeOfError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_TypeOfError(tvb, offset, &asn1_ctx, tree, hf_sabp_TypeOfError_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WarningSecurityInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_WarningSecurityInfo(tvb, offset, &asn1_ctx, tree, hf_sabp_WarningSecurityInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Warning_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Warning_Type(tvb, offset, &asn1_ctx, tree, hf_sabp_Warning_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Write_Replace_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Write_Replace(tvb, offset, &asn1_ctx, tree, hf_sabp_Write_Replace_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Write_Replace_Complete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Write_Replace_Complete(tvb, offset, &asn1_ctx, tree, hf_sabp_Write_Replace_Complete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Write_Replace_Failure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Write_Replace_Failure(tvb, offset, &asn1_ctx, tree, hf_sabp_Write_Replace_Failure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Kill_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Kill(tvb, offset, &asn1_ctx, tree, hf_sabp_Kill_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Kill_Complete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Kill_Complete(tvb, offset, &asn1_ctx, tree, hf_sabp_Kill_Complete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Kill_Failure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Kill_Failure(tvb, offset, &asn1_ctx, tree, hf_sabp_Kill_Failure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Load_Query_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Load_Query(tvb, offset, &asn1_ctx, tree, hf_sabp_Load_Query_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Load_Query_Complete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Load_Query_Complete(tvb, offset, &asn1_ctx, tree, hf_sabp_Load_Query_Complete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Load_Query_Failure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Load_Query_Failure(tvb, offset, &asn1_ctx, tree, hf_sabp_Load_Query_Failure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Message_Status_Query_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Message_Status_Query(tvb, offset, &asn1_ctx, tree, hf_sabp_Message_Status_Query_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Message_Status_Query_Complete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Message_Status_Query_Complete(tvb, offset, &asn1_ctx, tree, hf_sabp_Message_Status_Query_Complete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Message_Status_Query_Failure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Message_Status_Query_Failure(tvb, offset, &asn1_ctx, tree, hf_sabp_Message_Status_Query_Failure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Reset(tvb, offset, &asn1_ctx, tree, hf_sabp_Reset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_Complete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Reset_Complete(tvb, offset, &asn1_ctx, tree, hf_sabp_Reset_Complete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_Failure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Reset_Failure(tvb, offset, &asn1_ctx, tree, hf_sabp_Reset_Failure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Restart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Restart(tvb, offset, &asn1_ctx, tree, hf_sabp_Restart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Failure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Failure(tvb, offset, &asn1_ctx, tree, hf_sabp_Failure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Error_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_Error_Indication(tvb, offset, &asn1_ctx, tree, hf_sabp_Error_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SABP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_sabp_SABP_PDU(tvb, offset, &asn1_ctx, tree, hf_sabp_SABP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sabp_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sabp_extension_dissector_table, ProtocolExtensionID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sabp_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sabp_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(sabp_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}


/* 3GPP TS 23.041 version 11.4.0
 * 9.4.2.2.5 CB Data
 */
static void
dissect_sabp_cb_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *cbs_page_item;
  proto_tree *subtree;
  tvbuff_t *page_tvb, *unpacked_tvb;
  int offset = 0;
  int n;
  uint8_t nr_pages, len, cb_inf_msg_len;


  /* Octet 1 Number-of-Pages */
  nr_pages = tvb_get_uint8(tvb, offset);
  proto_tree_add_item(tree, hf_sabp_no_of_pages, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  /*
   * NOTE: n equal to or less than 15
   */
  if(nr_pages > 15){
    /* Error */
    return;
  }
  for (n = 0; n < nr_pages; n++) {
    subtree = proto_tree_add_subtree_format(tree, tvb, offset, 83, ett_sabp_cbs_page, NULL,
                "CB page %u data",  n+1);
    /* octet 2 - 83 CBS-Message-Information-Page 1  */
    cbs_page_item = proto_tree_add_item(subtree, hf_sabp_cb_msg_inf_page, tvb, offset, 82, ENC_NA);
    cb_inf_msg_len = tvb_get_uint8(tvb,offset+82);
    page_tvb = tvb_new_subset_length(tvb, offset, cb_inf_msg_len);
    unpacked_tvb = dissect_cbs_data(sms_encoding, page_tvb, subtree, pinfo, 0);
    len = tvb_captured_length(unpacked_tvb);
    if (unpacked_tvb != NULL){
      if (tree != NULL){
        proto_tree *cbs_page_subtree = proto_item_add_subtree(cbs_page_item, ett_sabp_cbs_page_content);
        proto_tree_add_item(cbs_page_subtree, hf_sabp_cbs_page_content, unpacked_tvb, 0, len, ENC_UTF_8);
      }
    }

    offset = offset+82;
    /* 84 CBS-Message-Information-Length 1 */
    proto_tree_add_item(subtree, hf_sabp_cb_inf_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
  }
}

static int
dissect_sabp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item  *sabp_item = NULL;
  proto_tree  *sabp_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  /* create the sabp protocol tree */
  sabp_item = proto_tree_add_item(tree, proto_sabp, tvb, 0, -1, ENC_NA);
  sabp_tree = proto_item_add_subtree(sabp_item, ett_sabp);

  return dissect_SABP_PDU_PDU(tvb, pinfo, sabp_tree, NULL);
}

/* Note a little bit of a hack assumes length max takes two bytes and that the length starts at byte 4 */
static int
dissect_sabp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  uint32_t type_length, msg_len;
  unsigned tvb_length;
  int bit_offset;
  bool is_fragmented;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);

  tvb_length = tvb_reported_length(tvb);

  if (tvb_length < 5) {
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    return tvb_captured_length(tvb);
  }

  /* Length should be in the 3:d octet */
  bit_offset = 24;
  /* Get the length of the sabp packet. Offset in bits */
  do {
    bit_offset = dissect_per_length_determinant(tvb, bit_offset, &asn1_ctx, NULL, -1, &type_length, &is_fragmented);
    bit_offset += 8*type_length;
    msg_len = (bit_offset + 7) >> 3;
    if (is_fragmented) {
      /* Next length field will take 1 or 2 bytes; let's ask for the maximum */
      msg_len += 2;
    }
    if (msg_len > tvb_length) {
      pinfo->desegment_offset = 0;
      pinfo->desegment_len = msg_len - tvb_length;
      return tvb_captured_length(tvb);
    }
  } while (is_fragmented);

  return dissect_sabp(tvb, pinfo, tree, data);
}

/*--- proto_register_sabp -------------------------------------------*/
void proto_register_sabp(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_sabp_no_of_pages,
      { "Number-of-Pages", "sabp.no_of_pages",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_cb_msg_inf_page,
      { "CBS-Message-Information-Page", "sabp.cb_msg_inf_page",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_cbs_page_content,
      { "CBS Page Content", "sabp.cb_page_content",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_cb_inf_len,
      { "CBS-Message-Information-Length", "sabp.cb_inf_len",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_sabp_Broadcast_Message_Content_PDU,
      { "Broadcast-Message-Content", "sabp.Broadcast_Message_Content",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Broadcast_Message_Content_Validity_Indicator_PDU,
      { "Broadcast-Message-Content-Validity-Indicator", "sabp.Broadcast_Message_Content_Validity_Indicator",
        FT_UINT32, BASE_DEC, VALS(sabp_Broadcast_Message_Content_Validity_Indicator_vals), 0,
        NULL, HFILL }},
    { &hf_sabp_Category_PDU,
      { "Category", "sabp.Category",
        FT_UINT32, BASE_DEC, VALS(sabp_Category_vals), 0,
        NULL, HFILL }},
    { &hf_sabp_Cause_PDU,
      { "Cause", "sabp.Cause",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sabp_Cause_vals_ext, 0,
        NULL, HFILL }},
    { &hf_sabp_Criticality_Diagnostics_PDU,
      { "Criticality-Diagnostics", "sabp.Criticality_Diagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_MessageStructure_PDU,
      { "MessageStructure", "sabp.MessageStructure",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Data_Coding_Scheme_PDU,
      { "Data-Coding-Scheme", "sabp.Data_Coding_Scheme",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Failure_List_PDU,
      { "Failure-List", "sabp.Failure_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Message_Identifier_PDU,
      { "Message-Identifier", "sabp.Message_Identifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_New_Serial_Number_PDU,
      { "New-Serial-Number", "sabp.New_Serial_Number",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Number_of_Broadcasts_Completed_List_PDU,
      { "Number-of-Broadcasts-Completed-List", "sabp.Number_of_Broadcasts_Completed_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Number_of_Broadcasts_Requested_PDU,
      { "Number-of-Broadcasts-Requested", "sabp.Number_of_Broadcasts_Requested",
        FT_UINT32, BASE_DEC, VALS(sabp_Number_of_Broadcasts_Requested_vals), 0,
        NULL, HFILL }},
    { &hf_sabp_Old_Serial_Number_PDU,
      { "Old-Serial-Number", "sabp.Old_Serial_Number",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Paging_ETWS_Indicator_PDU,
      { "Paging-ETWS-Indicator", "sabp.Paging_ETWS_Indicator",
        FT_UINT32, BASE_DEC, VALS(sabp_Paging_ETWS_Indicator_vals), 0,
        NULL, HFILL }},
    { &hf_sabp_Radio_Resource_Loading_List_PDU,
      { "Radio-Resource-Loading-List", "sabp.Radio_Resource_Loading_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Recovery_Indication_PDU,
      { "Recovery-Indication", "sabp.Recovery_Indication",
        FT_UINT32, BASE_DEC, VALS(sabp_Recovery_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_sabp_Repetition_Period_PDU,
      { "Repetition-Period", "sabp.Repetition_Period",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Serial_Number_PDU,
      { "Serial-Number", "sabp.Serial_Number",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Service_Areas_List_PDU,
      { "Service-Areas-List", "sabp.Service_Areas_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_TypeOfError_PDU,
      { "TypeOfError", "sabp.TypeOfError",
        FT_UINT32, BASE_DEC, VALS(sabp_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_sabp_WarningSecurityInfo_PDU,
      { "WarningSecurityInfo", "sabp.WarningSecurityInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Warning_Type_PDU,
      { "Warning-Type", "sabp.Warning_Type",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Write_Replace_PDU,
      { "Write-Replace", "sabp.Write_Replace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Write_Replace_Complete_PDU,
      { "Write-Replace-Complete", "sabp.Write_Replace_Complete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Write_Replace_Failure_PDU,
      { "Write-Replace-Failure", "sabp.Write_Replace_Failure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Kill_PDU,
      { "Kill", "sabp.Kill_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Kill_Complete_PDU,
      { "Kill-Complete", "sabp.Kill_Complete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Kill_Failure_PDU,
      { "Kill-Failure", "sabp.Kill_Failure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Load_Query_PDU,
      { "Load-Query", "sabp.Load_Query_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Load_Query_Complete_PDU,
      { "Load-Query-Complete", "sabp.Load_Query_Complete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Load_Query_Failure_PDU,
      { "Load-Query-Failure", "sabp.Load_Query_Failure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Message_Status_Query_PDU,
      { "Message-Status-Query", "sabp.Message_Status_Query_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Message_Status_Query_Complete_PDU,
      { "Message-Status-Query-Complete", "sabp.Message_Status_Query_Complete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Message_Status_Query_Failure_PDU,
      { "Message-Status-Query-Failure", "sabp.Message_Status_Query_Failure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Reset_PDU,
      { "Reset", "sabp.Reset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Reset_Complete_PDU,
      { "Reset-Complete", "sabp.Reset_Complete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Reset_Failure_PDU,
      { "Reset-Failure", "sabp.Reset_Failure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Restart_PDU,
      { "Restart", "sabp.Restart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Failure_PDU,
      { "Failure", "sabp.Failure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_Error_Indication_PDU,
      { "Error-Indication", "sabp.Error_Indication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_SABP_PDU_PDU,
      { "SABP-PDU", "sabp.SABP_PDU",
        FT_UINT32, BASE_DEC, VALS(sabp_SABP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_sabp_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "sabp.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_id,
      { "id", "sabp.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sabp_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_sabp_criticality,
      { "criticality", "sabp.criticality",
        FT_UINT32, BASE_DEC, VALS(sabp_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_sabp_protocolIE_Field_value,
      { "value", "sabp.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Field_value", HFILL }},
    { &hf_sabp_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "sabp.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_ext_id,
      { "id", "sabp.id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionID", HFILL }},
    { &hf_sabp_extensionValue,
      { "extensionValue", "sabp.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_procedureCode,
      { "procedureCode", "sabp.procedureCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sabp_ProcedureCode_vals_ext, 0,
        NULL, HFILL }},
    { &hf_sabp_triggeringMessage,
      { "triggeringMessage", "sabp.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(sabp_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_sabp_procedureCriticality,
      { "procedureCriticality", "sabp.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(sabp_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_sabp_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "sabp.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_sabp_iE_Extensions,
      { "iE-Extensions", "sabp.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_sabp_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "sabp.CriticalityDiagnostics_IE_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_iECriticality,
      { "iECriticality", "sabp.iECriticality",
        FT_UINT32, BASE_DEC, VALS(sabp_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_sabp_iE_ID,
      { "iE-ID", "sabp.iE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sabp_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_sabp_repetitionNumber,
      { "repetitionNumber", "sabp.repetitionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RepetitionNumber0", HFILL }},
    { &hf_sabp_MessageStructure_item,
      { "MessageStructure item", "sabp.MessageStructure_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_repetitionNumber1,
      { "repetitionNumber", "sabp.repetitionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RepetitionNumber1", HFILL }},
    { &hf_sabp_Failure_List_item,
      { "Failure-List-Item", "sabp.Failure_List_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_service_area_identifier,
      { "service-area-identifier", "sabp.service_area_identifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_cause,
      { "cause", "sabp.cause",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sabp_Cause_vals_ext, 0,
        NULL, HFILL }},
    { &hf_sabp_Number_of_Broadcasts_Completed_List_item,
      { "Number-of-Broadcasts-Completed-List-Item", "sabp.Number_of_Broadcasts_Completed_List_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_number_of_broadcasts_completed,
      { "number-of-broadcasts-completed", "sabp.number_of_broadcasts_completed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_sabp_number_of_broadcasts_completed_info,
      { "number-of-broadcasts-completed-info", "sabp.number_of_broadcasts_completed_info",
        FT_UINT32, BASE_DEC, VALS(sabp_Number_Of_Broadcasts_Completed_Info_vals), 0,
        NULL, HFILL }},
    { &hf_sabp_Radio_Resource_Loading_List_item,
      { "Radio-Resource-Loading-List-Item", "sabp.Radio_Resource_Loading_List_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_available_bandwidth,
      { "available-bandwidth", "sabp.available_bandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_pLMNidentity,
      { "pLMNidentity", "sabp.pLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_lac,
      { "lac", "sabp.lac",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_sabp_sac,
      { "sac", "sabp.sac",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_sabp_Service_Areas_List_item,
      { "Service-Area-Identifier", "sabp.Service_Area_Identifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_protocolIEs,
      { "protocolIEs", "sabp.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_sabp_protocolExtensions,
      { "protocolExtensions", "sabp.protocolExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_sabp_initiatingMessage,
      { "initiatingMessage", "sabp.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_successfulOutcome,
      { "successfulOutcome", "sabp.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "sabp.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sabp_initiatingMessage_value,
      { "value", "sabp.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_sabp_successfulOutcome_value,
      { "value", "sabp.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_sabp_unsuccessfulOutcome_value,
      { "value", "sabp.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_sabp,
    &ett_sabp_e212,
    &ett_sabp_cbs_data_coding,
    &ett_sabp_bcast_msg,
    &ett_sabp_cbs_serial_number,
    &ett_sabp_cbs_new_serial_number,
    &ett_sabp_cbs_page,
    &ett_sabp_cbs_page_content,
    &ett_sabp_ProtocolIE_Container,
    &ett_sabp_ProtocolIE_Field,
    &ett_sabp_ProtocolExtensionContainer,
    &ett_sabp_ProtocolExtensionField,
    &ett_sabp_Criticality_Diagnostics,
    &ett_sabp_CriticalityDiagnostics_IE_List,
    &ett_sabp_CriticalityDiagnostics_IE_List_item,
    &ett_sabp_MessageStructure,
    &ett_sabp_MessageStructure_item,
    &ett_sabp_Failure_List,
    &ett_sabp_Failure_List_Item,
    &ett_sabp_Number_of_Broadcasts_Completed_List,
    &ett_sabp_Number_of_Broadcasts_Completed_List_Item,
    &ett_sabp_Radio_Resource_Loading_List,
    &ett_sabp_Radio_Resource_Loading_List_Item,
    &ett_sabp_Service_Area_Identifier,
    &ett_sabp_Service_Areas_List,
    &ett_sabp_Write_Replace,
    &ett_sabp_Write_Replace_Complete,
    &ett_sabp_Write_Replace_Failure,
    &ett_sabp_Kill,
    &ett_sabp_Kill_Complete,
    &ett_sabp_Kill_Failure,
    &ett_sabp_Load_Query,
    &ett_sabp_Load_Query_Complete,
    &ett_sabp_Load_Query_Failure,
    &ett_sabp_Message_Status_Query,
    &ett_sabp_Message_Status_Query_Complete,
    &ett_sabp_Message_Status_Query_Failure,
    &ett_sabp_Reset,
    &ett_sabp_Reset_Complete,
    &ett_sabp_Reset_Failure,
    &ett_sabp_Restart,
    &ett_sabp_Failure,
    &ett_sabp_Error_Indication,
    &ett_sabp_SABP_PDU,
    &ett_sabp_InitiatingMessage,
    &ett_sabp_SuccessfulOutcome,
    &ett_sabp_UnsuccessfulOutcome,
  };


  /* Register protocol */
  proto_sabp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_sabp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  sabp_handle = register_dissector("sabp", dissect_sabp, proto_sabp);
  sabp_tcp_handle = register_dissector("sabp.tcp", dissect_sabp_tcp, proto_sabp);

  /* Register dissector tables */
  sabp_ies_dissector_table = register_dissector_table("sabp.ies", "SABP-PROTOCOL-IES", proto_sabp, FT_UINT32, BASE_DEC);
  sabp_extension_dissector_table = register_dissector_table("sabp.extension", "SABP-PROTOCOL-EXTENSION", proto_sabp, FT_UINT32, BASE_DEC);
  sabp_proc_imsg_dissector_table = register_dissector_table("sabp.proc.imsg", "SABP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_sabp, FT_UINT32, BASE_DEC);
  sabp_proc_sout_dissector_table = register_dissector_table("sabp.proc.sout", "SABP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_sabp, FT_UINT32, BASE_DEC);
  sabp_proc_uout_dissector_table = register_dissector_table("sabp.proc.uout", "SABP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_sabp, FT_UINT32, BASE_DEC);
}


/*--- proto_reg_handoff_sabp ---------------------------------------*/
void
proto_reg_handoff_sabp(void)
{
  dissector_add_uint_with_preference("udp.port", SABP_PORT, sabp_handle);
  dissector_add_uint_with_preference("tcp.port", SABP_PORT, sabp_tcp_handle);
  dissector_add_uint("sctp.ppi", SABP_PAYLOAD_PROTOCOL_ID, sabp_handle);

  dissector_add_uint("sabp.ies", id_Message_Identifier, create_dissector_handle(dissect_Message_Identifier_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_New_Serial_Number, create_dissector_handle(dissect_New_Serial_Number_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Old_Serial_Number, create_dissector_handle(dissect_Old_Serial_Number_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Service_Areas_List, create_dissector_handle(dissect_Service_Areas_List_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Category, create_dissector_handle(dissect_Category_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Repetition_Period, create_dissector_handle(dissect_Repetition_Period_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Number_of_Broadcasts_Requested, create_dissector_handle(dissect_Number_of_Broadcasts_Requested_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Data_Coding_Scheme, create_dissector_handle(dissect_Data_Coding_Scheme_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Broadcast_Message_Content, create_dissector_handle(dissect_Broadcast_Message_Content_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Number_of_Broadcasts_Completed_List, create_dissector_handle(dissect_Number_of_Broadcasts_Completed_List_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Criticality_Diagnostics, create_dissector_handle(dissect_Criticality_Diagnostics_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Failure_List, create_dissector_handle(dissect_Failure_List_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Radio_Resource_Loading_List, create_dissector_handle(dissect_Radio_Resource_Loading_List_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Recovery_Indication, create_dissector_handle(dissect_Recovery_Indication_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Serial_Number, create_dissector_handle(dissect_Serial_Number_PDU, proto_sabp));
  dissector_add_uint("sabp.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_sabp));
  dissector_add_uint("sabp.extension", id_MessageStructure, create_dissector_handle(dissect_MessageStructure_PDU, proto_sabp));
  dissector_add_uint("sabp.extension", id_TypeOfError, create_dissector_handle(dissect_TypeOfError_PDU, proto_sabp));
  dissector_add_uint("sabp.extension", id_Paging_ETWS_Indicator, create_dissector_handle(dissect_Paging_ETWS_Indicator_PDU, proto_sabp));
  dissector_add_uint("sabp.extension", id_Warning_Type, create_dissector_handle(dissect_Warning_Type_PDU, proto_sabp));
  dissector_add_uint("sabp.extension", id_WarningSecurityInfo, create_dissector_handle(dissect_WarningSecurityInfo_PDU, proto_sabp));
  dissector_add_uint("sabp.extension", id_Broadcast_Message_Content_Validity_Indicator, create_dissector_handle(dissect_Broadcast_Message_Content_Validity_Indicator_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.imsg", id_Write_Replace, create_dissector_handle(dissect_Write_Replace_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.sout", id_Write_Replace, create_dissector_handle(dissect_Write_Replace_Complete_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.uout", id_Write_Replace, create_dissector_handle(dissect_Write_Replace_Failure_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.imsg", id_Kill, create_dissector_handle(dissect_Kill_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.sout", id_Kill, create_dissector_handle(dissect_Kill_Complete_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.uout", id_Kill, create_dissector_handle(dissect_Kill_Failure_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.imsg", id_Load_Status_Enquiry, create_dissector_handle(dissect_Load_Query_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.sout", id_Load_Status_Enquiry, create_dissector_handle(dissect_Load_Query_Complete_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.uout", id_Load_Status_Enquiry, create_dissector_handle(dissect_Load_Query_Failure_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.imsg", id_Message_Status_Query, create_dissector_handle(dissect_Message_Status_Query_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.sout", id_Message_Status_Query, create_dissector_handle(dissect_Message_Status_Query_Complete_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.uout", id_Message_Status_Query, create_dissector_handle(dissect_Message_Status_Query_Failure_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.imsg", id_Reset, create_dissector_handle(dissect_Reset_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.sout", id_Reset, create_dissector_handle(dissect_Reset_Complete_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.uout", id_Reset, create_dissector_handle(dissect_Reset_Failure_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.imsg", id_Restart_Indication, create_dissector_handle(dissect_Restart_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.imsg", id_Failure_Indication, create_dissector_handle(dissect_Failure_PDU, proto_sabp));
  dissector_add_uint("sabp.proc.imsg", id_Error_Indication, create_dissector_handle(dissect_Error_Indication_PDU, proto_sabp));

}


