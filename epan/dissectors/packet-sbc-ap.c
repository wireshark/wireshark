/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-sbc-ap.c                                                            */
/* ../../tools/asn2wrs.py -p sbc-ap -c ./sbc-ap.cnf -s ./packet-sbc-ap-template -D . -O ../../epan/dissectors SBC-AP-CommonDataTypes.asn SBC-AP-Constants.asn SBC-AP-Containers.asn SBC-AP-IEs.asn SBC-AP-PDU-Contents.asn SBC-AP-PDU-Descriptions.asn */

/* Input file: packet-sbc-ap-template.c */

#line 1 "../../asn1/sbc-ap/packet-sbc-ap-template.c"
/* packet-sbc-ap.c
 * Routines for SBc Application Part (SBc-AP) packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Ref 3GPP TS 29.168
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/sctpppids.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"

#define PNAME  "SBc Application Part"
#define PSNAME "SBCAP"
#define PFNAME "sbcap"

void proto_register_sbc_ap(void);
void proto_reg_handoff_sbc_ap(void);

/* The registered port number for SBc-AP is 29168.
 * The registered payload protocol identifier for SBc-AP is 24.
 */
#define SBC_AP_PORT 29168
static dissector_handle_t sbc_ap_handle=NULL;



/*--- Included file: packet-sbc-ap-val.h ---*/
#line 1 "../../asn1/sbc-ap/packet-sbc-ap-val.h"
#define maxNrOfErrors                  256
#define maxnoofCellID                  65535
#define maxNrOfTAIs                    65535
#define maxnoofgencyEmerAreaID         65535
#define maxnoofTAIforWarning           65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxnoofEmerAreaIDs             65535

typedef enum _ProcedureCode_enum {
  id_Write_Replace_Warning =   0,
  id_Stop_Warning =   1
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
  id_Extended_Repetition_Period =  21
} ProtocolIE_ID_enum;

/*--- End of included file: packet-sbc-ap-val.h ---*/
#line 55 "../../asn1/sbc-ap/packet-sbc-ap-template.c"

/* Initialize the protocol and registered fields */
static int proto_sbc_ap = -1;


/*--- Included file: packet-sbc-ap-hf.c ---*/
#line 1 "../../asn1/sbc-ap/packet-sbc-ap-hf.c"
static int hf_sbc_ap_Cause_PDU = -1;              /* Cause */
static int hf_sbc_ap_Concurrent_Warning_Message_Indicator_PDU = -1;  /* Concurrent_Warning_Message_Indicator */
static int hf_sbc_ap_Criticality_Diagnostics_PDU = -1;  /* Criticality_Diagnostics */
static int hf_sbc_ap_Data_Coding_Scheme_PDU = -1;  /* Data_Coding_Scheme */
static int hf_sbc_ap_Extended_Repetition_Period_PDU = -1;  /* Extended_Repetition_Period */
static int hf_sbc_ap_List_of_TAIs_PDU = -1;       /* List_of_TAIs */
static int hf_sbc_ap_Message_Identifier_PDU = -1;  /* Message_Identifier */
static int hf_sbc_ap_Number_of_Broadcasts_Requested_PDU = -1;  /* Number_of_Broadcasts_Requested */
static int hf_sbc_ap_Omc_Id_PDU = -1;             /* Omc_Id */
static int hf_sbc_ap_Repetition_Period_PDU = -1;  /* Repetition_Period */
static int hf_sbc_ap_Serial_Number_PDU = -1;      /* Serial_Number */
static int hf_sbc_ap_Warning_Area_List_PDU = -1;  /* Warning_Area_List */
static int hf_sbc_ap_Warning_Message_Content_PDU = -1;  /* Warning_Message_Content */
static int hf_sbc_ap_Warning_Security_Information_PDU = -1;  /* Warning_Security_Information */
static int hf_sbc_ap_Warning_Type_PDU = -1;       /* Warning_Type */
static int hf_sbc_ap_Write_Replace_Warning_Request_PDU = -1;  /* Write_Replace_Warning_Request */
static int hf_sbc_ap_Write_Replace_Warning_Response_PDU = -1;  /* Write_Replace_Warning_Response */
static int hf_sbc_ap_Stop_Warning_Request_PDU = -1;  /* Stop_Warning_Request */
static int hf_sbc_ap_Stop_Warning_Response_PDU = -1;  /* Stop_Warning_Response */
static int hf_sbc_ap_SBC_AP_PDU_PDU = -1;         /* SBC_AP_PDU */
static int hf_sbc_ap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_sbc_ap_id = -1;                     /* ProtocolIE_ID */
static int hf_sbc_ap_criticality = -1;            /* Criticality */
static int hf_sbc_ap_ie_field_value = -1;         /* T_ie_field_value */
static int hf_sbc_ap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_sbc_ap_ext_id = -1;                 /* ProtocolExtensionID */
static int hf_sbc_ap_extensionValue = -1;         /* T_extensionValue */
static int hf_sbc_ap_procedureCode = -1;          /* ProcedureCode */
static int hf_sbc_ap_triggeringMessage = -1;      /* TriggeringMessage */
static int hf_sbc_ap_procedureCriticality = -1;   /* Criticality */
static int hf_sbc_ap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_sbc_ap_iE_Extensions = -1;          /* ProtocolExtensionContainer */
static int hf_sbc_ap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_sbc_ap_iECriticality = -1;          /* Criticality */
static int hf_sbc_ap_iE_ID = -1;                  /* ProtocolIE_ID */
static int hf_sbc_ap_typeOfError = -1;            /* TypeOfError */
static int hf_sbc_ap_ECGIList_item = -1;          /* EUTRAN_CGI */
static int hf_sbc_ap_Emergency_Area_ID_List_item = -1;  /* Emergency_Area_ID */
static int hf_sbc_ap_pLMNidentity = -1;           /* PLMNidentity */
static int hf_sbc_ap_cell_ID = -1;                /* CellIdentity */
static int hf_sbc_ap_List_of_TAIs_item = -1;      /* List_of_TAIs_item */
static int hf_sbc_ap_tai = -1;                    /* TAI */
static int hf_sbc_ap_TAI_List_for_Warning_item = -1;  /* TAI */
static int hf_sbc_ap_tAC = -1;                    /* TAC */
static int hf_sbc_ap_cell_ID_List = -1;           /* ECGIList */
static int hf_sbc_ap_tracking_Area_List_for_Warning = -1;  /* TAI_List_for_Warning */
static int hf_sbc_ap_emergency_Area_ID_List = -1;  /* Emergency_Area_ID_List */
static int hf_sbc_ap_protocolIEs = -1;            /* ProtocolIE_Container */
static int hf_sbc_ap_protocolExtensions = -1;     /* ProtocolExtensionContainer */
static int hf_sbc_ap_initiatingMessage = -1;      /* InitiatingMessage */
static int hf_sbc_ap_successfulOutcome = -1;      /* SuccessfulOutcome */
static int hf_sbc_ap_unsuccessfulOutcome = -1;    /* UnsuccessfulOutcome */
static int hf_sbc_ap_initiatingMessagevalue = -1;  /* InitiatingMessage_value */
static int hf_sbc_ap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_sbc_ap_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-sbc-ap-hf.c ---*/
#line 60 "../../asn1/sbc-ap/packet-sbc-ap-template.c"

/* Initialize the subtree pointers */
static int ett_sbc_ap = -1;


/*--- Included file: packet-sbc-ap-ett.c ---*/
#line 1 "../../asn1/sbc-ap/packet-sbc-ap-ett.c"
static gint ett_sbc_ap_ProtocolIE_Container = -1;
static gint ett_sbc_ap_ProtocolIE_Field = -1;
static gint ett_sbc_ap_ProtocolExtensionContainer = -1;
static gint ett_sbc_ap_ProtocolExtensionField = -1;
static gint ett_sbc_ap_Criticality_Diagnostics = -1;
static gint ett_sbc_ap_CriticalityDiagnostics_IE_List = -1;
static gint ett_sbc_ap_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_sbc_ap_ECGIList = -1;
static gint ett_sbc_ap_Emergency_Area_ID_List = -1;
static gint ett_sbc_ap_EUTRAN_CGI = -1;
static gint ett_sbc_ap_List_of_TAIs = -1;
static gint ett_sbc_ap_List_of_TAIs_item = -1;
static gint ett_sbc_ap_TAI_List_for_Warning = -1;
static gint ett_sbc_ap_TAI = -1;
static gint ett_sbc_ap_Warning_Area_List = -1;
static gint ett_sbc_ap_Write_Replace_Warning_Request = -1;
static gint ett_sbc_ap_Write_Replace_Warning_Response = -1;
static gint ett_sbc_ap_Stop_Warning_Request = -1;
static gint ett_sbc_ap_Stop_Warning_Response = -1;
static gint ett_sbc_ap_SBC_AP_PDU = -1;
static gint ett_sbc_ap_InitiatingMessage = -1;
static gint ett_sbc_ap_SuccessfulOutcome = -1;
static gint ett_sbc_ap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-sbc-ap-ett.c ---*/
#line 65 "../../asn1/sbc-ap/packet-sbc-ap-template.c"

enum{
	INITIATING_MESSAGE,
	SUCCESSFUL_OUTCOME,
	UNSUCCESSFUL_OUTCOME
};

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ProtocolExtensionID;
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


/*--- Included file: packet-sbc-ap-fn.c ---*/
#line 1 "../../asn1/sbc-ap/packet-sbc-ap-fn.c"

static const value_string sbc_ap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_sbc_ap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string sbc_ap_ProcedureCode_vals[] = {
  { id_Write_Replace_Warning, "id-Write-Replace-Warning" },
  { id_Stop_Warning, "id-Stop-Warning" },
  { 0, NULL }
};


static int
dissect_sbc_ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, FALSE);

#line 62 "../../asn1/sbc-ap/sbc-ap.cnf"
   col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
                   val_to_str(ProcedureCode, sbc_ap_ProcedureCode_vals,
                              "unknown message"));

  return offset;
}



static int
dissect_sbc_ap_ProtocolExtensionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolExtensionID, FALSE);

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
  { 0, NULL }
};


static int
dissect_sbc_ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolIE_ID, FALSE);

#line 45 "../../asn1/sbc-ap/sbc-ap.cnf"
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
                                     4, NULL, FALSE, 0, NULL);

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
                                                  0, maxProtocolIEs, FALSE);

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
                                                  1, maxProtocolExtensions, FALSE);

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
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_sbc_ap_CellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL, NULL);

  return offset;
}


static const value_string sbc_ap_Concurrent_Warning_Message_Indicator_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_sbc_ap_Concurrent_Warning_Message_Indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  1, maxNrOfErrors, FALSE);

  return offset;
}


static const per_sequence_t Criticality_Diagnostics_sequence[] = {
  { &hf_sbc_ap_procedureCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProcedureCode },
  { &hf_sbc_ap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_TriggeringMessage },
  { &hf_sbc_ap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_Criticality },
  { &hf_sbc_ap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_CriticalityDiagnostics_IE_List },
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
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, NULL);

  return offset;
}




static int
dissect_sbc_ap_PLMNidentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 99 "../../asn1/sbc-ap/sbc-ap.cnf"
  tvbuff_t *parameter_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &parameter_tvb);
	if(tvb_length(tvb)==0)
		return offset;

	if (!parameter_tvb)
		return offset;
	dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, tree, 0, FALSE);


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
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_EUTRAN_CGI, EUTRAN_CGI_sequence);

  return offset;
}


static const per_sequence_t ECGIList_sequence_of[1] = {
  { &hf_sbc_ap_ECGIList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_EUTRAN_CGI },
};

static int
dissect_sbc_ap_ECGIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_ECGIList, ECGIList_sequence_of,
                                                  1, maxnoofCellID, FALSE);

  return offset;
}



static int
dissect_sbc_ap_Emergency_Area_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}


static const per_sequence_t Emergency_Area_ID_List_sequence_of[1] = {
  { &hf_sbc_ap_Emergency_Area_ID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_Emergency_Area_ID },
};

static int
dissect_sbc_ap_Emergency_Area_ID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_Emergency_Area_ID_List, Emergency_Area_ID_List_sequence_of,
                                                  1, maxnoofEmerAreaIDs, FALSE);

  return offset;
}



static int
dissect_sbc_ap_Extended_Repetition_Period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            4096U, 131071U, NULL, FALSE);

  return offset;
}



static int
dissect_sbc_ap_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

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
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_TAI, TAI_sequence);

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
                                                  1, maxNrOfTAIs, FALSE);

  return offset;
}



static int
dissect_sbc_ap_Message_Identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_sbc_ap_Number_of_Broadcasts_Requested(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_sbc_ap_Omc_Id(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, FALSE, NULL);

  return offset;
}



static int
dissect_sbc_ap_Repetition_Period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4096U, NULL, FALSE);

  return offset;
}



static int
dissect_sbc_ap_Serial_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t TAI_List_for_Warning_sequence_of[1] = {
  { &hf_sbc_ap_TAI_List_for_Warning_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sbc_ap_TAI },
};

static int
dissect_sbc_ap_TAI_List_for_Warning(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sbc_ap_TAI_List_for_Warning, TAI_List_for_Warning_sequence_of,
                                                  1, maxnoofTAIforWarning, FALSE);

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
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 9600, FALSE, NULL);

  return offset;
}



static int
dissect_sbc_ap_Warning_Security_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       50, 50, FALSE, NULL);

  return offset;
}



static int
dissect_sbc_ap_Warning_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t Write_Replace_Warning_Request_sequence[] = {
  { &hf_sbc_ap_protocolIEs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sbc_ap_ProtocolIE_Container },
  { &hf_sbc_ap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sbc_ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_sbc_ap_Write_Replace_Warning_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_sbc_ap_Stop_Warning_Response, Stop_Warning_Response_sequence);

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

static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Cause(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Concurrent_Warning_Message_Indicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Concurrent_Warning_Message_Indicator(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Concurrent_Warning_Message_Indicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Criticality_Diagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Criticality_Diagnostics(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Criticality_Diagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Data_Coding_Scheme_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Data_Coding_Scheme(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Data_Coding_Scheme_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Extended_Repetition_Period_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Extended_Repetition_Period(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Extended_Repetition_Period_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_List_of_TAIs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_List_of_TAIs(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_List_of_TAIs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Message_Identifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Message_Identifier(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Message_Identifier_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Number_of_Broadcasts_Requested_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Number_of_Broadcasts_Requested(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Number_of_Broadcasts_Requested_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Omc_Id_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Omc_Id(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Omc_Id_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Repetition_Period_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Repetition_Period(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Repetition_Period_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Serial_Number_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Serial_Number(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Serial_Number_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Warning_Area_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Warning_Area_List(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Warning_Area_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Warning_Message_Content_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Warning_Message_Content(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Warning_Message_Content_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Warning_Security_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Warning_Security_Information(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Warning_Security_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Warning_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Warning_Type(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Warning_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Write_Replace_Warning_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Write_Replace_Warning_Request(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Write_Replace_Warning_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Write_Replace_Warning_Response_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Write_Replace_Warning_Response(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Write_Replace_Warning_Response_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Stop_Warning_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Stop_Warning_Request(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Stop_Warning_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Stop_Warning_Response_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_Stop_Warning_Response(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_Stop_Warning_Response_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SBC_AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sbc_ap_SBC_AP_PDU(tvb, offset, &asn1_ctx, tree, hf_sbc_ap_SBC_AP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-sbc-ap-fn.c ---*/
#line 92 "../../asn1/sbc-ap/packet-sbc-ap-template.c"

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


static void
dissect_sbc_ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item      *sbc_ap_item = NULL;
    proto_tree      *sbc_ap_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* create the sbc_ap protocol tree */
    if (tree) {
        sbc_ap_item = proto_tree_add_item(tree, proto_sbc_ap, tvb, 0, -1, ENC_NA);
        sbc_ap_tree = proto_item_add_subtree(sbc_ap_item, ett_sbc_ap);

        dissect_SBC_AP_PDU_PDU(tvb, pinfo, sbc_ap_tree, NULL);
    }
}
/*--- proto_register_sbc_ap -------------------------------------------*/
void proto_register_sbc_ap(void) {

  /* List of fields */
  static hf_register_info hf[] = {


/*--- Included file: packet-sbc-ap-hfarr.c ---*/
#line 1 "../../asn1/sbc-ap/packet-sbc-ap-hfarr.c"
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
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_List_of_TAIs_PDU,
      { "List-of-TAIs", "sbc-ap.List_of_TAIs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Message_Identifier_PDU,
      { "Message-Identifier", "sbc-ap.Message_Identifier",
        FT_BYTES, BASE_NONE, NULL, 0,
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
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Serial_Number_PDU,
      { "Serial-Number", "sbc-ap.Serial_Number",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Area_List_PDU,
      { "Warning-Area-List", "sbc-ap.Warning_Area_List",
        FT_UINT32, BASE_DEC, VALS(sbc_ap_Warning_Area_List_vals), 0,
        NULL, HFILL }},
    { &hf_sbc_ap_Warning_Message_Content_PDU,
      { "Warning-Message-Content", "sbc-ap.Warning_Message_Content",
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
    { &hf_sbc_ap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "sbc-ap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_sbc_ap_iE_Extensions,
      { "iE-Extensions", "sbc-ap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
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
    { &hf_sbc_ap_pLMNidentity,
      { "pLMNidentity", "sbc-ap.pLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_cell_ID,
      { "cell-ID", "sbc-ap.cell_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CellIdentity", HFILL }},
    { &hf_sbc_ap_List_of_TAIs_item,
      { "List-of-TAIs item", "sbc-ap.List_of_TAIs_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_tai,
      { "tai", "sbc-ap.tai_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_TAI_List_for_Warning_item,
      { "TAI", "sbc-ap.TAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sbc_ap_tAC,
      { "tAC", "sbc-ap.tAC",
        FT_BYTES, BASE_NONE, NULL, 0,
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

/*--- End of included file: packet-sbc-ap-hfarr.c ---*/
#line 154 "../../asn1/sbc-ap/packet-sbc-ap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_sbc_ap,

/*--- Included file: packet-sbc-ap-ettarr.c ---*/
#line 1 "../../asn1/sbc-ap/packet-sbc-ap-ettarr.c"
    &ett_sbc_ap_ProtocolIE_Container,
    &ett_sbc_ap_ProtocolIE_Field,
    &ett_sbc_ap_ProtocolExtensionContainer,
    &ett_sbc_ap_ProtocolExtensionField,
    &ett_sbc_ap_Criticality_Diagnostics,
    &ett_sbc_ap_CriticalityDiagnostics_IE_List,
    &ett_sbc_ap_CriticalityDiagnostics_IE_List_item,
    &ett_sbc_ap_ECGIList,
    &ett_sbc_ap_Emergency_Area_ID_List,
    &ett_sbc_ap_EUTRAN_CGI,
    &ett_sbc_ap_List_of_TAIs,
    &ett_sbc_ap_List_of_TAIs_item,
    &ett_sbc_ap_TAI_List_for_Warning,
    &ett_sbc_ap_TAI,
    &ett_sbc_ap_Warning_Area_List,
    &ett_sbc_ap_Write_Replace_Warning_Request,
    &ett_sbc_ap_Write_Replace_Warning_Response,
    &ett_sbc_ap_Stop_Warning_Request,
    &ett_sbc_ap_Stop_Warning_Response,
    &ett_sbc_ap_SBC_AP_PDU,
    &ett_sbc_ap_InitiatingMessage,
    &ett_sbc_ap_SuccessfulOutcome,
    &ett_sbc_ap_UnsuccessfulOutcome,

/*--- End of included file: packet-sbc-ap-ettarr.c ---*/
#line 160 "../../asn1/sbc-ap/packet-sbc-ap-template.c"
  };


  /* Register protocol */
  proto_sbc_ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_sbc_ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


  /* Register dissector tables */
  sbc_ap_ies_dissector_table = register_dissector_table("sbc_ap.ies", "SBC-AP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  sbc_ap_extension_dissector_table = register_dissector_table("sbc_ap.extension", "SBC-AP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  sbc_ap_proc_imsg_dissector_table = register_dissector_table("sbc_ap.proc.imsg", "SBC-AP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  sbc_ap_proc_sout_dissector_table = register_dissector_table("sbc_ap.proc.sout", "SBC-AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  sbc_ap_proc_uout_dissector_table = register_dissector_table("sbc_ap.proc.uout", "SBC-AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);


}


/*--- proto_reg_handoff_sbc_ap ---------------------------------------*/
void
proto_reg_handoff_sbc_ap(void)
{
    static gboolean inited = FALSE;
	static guint SctpPort;

    if( !inited ) {
        sbc_ap_handle = create_dissector_handle(dissect_sbc_ap, proto_sbc_ap);
        dissector_add_uint("sctp.ppi", SBC_AP_PAYLOAD_PROTOCOL_ID,   sbc_ap_handle);
        inited = TRUE;

/*--- Included file: packet-sbc-ap-dis-tab.c ---*/
#line 1 "../../asn1/sbc-ap/packet-sbc-ap-dis-tab.c"
  dissector_add_uint("sbc_ap.ies", id_Cause, new_create_dissector_handle(dissect_Cause_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Criticality_Diagnostics, new_create_dissector_handle(dissect_Criticality_Diagnostics_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Data_Coding_Scheme, new_create_dissector_handle(dissect_Data_Coding_Scheme_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Message_Identifier, new_create_dissector_handle(dissect_Message_Identifier_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Number_of_Broadcasts_Requested, new_create_dissector_handle(dissect_Number_of_Broadcasts_Requested_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Repetition_Period, new_create_dissector_handle(dissect_Repetition_Period_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Serial_Number, new_create_dissector_handle(dissect_Serial_Number_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_List_of_TAIs, new_create_dissector_handle(dissect_List_of_TAIs_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Warning_Area_List, new_create_dissector_handle(dissect_Warning_Area_List_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Warning_Message_Content, new_create_dissector_handle(dissect_Warning_Message_Content_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Warning_Security_Information, new_create_dissector_handle(dissect_Warning_Security_Information_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Warning_Type, new_create_dissector_handle(dissect_Warning_Type_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Omc_Id, new_create_dissector_handle(dissect_Omc_Id_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Concurrent_Warning_Message_Indicator, new_create_dissector_handle(dissect_Concurrent_Warning_Message_Indicator_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.ies", id_Extended_Repetition_Period, new_create_dissector_handle(dissect_Extended_Repetition_Period_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.proc.imsg", id_Write_Replace_Warning, new_create_dissector_handle(dissect_Write_Replace_Warning_Request_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.proc.sout", id_Write_Replace_Warning, new_create_dissector_handle(dissect_Write_Replace_Warning_Response_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.proc.imsg", id_Stop_Warning, new_create_dissector_handle(dissect_Stop_Warning_Request_PDU, proto_sbc_ap));
  dissector_add_uint("sbc_ap.proc.sout", id_Stop_Warning, new_create_dissector_handle(dissect_Stop_Warning_Response_PDU, proto_sbc_ap));


/*--- End of included file: packet-sbc-ap-dis-tab.c ---*/
#line 193 "../../asn1/sbc-ap/packet-sbc-ap-template.c"
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





