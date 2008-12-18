/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-sabp.c                                                              */
/* ../../tools/asn2wrs.py -p sabp -c sabp.cnf -s packet-sabp-template SABP-CommonDataTypes.asn SABP-Constants.asn SABP-Containers.asn SABP-IEs.asn SABP-PDU-Contents.asn SABP-PDU-Descriptions.asn */

/* Input file: packet-sabp-template.c */

#line 1 "packet-sabp-template.c"
/* packet-sbap.c
 * Routines for UTRAN Iu-BC Interface: Service Area Broadcast Protocol (SBAP) packet dissection
 * Copyright 2007, Tomas Kukosa <tomas.kukosa@siemens.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Ref: 3GPP TS 25.419 version 7.7.0 (2006-03)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include <epan/asn1.h>
#include <epan/emem.h>

#include "packet-tcp.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-gsm_map.h"
#include "packet-gsm_sms.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "UTRAN IuBC interface SABP signaling"
#define PSNAME "SABP"
#define PFNAME "sabp"


/*--- Included file: packet-sabp-val.h ---*/
#line 1 "packet-sabp-val.h"
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
  id_TypeOfError =  17
} ProtocolIE_ID_enum;

/*--- End of included file: packet-sabp-val.h ---*/
#line 58 "packet-sabp-template.c"

/* Initialize the protocol and registered fields */
static int proto_sabp = -1;

static int hf_sabp_no_of_pages = -1;

/*--- Included file: packet-sabp-hf.c ---*/
#line 1 "packet-sabp-hf.c"
static int hf_sabp_Broadcast_Message_Content_PDU = -1;  /* Broadcast_Message_Content */
static int hf_sabp_Category_PDU = -1;             /* Category */
static int hf_sabp_Cause_PDU = -1;                /* Cause */
static int hf_sabp_Criticality_Diagnostics_PDU = -1;  /* Criticality_Diagnostics */
static int hf_sabp_MessageStructure_PDU = -1;     /* MessageStructure */
static int hf_sabp_Data_Coding_Scheme_PDU = -1;   /* Data_Coding_Scheme */
static int hf_sabp_Failure_List_PDU = -1;         /* Failure_List */
static int hf_sabp_Message_Identifier_PDU = -1;   /* Message_Identifier */
static int hf_sabp_New_Serial_Number_PDU = -1;    /* New_Serial_Number */
static int hf_sabp_Number_of_Broadcasts_Completed_List_PDU = -1;  /* Number_of_Broadcasts_Completed_List */
static int hf_sabp_Number_of_Broadcasts_Requested_PDU = -1;  /* Number_of_Broadcasts_Requested */
static int hf_sabp_Old_Serial_Number_PDU = -1;    /* Old_Serial_Number */
static int hf_sabp_Radio_Resource_Loading_List_PDU = -1;  /* Radio_Resource_Loading_List */
static int hf_sabp_Recovery_Indication_PDU = -1;  /* Recovery_Indication */
static int hf_sabp_Repetition_Period_PDU = -1;    /* Repetition_Period */
static int hf_sabp_Serial_Number_PDU = -1;        /* Serial_Number */
static int hf_sabp_Service_Areas_List_PDU = -1;   /* Service_Areas_List */
static int hf_sabp_TypeOfError_PDU = -1;          /* TypeOfError */
static int hf_sabp_Write_Replace_PDU = -1;        /* Write_Replace */
static int hf_sabp_Write_Replace_Complete_PDU = -1;  /* Write_Replace_Complete */
static int hf_sabp_Write_Replace_Failure_PDU = -1;  /* Write_Replace_Failure */
static int hf_sabp_Kill_PDU = -1;                 /* Kill */
static int hf_sabp_Kill_Complete_PDU = -1;        /* Kill_Complete */
static int hf_sabp_Kill_Failure_PDU = -1;         /* Kill_Failure */
static int hf_sabp_Load_Query_PDU = -1;           /* Load_Query */
static int hf_sabp_Load_Query_Complete_PDU = -1;  /* Load_Query_Complete */
static int hf_sabp_Load_Query_Failure_PDU = -1;   /* Load_Query_Failure */
static int hf_sabp_Message_Status_Query_PDU = -1;  /* Message_Status_Query */
static int hf_sabp_Message_Status_Query_Complete_PDU = -1;  /* Message_Status_Query_Complete */
static int hf_sabp_Message_Status_Query_Failure_PDU = -1;  /* Message_Status_Query_Failure */
static int hf_sabp_Reset_PDU = -1;                /* Reset */
static int hf_sabp_Reset_Complete_PDU = -1;       /* Reset_Complete */
static int hf_sabp_Reset_Failure_PDU = -1;        /* Reset_Failure */
static int hf_sabp_Restart_PDU = -1;              /* Restart */
static int hf_sabp_Failure_PDU = -1;              /* Failure */
static int hf_sabp_Error_Indication_PDU = -1;     /* Error_Indication */
static int hf_sabp_SABP_PDU_PDU = -1;             /* SABP_PDU */
static int hf_sabp_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_sabp_id = -1;                       /* ProtocolIE_ID */
static int hf_sabp_criticality = -1;              /* Criticality */
static int hf_sabp_protocolIE_Field_value = -1;   /* ProtocolIE_Field_value */
static int hf_sabp_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_sabp_ext_id = -1;                   /* ProtocolExtensionID */
static int hf_sabp_extensionValue = -1;           /* T_extensionValue */
static int hf_sabp_procedureCode = -1;            /* ProcedureCode */
static int hf_sabp_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_sabp_procedureCriticality = -1;     /* Criticality */
static int hf_sabp_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_sabp_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_sabp_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_sabp_iECriticality = -1;            /* Criticality */
static int hf_sabp_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_sabp_repetitionNumber = -1;         /* RepetitionNumber0 */
static int hf_sabp_MessageStructure_item = -1;    /* MessageStructure_item */
static int hf_sabp_repetitionNumber1 = -1;        /* RepetitionNumber1 */
static int hf_sabp_Failure_List_item = -1;        /* Failure_List_Item */
static int hf_sabp_service_area_identifier = -1;  /* Service_Area_Identifier */
static int hf_sabp_cause = -1;                    /* Cause */
static int hf_sabp_Number_of_Broadcasts_Completed_List_item = -1;  /* Number_of_Broadcasts_Completed_List_Item */
static int hf_sabp_number_of_broadcasts_completed = -1;  /* INTEGER_0_65535 */
static int hf_sabp_number_of_broadcasts_completed_info = -1;  /* Number_Of_Broadcasts_Completed_Info */
static int hf_sabp_Radio_Resource_Loading_List_item = -1;  /* Radio_Resource_Loading_List_Item */
static int hf_sabp_available_bandwidth = -1;      /* Available_Bandwidth */
static int hf_sabp_pLMNidentity = -1;             /* PLMNidentity */
static int hf_sabp_lac = -1;                      /* OCTET_STRING_SIZE_2 */
static int hf_sabp_sac = -1;                      /* OCTET_STRING_SIZE_2 */
static int hf_sabp_Service_Areas_List_item = -1;  /* Service_Area_Identifier */
static int hf_sabp_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_sabp_protocolExtensions = -1;       /* ProtocolExtensionContainer */
static int hf_sabp_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_sabp_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_sabp_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_sabp_initiatingMessage_value = -1;  /* InitiatingMessage_value */
static int hf_sabp_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_sabp_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-sabp-hf.c ---*/
#line 64 "packet-sabp-template.c"

/* Initialize the subtree pointers */
static int ett_sabp = -1;
static int ett_sabp_e212 = -1;
static int ett_sabp_cbs_data_coding = -1;
static int ett_sabp_bcast_msg = -1;


/*--- Included file: packet-sabp-ett.c ---*/
#line 1 "packet-sabp-ett.c"
static gint ett_sabp_ProtocolIE_Container = -1;
static gint ett_sabp_ProtocolIE_Field = -1;
static gint ett_sabp_ProtocolExtensionContainer = -1;
static gint ett_sabp_ProtocolExtensionField = -1;
static gint ett_sabp_Criticality_Diagnostics = -1;
static gint ett_sabp_CriticalityDiagnostics_IE_List = -1;
static gint ett_sabp_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_sabp_MessageStructure = -1;
static gint ett_sabp_MessageStructure_item = -1;
static gint ett_sabp_Failure_List = -1;
static gint ett_sabp_Failure_List_Item = -1;
static gint ett_sabp_Number_of_Broadcasts_Completed_List = -1;
static gint ett_sabp_Number_of_Broadcasts_Completed_List_Item = -1;
static gint ett_sabp_Radio_Resource_Loading_List = -1;
static gint ett_sabp_Radio_Resource_Loading_List_Item = -1;
static gint ett_sabp_Service_Area_Identifier = -1;
static gint ett_sabp_Service_Areas_List = -1;
static gint ett_sabp_Write_Replace = -1;
static gint ett_sabp_Write_Replace_Complete = -1;
static gint ett_sabp_Write_Replace_Failure = -1;
static gint ett_sabp_Kill = -1;
static gint ett_sabp_Kill_Complete = -1;
static gint ett_sabp_Kill_Failure = -1;
static gint ett_sabp_Load_Query = -1;
static gint ett_sabp_Load_Query_Complete = -1;
static gint ett_sabp_Load_Query_Failure = -1;
static gint ett_sabp_Message_Status_Query = -1;
static gint ett_sabp_Message_Status_Query_Complete = -1;
static gint ett_sabp_Message_Status_Query_Failure = -1;
static gint ett_sabp_Reset = -1;
static gint ett_sabp_Reset_Complete = -1;
static gint ett_sabp_Reset_Failure = -1;
static gint ett_sabp_Restart = -1;
static gint ett_sabp_Failure = -1;
static gint ett_sabp_Error_Indication = -1;
static gint ett_sabp_SABP_PDU = -1;
static gint ett_sabp_InitiatingMessage = -1;
static gint ett_sabp_SuccessfulOutcome = -1;
static gint ett_sabp_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-sabp-ett.c ---*/
#line 72 "packet-sabp-template.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ProtocolExtensionID;
static guint8 sms_encoding;

/* desegmentation of sabp over TCP */
static gboolean gbl_sabp_desegment = TRUE;

/* Dissector tables */
static dissector_table_t sabp_ies_dissector_table;
static dissector_table_t sabp_extension_dissector_table;
static dissector_table_t sabp_proc_imsg_dissector_table;
static dissector_table_t sabp_proc_sout_dissector_table;
static dissector_table_t sabp_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


/*--- Included file: packet-sabp-fn.c ---*/
#line 1 "packet-sabp-fn.c"

static const value_string sabp_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_sabp_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

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


static int
dissect_sabp_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, FALSE);

#line 54 "sabp.cnf"
	if (check_col(actx->pinfo->cinfo, COL_INFO))
       col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
                   val_to_str(ProcedureCode, sabp_ProcedureCode_vals,
                              "unknown message"));

  return offset;
}



static int
dissect_sabp_ProtocolExtensionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolExtensionID, FALSE);

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
  { 0, NULL }
};


static int
dissect_sabp_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolIE_ID, FALSE);

#line 41 "sabp.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str(ProtocolIE_ID, VALS(sabp_ProtocolIE_ID_vals), "unknown (%d)"));
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
                                     4, NULL, FALSE, 0, NULL);

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
                                                  0, maxProtocolIEs);

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
                                                  1, maxProtocolExtensions);

  return offset;
}



static int
dissect_sabp_Available_Bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 20480U, NULL, FALSE);

  return offset;
}



static int
dissect_sabp_Broadcast_Message_Content(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 9968, FALSE, NULL);

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
                                     4, NULL, TRUE, 0, NULL);

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


static int
dissect_sabp_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_sabp_RepetitionNumber0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

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
                                                  1, maxNrOfErrors);

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
                                                            1U, 256U, NULL, FALSE);

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
                                                  1, maxNrOfLevels);

  return offset;
}



static int
dissect_sabp_Data_Coding_Scheme(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 161 "sabp.cnf"
 tvbuff_t *parameter_tvb=NULL;
 proto_tree *subtree;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, &parameter_tvb);


	if (!parameter_tvb)
		return offset;
	subtree = proto_item_add_subtree(actx->created_item, ett_sabp_cbs_data_coding);
	sms_encoding = dissect_cbs_data_coding_scheme(parameter_tvb, actx->pinfo, subtree);




  return offset;
}




static int
dissect_sabp_PLMNidentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 149 "sabp.cnf"
  tvbuff_t *parameter_tvb=NULL;
 proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &parameter_tvb);

	 if (!parameter_tvb)
		return offset;
	subtree = proto_item_add_subtree(actx->created_item, ett_sabp_e212);
	dissect_e212_mcc_mnc(parameter_tvb, subtree, 0);



  return offset;
}



static int
dissect_sabp_OCTET_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t Service_Area_Identifier_sequence[] = {
  { &hf_sabp_pLMNidentity   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_PLMNidentity },
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
                                                  1, maxnoofSAI);

  return offset;
}



static int
dissect_sabp_Message_Identifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL);

  return offset;
}



static int
dissect_sabp_Serial_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL);

  return offset;
}



static int
dissect_sabp_New_Serial_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_sabp_Serial_Number(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_sabp_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  1, maxnoofSAI);

  return offset;
}


static const value_string sabp_Number_of_Broadcasts_Requested_vals[] = {
  {   0, "broadcast-indefinitely" },
  { 0, NULL }
};


static int
dissect_sabp_Number_of_Broadcasts_Requested(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_sabp_Old_Serial_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_sabp_Serial_Number(tvb, offset, actx, tree, hf_index);

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
                                                  1, maxnoofSAI);

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
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_sabp_Repetition_Period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4096U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Service_Areas_List_sequence_of[1] = {
  { &hf_sabp_Service_Areas_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sabp_Service_Area_Identifier },
};

static int
dissect_sabp_Service_Areas_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_sabp_Service_Areas_List, Service_Areas_List_sequence_of,
                                                  1, maxnoofSAI);

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
                                     2, NULL, TRUE, 0, NULL);

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

static int dissect_Broadcast_Message_Content_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Broadcast_Message_Content(tvb, offset, &asn1_ctx, tree, hf_sabp_Broadcast_Message_Content_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Category_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Category(tvb, offset, &asn1_ctx, tree, hf_sabp_Category_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Cause(tvb, offset, &asn1_ctx, tree, hf_sabp_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Criticality_Diagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Criticality_Diagnostics(tvb, offset, &asn1_ctx, tree, hf_sabp_Criticality_Diagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MessageStructure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_MessageStructure(tvb, offset, &asn1_ctx, tree, hf_sabp_MessageStructure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Data_Coding_Scheme_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Data_Coding_Scheme(tvb, offset, &asn1_ctx, tree, hf_sabp_Data_Coding_Scheme_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Failure_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Failure_List(tvb, offset, &asn1_ctx, tree, hf_sabp_Failure_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Message_Identifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Message_Identifier(tvb, offset, &asn1_ctx, tree, hf_sabp_Message_Identifier_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_New_Serial_Number_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_New_Serial_Number(tvb, offset, &asn1_ctx, tree, hf_sabp_New_Serial_Number_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Number_of_Broadcasts_Completed_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Number_of_Broadcasts_Completed_List(tvb, offset, &asn1_ctx, tree, hf_sabp_Number_of_Broadcasts_Completed_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Number_of_Broadcasts_Requested_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Number_of_Broadcasts_Requested(tvb, offset, &asn1_ctx, tree, hf_sabp_Number_of_Broadcasts_Requested_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Old_Serial_Number_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Old_Serial_Number(tvb, offset, &asn1_ctx, tree, hf_sabp_Old_Serial_Number_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Radio_Resource_Loading_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Radio_Resource_Loading_List(tvb, offset, &asn1_ctx, tree, hf_sabp_Radio_Resource_Loading_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Recovery_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Recovery_Indication(tvb, offset, &asn1_ctx, tree, hf_sabp_Recovery_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Repetition_Period_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Repetition_Period(tvb, offset, &asn1_ctx, tree, hf_sabp_Repetition_Period_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Serial_Number_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Serial_Number(tvb, offset, &asn1_ctx, tree, hf_sabp_Serial_Number_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Service_Areas_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Service_Areas_List(tvb, offset, &asn1_ctx, tree, hf_sabp_Service_Areas_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TypeOfError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_TypeOfError(tvb, offset, &asn1_ctx, tree, hf_sabp_TypeOfError_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Write_Replace_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Write_Replace(tvb, offset, &asn1_ctx, tree, hf_sabp_Write_Replace_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Write_Replace_Complete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Write_Replace_Complete(tvb, offset, &asn1_ctx, tree, hf_sabp_Write_Replace_Complete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Write_Replace_Failure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Write_Replace_Failure(tvb, offset, &asn1_ctx, tree, hf_sabp_Write_Replace_Failure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Kill_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Kill(tvb, offset, &asn1_ctx, tree, hf_sabp_Kill_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Kill_Complete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Kill_Complete(tvb, offset, &asn1_ctx, tree, hf_sabp_Kill_Complete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Kill_Failure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Kill_Failure(tvb, offset, &asn1_ctx, tree, hf_sabp_Kill_Failure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Load_Query_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Load_Query(tvb, offset, &asn1_ctx, tree, hf_sabp_Load_Query_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Load_Query_Complete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Load_Query_Complete(tvb, offset, &asn1_ctx, tree, hf_sabp_Load_Query_Complete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Load_Query_Failure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Load_Query_Failure(tvb, offset, &asn1_ctx, tree, hf_sabp_Load_Query_Failure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Message_Status_Query_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Message_Status_Query(tvb, offset, &asn1_ctx, tree, hf_sabp_Message_Status_Query_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Message_Status_Query_Complete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Message_Status_Query_Complete(tvb, offset, &asn1_ctx, tree, hf_sabp_Message_Status_Query_Complete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Message_Status_Query_Failure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Message_Status_Query_Failure(tvb, offset, &asn1_ctx, tree, hf_sabp_Message_Status_Query_Failure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Reset(tvb, offset, &asn1_ctx, tree, hf_sabp_Reset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_Complete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Reset_Complete(tvb, offset, &asn1_ctx, tree, hf_sabp_Reset_Complete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_Failure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Reset_Failure(tvb, offset, &asn1_ctx, tree, hf_sabp_Reset_Failure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Restart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Restart(tvb, offset, &asn1_ctx, tree, hf_sabp_Restart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Failure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Failure(tvb, offset, &asn1_ctx, tree, hf_sabp_Failure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Error_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_Error_Indication(tvb, offset, &asn1_ctx, tree, hf_sabp_Error_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SABP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_sabp_SABP_PDU(tvb, offset, &asn1_ctx, tree, hf_sabp_SABP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-sabp-fn.c ---*/
#line 96 "packet-sabp-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_port(sabp_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_port(sabp_extension_dissector_table, ProtocolExtensionID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_port(sabp_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_port(sabp_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_port(sabp_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static guint
get_sabp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint32 type_length;
	int bit_offset;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);

	/* Length should be in the 3:d octet */
	offset = offset + 3;

	bit_offset = offset<<3;
	/* Get the length of the sabp packet. offset in bits  */
	offset = dissect_per_length_determinant(tvb, bit_offset, &asn1_ctx, NULL, -1, &type_length);

	/* return the remaining length of the PDU */
	return type_length+5;
}


static void
dissect_sabp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*sabp_item = NULL;
	proto_tree	*sabp_tree = NULL;

	/* make entry in the Protocol column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

	/* create the sbap protocol tree */
	sabp_item = proto_tree_add_item(tree, proto_sabp, tvb, 0, -1, FALSE);
	sabp_tree = proto_item_add_subtree(sabp_item, ett_sabp);
	
	dissect_SABP_PDU_PDU(tvb, pinfo, sabp_tree);
}

/* Note a little bit of a hack assumes length max takes two bytes and that the length starts at byte 4 */
static void
dissect_sabp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, gbl_sabp_desegment, 5,
					 get_sabp_pdu_len, dissect_sabp);
}

/*--- proto_register_sbap -------------------------------------------*/
void proto_register_sabp(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_sabp_no_of_pages,
      { "Number-of-Pages", "sabp.no_of_pages",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Number-of-Pages", HFILL }},


/*--- Included file: packet-sabp-hfarr.c ---*/
#line 1 "packet-sabp-hfarr.c"
    { &hf_sabp_Broadcast_Message_Content_PDU,
      { "Broadcast-Message-Content", "sabp.Broadcast_Message_Content",
        FT_BYTES, BASE_HEX, NULL, 0,
        "sabp.Broadcast_Message_Content", HFILL }},
    { &hf_sabp_Category_PDU,
      { "Category", "sabp.Category",
        FT_UINT32, BASE_DEC, VALS(sabp_Category_vals), 0,
        "sabp.Category", HFILL }},
    { &hf_sabp_Cause_PDU,
      { "Cause", "sabp.Cause",
        FT_UINT32, BASE_DEC, VALS(sabp_Cause_vals), 0,
        "sabp.Cause", HFILL }},
    { &hf_sabp_Criticality_Diagnostics_PDU,
      { "Criticality-Diagnostics", "sabp.Criticality_Diagnostics",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Criticality_Diagnostics", HFILL }},
    { &hf_sabp_MessageStructure_PDU,
      { "MessageStructure", "sabp.MessageStructure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.MessageStructure", HFILL }},
    { &hf_sabp_Data_Coding_Scheme_PDU,
      { "Data-Coding-Scheme", "sabp.Data_Coding_Scheme",
        FT_BYTES, BASE_HEX, NULL, 0,
        "sabp.Data_Coding_Scheme", HFILL }},
    { &hf_sabp_Failure_List_PDU,
      { "Failure-List", "sabp.Failure_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.Failure_List", HFILL }},
    { &hf_sabp_Message_Identifier_PDU,
      { "Message-Identifier", "sabp.Message_Identifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "sabp.Message_Identifier", HFILL }},
    { &hf_sabp_New_Serial_Number_PDU,
      { "New-Serial-Number", "sabp.New_Serial_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "sabp.New_Serial_Number", HFILL }},
    { &hf_sabp_Number_of_Broadcasts_Completed_List_PDU,
      { "Number-of-Broadcasts-Completed-List", "sabp.Number_of_Broadcasts_Completed_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.Number_of_Broadcasts_Completed_List", HFILL }},
    { &hf_sabp_Number_of_Broadcasts_Requested_PDU,
      { "Number-of-Broadcasts-Requested", "sabp.Number_of_Broadcasts_Requested",
        FT_UINT32, BASE_DEC, VALS(sabp_Number_of_Broadcasts_Requested_vals), 0,
        "sabp.Number_of_Broadcasts_Requested", HFILL }},
    { &hf_sabp_Old_Serial_Number_PDU,
      { "Old-Serial-Number", "sabp.Old_Serial_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "sabp.Old_Serial_Number", HFILL }},
    { &hf_sabp_Radio_Resource_Loading_List_PDU,
      { "Radio-Resource-Loading-List", "sabp.Radio_Resource_Loading_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.Radio_Resource_Loading_List", HFILL }},
    { &hf_sabp_Recovery_Indication_PDU,
      { "Recovery-Indication", "sabp.Recovery_Indication",
        FT_UINT32, BASE_DEC, VALS(sabp_Recovery_Indication_vals), 0,
        "sabp.Recovery_Indication", HFILL }},
    { &hf_sabp_Repetition_Period_PDU,
      { "Repetition-Period", "sabp.Repetition_Period",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.Repetition_Period", HFILL }},
    { &hf_sabp_Serial_Number_PDU,
      { "Serial-Number", "sabp.Serial_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "sabp.Serial_Number", HFILL }},
    { &hf_sabp_Service_Areas_List_PDU,
      { "Service-Areas-List", "sabp.Service_Areas_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.Service_Areas_List", HFILL }},
    { &hf_sabp_TypeOfError_PDU,
      { "TypeOfError", "sabp.TypeOfError",
        FT_UINT32, BASE_DEC, VALS(sabp_TypeOfError_vals), 0,
        "sabp.TypeOfError", HFILL }},
    { &hf_sabp_Write_Replace_PDU,
      { "Write-Replace", "sabp.Write_Replace",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Write_Replace", HFILL }},
    { &hf_sabp_Write_Replace_Complete_PDU,
      { "Write-Replace-Complete", "sabp.Write_Replace_Complete",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Write_Replace_Complete", HFILL }},
    { &hf_sabp_Write_Replace_Failure_PDU,
      { "Write-Replace-Failure", "sabp.Write_Replace_Failure",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Write_Replace_Failure", HFILL }},
    { &hf_sabp_Kill_PDU,
      { "Kill", "sabp.Kill",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Kill", HFILL }},
    { &hf_sabp_Kill_Complete_PDU,
      { "Kill-Complete", "sabp.Kill_Complete",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Kill_Complete", HFILL }},
    { &hf_sabp_Kill_Failure_PDU,
      { "Kill-Failure", "sabp.Kill_Failure",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Kill_Failure", HFILL }},
    { &hf_sabp_Load_Query_PDU,
      { "Load-Query", "sabp.Load_Query",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Load_Query", HFILL }},
    { &hf_sabp_Load_Query_Complete_PDU,
      { "Load-Query-Complete", "sabp.Load_Query_Complete",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Load_Query_Complete", HFILL }},
    { &hf_sabp_Load_Query_Failure_PDU,
      { "Load-Query-Failure", "sabp.Load_Query_Failure",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Load_Query_Failure", HFILL }},
    { &hf_sabp_Message_Status_Query_PDU,
      { "Message-Status-Query", "sabp.Message_Status_Query",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Message_Status_Query", HFILL }},
    { &hf_sabp_Message_Status_Query_Complete_PDU,
      { "Message-Status-Query-Complete", "sabp.Message_Status_Query_Complete",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Message_Status_Query_Complete", HFILL }},
    { &hf_sabp_Message_Status_Query_Failure_PDU,
      { "Message-Status-Query-Failure", "sabp.Message_Status_Query_Failure",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Message_Status_Query_Failure", HFILL }},
    { &hf_sabp_Reset_PDU,
      { "Reset", "sabp.Reset",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Reset", HFILL }},
    { &hf_sabp_Reset_Complete_PDU,
      { "Reset-Complete", "sabp.Reset_Complete",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Reset_Complete", HFILL }},
    { &hf_sabp_Reset_Failure_PDU,
      { "Reset-Failure", "sabp.Reset_Failure",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Reset_Failure", HFILL }},
    { &hf_sabp_Restart_PDU,
      { "Restart", "sabp.Restart",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Restart", HFILL }},
    { &hf_sabp_Failure_PDU,
      { "Failure", "sabp.Failure",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Failure", HFILL }},
    { &hf_sabp_Error_Indication_PDU,
      { "Error-Indication", "sabp.Error_Indication",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Error_Indication", HFILL }},
    { &hf_sabp_SABP_PDU_PDU,
      { "SABP-PDU", "sabp.SABP_PDU",
        FT_UINT32, BASE_DEC, VALS(sabp_SABP_PDU_vals), 0,
        "sabp.SABP_PDU", HFILL }},
    { &hf_sabp_ProtocolIE_Container_item,
      { "ProtocolIE-Container", "sabp.ProtocolIE_Container_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.ProtocolIE_Field", HFILL }},
    { &hf_sabp_id,
      { "id", "sabp.id",
        FT_UINT32, BASE_DEC, VALS(sabp_ProtocolIE_ID_vals), 0,
        "sabp.ProtocolIE_ID", HFILL }},
    { &hf_sabp_criticality,
      { "criticality", "sabp.criticality",
        FT_UINT32, BASE_DEC, VALS(sabp_Criticality_vals), 0,
        "sabp.Criticality", HFILL }},
    { &hf_sabp_protocolIE_Field_value,
      { "value", "sabp.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.ProtocolIE_Field_value", HFILL }},
    { &hf_sabp_ProtocolExtensionContainer_item,
      { "ProtocolExtensionContainer", "sabp.ProtocolExtensionContainer_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.ProtocolExtensionField", HFILL }},
    { &hf_sabp_ext_id,
      { "id", "sabp.id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.ProtocolExtensionID", HFILL }},
    { &hf_sabp_extensionValue,
      { "extensionValue", "sabp.extensionValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.T_extensionValue", HFILL }},
    { &hf_sabp_procedureCode,
      { "procedureCode", "sabp.procedureCode",
        FT_UINT32, BASE_DEC, VALS(sabp_ProcedureCode_vals), 0,
        "sabp.ProcedureCode", HFILL }},
    { &hf_sabp_triggeringMessage,
      { "triggeringMessage", "sabp.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(sabp_TriggeringMessage_vals), 0,
        "sabp.TriggeringMessage", HFILL }},
    { &hf_sabp_procedureCriticality,
      { "procedureCriticality", "sabp.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(sabp_Criticality_vals), 0,
        "sabp.Criticality", HFILL }},
    { &hf_sabp_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "sabp.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_sabp_iE_Extensions,
      { "iE-Extensions", "sabp.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.ProtocolExtensionContainer", HFILL }},
    { &hf_sabp_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List", "sabp.CriticalityDiagnostics_IE_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.CriticalityDiagnostics_IE_List_item", HFILL }},
    { &hf_sabp_iECriticality,
      { "iECriticality", "sabp.iECriticality",
        FT_UINT32, BASE_DEC, VALS(sabp_Criticality_vals), 0,
        "sabp.Criticality", HFILL }},
    { &hf_sabp_iE_ID,
      { "iE-ID", "sabp.iE_ID",
        FT_UINT32, BASE_DEC, VALS(sabp_ProtocolIE_ID_vals), 0,
        "sabp.ProtocolIE_ID", HFILL }},
    { &hf_sabp_repetitionNumber,
      { "repetitionNumber", "sabp.repetitionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.RepetitionNumber0", HFILL }},
    { &hf_sabp_MessageStructure_item,
      { "MessageStructure", "sabp.MessageStructure_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.MessageStructure_item", HFILL }},
    { &hf_sabp_repetitionNumber1,
      { "repetitionNumber", "sabp.repetitionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.RepetitionNumber1", HFILL }},
    { &hf_sabp_Failure_List_item,
      { "Failure-List", "sabp.Failure_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Failure_List_Item", HFILL }},
    { &hf_sabp_service_area_identifier,
      { "service-area-identifier", "sabp.service_area_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Service_Area_Identifier", HFILL }},
    { &hf_sabp_cause,
      { "cause", "sabp.cause",
        FT_UINT32, BASE_DEC, VALS(sabp_Cause_vals), 0,
        "sabp.Cause", HFILL }},
    { &hf_sabp_Number_of_Broadcasts_Completed_List_item,
      { "Number-of-Broadcasts-Completed-List", "sabp.Number_of_Broadcasts_Completed_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Number_of_Broadcasts_Completed_List_Item", HFILL }},
    { &hf_sabp_number_of_broadcasts_completed,
      { "number-of-broadcasts-completed", "sabp.number_of_broadcasts_completed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.INTEGER_0_65535", HFILL }},
    { &hf_sabp_number_of_broadcasts_completed_info,
      { "number-of-broadcasts-completed-info", "sabp.number_of_broadcasts_completed_info",
        FT_UINT32, BASE_DEC, VALS(sabp_Number_Of_Broadcasts_Completed_Info_vals), 0,
        "sabp.Number_Of_Broadcasts_Completed_Info", HFILL }},
    { &hf_sabp_Radio_Resource_Loading_List_item,
      { "Radio-Resource-Loading-List", "sabp.Radio_Resource_Loading_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Radio_Resource_Loading_List_Item", HFILL }},
    { &hf_sabp_available_bandwidth,
      { "available-bandwidth", "sabp.available_bandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.Available_Bandwidth", HFILL }},
    { &hf_sabp_pLMNidentity,
      { "pLMNidentity", "sabp.pLMNidentity",
        FT_BYTES, BASE_HEX, NULL, 0,
        "sabp.PLMNidentity", HFILL }},
    { &hf_sabp_lac,
      { "lac", "sabp.lac",
        FT_BYTES, BASE_HEX, NULL, 0,
        "sabp.OCTET_STRING_SIZE_2", HFILL }},
    { &hf_sabp_sac,
      { "sac", "sabp.sac",
        FT_BYTES, BASE_HEX, NULL, 0,
        "sabp.OCTET_STRING_SIZE_2", HFILL }},
    { &hf_sabp_Service_Areas_List_item,
      { "Service-Areas-List", "sabp.Service_Areas_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.Service_Area_Identifier", HFILL }},
    { &hf_sabp_protocolIEs,
      { "protocolIEs", "sabp.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.ProtocolIE_Container", HFILL }},
    { &hf_sabp_protocolExtensions,
      { "protocolExtensions", "sabp.protocolExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "sabp.ProtocolExtensionContainer", HFILL }},
    { &hf_sabp_initiatingMessage,
      { "initiatingMessage", "sabp.initiatingMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.InitiatingMessage", HFILL }},
    { &hf_sabp_successfulOutcome,
      { "successfulOutcome", "sabp.successfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.SuccessfulOutcome", HFILL }},
    { &hf_sabp_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "sabp.unsuccessfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.UnsuccessfulOutcome", HFILL }},
    { &hf_sabp_initiatingMessage_value,
      { "value", "sabp.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.InitiatingMessage_value", HFILL }},
    { &hf_sabp_successfulOutcome_value,
      { "value", "sabp.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.SuccessfulOutcome_value", HFILL }},
    { &hf_sabp_unsuccessfulOutcome_value,
      { "value", "sabp.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "sabp.UnsuccessfulOutcome_value", HFILL }},

/*--- End of included file: packet-sabp-hfarr.c ---*/
#line 179 "packet-sabp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_sabp,
		  &ett_sabp_e212,
		  &ett_sabp_cbs_data_coding,
		  &ett_sabp_bcast_msg,

/*--- Included file: packet-sabp-ettarr.c ---*/
#line 1 "packet-sabp-ettarr.c"
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

/*--- End of included file: packet-sabp-ettarr.c ---*/
#line 188 "packet-sabp-template.c"
  };


  /* Register protocol */
  proto_sabp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_sabp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
 
  /* Register dissector */
  register_dissector("sabp", dissect_sabp, proto_sabp);
  register_dissector("sabp.tcp", dissect_sabp_tcp, proto_sabp);

  /* Register dissector tables */
  sabp_ies_dissector_table = register_dissector_table("sabp.ies", "SABP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  sabp_extension_dissector_table = register_dissector_table("sabp.extension", "SABP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  sabp_proc_imsg_dissector_table = register_dissector_table("sabp.proc.imsg", "SABP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  sabp_proc_sout_dissector_table = register_dissector_table("sabp.proc.sout", "SABP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  sabp_proc_uout_dissector_table = register_dissector_table("sabp.proc.uout", "SABP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);

}


/*--- proto_reg_handoff_sbap ---------------------------------------*/
void
proto_reg_handoff_sabp(void)
{
  dissector_handle_t sabp_handle;
  dissector_handle_t sabp_tcp_handle;

  sabp_handle = find_dissector("sabp");
  sabp_tcp_handle = find_dissector("sabp.tcp");
  dissector_add("udp.port", 3452, sabp_handle);
  dissector_add("tcp.port", 3452, sabp_tcp_handle);


/*--- Included file: packet-sabp-dis-tab.c ---*/
#line 1 "packet-sabp-dis-tab.c"
  dissector_add("sabp.ies", id_Message_Identifier, new_create_dissector_handle(dissect_Message_Identifier_PDU, proto_sabp));
  dissector_add("sabp.ies", id_New_Serial_Number, new_create_dissector_handle(dissect_New_Serial_Number_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Old_Serial_Number, new_create_dissector_handle(dissect_Old_Serial_Number_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Service_Areas_List, new_create_dissector_handle(dissect_Service_Areas_List_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Category, new_create_dissector_handle(dissect_Category_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Repetition_Period, new_create_dissector_handle(dissect_Repetition_Period_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Number_of_Broadcasts_Requested, new_create_dissector_handle(dissect_Number_of_Broadcasts_Requested_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Data_Coding_Scheme, new_create_dissector_handle(dissect_Data_Coding_Scheme_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Broadcast_Message_Content, new_create_dissector_handle(dissect_Broadcast_Message_Content_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Number_of_Broadcasts_Completed_List, new_create_dissector_handle(dissect_Number_of_Broadcasts_Completed_List_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Criticality_Diagnostics, new_create_dissector_handle(dissect_Criticality_Diagnostics_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Failure_List, new_create_dissector_handle(dissect_Failure_List_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Radio_Resource_Loading_List, new_create_dissector_handle(dissect_Radio_Resource_Loading_List_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Recovery_Indication, new_create_dissector_handle(dissect_Recovery_Indication_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Serial_Number, new_create_dissector_handle(dissect_Serial_Number_PDU, proto_sabp));
  dissector_add("sabp.ies", id_Cause, new_create_dissector_handle(dissect_Cause_PDU, proto_sabp));
  dissector_add("sabp.extension", id_MessageStructure, new_create_dissector_handle(dissect_MessageStructure_PDU, proto_sabp));
  dissector_add("sabp.extension", id_TypeOfError, new_create_dissector_handle(dissect_TypeOfError_PDU, proto_sabp));
  dissector_add("sabp.proc.imsg", id_Write_Replace, new_create_dissector_handle(dissect_Write_Replace_PDU, proto_sabp));
  dissector_add("sabp.proc.sout", id_Write_Replace, new_create_dissector_handle(dissect_Write_Replace_Complete_PDU, proto_sabp));
  dissector_add("sabp.proc.uout", id_Write_Replace, new_create_dissector_handle(dissect_Write_Replace_Failure_PDU, proto_sabp));
  dissector_add("sabp.proc.imsg", id_Kill, new_create_dissector_handle(dissect_Kill_PDU, proto_sabp));
  dissector_add("sabp.proc.sout", id_Kill, new_create_dissector_handle(dissect_Kill_Complete_PDU, proto_sabp));
  dissector_add("sabp.proc.uout", id_Kill, new_create_dissector_handle(dissect_Kill_Failure_PDU, proto_sabp));
  dissector_add("sabp.proc.imsg", id_Load_Status_Enquiry, new_create_dissector_handle(dissect_Load_Query_PDU, proto_sabp));
  dissector_add("sabp.proc.sout", id_Load_Status_Enquiry, new_create_dissector_handle(dissect_Load_Query_Complete_PDU, proto_sabp));
  dissector_add("sabp.proc.uout", id_Load_Status_Enquiry, new_create_dissector_handle(dissect_Load_Query_Failure_PDU, proto_sabp));
  dissector_add("sabp.proc.imsg", id_Message_Status_Query, new_create_dissector_handle(dissect_Message_Status_Query_PDU, proto_sabp));
  dissector_add("sabp.proc.sout", id_Message_Status_Query, new_create_dissector_handle(dissect_Message_Status_Query_Complete_PDU, proto_sabp));
  dissector_add("sabp.proc.uout", id_Message_Status_Query, new_create_dissector_handle(dissect_Message_Status_Query_Failure_PDU, proto_sabp));
  dissector_add("sabp.proc.imsg", id_Reset, new_create_dissector_handle(dissect_Reset_PDU, proto_sabp));
  dissector_add("sabp.proc.sout", id_Reset, new_create_dissector_handle(dissect_Reset_Complete_PDU, proto_sabp));
  dissector_add("sabp.proc.uout", id_Reset, new_create_dissector_handle(dissect_Reset_Failure_PDU, proto_sabp));
  dissector_add("sabp.proc.imsg", id_Restart_Indication, new_create_dissector_handle(dissect_Restart_PDU, proto_sabp));
  dissector_add("sabp.proc.imsg", id_Failure_Indication, new_create_dissector_handle(dissect_Failure_PDU, proto_sabp));
  dissector_add("sabp.proc.imsg", id_Error_Indication, new_create_dissector_handle(dissect_Error_Indication_PDU, proto_sabp));


/*--- End of included file: packet-sabp-dis-tab.c ---*/
#line 224 "packet-sabp-template.c"

}


