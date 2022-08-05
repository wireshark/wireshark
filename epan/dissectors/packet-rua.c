/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-rua.c                                                               */
/* asn2wrs.py -p rua -c ./rua.cnf -s ./packet-rua-template -D . -O ../.. RUA-CommonDataTypes.asn RUA-Constants.asn RUA-Containers.asn RUA-IEs.asn RUA-PDU-Contents.asn RUA-PDU-Descriptions.asn */

/* Input file: packet-rua-template.c */

#line 1 "./asn1/rua/packet-rua-template.c"
/* packet-rua-template.c
 * Routines for UMTS Home Node B RANAP User Adaptation (RUA) packet dissection
 * Copyright 2010 Neil Piercy, ip.access Limited <Neil.Piercy@ipaccess.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: 3GPP TS 25.468 version 8.1.0 Release 8
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/sctpppids.h>
#include <epan/asn1.h>
#include <epan/prefs.h>

#include "packet-per.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "UTRAN Iuh interface RUA signalling"
#define PSNAME "RUA"
#define PFNAME "rua"
/* Dissector to use SCTP PPID 19 or a configured SCTP port. IANA assigned port = 29169*/
#define SCTP_PORT_RUA              29169

void proto_register_rua(void);


/*--- Included file: packet-rua-val.h ---*/
#line 1 "./asn1/rua/packet-rua-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxNrOfErrors                  256

typedef enum _ProcedureCode_enum {
  id_Connect   =   1,
  id_DirectTransfer =   2,
  id_Disconnect =   3,
  id_ConnectionlessTransfer =   4,
  id_ErrorIndication =   5,
  id_privateMessage =   6
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_Cause     =   1,
  id_CriticalityDiagnostics =   2,
  id_Context_ID =   3,
  id_RANAP_Message =   4,
  id_IntraDomainNasNodeSelector =   5,
  id_Establishment_Cause =   6,
  id_CN_DomainIndicator =   7,
  id_CSGMembershipStatus =   9
} ProtocolIE_ID_enum;

/*--- End of included file: packet-rua-val.h ---*/
#line 37 "./asn1/rua/packet-rua-template.c"

/* Initialize the protocol and registered fields */
static int proto_rua = -1;


/*--- Included file: packet-rua-hf.c ---*/
#line 1 "./asn1/rua/packet-rua-hf.c"
static int hf_rua_CN_DomainIndicator_PDU = -1;    /* CN_DomainIndicator */
static int hf_rua_CSGMembershipStatus_PDU = -1;   /* CSGMembershipStatus */
static int hf_rua_Establishment_Cause_PDU = -1;   /* Establishment_Cause */
static int hf_rua_Context_ID_PDU = -1;            /* Context_ID */
static int hf_rua_IntraDomainNasNodeSelector_PDU = -1;  /* IntraDomainNasNodeSelector */
static int hf_rua_RANAP_Message_PDU = -1;         /* RANAP_Message */
static int hf_rua_Cause_PDU = -1;                 /* Cause */
static int hf_rua_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_rua_Connect_PDU = -1;               /* Connect */
static int hf_rua_DirectTransfer_PDU = -1;        /* DirectTransfer */
static int hf_rua_Disconnect_PDU = -1;            /* Disconnect */
static int hf_rua_ConnectionlessTransfer_PDU = -1;  /* ConnectionlessTransfer */
static int hf_rua_ErrorIndication_PDU = -1;       /* ErrorIndication */
static int hf_rua_PrivateMessage_PDU = -1;        /* PrivateMessage */
static int hf_rua_RUA_PDU_PDU = -1;               /* RUA_PDU */
static int hf_rua_local = -1;                     /* INTEGER_0_65535 */
static int hf_rua_global = -1;                    /* OBJECT_IDENTIFIER */
static int hf_rua_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_rua_protocol_ie_field_id = -1;      /* ProtocolIE_ID */
static int hf_rua_criticality = -1;               /* Criticality */
static int hf_rua_ie_field_value = -1;            /* ProtocolIE_Field_value */
static int hf_rua_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_rua_id = -1;                        /* ProtocolIE_ID */
static int hf_rua_extensionValue = -1;            /* T_extensionValue */
static int hf_rua_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_rua_private_ie_field_id = -1;       /* PrivateIE_ID */
static int hf_rua_private_value = -1;             /* PrivateIE_Field_value */
static int hf_rua_version = -1;                   /* T_version */
static int hf_rua_release99 = -1;                 /* T_release99 */
static int hf_rua_cn_Type = -1;                   /* T_cn_Type */
static int hf_rua_gsm_Map_IDNNS = -1;             /* Gsm_map_IDNNS */
static int hf_rua_ansi_41_IDNNS = -1;             /* Ansi_41_IDNNS */
static int hf_rua_later = -1;                     /* T_later */
static int hf_rua_futurecoding = -1;              /* BIT_STRING_SIZE_15 */
static int hf_rua_routingbasis = -1;              /* T_routingbasis */
static int hf_rua_localPTMSI = -1;                /* T_localPTMSI */
static int hf_rua_routingparameter = -1;          /* RoutingParameter */
static int hf_rua_tMSIofsamePLMN = -1;            /* T_tMSIofsamePLMN */
static int hf_rua_tMSIofdifferentPLMN = -1;       /* T_tMSIofdifferentPLMN */
static int hf_rua_iMSIresponsetopaging = -1;      /* T_iMSIresponsetopaging */
static int hf_rua_iMSIcauseUEinitiatedEvent = -1;  /* T_iMSIcauseUEinitiatedEvent */
static int hf_rua_iMEI = -1;                      /* T_iMEI */
static int hf_rua_spare2 = -1;                    /* T_spare2 */
static int hf_rua_spare1 = -1;                    /* T_spare1 */
static int hf_rua_dummy = -1;                     /* BOOLEAN */
static int hf_rua_radioNetwork = -1;              /* CauseRadioNetwork */
static int hf_rua_transport = -1;                 /* CauseTransport */
static int hf_rua_protocol = -1;                  /* CauseProtocol */
static int hf_rua_misc = -1;                      /* CauseMisc */
static int hf_rua_procedureCode = -1;             /* ProcedureCode */
static int hf_rua_triggeringMessage = -1;         /* TriggeringMessage */
static int hf_rua_procedureCriticality = -1;      /* Criticality */
static int hf_rua_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_rua_iE_Extensions = -1;             /* ProtocolExtensionContainer */
static int hf_rua_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_rua_iECriticality = -1;             /* Criticality */
static int hf_rua_iE_ID = -1;                     /* ProtocolIE_ID */
static int hf_rua_typeOfError = -1;               /* TypeOfError */
static int hf_rua_protocolIEs = -1;               /* ProtocolIE_Container */
static int hf_rua_protocolExtensions = -1;        /* ProtocolExtensionContainer */
static int hf_rua_privateIEs = -1;                /* PrivateIE_Container */
static int hf_rua_initiatingMessage = -1;         /* InitiatingMessage */
static int hf_rua_successfulOutcome = -1;         /* SuccessfulOutcome */
static int hf_rua_unsuccessfulOutcome = -1;       /* UnsuccessfulOutcome */
static int hf_rua_initiatingMessagevalue = -1;    /* InitiatingMessage_value */
static int hf_rua_successfulOutcome_value = -1;   /* SuccessfulOutcome_value */
static int hf_rua_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-rua-hf.c ---*/
#line 42 "./asn1/rua/packet-rua-template.c"

/* Initialize the subtree pointers */
static int ett_rua = -1;

 /* initialise sub-dissector handles */
 static dissector_handle_t ranap_handle = NULL;


/*--- Included file: packet-rua-ett.c ---*/
#line 1 "./asn1/rua/packet-rua-ett.c"
static gint ett_rua_PrivateIE_ID = -1;
static gint ett_rua_ProtocolIE_Container = -1;
static gint ett_rua_ProtocolIE_Field = -1;
static gint ett_rua_ProtocolExtensionContainer = -1;
static gint ett_rua_ProtocolExtensionField = -1;
static gint ett_rua_PrivateIE_Container = -1;
static gint ett_rua_PrivateIE_Field = -1;
static gint ett_rua_IntraDomainNasNodeSelector = -1;
static gint ett_rua_T_version = -1;
static gint ett_rua_T_release99 = -1;
static gint ett_rua_T_cn_Type = -1;
static gint ett_rua_T_later = -1;
static gint ett_rua_Gsm_map_IDNNS = -1;
static gint ett_rua_T_routingbasis = -1;
static gint ett_rua_T_localPTMSI = -1;
static gint ett_rua_T_tMSIofsamePLMN = -1;
static gint ett_rua_T_tMSIofdifferentPLMN = -1;
static gint ett_rua_T_iMSIresponsetopaging = -1;
static gint ett_rua_T_iMSIcauseUEinitiatedEvent = -1;
static gint ett_rua_T_iMEI = -1;
static gint ett_rua_T_spare2 = -1;
static gint ett_rua_T_spare1 = -1;
static gint ett_rua_Cause = -1;
static gint ett_rua_CriticalityDiagnostics = -1;
static gint ett_rua_CriticalityDiagnostics_IE_List = -1;
static gint ett_rua_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_rua_Connect = -1;
static gint ett_rua_DirectTransfer = -1;
static gint ett_rua_Disconnect = -1;
static gint ett_rua_ConnectionlessTransfer = -1;
static gint ett_rua_ErrorIndication = -1;
static gint ett_rua_PrivateMessage = -1;
static gint ett_rua_RUA_PDU = -1;
static gint ett_rua_InitiatingMessage = -1;
static gint ett_rua_SuccessfulOutcome = -1;
static gint ett_rua_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-rua-ett.c ---*/
#line 50 "./asn1/rua/packet-rua-template.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;

/* Dissector tables */
static dissector_table_t rua_ies_dissector_table;
static dissector_table_t rua_extension_dissector_table;
static dissector_table_t rua_proc_imsg_dissector_table;
static dissector_table_t rua_proc_sout_dissector_table;
static dissector_table_t rua_proc_uout_dissector_table;

static dissector_handle_t rua_handle;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

void proto_reg_handoff_rua(void);


/*--- Included file: packet-rua-fn.c ---*/
#line 1 "./asn1/rua/packet-rua-fn.c"

static const value_string rua_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_rua_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string rua_ProcedureCode_vals[] = {
  { id_Connect, "id-Connect" },
  { id_DirectTransfer, "id-DirectTransfer" },
  { id_Disconnect, "id-Disconnect" },
  { id_ConnectionlessTransfer, "id-ConnectionlessTransfer" },
  { id_ErrorIndication, "id-ErrorIndication" },
  { id_privateMessage, "id-privateMessage" },
  { 0, NULL }
};


static int
dissect_rua_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, FALSE);

#line 52 "./asn1/rua/rua.cnf"
  if (strcmp(val_to_str(ProcedureCode, rua_ProcedureCode_vals, "Unknown"), "Unknown") == 0) {
    col_set_str(actx->pinfo->cinfo, COL_INFO,
                      "Unknown Message ");
  } /* Known Procedures should be included below and broken out as ELEMENTARY names to avoid confusion */


  return offset;
}



static int
dissect_rua_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_rua_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string rua_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_rua_local           , ASN1_NO_EXTENSIONS     , dissect_rua_INTEGER_0_65535 },
  {   1, &hf_rua_global          , ASN1_NO_EXTENSIONS     , dissect_rua_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_rua_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rua_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string rua_ProtocolIE_ID_vals[] = {
  { id_Cause, "id-Cause" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_Context_ID, "id-Context-ID" },
  { id_RANAP_Message, "id-RANAP-Message" },
  { id_IntraDomainNasNodeSelector, "id-IntraDomainNasNodeSelector" },
  { id_Establishment_Cause, "id-Establishment-Cause" },
  { id_CN_DomainIndicator, "id-CN-DomainIndicator" },
  { id_CSGMembershipStatus, "id-CSGMembershipStatus" },
  { 0, NULL }
};


static int
dissect_rua_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &ProtocolIE_ID, FALSE);

#line 41 "./asn1/rua/rua.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str(ProtocolIE_ID, VALS(rua_ProtocolIE_ID_vals), "unknown (%d)"));
  }

  return offset;
}


static const value_string rua_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessful-outcome" },
  { 0, NULL }
};


static int
dissect_rua_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_rua_ProtocolIE_Field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_rua_protocol_ie_field_id, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_ProtocolIE_ID },
  { &hf_rua_criticality     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_Criticality },
  { &hf_rua_ie_field_value  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_ProtocolIE_Field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_rua_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_ProtocolIE_Field },
};

static int
dissect_rua_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rua_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}



static int
dissect_rua_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_rua_id              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_ProtocolIE_ID },
  { &hf_rua_criticality     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_Criticality },
  { &hf_rua_extensionValue  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_rua_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_ProtocolExtensionField },
};

static int
dissect_rua_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rua_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_rua_PrivateIE_Field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_rua_private_ie_field_id, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_PrivateIE_ID },
  { &hf_rua_criticality     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_Criticality },
  { &hf_rua_private_value   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_PrivateIE_Field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_rua_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_PrivateIE_Field },
};

static int
dissect_rua_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rua_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, FALSE);

  return offset;
}


static const value_string rua_CN_DomainIndicator_vals[] = {
  {   0, "cs-domain" },
  {   1, "ps-domain" },
  { 0, NULL }
};


static int
dissect_rua_CN_DomainIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string rua_CSGMembershipStatus_vals[] = {
  {   0, "member" },
  {   1, "non-member" },
  { 0, NULL }
};


static int
dissect_rua_CSGMembershipStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string rua_Establishment_Cause_vals[] = {
  {   0, "emergency-call" },
  {   1, "normal-call" },
  { 0, NULL }
};


static int
dissect_rua_Establishment_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_rua_Context_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_rua_RoutingParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t T_localPTMSI_sequence[] = {
  { &hf_rua_routingparameter, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_RoutingParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_T_localPTMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_T_localPTMSI, T_localPTMSI_sequence);

  return offset;
}


static const per_sequence_t T_tMSIofsamePLMN_sequence[] = {
  { &hf_rua_routingparameter, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_RoutingParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_T_tMSIofsamePLMN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_T_tMSIofsamePLMN, T_tMSIofsamePLMN_sequence);

  return offset;
}


static const per_sequence_t T_tMSIofdifferentPLMN_sequence[] = {
  { &hf_rua_routingparameter, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_RoutingParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_T_tMSIofdifferentPLMN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_T_tMSIofdifferentPLMN, T_tMSIofdifferentPLMN_sequence);

  return offset;
}


static const per_sequence_t T_iMSIresponsetopaging_sequence[] = {
  { &hf_rua_routingparameter, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_RoutingParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_T_iMSIresponsetopaging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_T_iMSIresponsetopaging, T_iMSIresponsetopaging_sequence);

  return offset;
}


static const per_sequence_t T_iMSIcauseUEinitiatedEvent_sequence[] = {
  { &hf_rua_routingparameter, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_RoutingParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_T_iMSIcauseUEinitiatedEvent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_T_iMSIcauseUEinitiatedEvent, T_iMSIcauseUEinitiatedEvent_sequence);

  return offset;
}


static const per_sequence_t T_iMEI_sequence[] = {
  { &hf_rua_routingparameter, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_RoutingParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_T_iMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_T_iMEI, T_iMEI_sequence);

  return offset;
}


static const per_sequence_t T_spare2_sequence[] = {
  { &hf_rua_routingparameter, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_RoutingParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_T_spare2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_T_spare2, T_spare2_sequence);

  return offset;
}


static const per_sequence_t T_spare1_sequence[] = {
  { &hf_rua_routingparameter, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_RoutingParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_T_spare1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_T_spare1, T_spare1_sequence);

  return offset;
}


static const value_string rua_T_routingbasis_vals[] = {
  {   0, "localPTMSI" },
  {   1, "tMSIofsamePLMN" },
  {   2, "tMSIofdifferentPLMN" },
  {   3, "iMSIresponsetopaging" },
  {   4, "iMSIcauseUEinitiatedEvent" },
  {   5, "iMEI" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_routingbasis_choice[] = {
  {   0, &hf_rua_localPTMSI      , ASN1_NO_EXTENSIONS     , dissect_rua_T_localPTMSI },
  {   1, &hf_rua_tMSIofsamePLMN  , ASN1_NO_EXTENSIONS     , dissect_rua_T_tMSIofsamePLMN },
  {   2, &hf_rua_tMSIofdifferentPLMN, ASN1_NO_EXTENSIONS     , dissect_rua_T_tMSIofdifferentPLMN },
  {   3, &hf_rua_iMSIresponsetopaging, ASN1_NO_EXTENSIONS     , dissect_rua_T_iMSIresponsetopaging },
  {   4, &hf_rua_iMSIcauseUEinitiatedEvent, ASN1_NO_EXTENSIONS     , dissect_rua_T_iMSIcauseUEinitiatedEvent },
  {   5, &hf_rua_iMEI            , ASN1_NO_EXTENSIONS     , dissect_rua_T_iMEI },
  {   6, &hf_rua_spare2          , ASN1_NO_EXTENSIONS     , dissect_rua_T_spare2 },
  {   7, &hf_rua_spare1          , ASN1_NO_EXTENSIONS     , dissect_rua_T_spare1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rua_T_routingbasis(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rua_T_routingbasis, T_routingbasis_choice,
                                 NULL);

  return offset;
}



static int
dissect_rua_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t Gsm_map_IDNNS_sequence[] = {
  { &hf_rua_routingbasis    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_T_routingbasis },
  { &hf_rua_dummy           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_Gsm_map_IDNNS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_Gsm_map_IDNNS, Gsm_map_IDNNS_sequence);

  return offset;
}



static int
dissect_rua_Ansi_41_IDNNS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     14, 14, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string rua_T_cn_Type_vals[] = {
  {   0, "gsm-Map-IDNNS" },
  {   1, "ansi-41-IDNNS" },
  { 0, NULL }
};

static const per_choice_t T_cn_Type_choice[] = {
  {   0, &hf_rua_gsm_Map_IDNNS   , ASN1_NO_EXTENSIONS     , dissect_rua_Gsm_map_IDNNS },
  {   1, &hf_rua_ansi_41_IDNNS   , ASN1_NO_EXTENSIONS     , dissect_rua_Ansi_41_IDNNS },
  { 0, NULL, 0, NULL }
};

static int
dissect_rua_T_cn_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rua_T_cn_Type, T_cn_Type_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_release99_sequence[] = {
  { &hf_rua_cn_Type         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_T_cn_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_T_release99(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_T_release99, T_release99_sequence);

  return offset;
}



static int
dissect_rua_BIT_STRING_SIZE_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     15, 15, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t T_later_sequence[] = {
  { &hf_rua_futurecoding    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_BIT_STRING_SIZE_15 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_T_later(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_T_later, T_later_sequence);

  return offset;
}


static const value_string rua_T_version_vals[] = {
  {   0, "release99" },
  {   1, "later" },
  { 0, NULL }
};

static const per_choice_t T_version_choice[] = {
  {   0, &hf_rua_release99       , ASN1_NO_EXTENSIONS     , dissect_rua_T_release99 },
  {   1, &hf_rua_later           , ASN1_NO_EXTENSIONS     , dissect_rua_T_later },
  { 0, NULL, 0, NULL }
};

static int
dissect_rua_T_version(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rua_T_version, T_version_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t IntraDomainNasNodeSelector_sequence[] = {
  { &hf_rua_version         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_T_version },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_IntraDomainNasNodeSelector(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_IntraDomainNasNodeSelector, IntraDomainNasNodeSelector_sequence);

  return offset;
}



static int
dissect_rua_RANAP_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 95 "./asn1/rua/rua.cnf"
  tvbuff_t *ranap_message_tvb=NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &ranap_message_tvb);

 if ((tvb_reported_length(ranap_message_tvb)>0)&&(ranap_handle)) {  /* RUA has a RANAP-PDU */
     col_set_str(actx->pinfo->cinfo, COL_INFO,
             "(RUA) ");                                    /* Set info to (RUA) to make room for RANAP */
     col_set_fence(actx->pinfo->cinfo, COL_INFO);
     call_dissector(ranap_handle,ranap_message_tvb,actx->pinfo, proto_tree_get_root(tree));
  }


  return offset;
}


static const value_string rua_CauseRadioNetwork_vals[] = {
  {   0, "normal" },
  {   1, "connect-failed" },
  {   2, "network-release" },
  {   3, "unspecified" },
  { 0, NULL }
};


static int
dissect_rua_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string rua_CauseTransport_vals[] = {
  {   0, "transport-resource-unavailable" },
  {   1, "unspecified" },
  { 0, NULL }
};


static int
dissect_rua_CauseTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string rua_CauseProtocol_vals[] = {
  {   0, "transfer-syntax-error" },
  {   1, "abstract-syntax-error-reject" },
  {   2, "abstract-syntax-error-ignore-and-notify" },
  {   3, "message-not-compatible-with-receiver-state" },
  {   4, "semantic-error" },
  {   5, "unspecified" },
  {   6, "abstract-syntax-error-falsely-constructed-message" },
  { 0, NULL }
};


static int
dissect_rua_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string rua_CauseMisc_vals[] = {
  {   0, "processing-overload" },
  {   1, "hardware-failure" },
  {   2, "o-and-m-intervention" },
  {   3, "unspecified" },
  { 0, NULL }
};


static int
dissect_rua_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string rua_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transport" },
  {   2, "protocol" },
  {   3, "misc" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_rua_radioNetwork    , ASN1_EXTENSION_ROOT    , dissect_rua_CauseRadioNetwork },
  {   1, &hf_rua_transport       , ASN1_EXTENSION_ROOT    , dissect_rua_CauseTransport },
  {   2, &hf_rua_protocol        , ASN1_EXTENSION_ROOT    , dissect_rua_CauseProtocol },
  {   3, &hf_rua_misc            , ASN1_EXTENSION_ROOT    , dissect_rua_CauseMisc },
  { 0, NULL, 0, NULL }
};

static int
dissect_rua_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rua_Cause, Cause_choice,
                                 NULL);

  return offset;
}


static const value_string rua_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_rua_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_rua_iECriticality   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rua_Criticality },
  { &hf_rua_iE_ID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rua_ProtocolIE_ID },
  { &hf_rua_typeOfError     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rua_TypeOfError },
  { &hf_rua_iE_Extensions   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rua_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_rua_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_rua_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rua_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxNrOfErrors, FALSE);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_rua_procedureCode   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rua_ProcedureCode },
  { &hf_rua_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rua_TriggeringMessage },
  { &hf_rua_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rua_Criticality },
  { &hf_rua_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rua_CriticalityDiagnostics_IE_List },
  { &hf_rua_iE_Extensions   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rua_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}


static const per_sequence_t Connect_sequence[] = {
  { &hf_rua_protocolIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rua_ProtocolIE_Container },
  { &hf_rua_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rua_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_Connect(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 64 "./asn1/rua/rua.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
             "CONNECT ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_Connect, Connect_sequence);




  return offset;
}


static const per_sequence_t DirectTransfer_sequence[] = {
  { &hf_rua_protocolIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rua_ProtocolIE_Container },
  { &hf_rua_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rua_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_DirectTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 69 "./asn1/rua/rua.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
             "DIRECT_TRANSFER ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_DirectTransfer, DirectTransfer_sequence);




  return offset;
}


static const per_sequence_t Disconnect_sequence[] = {
  { &hf_rua_protocolIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rua_ProtocolIE_Container },
  { &hf_rua_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rua_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_Disconnect(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 74 "./asn1/rua/rua.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
             "DISCONNECT ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_Disconnect, Disconnect_sequence);




  return offset;
}


static const per_sequence_t ConnectionlessTransfer_sequence[] = {
  { &hf_rua_protocolIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rua_ProtocolIE_Container },
  { &hf_rua_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rua_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_ConnectionlessTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 79 "./asn1/rua/rua.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
             "CONNECTIONLESS_TRANSFER ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_ConnectionlessTransfer, ConnectionlessTransfer_sequence);




  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_rua_protocolIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rua_ProtocolIE_Container },
  { &hf_rua_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rua_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 84 "./asn1/rua/rua.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
             "ERROR_INDICATION ");
    col_set_fence(actx->pinfo->cinfo, COL_INFO); /* Protect info from CriticalityDiagnostics decodes */
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_ErrorIndication, ErrorIndication_sequence);




  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_rua_privateIEs      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rua_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 90 "./asn1/rua/rua.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
             "PRIVATE_MESSAGE ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_PrivateMessage, PrivateMessage_sequence);




  return offset;
}



static int
dissect_rua_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_rua_procedureCode   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_ProcedureCode },
  { &hf_rua_criticality     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_Criticality },
  { &hf_rua_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_rua_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_rua_procedureCode   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_ProcedureCode },
  { &hf_rua_criticality     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_Criticality },
  { &hf_rua_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_rua_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_rua_procedureCode   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_ProcedureCode },
  { &hf_rua_criticality     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_Criticality },
  { &hf_rua_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rua_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_rua_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rua_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string rua_RUA_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t RUA_PDU_choice[] = {
  {   0, &hf_rua_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_rua_InitiatingMessage },
  {   1, &hf_rua_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_rua_SuccessfulOutcome },
  {   2, &hf_rua_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_rua_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_rua_RUA_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rua_RUA_PDU, RUA_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_CN_DomainIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_CN_DomainIndicator(tvb, offset, &asn1_ctx, tree, hf_rua_CN_DomainIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSGMembershipStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_CSGMembershipStatus(tvb, offset, &asn1_ctx, tree, hf_rua_CSGMembershipStatus_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Establishment_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_Establishment_Cause(tvb, offset, &asn1_ctx, tree, hf_rua_Establishment_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Context_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_Context_ID(tvb, offset, &asn1_ctx, tree, hf_rua_Context_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IntraDomainNasNodeSelector_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_IntraDomainNasNodeSelector(tvb, offset, &asn1_ctx, tree, hf_rua_IntraDomainNasNodeSelector_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANAP_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_RANAP_Message(tvb, offset, &asn1_ctx, tree, hf_rua_RANAP_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_Cause(tvb, offset, &asn1_ctx, tree, hf_rua_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_rua_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Connect_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_Connect(tvb, offset, &asn1_ctx, tree, hf_rua_Connect_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DirectTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_DirectTransfer(tvb, offset, &asn1_ctx, tree, hf_rua_DirectTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Disconnect_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_Disconnect(tvb, offset, &asn1_ctx, tree, hf_rua_Disconnect_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ConnectionlessTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_ConnectionlessTransfer(tvb, offset, &asn1_ctx, tree, hf_rua_ConnectionlessTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_rua_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_rua_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RUA_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_rua_RUA_PDU(tvb, offset, &asn1_ctx, tree, hf_rua_RUA_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-rua-fn.c ---*/
#line 73 "./asn1/rua/packet-rua-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(rua_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(rua_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(rua_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(rua_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(rua_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_rua(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item  *rua_item = NULL;
    proto_tree  *rua_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RUA");

    /* create the rua protocol tree */
    rua_item = proto_tree_add_item(tree, proto_rua, tvb, 0, -1, ENC_NA);
    rua_tree = proto_item_add_subtree(rua_item, ett_rua);

    return dissect_RUA_PDU_PDU(tvb, pinfo, rua_tree, data);
}

/*--- proto_register_rua -------------------------------------------*/
void proto_register_rua(void) {

  /* List of fields */

  static hf_register_info hf[] = {


/*--- Included file: packet-rua-hfarr.c ---*/
#line 1 "./asn1/rua/packet-rua-hfarr.c"
    { &hf_rua_CN_DomainIndicator_PDU,
      { "CN-DomainIndicator", "rua.CN_DomainIndicator",
        FT_UINT32, BASE_DEC, VALS(rua_CN_DomainIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_rua_CSGMembershipStatus_PDU,
      { "CSGMembershipStatus", "rua.CSGMembershipStatus",
        FT_UINT32, BASE_DEC, VALS(rua_CSGMembershipStatus_vals), 0,
        NULL, HFILL }},
    { &hf_rua_Establishment_Cause_PDU,
      { "Establishment-Cause", "rua.Establishment_Cause",
        FT_UINT32, BASE_DEC, VALS(rua_Establishment_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_rua_Context_ID_PDU,
      { "Context-ID", "rua.Context_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_IntraDomainNasNodeSelector_PDU,
      { "IntraDomainNasNodeSelector", "rua.IntraDomainNasNodeSelector_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_RANAP_Message_PDU,
      { "RANAP-Message", "rua.RANAP_Message",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_Cause_PDU,
      { "Cause", "rua.Cause",
        FT_UINT32, BASE_DEC, VALS(rua_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_rua_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "rua.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_Connect_PDU,
      { "Connect", "rua.Connect_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_DirectTransfer_PDU,
      { "DirectTransfer", "rua.DirectTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_Disconnect_PDU,
      { "Disconnect", "rua.Disconnect_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_ConnectionlessTransfer_PDU,
      { "ConnectionlessTransfer", "rua.ConnectionlessTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_ErrorIndication_PDU,
      { "ErrorIndication", "rua.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_PrivateMessage_PDU,
      { "PrivateMessage", "rua.PrivateMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_RUA_PDU_PDU,
      { "RUA-PDU", "rua.RUA_PDU",
        FT_UINT32, BASE_DEC, VALS(rua_RUA_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_rua_local,
      { "local", "rua.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_rua_global,
      { "global", "rua.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_rua_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "rua.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_protocol_ie_field_id,
      { "id", "rua.id",
        FT_UINT32, BASE_DEC, VALS(rua_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_rua_criticality,
      { "criticality", "rua.criticality",
        FT_UINT32, BASE_DEC, VALS(rua_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_rua_ie_field_value,
      { "value", "rua.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Field_value", HFILL }},
    { &hf_rua_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "rua.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_id,
      { "id", "rua.id",
        FT_UINT32, BASE_DEC, VALS(rua_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_rua_extensionValue,
      { "extensionValue", "rua.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_PrivateIE_Container_item,
      { "PrivateIE-Field", "rua.PrivateIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_private_ie_field_id,
      { "id", "rua.id",
        FT_UINT32, BASE_DEC, VALS(rua_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_rua_private_value,
      { "value", "rua.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateIE_Field_value", HFILL }},
    { &hf_rua_version,
      { "version", "rua.version",
        FT_UINT32, BASE_DEC, VALS(rua_T_version_vals), 0,
        NULL, HFILL }},
    { &hf_rua_release99,
      { "release99", "rua.release99_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_cn_Type,
      { "cn-Type", "rua.cn_Type",
        FT_UINT32, BASE_DEC, VALS(rua_T_cn_Type_vals), 0,
        NULL, HFILL }},
    { &hf_rua_gsm_Map_IDNNS,
      { "gsm-Map-IDNNS", "rua.gsm_Map_IDNNS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_ansi_41_IDNNS,
      { "ansi-41-IDNNS", "rua.ansi_41_IDNNS",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_later,
      { "later", "rua.later_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_futurecoding,
      { "futurecoding", "rua.futurecoding",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_15", HFILL }},
    { &hf_rua_routingbasis,
      { "routingbasis", "rua.routingbasis",
        FT_UINT32, BASE_DEC, VALS(rua_T_routingbasis_vals), 0,
        NULL, HFILL }},
    { &hf_rua_localPTMSI,
      { "localPTMSI", "rua.localPTMSI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_routingparameter,
      { "routingparameter", "rua.routingparameter",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_tMSIofsamePLMN,
      { "tMSIofsamePLMN", "rua.tMSIofsamePLMN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_tMSIofdifferentPLMN,
      { "tMSIofdifferentPLMN", "rua.tMSIofdifferentPLMN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_iMSIresponsetopaging,
      { "iMSIresponsetopaging", "rua.iMSIresponsetopaging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_iMSIcauseUEinitiatedEvent,
      { "iMSIcauseUEinitiatedEvent", "rua.iMSIcauseUEinitiatedEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_iMEI,
      { "iMEI", "rua.iMEI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_spare2,
      { "spare2", "rua.spare2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_spare1,
      { "spare1", "rua.spare1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_dummy,
      { "dummy", "rua.dummy",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_rua_radioNetwork,
      { "radioNetwork", "rua.radioNetwork",
        FT_UINT32, BASE_DEC, VALS(rua_CauseRadioNetwork_vals), 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_rua_transport,
      { "transport", "rua.transport",
        FT_UINT32, BASE_DEC, VALS(rua_CauseTransport_vals), 0,
        "CauseTransport", HFILL }},
    { &hf_rua_protocol,
      { "protocol", "rua.protocol",
        FT_UINT32, BASE_DEC, VALS(rua_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_rua_misc,
      { "misc", "rua.misc",
        FT_UINT32, BASE_DEC, VALS(rua_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_rua_procedureCode,
      { "procedureCode", "rua.procedureCode",
        FT_UINT32, BASE_DEC, VALS(rua_ProcedureCode_vals), 0,
        NULL, HFILL }},
    { &hf_rua_triggeringMessage,
      { "triggeringMessage", "rua.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(rua_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_rua_procedureCriticality,
      { "procedureCriticality", "rua.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(rua_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_rua_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "rua.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_rua_iE_Extensions,
      { "iE-Extensions", "rua.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_rua_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "rua.CriticalityDiagnostics_IE_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_iECriticality,
      { "iECriticality", "rua.iECriticality",
        FT_UINT32, BASE_DEC, VALS(rua_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_rua_iE_ID,
      { "iE-ID", "rua.iE_ID",
        FT_UINT32, BASE_DEC, VALS(rua_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_rua_typeOfError,
      { "typeOfError", "rua.typeOfError",
        FT_UINT32, BASE_DEC, VALS(rua_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_rua_protocolIEs,
      { "protocolIEs", "rua.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_rua_protocolExtensions,
      { "protocolExtensions", "rua.protocolExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_rua_privateIEs,
      { "privateIEs", "rua.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_rua_initiatingMessage,
      { "initiatingMessage", "rua.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_successfulOutcome,
      { "successfulOutcome", "rua.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "rua.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rua_initiatingMessagevalue,
      { "value", "rua.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_rua_successfulOutcome_value,
      { "value", "rua.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_rua_unsuccessfulOutcome_value,
      { "value", "rua.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},

/*--- End of included file: packet-rua-hfarr.c ---*/
#line 123 "./asn1/rua/packet-rua-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
          &ett_rua,

/*--- Included file: packet-rua-ettarr.c ---*/
#line 1 "./asn1/rua/packet-rua-ettarr.c"
    &ett_rua_PrivateIE_ID,
    &ett_rua_ProtocolIE_Container,
    &ett_rua_ProtocolIE_Field,
    &ett_rua_ProtocolExtensionContainer,
    &ett_rua_ProtocolExtensionField,
    &ett_rua_PrivateIE_Container,
    &ett_rua_PrivateIE_Field,
    &ett_rua_IntraDomainNasNodeSelector,
    &ett_rua_T_version,
    &ett_rua_T_release99,
    &ett_rua_T_cn_Type,
    &ett_rua_T_later,
    &ett_rua_Gsm_map_IDNNS,
    &ett_rua_T_routingbasis,
    &ett_rua_T_localPTMSI,
    &ett_rua_T_tMSIofsamePLMN,
    &ett_rua_T_tMSIofdifferentPLMN,
    &ett_rua_T_iMSIresponsetopaging,
    &ett_rua_T_iMSIcauseUEinitiatedEvent,
    &ett_rua_T_iMEI,
    &ett_rua_T_spare2,
    &ett_rua_T_spare1,
    &ett_rua_Cause,
    &ett_rua_CriticalityDiagnostics,
    &ett_rua_CriticalityDiagnostics_IE_List,
    &ett_rua_CriticalityDiagnostics_IE_List_item,
    &ett_rua_Connect,
    &ett_rua_DirectTransfer,
    &ett_rua_Disconnect,
    &ett_rua_ConnectionlessTransfer,
    &ett_rua_ErrorIndication,
    &ett_rua_PrivateMessage,
    &ett_rua_RUA_PDU,
    &ett_rua_InitiatingMessage,
    &ett_rua_SuccessfulOutcome,
    &ett_rua_UnsuccessfulOutcome,

/*--- End of included file: packet-rua-ettarr.c ---*/
#line 129 "./asn1/rua/packet-rua-template.c"
  };


  /* Register protocol */
  proto_rua = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rua, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  rua_handle = register_dissector("rua", dissect_rua, proto_rua);

  /* Register dissector tables */
  rua_ies_dissector_table = register_dissector_table("rua.ies", "RUA-PROTOCOL-IES", proto_rua, FT_UINT32, BASE_DEC);
  rua_extension_dissector_table = register_dissector_table("rua.extension", "RUA-PROTOCOL-EXTENSION", proto_rua, FT_UINT32, BASE_DEC);
  rua_proc_imsg_dissector_table = register_dissector_table("rua.proc.imsg", "RUA-ELEMENTARY-PROCEDURE InitiatingMessage", proto_rua, FT_UINT32, BASE_DEC);
  rua_proc_sout_dissector_table = register_dissector_table("rua.proc.sout", "RUA-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_rua, FT_UINT32, BASE_DEC);
  rua_proc_uout_dissector_table = register_dissector_table("rua.proc.uout", "RUA-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_rua, FT_UINT32, BASE_DEC);

  /* rua_module = prefs_register_protocol(proto_rua, NULL); */

}


/*--- proto_reg_handoff_rua ---------------------------------------*/
void
proto_reg_handoff_rua(void)
{
        ranap_handle = find_dissector_add_dependency("ranap", proto_rua);
        dissector_add_uint("sctp.ppi", RUA_PAYLOAD_PROTOCOL_ID, rua_handle);
        dissector_add_uint_with_preference("sctp.port", SCTP_PORT_RUA, rua_handle);

/*--- Included file: packet-rua-dis-tab.c ---*/
#line 1 "./asn1/rua/packet-rua-dis-tab.c"
  dissector_add_uint("rua.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_rua));
  dissector_add_uint("rua.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_rua));
  dissector_add_uint("rua.ies", id_Context_ID, create_dissector_handle(dissect_Context_ID_PDU, proto_rua));
  dissector_add_uint("rua.ies", id_RANAP_Message, create_dissector_handle(dissect_RANAP_Message_PDU, proto_rua));
  dissector_add_uint("rua.ies", id_IntraDomainNasNodeSelector, create_dissector_handle(dissect_IntraDomainNasNodeSelector_PDU, proto_rua));
  dissector_add_uint("rua.ies", id_Establishment_Cause, create_dissector_handle(dissect_Establishment_Cause_PDU, proto_rua));
  dissector_add_uint("rua.ies", id_CN_DomainIndicator, create_dissector_handle(dissect_CN_DomainIndicator_PDU, proto_rua));
  dissector_add_uint("rua.extension", id_CSGMembershipStatus, create_dissector_handle(dissect_CSGMembershipStatus_PDU, proto_rua));
  dissector_add_uint("rua.proc.imsg", id_Connect, create_dissector_handle(dissect_Connect_PDU, proto_rua));
  dissector_add_uint("rua.proc.imsg", id_DirectTransfer, create_dissector_handle(dissect_DirectTransfer_PDU, proto_rua));
  dissector_add_uint("rua.proc.imsg", id_Disconnect, create_dissector_handle(dissect_Disconnect_PDU, proto_rua));
  dissector_add_uint("rua.proc.imsg", id_ConnectionlessTransfer, create_dissector_handle(dissect_ConnectionlessTransfer_PDU, proto_rua));
  dissector_add_uint("rua.proc.imsg", id_ErrorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_rua));
  dissector_add_uint("rua.proc.imsg", id_privateMessage, create_dissector_handle(dissect_PrivateMessage_PDU, proto_rua));


/*--- End of included file: packet-rua-dis-tab.c ---*/
#line 161 "./asn1/rua/packet-rua-template.c"
}
