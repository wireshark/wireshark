/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-tcap.c                                                              */
/* asn2wrs.py -b -p tcap -c ./tcap.cnf -s ./packet-tcap-template -D . -O ../.. tcap.asn UnidialoguePDUs.asn DialoguePDUs.asn */

/* Input file: packet-tcap-template.c */

#line 1 "./asn1/tcap/packet-tcap-template.c"
/* packet-tcap-template.c
 * Routines for  TCAP
 * Copyright 2004 - 2005, Tim Endean <endeant@hotmail.com>
 * Built from the gsm-map dissector Copyright 2004 - 2005, Anders Broman <anders.broman@ericsson.com>
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
 * References: ETSI 300 374
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/address_types.h>
#include <epan/strutil.h>
#include <epan/show_exception.h>

#include "packet-ber.h"
#include "packet-tcap.h"
#include "packet-mtp3.h"


#define PNAME  "Transaction Capabilities Application Part"
#define PSNAME "TCAP"
#define PFNAME "tcap"

/* Initialize the protocol and registered fields */
static int proto_tcap = -1;
static int hf_tcap_tag = -1;
static int hf_tcap_length = -1;
static int hf_tcap_data = -1;
static int hf_tcap_tid = -1;
static int hf_tcap_constructor_eoc=-1;

int hf_tcapsrt_SessionId=-1;
int hf_tcapsrt_Duplicate=-1;
int hf_tcapsrt_BeginSession=-1;
int hf_tcapsrt_EndSession=-1;
int hf_tcapsrt_SessionTime=-1;


/*--- Included file: packet-tcap-hf.c ---*/
#line 1 "./asn1/tcap/packet-tcap-hf.c"
static int hf_tcap_UniDialoguePDU_PDU = -1;       /* UniDialoguePDU */
static int hf_tcap_DialoguePDU_PDU = -1;          /* DialoguePDU */
static int hf_tcap_oid = -1;                      /* OBJECT_IDENTIFIER */
static int hf_tcap_dialog = -1;                   /* Dialog1 */
static int hf_tcap_unidirectional = -1;           /* Unidirectional */
static int hf_tcap_begin = -1;                    /* Begin */
static int hf_tcap_end = -1;                      /* End */
static int hf_tcap_continue = -1;                 /* Continue */
static int hf_tcap_abort = -1;                    /* Abort */
static int hf_tcap_dialoguePortion = -1;          /* DialoguePortion */
static int hf_tcap_components = -1;               /* ComponentPortion */
static int hf_tcap_otid = -1;                     /* OrigTransactionID */
static int hf_tcap_dtid = -1;                     /* DestTransactionID */
static int hf_tcap_reason = -1;                   /* Reason */
static int hf_tcap_p_abortCause = -1;             /* P_AbortCause */
static int hf_tcap_u_abortCause = -1;             /* DialoguePortion */
static int hf_tcap__untag_item = -1;              /* Component */
static int hf_tcap_invoke = -1;                   /* Invoke */
static int hf_tcap_returnResultLast = -1;         /* ReturnResult */
static int hf_tcap_returnError = -1;              /* ReturnError */
static int hf_tcap_reject = -1;                   /* Reject */
static int hf_tcap_returnResultNotLast = -1;      /* ReturnResult */
static int hf_tcap_invokeID = -1;                 /* InvokeIdType */
static int hf_tcap_linkedID = -1;                 /* InvokeIdType */
static int hf_tcap_opCode = -1;                   /* OPERATION */
static int hf_tcap_parameter = -1;                /* Parameter */
static int hf_tcap_resultretres = -1;             /* T_resultretres */
static int hf_tcap_errorCode = -1;                /* ErrorCode */
static int hf_tcap_invokeIDRej = -1;              /* T_invokeIDRej */
static int hf_tcap_derivable = -1;                /* InvokeIdType */
static int hf_tcap_not_derivable = -1;            /* NULL */
static int hf_tcap_problem = -1;                  /* T_problem */
static int hf_tcap_generalProblem = -1;           /* GeneralProblem */
static int hf_tcap_invokeProblem = -1;            /* InvokeProblem */
static int hf_tcap_returnResultProblem = -1;      /* ReturnResultProblem */
static int hf_tcap_returnErrorProblem = -1;       /* ReturnErrorProblem */
static int hf_tcap_localValue = -1;               /* INTEGER */
static int hf_tcap_globalValue = -1;              /* OBJECT_IDENTIFIER */
static int hf_tcap_nationaler = -1;               /* INTEGER_M32768_32767 */
static int hf_tcap_privateer = -1;                /* INTEGER */
static int hf_tcap_unidialoguePDU = -1;           /* AUDT_apdu */
static int hf_tcap_audt_protocol_version = -1;    /* AUDT_protocol_version */
static int hf_tcap_audt_application_context_name = -1;  /* AUDT_application_context_name */
static int hf_tcap_audt_user_information = -1;    /* AUDT_user_information */
static int hf_tcap_audt_user_information_item = -1;  /* EXTERNAL */
static int hf_tcap_dialogueRequest = -1;          /* AARQ_apdu */
static int hf_tcap_dialogueResponse = -1;         /* AARE_apdu */
static int hf_tcap_dialogueAbort = -1;            /* ABRT_apdu */
static int hf_tcap_aarq_protocol_version = -1;    /* AARQ_protocol_version */
static int hf_tcap_aarq_application_context_name = -1;  /* AARQ_application_context_name */
static int hf_tcap_aarq_user_information = -1;    /* AARQ_user_information */
static int hf_tcap_aarq_user_information_item = -1;  /* EXTERNAL */
static int hf_tcap_aare_protocol_version = -1;    /* AARE_protocol_version */
static int hf_tcap_aare_application_context_name = -1;  /* AARE_application_context_name */
static int hf_tcap_result = -1;                   /* Associate_result */
static int hf_tcap_result_source_diagnostic = -1;  /* Associate_source_diagnostic */
static int hf_tcap_aare_user_information = -1;    /* AARE_user_information */
static int hf_tcap_aare_user_information_item = -1;  /* EXTERNAL */
static int hf_tcap_abort_source = -1;             /* ABRT_source */
static int hf_tcap_abrt_user_information = -1;    /* ABRT_user_information */
static int hf_tcap_abrt_user_information_item = -1;  /* EXTERNAL */
static int hf_tcap_dialogue_service_user = -1;    /* T_dialogue_service_user */
static int hf_tcap_dialogue_service_provider = -1;  /* T_dialogue_service_provider */
/* named bits */
static int hf_tcap_AUDT_protocol_version_version1 = -1;
static int hf_tcap_AARQ_protocol_version_version1 = -1;
static int hf_tcap_AARE_protocol_version_version1 = -1;

/*--- End of included file: packet-tcap-hf.c ---*/
#line 61 "./asn1/tcap/packet-tcap-template.c"

/* Initialize the subtree pointers */
static gint ett_tcap = -1;
static gint ett_param = -1;

static gint ett_otid = -1;
static gint ett_dtid = -1;
gint ett_tcap_stat = -1;

static struct tcapsrt_info_t * gp_tcapsrt_info;
static gboolean tcap_subdissector_used=FALSE;
static dissector_handle_t requested_subdissector_handle = NULL;

static int ss7pc_address_type = -1;

static struct tcaphash_context_t * gp_tcap_context=NULL;


/*--- Included file: packet-tcap-ett.c ---*/
#line 1 "./asn1/tcap/packet-tcap-ett.c"
static gint ett_tcap_ExternalPDU_U = -1;
static gint ett_tcap_TCMessage = -1;
static gint ett_tcap_Unidirectional = -1;
static gint ett_tcap_Begin = -1;
static gint ett_tcap_End = -1;
static gint ett_tcap_Continue = -1;
static gint ett_tcap_Abort = -1;
static gint ett_tcap_Reason = -1;
static gint ett_tcap_SEQUENCE_SIZE_1_MAX_OF_Component = -1;
static gint ett_tcap_Component = -1;
static gint ett_tcap_Invoke = -1;
static gint ett_tcap_ReturnResult = -1;
static gint ett_tcap_T_resultretres = -1;
static gint ett_tcap_ReturnError = -1;
static gint ett_tcap_Reject = -1;
static gint ett_tcap_T_invokeIDRej = -1;
static gint ett_tcap_T_problem = -1;
static gint ett_tcap_OPERATION = -1;
static gint ett_tcap_ErrorCode = -1;
static gint ett_tcap_UniDialoguePDU = -1;
static gint ett_tcap_AUDT_apdu_U = -1;
static gint ett_tcap_AUDT_protocol_version = -1;
static gint ett_tcap_AUDT_user_information = -1;
static gint ett_tcap_DialoguePDU = -1;
static gint ett_tcap_AARQ_apdu_U = -1;
static gint ett_tcap_AARQ_protocol_version = -1;
static gint ett_tcap_AARQ_user_information = -1;
static gint ett_tcap_AARE_apdu_U = -1;
static gint ett_tcap_AARE_protocol_version = -1;
static gint ett_tcap_AARE_user_information = -1;
static gint ett_tcap_ABRT_apdu_U = -1;
static gint ett_tcap_ABRT_user_information = -1;
static gint ett_tcap_Associate_source_diagnostic = -1;

/*--- End of included file: packet-tcap-ett.c ---*/
#line 79 "./asn1/tcap/packet-tcap-template.c"

/* When several Tcap components are received in a single TCAP message,
   we have to use several buffers for the stored parameters
   because else this data are erased during TAP dissector call */
#define MAX_TCAP_INSTANCE 10
static int tcapsrt_global_current=0;
static struct tcapsrt_info_t tcapsrt_global_info[MAX_TCAP_INSTANCE];

#define MAX_SSN 254
static range_t *global_ssn_range;
static range_t *ssn_range;
struct tcap_private_t tcap_private;

gboolean gtcap_HandleSRT=FALSE;
/* These two timeout (in second) are used when some message are lost,
   or when the same TCAP transcation identifier is reused */
guint gtcap_RepetitionTimeout = 10;
guint gtcap_LostTimeout = 30;
gboolean gtcap_PersistentSRT=FALSE;
gboolean gtcap_DisplaySRT=FALSE;
gboolean gtcap_StatSRT=FALSE;

/* Global hash tables*/
static GHashTable *tcaphash_context = NULL;
static GHashTable *tcaphash_begin = NULL;
static GHashTable *tcaphash_cont = NULL;
static GHashTable *tcaphash_end = NULL;
static GHashTable *tcaphash_ansi = NULL;

static guint32 tcapsrt_global_SessionId=1;

static dissector_handle_t tcap_handle = NULL;
static dissector_table_t ber_oid_dissector_table;
static const char * cur_oid;
static const char * tcapext_oid;
static proto_tree * tcap_top_tree=NULL;
static proto_tree * tcap_stat_tree=NULL;

static dissector_handle_t data_handle;
static dissector_handle_t ansi_tcap_handle;

static void raz_tcap_private(struct tcap_private_t * p_tcap_private);
static int dissect_tcap_param(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_tcap_ITU_ComponentPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_);

static GHashTable* ansi_sub_dissectors = NULL;
static GHashTable* itu_sub_dissectors = NULL;

extern void add_ansi_tcap_subdissector(guint32 ssn, dissector_handle_t dissector) {
  g_hash_table_insert(ansi_sub_dissectors,GUINT_TO_POINTER(ssn),dissector);
  dissector_add_uint("sccp.ssn",ssn,tcap_handle);
}

extern void add_itu_tcap_subdissector(guint32 ssn, dissector_handle_t dissector) {
  g_hash_table_insert(itu_sub_dissectors,GUINT_TO_POINTER(ssn),dissector);
  dissector_add_uint("sccp.ssn",ssn,tcap_handle);
}

extern void delete_ansi_tcap_subdissector(guint32 ssn, dissector_handle_t dissector _U_) {
  g_hash_table_remove(ansi_sub_dissectors,GUINT_TO_POINTER(ssn));
  if (!get_itu_tcap_subdissector(ssn))
      dissector_delete_uint("sccp.ssn",ssn,tcap_handle);
}
extern void delete_itu_tcap_subdissector(guint32 ssn, dissector_handle_t dissector _U_) {
  g_hash_table_remove(itu_sub_dissectors,GUINT_TO_POINTER(ssn));
  if (!get_ansi_tcap_subdissector(ssn))
    dissector_delete_uint("sccp.ssn", ssn,tcap_handle);
}

dissector_handle_t get_ansi_tcap_subdissector(guint32 ssn) {
  return (dissector_handle_t)g_hash_table_lookup(ansi_sub_dissectors,GUINT_TO_POINTER(ssn));
}

dissector_handle_t get_itu_tcap_subdissector(guint32 ssn) {
  return (dissector_handle_t)g_hash_table_lookup(itu_sub_dissectors,GUINT_TO_POINTER(ssn));
}


/*--- Included file: packet-tcap-fn.c ---*/
#line 1 "./asn1/tcap/packet-tcap-fn.c"


static int
dissect_tcap_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_tcap_Dialog1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 72 "./asn1/tcap/tcap.cnf"

  offset = dissect_tcap_DialoguePDU(TRUE, tvb, offset, actx, tree, -1);



  return offset;
}


static const ber_sequence_t ExternalPDU_U_sequence[] = {
  { &hf_tcap_oid            , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_tcap_OBJECT_IDENTIFIER },
  { &hf_tcap_dialog         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_tcap_Dialog1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_ExternalPDU_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExternalPDU_U_sequence, hf_index, ett_tcap_ExternalPDU_U);

  return offset;
}



static int
dissect_tcap_ExternalPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 67 "./asn1/tcap/tcap.cnf"

  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_UNI, 8, TRUE, dissect_tcap_ExternalPDU_U);




  return offset;
}



static int
dissect_tcap_DialogueOC(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 62 "./asn1/tcap/tcap.cnf"

  offset = dissect_tcap_ExternalPDU(FALSE /*implicit_tag*/, tvb, offset, actx, tree, -1);



  return offset;
}



static int
dissect_tcap_DialoguePortion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 11, TRUE, dissect_tcap_DialogueOC);

  return offset;
}



static int
dissect_tcap_InvokeIdType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_tcap_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string tcap_OPERATION_vals[] = {
  {   0, "localValue" },
  {   1, "globalValue" },
  { 0, NULL }
};

static const ber_choice_t OPERATION_choice[] = {
  {   0, &hf_tcap_localValue     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tcap_INTEGER },
  {   1, &hf_tcap_globalValue    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_tcap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_OPERATION(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 OPERATION_choice, hf_index, ett_tcap_OPERATION,
                                 NULL);

  return offset;
}



static int
dissect_tcap_Parameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 77 "./asn1/tcap/tcap.cnf"

  offset = dissect_tcap_param(actx,tree,tvb,offset);



  return offset;
}


static const ber_sequence_t Invoke_sequence[] = {
  { &hf_tcap_invokeID       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tcap_InvokeIdType },
  { &hf_tcap_linkedID       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcap_InvokeIdType },
  { &hf_tcap_opCode         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tcap_OPERATION },
  { &hf_tcap_parameter      , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_Parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_Invoke(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_tcap_Invoke);

  return offset;
}


static const ber_sequence_t T_resultretres_sequence[] = {
  { &hf_tcap_opCode         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tcap_OPERATION },
  { &hf_tcap_parameter      , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_Parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_T_resultretres(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_resultretres_sequence, hf_index, ett_tcap_T_resultretres);

  return offset;
}


static const ber_sequence_t ReturnResult_sequence[] = {
  { &hf_tcap_invokeID       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tcap_InvokeIdType },
  { &hf_tcap_resultretres   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_T_resultretres },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_ReturnResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_tcap_ReturnResult);

  return offset;
}



static int
dissect_tcap_INTEGER_M32768_32767(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string tcap_ErrorCode_vals[] = {
  {  19, "nationaler" },
  {  20, "privateer" },
  { 0, NULL }
};

static const ber_choice_t ErrorCode_choice[] = {
  {  19, &hf_tcap_nationaler     , BER_CLASS_PRI, 19, BER_FLAGS_IMPLTAG, dissect_tcap_INTEGER_M32768_32767 },
  {  20, &hf_tcap_privateer      , BER_CLASS_PRI, 20, BER_FLAGS_IMPLTAG, dissect_tcap_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_ErrorCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ErrorCode_choice, hf_index, ett_tcap_ErrorCode,
                                 NULL);

  return offset;
}


static const ber_sequence_t ReturnError_sequence[] = {
  { &hf_tcap_invokeID       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tcap_InvokeIdType },
  { &hf_tcap_errorCode      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tcap_ErrorCode },
  { &hf_tcap_parameter      , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_Parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_ReturnError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnError_sequence, hf_index, ett_tcap_ReturnError);

  return offset;
}



static int
dissect_tcap_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string tcap_T_invokeIDRej_vals[] = {
  {   0, "derivable" },
  {   1, "not-derivable" },
  { 0, NULL }
};

static const ber_choice_t T_invokeIDRej_choice[] = {
  {   0, &hf_tcap_derivable      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tcap_InvokeIdType },
  {   1, &hf_tcap_not_derivable  , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_tcap_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_T_invokeIDRej(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_invokeIDRej_choice, hf_index, ett_tcap_T_invokeIDRej,
                                 NULL);

  return offset;
}


static const value_string tcap_GeneralProblem_vals[] = {
  {   0, "unrecognizedComponent" },
  {   1, "mistypedComponent" },
  {   2, "badlyStructuredComponent" },
  { 0, NULL }
};


static int
dissect_tcap_GeneralProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string tcap_InvokeProblem_vals[] = {
  {   0, "duplicateInvokeID" },
  {   1, "unrecognizedOperation" },
  {   2, "mistypedParameter" },
  {   3, "resourceLimitation" },
  {   4, "initiatingRelease" },
  {   5, "unrecognizedLinkedID" },
  {   6, "linkedResponseUnexpected" },
  {   7, "unexpectedLinkedOperation" },
  { 0, NULL }
};


static int
dissect_tcap_InvokeProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string tcap_ReturnResultProblem_vals[] = {
  {   0, "unrecognizedInvokeID" },
  {   1, "returnResultUnexpected" },
  {   2, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_tcap_ReturnResultProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string tcap_ReturnErrorProblem_vals[] = {
  {   0, "unrecognizedInvokeID" },
  {   1, "returnErrorUnexpected" },
  {   2, "unrecognizedError" },
  {   3, "unexpectedError" },
  {   4, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_tcap_ReturnErrorProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string tcap_T_problem_vals[] = {
  {   0, "generalProblem" },
  {   1, "invokeProblem" },
  {   2, "returnResultProblem" },
  {   3, "returnErrorProblem" },
  { 0, NULL }
};

static const ber_choice_t T_problem_choice[] = {
  {   0, &hf_tcap_generalProblem , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_tcap_GeneralProblem },
  {   1, &hf_tcap_invokeProblem  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_tcap_InvokeProblem },
  {   2, &hf_tcap_returnResultProblem, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_tcap_ReturnResultProblem },
  {   3, &hf_tcap_returnErrorProblem, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_tcap_ReturnErrorProblem },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_T_problem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_problem_choice, hf_index, ett_tcap_T_problem,
                                 NULL);

  return offset;
}


static const ber_sequence_t Reject_sequence[] = {
  { &hf_tcap_invokeIDRej    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tcap_T_invokeIDRej },
  { &hf_tcap_problem        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tcap_T_problem },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_Reject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Reject_sequence, hf_index, ett_tcap_Reject);

  return offset;
}


static const value_string tcap_Component_vals[] = {
  {   1, "invoke" },
  {   2, "returnResultLast" },
  {   3, "returnError" },
  {   4, "reject" },
  {   7, "returnResultNotLast" },
  { 0, NULL }
};

static const ber_choice_t Component_choice[] = {
  {   1, &hf_tcap_invoke         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_tcap_Invoke },
  {   2, &hf_tcap_returnResultLast, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_tcap_ReturnResult },
  {   3, &hf_tcap_returnError    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_tcap_ReturnError },
  {   4, &hf_tcap_reject         , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_tcap_Reject },
  {   7, &hf_tcap_returnResultNotLast, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_tcap_ReturnResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_Component(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 82 "./asn1/tcap/tcap.cnf"
  tvbuff_t *next_tvb;
  gint8 ber_class;
  gboolean pc;
  gint tag;
  guint32 len, comp_offset;
  volatile guint32 _offset;
  gint ind_field;

  comp_offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
  comp_offset = dissect_ber_length(actx->pinfo, tree, tvb, comp_offset, &len, &ind_field);
  /* we can believe the length now */
  next_tvb = tvb_new_subset_length(tvb, offset, len+comp_offset-offset);

  if (!next_tvb)
    return comp_offset;

  _offset = offset;
  TRY {
    _offset = dissect_ber_choice(actx, tree, tvb, _offset,
                                 Component_choice, hf_index, ett_tcap_Component,
                                 NULL);
  }
  CATCH_NONFATAL_ERRORS {
    show_exception(tvb, actx->pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
  }
  ENDTRY;
  offset = _offset;

  dissect_tcap_ITU_ComponentPDU(implicit_tag, next_tvb, 0, actx, tcap_top_tree, hf_index);

/* return comp_offset+len; or return offset (will be automatically added) */



  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_Component_sequence_of[1] = {
  { &hf_tcap__untag_item    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tcap_Component },
};

static int
dissect_tcap_SEQUENCE_SIZE_1_MAX_OF_Component(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_Component_sequence_of, hf_index, ett_tcap_SEQUENCE_SIZE_1_MAX_OF_Component);

  return offset;
}



static int
dissect_tcap_ComponentPortion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 12, TRUE, dissect_tcap_SEQUENCE_SIZE_1_MAX_OF_Component);

  return offset;
}


static const ber_sequence_t Unidirectional_sequence[] = {
  { &hf_tcap_dialoguePortion, BER_CLASS_APP, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_DialoguePortion },
  { &hf_tcap_components     , BER_CLASS_APP, 12, BER_FLAGS_NOOWNTAG, dissect_tcap_ComponentPortion },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_Unidirectional(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Unidirectional_sequence, hf_index, ett_tcap_Unidirectional);

  return offset;
}



static int
dissect_tcap_OCTET_STRING_SIZE_1_4(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_tcap_OrigTransactionID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 131 "./asn1/tcap/tcap.cnf"
  tvbuff_t *parameter_tvb;
  guint8 len, i;
  proto_tree *subtree;
  int saved_offset;

  hf_index = hf_tcap_tid;
  saved_offset = offset;
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 8, TRUE, dissect_tcap_OCTET_STRING_SIZE_1_4);

  PROTO_ITEM_SET_HIDDEN(actx->created_item);
  offset = saved_offset;

  subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_otid, NULL, "Source Transaction ID");
  offset = dissect_ber_octet_string(implicit_tag, actx, subtree, tvb, offset, hf_tcap_otid,
                                    &parameter_tvb);

  if (parameter_tvb) {
    len = tvb_reported_length_remaining(parameter_tvb, 0);
    switch(len) {
    case 1:
      gp_tcapsrt_info->src_tid=tvb_get_guint8(parameter_tvb, 0);
      break;
    case 2:
      gp_tcapsrt_info->src_tid=tvb_get_ntohs(parameter_tvb, 0);
      break;
    case 4:
      gp_tcapsrt_info->src_tid=tvb_get_ntohl(parameter_tvb, 0);
      break;
    default:
      gp_tcapsrt_info->src_tid=0;
      break;
    }

    if (len) {
      col_append_str(actx->pinfo->cinfo, COL_INFO, "otid(");
      for (i = 0; i < len; i++) {
        col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%02x",tvb_get_guint8(parameter_tvb,i));
      }
      col_append_str(actx->pinfo->cinfo, COL_INFO, ") ");
    }
  }



  return offset;
}


static const ber_sequence_t Begin_sequence[] = {
  { &hf_tcap_otid           , BER_CLASS_APP, 8, BER_FLAGS_NOOWNTAG, dissect_tcap_OrigTransactionID },
  { &hf_tcap_dialoguePortion, BER_CLASS_APP, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_DialoguePortion },
  { &hf_tcap_components     , BER_CLASS_APP, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ComponentPortion },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_Begin(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 215 "./asn1/tcap/tcap.cnf"
gp_tcapsrt_info->ope=TC_BEGIN;

/*  Do not change col_add_str() to col_append_str() here: we _want_ this call
 *  to overwrite whatever's currently in the INFO column (e.g., "UDT" from
 *  the SCCP dissector).
 *
 *  If there's something there that should not be overwritten, whoever
 *  put that info there should call col_set_fence() to protect it.
 */
  col_set_str(actx->pinfo->cinfo, COL_INFO, "Begin ");

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Begin_sequence, hf_index, ett_tcap_Begin);

  return offset;
}



static int
dissect_tcap_DestTransactionID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 174 "./asn1/tcap/tcap.cnf"
  tvbuff_t *parameter_tvb;
  guint8 len , i;
  proto_tree *subtree;
  int saved_offset;

  hf_index = hf_tcap_tid;
  saved_offset = offset;
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 9, TRUE, dissect_tcap_OCTET_STRING_SIZE_1_4);

  PROTO_ITEM_SET_HIDDEN(actx->created_item);
  offset = saved_offset;

  subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_dtid, NULL, "Destination Transaction ID");
  offset = dissect_ber_octet_string(implicit_tag, actx, subtree, tvb, offset, hf_tcap_dtid,
                                    &parameter_tvb);

  if (parameter_tvb) {
    len = tvb_reported_length_remaining(parameter_tvb, 0);
    switch(len) {
    case 1:
      gp_tcapsrt_info->dst_tid=tvb_get_guint8(parameter_tvb, 0);
      break;
    case 2:
      gp_tcapsrt_info->dst_tid=tvb_get_ntohs(parameter_tvb, 0);
      break;
    case 4:
      gp_tcapsrt_info->dst_tid=tvb_get_ntohl(parameter_tvb, 0);
      break;
    default:
      gp_tcapsrt_info->dst_tid=0;
      break;
    }

    if (len) {
      col_append_str(actx->pinfo->cinfo, COL_INFO, "dtid(");
      for(i = 0; i < len; i++) {
        col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%02x",tvb_get_guint8(parameter_tvb,i));
      }
      col_append_str(actx->pinfo->cinfo, COL_INFO, ") ");
    }
  }


  return offset;
}


static const ber_sequence_t End_sequence[] = {
  { &hf_tcap_dtid           , BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_tcap_DestTransactionID },
  { &hf_tcap_dialoguePortion, BER_CLASS_APP, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_DialoguePortion },
  { &hf_tcap_components     , BER_CLASS_APP, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ComponentPortion },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_End(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 229 "./asn1/tcap/tcap.cnf"
gp_tcapsrt_info->ope=TC_END;

  col_set_str(actx->pinfo->cinfo, COL_INFO, "End ");

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   End_sequence, hf_index, ett_tcap_End);

  return offset;
}


static const ber_sequence_t Continue_sequence[] = {
  { &hf_tcap_otid           , BER_CLASS_APP, 8, BER_FLAGS_NOOWNTAG, dissect_tcap_OrigTransactionID },
  { &hf_tcap_dtid           , BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_tcap_DestTransactionID },
  { &hf_tcap_dialoguePortion, BER_CLASS_APP, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_DialoguePortion },
  { &hf_tcap_components     , BER_CLASS_APP, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ComponentPortion },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_Continue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 236 "./asn1/tcap/tcap.cnf"
gp_tcapsrt_info->ope=TC_CONT;

  col_set_str(actx->pinfo->cinfo, COL_INFO, "Continue ");

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Continue_sequence, hf_index, ett_tcap_Continue);

  return offset;
}


static const value_string tcap_P_AbortCause_U_vals[] = {
  {   0, "unrecognizedMessageType" },
  {   1, "unrecognizedTransactionID" },
  {   2, "badlyFormattedTransactionPortion" },
  {   3, "incorrectTransactionPortion" },
  {   4, "resourceLimitation" },
  { 0, NULL }
};


static int
dissect_tcap_P_AbortCause_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_tcap_P_AbortCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 10, TRUE, dissect_tcap_P_AbortCause_U);

  return offset;
}


static const value_string tcap_Reason_vals[] = {
  {  10, "p-abortCause" },
  {  11, "u-abortCause" },
  { 0, NULL }
};

static const ber_choice_t Reason_choice[] = {
  {  10, &hf_tcap_p_abortCause   , BER_CLASS_APP, 10, BER_FLAGS_NOOWNTAG, dissect_tcap_P_AbortCause },
  {  11, &hf_tcap_u_abortCause   , BER_CLASS_APP, 11, BER_FLAGS_NOOWNTAG, dissect_tcap_DialoguePortion },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_Reason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Reason_choice, hf_index, ett_tcap_Reason,
                                 NULL);

  return offset;
}


static const ber_sequence_t Abort_sequence[] = {
  { &hf_tcap_dtid           , BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_tcap_DestTransactionID },
  { &hf_tcap_reason         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tcap_Reason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_Abort(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 243 "./asn1/tcap/tcap.cnf"
gp_tcapsrt_info->ope=TC_ABORT;

  col_set_str(actx->pinfo->cinfo, COL_INFO, "Abort ");

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Abort_sequence, hf_index, ett_tcap_Abort);

  return offset;
}


static const ber_choice_t TCMessage_choice[] = {
  {   1, &hf_tcap_unidirectional , BER_CLASS_APP, 1, BER_FLAGS_IMPLTAG, dissect_tcap_Unidirectional },
  {   2, &hf_tcap_begin          , BER_CLASS_APP, 2, BER_FLAGS_IMPLTAG, dissect_tcap_Begin },
  {   4, &hf_tcap_end            , BER_CLASS_APP, 4, BER_FLAGS_IMPLTAG, dissect_tcap_End },
  {   5, &hf_tcap_continue       , BER_CLASS_APP, 5, BER_FLAGS_IMPLTAG, dissect_tcap_Continue },
  {   7, &hf_tcap_abort          , BER_CLASS_APP, 7, BER_FLAGS_IMPLTAG, dissect_tcap_Abort },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_TCMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TCMessage_choice, hf_index, ett_tcap_TCMessage,
                                 NULL);

  return offset;
}


static const asn_namedbit AUDT_protocol_version_bits[] = {
  {  0, &hf_tcap_AUDT_protocol_version_version1, -1, -1, "version1", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_tcap_AUDT_protocol_version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    AUDT_protocol_version_bits, hf_index, ett_tcap_AUDT_protocol_version,
                                    NULL);

  return offset;
}



static int
dissect_tcap_AUDT_application_context_name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 116 "./asn1/tcap/tcap.cnf"
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &cur_oid);

  tcap_private.oid= (const void*) cur_oid;
  tcap_private.acv=TRUE;


  return offset;
}



static int
dissect_tcap_EXTERNAL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}


static const ber_sequence_t AUDT_user_information_sequence_of[1] = {
  { &hf_tcap_audt_user_information_item, BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_tcap_EXTERNAL },
};

static int
dissect_tcap_AUDT_user_information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AUDT_user_information_sequence_of, hf_index, ett_tcap_AUDT_user_information);

  return offset;
}


static const ber_sequence_t AUDT_apdu_U_sequence[] = {
  { &hf_tcap_audt_protocol_version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcap_AUDT_protocol_version },
  { &hf_tcap_audt_application_context_name, BER_CLASS_CON, 1, 0, dissect_tcap_AUDT_application_context_name },
  { &hf_tcap_audt_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcap_AUDT_user_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_AUDT_apdu_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AUDT_apdu_U_sequence, hf_index, ett_tcap_AUDT_apdu_U);

  return offset;
}



static int
dissect_tcap_AUDT_apdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, TRUE, dissect_tcap_AUDT_apdu_U);

  return offset;
}


const value_string tcap_UniDialoguePDU_vals[] = {
  {   0, "unidialoguePDU" },
  { 0, NULL }
};

static const ber_choice_t UniDialoguePDU_choice[] = {
  {   0, &hf_tcap_unidialoguePDU , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_tcap_AUDT_apdu },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_tcap_UniDialoguePDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UniDialoguePDU_choice, hf_index, ett_tcap_UniDialoguePDU,
                                 NULL);

  return offset;
}


static const asn_namedbit AARQ_protocol_version_bits[] = {
  {  0, &hf_tcap_AARQ_protocol_version_version1, -1, -1, "version1", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_tcap_AARQ_protocol_version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    AARQ_protocol_version_bits, hf_index, ett_tcap_AARQ_protocol_version,
                                    NULL);

  return offset;
}



static int
dissect_tcap_AARQ_application_context_name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 121 "./asn1/tcap/tcap.cnf"
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &cur_oid);

  tcap_private.oid= (const void*) cur_oid;
  tcap_private.acv=TRUE;


  return offset;
}


static const ber_sequence_t AARQ_user_information_sequence_of[1] = {
  { &hf_tcap_aarq_user_information_item, BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_tcap_EXTERNAL },
};

static int
dissect_tcap_AARQ_user_information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AARQ_user_information_sequence_of, hf_index, ett_tcap_AARQ_user_information);

  return offset;
}


static const ber_sequence_t AARQ_apdu_U_sequence[] = {
  { &hf_tcap_aarq_protocol_version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcap_AARQ_protocol_version },
  { &hf_tcap_aarq_application_context_name, BER_CLASS_CON, 1, 0, dissect_tcap_AARQ_application_context_name },
  { &hf_tcap_aarq_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcap_AARQ_user_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_AARQ_apdu_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AARQ_apdu_U_sequence, hf_index, ett_tcap_AARQ_apdu_U);

  return offset;
}



static int
dissect_tcap_AARQ_apdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, TRUE, dissect_tcap_AARQ_apdu_U);

  return offset;
}


static const asn_namedbit AARE_protocol_version_bits[] = {
  {  0, &hf_tcap_AARE_protocol_version_version1, -1, -1, "version1", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_tcap_AARE_protocol_version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    AARE_protocol_version_bits, hf_index, ett_tcap_AARE_protocol_version,
                                    NULL);

  return offset;
}



static int
dissect_tcap_AARE_application_context_name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 126 "./asn1/tcap/tcap.cnf"
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &cur_oid);

  tcap_private.oid= (const void*) cur_oid;
  tcap_private.acv=TRUE;


  return offset;
}


static const value_string tcap_Associate_result_vals[] = {
  {   0, "accepted" },
  {   1, "reject-permanent" },
  { 0, NULL }
};


static int
dissect_tcap_Associate_result(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string tcap_T_dialogue_service_user_vals[] = {
  {   0, "null" },
  {   1, "no-reason-given" },
  {   2, "application-context-name-not-supported" },
  { 0, NULL }
};


static int
dissect_tcap_T_dialogue_service_user(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string tcap_T_dialogue_service_provider_vals[] = {
  {   0, "null" },
  {   1, "no-reason-given" },
  {   2, "no-common-dialogue-portion" },
  { 0, NULL }
};


static int
dissect_tcap_T_dialogue_service_provider(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string tcap_Associate_source_diagnostic_vals[] = {
  {   1, "dialogue-service-user" },
  {   2, "dialogue-service-provider" },
  { 0, NULL }
};

static const ber_choice_t Associate_source_diagnostic_choice[] = {
  {   1, &hf_tcap_dialogue_service_user, BER_CLASS_CON, 1, 0, dissect_tcap_T_dialogue_service_user },
  {   2, &hf_tcap_dialogue_service_provider, BER_CLASS_CON, 2, 0, dissect_tcap_T_dialogue_service_provider },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_Associate_source_diagnostic(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Associate_source_diagnostic_choice, hf_index, ett_tcap_Associate_source_diagnostic,
                                 NULL);

  return offset;
}


static const ber_sequence_t AARE_user_information_sequence_of[1] = {
  { &hf_tcap_aare_user_information_item, BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_tcap_EXTERNAL },
};

static int
dissect_tcap_AARE_user_information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AARE_user_information_sequence_of, hf_index, ett_tcap_AARE_user_information);

  return offset;
}


static const ber_sequence_t AARE_apdu_U_sequence[] = {
  { &hf_tcap_aare_protocol_version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcap_AARE_protocol_version },
  { &hf_tcap_aare_application_context_name, BER_CLASS_CON, 1, 0, dissect_tcap_AARE_application_context_name },
  { &hf_tcap_result         , BER_CLASS_CON, 2, 0, dissect_tcap_Associate_result },
  { &hf_tcap_result_source_diagnostic, BER_CLASS_CON, 3, BER_FLAGS_NOTCHKTAG, dissect_tcap_Associate_source_diagnostic },
  { &hf_tcap_aare_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcap_AARE_user_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_AARE_apdu_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AARE_apdu_U_sequence, hf_index, ett_tcap_AARE_apdu_U);

  return offset;
}



static int
dissect_tcap_AARE_apdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 1, TRUE, dissect_tcap_AARE_apdu_U);

  return offset;
}


static const value_string tcap_ABRT_source_vals[] = {
  {   0, "dialogue-service-user" },
  {   1, "dialogue-service-provider" },
  { 0, NULL }
};


static int
dissect_tcap_ABRT_source(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ABRT_user_information_sequence_of[1] = {
  { &hf_tcap_abrt_user_information_item, BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_tcap_EXTERNAL },
};

static int
dissect_tcap_ABRT_user_information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ABRT_user_information_sequence_of, hf_index, ett_tcap_ABRT_user_information);

  return offset;
}


static const ber_sequence_t ABRT_apdu_U_sequence[] = {
  { &hf_tcap_abort_source   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_tcap_ABRT_source },
  { &hf_tcap_abrt_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcap_ABRT_user_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_ABRT_apdu_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ABRT_apdu_U_sequence, hf_index, ett_tcap_ABRT_apdu_U);

  return offset;
}



static int
dissect_tcap_ABRT_apdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 4, TRUE, dissect_tcap_ABRT_apdu_U);

  return offset;
}


const value_string tcap_DialoguePDU_vals[] = {
  {   0, "dialogueRequest" },
  {   1, "dialogueResponse" },
  {   4, "dialogueAbort" },
  { 0, NULL }
};

static const ber_choice_t DialoguePDU_choice[] = {
  {   0, &hf_tcap_dialogueRequest, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_tcap_AARQ_apdu },
  {   1, &hf_tcap_dialogueResponse, BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_tcap_AARE_apdu },
  {   4, &hf_tcap_dialogueAbort  , BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_tcap_ABRT_apdu },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_tcap_DialoguePDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DialoguePDU_choice, hf_index, ett_tcap_DialoguePDU,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_UniDialoguePDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcap_UniDialoguePDU(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcap_UniDialoguePDU_PDU);
  return offset;
}
static int dissect_DialoguePDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcap_DialoguePDU(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcap_DialoguePDU_PDU);
  return offset;
}


/*--- End of included file: packet-tcap-fn.c ---*/
#line 157 "./asn1/tcap/packet-tcap-template.c"

/*
 * DEBUG functions
 */
#undef DEBUG_TCAPSRT
/* #define DEBUG_TCAPSRT */

#ifdef DEBUG_TCAPSRT
#include <stdio.h>
#include <stdarg.h>
static guint debug_level = 99;

static void
dbg(guint level, const char* fmt, ...)
{
  va_list ap;

  if (level > debug_level) return;
  va_start(ap,fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}
#endif

static gint
tcaphash_context_equal(gconstpointer k1, gconstpointer k2)
{
  const struct tcaphash_context_key_t *key1 = (const struct tcaphash_context_key_t *) k1;
  const struct tcaphash_context_key_t *key2 = (const struct tcaphash_context_key_t *) k2;

  return (key1->session_id == key2->session_id);
}

/* calculate a hash key */
static guint
tcaphash_context_calchash(gconstpointer k)
{
  const struct tcaphash_context_key_t *key = (const struct tcaphash_context_key_t *) k;
  return key->session_id;
}


static gint
tcaphash_begin_equal(gconstpointer k1, gconstpointer k2)
{
  const struct tcaphash_begin_info_key_t *key1 = (const struct tcaphash_begin_info_key_t *) k1;
  const struct tcaphash_begin_info_key_t *key2 = (const struct tcaphash_begin_info_key_t *) k2;

  if (key1->hashKey == key2->hashKey) {
    if ( (key1->pc_hash == key2->pc_hash) && (key1->tid == key2->tid) )
      return TRUE;
  }
  return FALSE;
}

/* calculate a hash key */
static guint
tcaphash_begin_calchash(gconstpointer k)
{
  const struct tcaphash_begin_info_key_t *key = (const struct tcaphash_begin_info_key_t *) k;
  guint hashkey;
  /* hashkey = key->opc_hash<<16 + key->dpc_hash<<8 + key->src_tid; */
  hashkey = key->tid;
  return hashkey;
}

static gint
tcaphash_cont_equal(gconstpointer k1, gconstpointer k2)
{
  const struct tcaphash_cont_info_key_t *key1 = (const struct tcaphash_cont_info_key_t *) k1;
  const struct tcaphash_cont_info_key_t *key2 = (const struct tcaphash_cont_info_key_t *) k2;

  if (key1->hashKey == key2->hashKey) {

    if ( (key1->opc_hash == key2->opc_hash) &&
         (key1->dpc_hash == key2->dpc_hash) &&
         (key1->src_tid == key2->src_tid) &&
         (key1->dst_tid == key2->dst_tid) ) {
      return TRUE;
    }
    else if ( (key1->opc_hash == key2->dpc_hash) &&
              (key1->dpc_hash == key2->opc_hash) &&
              (key1->src_tid == key2->dst_tid) &&
              (key1->dst_tid == key2->src_tid) ) {
      return TRUE;
    }
  }
  return FALSE;
}

/* calculate a hash key */
static guint
tcaphash_cont_calchash(gconstpointer k)
{
  const struct tcaphash_cont_info_key_t *key = (const struct tcaphash_cont_info_key_t *) k;
  guint hashkey;
  hashkey = key->src_tid + key->dst_tid;
  return hashkey;
}


static gint
tcaphash_end_equal(gconstpointer k1, gconstpointer k2)
{
  const struct tcaphash_end_info_key_t *key1 = (const struct tcaphash_end_info_key_t *) k1;
  const struct tcaphash_end_info_key_t *key2 = (const struct tcaphash_end_info_key_t *) k2;

  if (key1->hashKey == key2->hashKey) {
    if ( (key1->pc_hash == key2->pc_hash) && (key1->tid == key2->tid) )
      return TRUE;
  }
  return FALSE;
}

/* calculate a hash key */
static guint
tcaphash_end_calchash(gconstpointer k)
{
  const struct tcaphash_end_info_key_t *key = (const struct tcaphash_end_info_key_t *) k;
  guint hashkey;
  hashkey = key->tid;
  return hashkey;
}

static gint
tcaphash_ansi_equal(gconstpointer k1, gconstpointer k2)
{
  const struct tcaphash_ansi_info_key_t *key1 = (const struct tcaphash_ansi_info_key_t *) k1;
  const struct tcaphash_ansi_info_key_t *key2 = (const struct tcaphash_ansi_info_key_t *) k2;

  if (key1->hashKey == key2->hashKey) {

    if ( ( (key1->opc_hash == key2->opc_hash) &&
           (key1->dpc_hash == key2->dpc_hash) &&
           (key1->tid == key2->tid) )
         ||
         ( (key1->opc_hash == key2->dpc_hash) &&
           (key1->dpc_hash == key2->opc_hash) &&
           (key1->tid == key2->tid) )
         )
      return TRUE;
  }
  return FALSE;
}

/* calculate a hash key */
static guint
tcaphash_ansi_calchash(gconstpointer k)
{
  const struct tcaphash_ansi_info_key_t *key = (const struct tcaphash_ansi_info_key_t *) k;
  guint hashkey;
  /* hashkey = key->opc_hash<<16 + key->dpc_hash<<8 + key->src_tid; */
  hashkey = key->tid;
  return hashkey;
}

/*
 * Update a record with the data of the Request
 */
static void
update_tcaphash_begincall(struct tcaphash_begincall_t *p_tcaphash_begincall,
                          packet_info *pinfo)
{
  p_tcaphash_begincall->context->first_frame = pinfo->num;
  p_tcaphash_begincall->context->last_frame = 0;
  p_tcaphash_begincall->context->responded = FALSE;
  p_tcaphash_begincall->context->begin_time = pinfo->abs_ts;
}

/*
 * Append a new dialogue, using the same Key, to the chained list
 * The time is stored too
 */
static struct tcaphash_begincall_t *
append_tcaphash_begincall(struct tcaphash_begincall_t *prev_begincall,
                          struct tcaphash_context_t *p_tcaphash_context,
                          packet_info *pinfo)
{
  struct tcaphash_begincall_t *p_new_tcaphash_begincall = NULL;

  /* Append the transaction to the list, when the same key is found
     This should append when the tcap-transaction Id is reused  */

  p_new_tcaphash_begincall = wmem_new0(wmem_file_scope(), struct tcaphash_begincall_t);
  p_new_tcaphash_begincall->context=p_tcaphash_context;
  p_tcaphash_context->begincall=p_new_tcaphash_begincall;
  p_new_tcaphash_begincall->beginkey=prev_begincall->beginkey;
  p_new_tcaphash_begincall->context->first_frame = pinfo->num;
  p_new_tcaphash_begincall->next_begincall=NULL;
  p_new_tcaphash_begincall->previous_begincall=prev_begincall;
  p_new_tcaphash_begincall->father=FALSE;

#ifdef DEBUG_TCAPSRT
  dbg(10,"+B%d ", p_new_tcaphash_begincall->context->session_id);
#endif
  /* Insert in the chained list */
  prev_begincall->next_begincall = p_new_tcaphash_begincall;
  if (prev_begincall->context->last_frame == 0) {
#ifdef DEBUG_TCAPSRT
    dbg(10,"last ");
#endif
    prev_begincall->context->last_frame = pinfo->num-1;
  }
  return p_new_tcaphash_begincall;
}

/*
 * Update a record with the data of the Request
 */
static void
update_tcaphash_ansicall(struct tcaphash_ansicall_t *p_tcaphash_ansicall,
                          packet_info *pinfo)
{
  p_tcaphash_ansicall->context->first_frame = pinfo->num;
  p_tcaphash_ansicall->context->last_frame = 0;
  p_tcaphash_ansicall->context->responded = FALSE;
  p_tcaphash_ansicall->context->begin_time = pinfo->abs_ts;
}

/*
 * Append a new dialogue, using the same Key, to the chained list
 * The time is stored too
 */
static struct tcaphash_ansicall_t *
append_tcaphash_ansicall(struct tcaphash_ansicall_t *prev_ansicall,
                          struct tcaphash_context_t *p_tcaphash_context,
                          packet_info *pinfo)
{
  struct tcaphash_ansicall_t *p_new_tcaphash_ansicall = NULL;

  /* Append the transaction to the list, when the same key is found
     This should append when the tcap-transaction Id is reused  */

  p_new_tcaphash_ansicall = wmem_new0(wmem_file_scope(), struct tcaphash_ansicall_t);
  p_new_tcaphash_ansicall->context=p_tcaphash_context;
  p_tcaphash_context->ansicall=p_new_tcaphash_ansicall;
  p_new_tcaphash_ansicall->ansikey=prev_ansicall->ansikey;
  p_new_tcaphash_ansicall->context->first_frame = pinfo->num;
  p_new_tcaphash_ansicall->next_ansicall=NULL;
  p_new_tcaphash_ansicall->previous_ansicall=prev_ansicall;
  p_new_tcaphash_ansicall->father=FALSE;

#ifdef DEBUG_TCAPSRT
  dbg(10,"+A%d ", p_new_tcaphash_ansicall->context->session_id);
#endif
  /* Insert in the chained list */
  prev_ansicall->next_ansicall = p_new_tcaphash_ansicall;
  if (prev_ansicall->context->last_frame == 0) {
#ifdef DEBUG_TCAPSRT
    dbg(10,"last ");
#endif
    prev_ansicall->context->last_frame = pinfo->num-1;
  }
  return p_new_tcaphash_ansicall;
}


static struct tcaphash_contcall_t *
append_tcaphash_contcall(struct tcaphash_contcall_t *prev_contcall,
                         struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_contcall_t *p_new_tcaphash_contcall = NULL;

  /* Append the transaction to the list, when the same key is found
     This should append when the tcap-transaction Id is reused  */

  p_new_tcaphash_contcall = wmem_new0(wmem_file_scope(), struct tcaphash_contcall_t);
  p_new_tcaphash_contcall->context=p_tcaphash_context;
  p_tcaphash_context->contcall=p_new_tcaphash_contcall;
  p_new_tcaphash_contcall->contkey=prev_contcall->contkey;
  p_new_tcaphash_contcall->next_contcall=NULL;
  p_new_tcaphash_contcall->previous_contcall=prev_contcall;
  p_new_tcaphash_contcall->father=FALSE;

#ifdef DEBUG_TCAPSRT
  dbg(10,"+C%d ", p_new_tcaphash_contcall->context->session_id);
#endif
  /* Insert in the chained list */
  prev_contcall->next_contcall = p_new_tcaphash_contcall;
  return p_new_tcaphash_contcall;
}


static struct tcaphash_endcall_t *
append_tcaphash_endcall(struct tcaphash_endcall_t *prev_endcall,
                        struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_endcall_t *p_new_tcaphash_endcall = NULL;

  /* Append the transaction to the list, when the same key is found
     This should append when the tcap-transaction Id is reused  */

  p_new_tcaphash_endcall = wmem_new0(wmem_file_scope(), struct tcaphash_endcall_t);
  p_new_tcaphash_endcall->context=p_tcaphash_context;
  p_tcaphash_context->endcall=p_new_tcaphash_endcall;
  p_new_tcaphash_endcall->endkey=prev_endcall->endkey;
  p_new_tcaphash_endcall->next_endcall=NULL;
  p_new_tcaphash_endcall->previous_endcall=prev_endcall;
  p_new_tcaphash_endcall->father=FALSE;

#ifdef DEBUG_TCAPSRT
  dbg(10,"+E%d ", p_new_tcaphash_endcall->context->session_id);
#endif
  /* Insert in the chained list */
  prev_endcall->next_endcall = p_new_tcaphash_endcall;
  return p_new_tcaphash_endcall;
}


/*
 * Find the dialog by Key and Time
 */
static struct tcaphash_begincall_t *
find_tcaphash_begin(struct tcaphash_begin_info_key_t *p_tcaphash_begin_key,
                    packet_info *pinfo, gboolean isBegin)
{
  struct tcaphash_begincall_t *p_tcaphash_begincall = NULL;
  p_tcaphash_begincall = (struct tcaphash_begincall_t *)g_hash_table_lookup(tcaphash_begin, p_tcaphash_begin_key);

  if(p_tcaphash_begincall) {
    do {
      if ( p_tcaphash_begincall->context ) {
        if ( ( isBegin &&
               pinfo->num == p_tcaphash_begincall->context->first_frame )
             ||
             ( !isBegin &&
               pinfo->num >= p_tcaphash_begincall->context->first_frame &&
               ( p_tcaphash_begincall->context->last_frame?pinfo->num <= p_tcaphash_begincall->context->last_frame:1 )
               )
             ) {
          /* We have a dialogue, with this key, opened before this request */
#ifdef DEBUG_TCAPSRT
          dbg(10,"B%d ", p_tcaphash_begincall->context->session_id);
#endif
          return p_tcaphash_begincall;
        }
#ifdef DEBUG_TCAPSRT
      dbg(60,"[B%d] ", p_tcaphash_begincall->context->session_id);
#endif
      }
      /* Break when list end is reached */
      if(p_tcaphash_begincall->next_begincall == NULL) {
#ifdef DEBUG_TCAPSRT
        dbg(23,"End of Blist ");
#endif
        break;
      }
      p_tcaphash_begincall = p_tcaphash_begincall->next_begincall;
    } while (p_tcaphash_begincall != NULL) ;
  } else {
#ifdef DEBUG_TCAPSRT
    dbg(23,"Not in Bhash ");
#endif
  }
  return NULL;
}



static struct tcaphash_contcall_t *
find_tcaphash_cont(struct tcaphash_cont_info_key_t *p_tcaphash_cont_key,
                   packet_info *pinfo)
{
  struct tcaphash_contcall_t *p_tcaphash_contcall = NULL;
  p_tcaphash_contcall = (struct tcaphash_contcall_t *)g_hash_table_lookup(tcaphash_cont, p_tcaphash_cont_key);

  if(p_tcaphash_contcall) {
    do {
      if ( p_tcaphash_contcall->context ) {
        if (pinfo->num >= p_tcaphash_contcall->context->first_frame &&
            (p_tcaphash_contcall->context->last_frame?pinfo->num <= p_tcaphash_contcall->context->last_frame:1) ) {
          /* We have a dialogue, with this key, opened before this request */
#ifdef DEBUG_TCAPSRT
          dbg(10,"C%d ", p_tcaphash_contcall->context->session_id);
#endif
          return p_tcaphash_contcall;
        }
#ifdef DEBUG_TCAPSRT
        dbg(60,"[C%d] ", p_tcaphash_contcall->context->session_id);
#endif
      }
      /* Break when list end is reached */
      if(p_tcaphash_contcall->next_contcall == NULL) {
#ifdef DEBUG_TCAPSRT
        dbg(23,"End of Clist ");
#endif
        break;
      }
      p_tcaphash_contcall = p_tcaphash_contcall->next_contcall;
    } while (p_tcaphash_contcall != NULL) ;
  } else {
#ifdef DEBUG_TCAPSRT
    dbg(23,"Not in Chash ");
#endif
  }
  return NULL;
}

static struct tcaphash_endcall_t *
find_tcaphash_end(struct tcaphash_end_info_key_t *p_tcaphash_end_key,
                  packet_info *pinfo, gboolean isEnd)
{
  struct tcaphash_endcall_t *p_tcaphash_endcall = NULL;
  p_tcaphash_endcall = (struct tcaphash_endcall_t *)g_hash_table_lookup(tcaphash_end, p_tcaphash_end_key);

  if(p_tcaphash_endcall) {
    do {
      if ( p_tcaphash_endcall->context ) {
        if ( ( isEnd &&
               (p_tcaphash_endcall->context->last_frame?pinfo->num == p_tcaphash_endcall->context->last_frame:1)
               )
             ||
             ( !isEnd &&
               pinfo->num >= p_tcaphash_endcall->context->first_frame &&
               (p_tcaphash_endcall->context->last_frame?pinfo->num <= p_tcaphash_endcall->context->last_frame:1)
               )
             ) {
          /* We have a dialogue, with this key, opened before this request */
#ifdef DEBUG_TCAPSRT
          dbg(10,"E%d ", p_tcaphash_endcall->context->session_id);
#endif
          return p_tcaphash_endcall;
        }
#ifdef DEBUG_TCAPSRT
          dbg(60,"[E%d] ", p_tcaphash_endcall->context->session_id);
#endif
      }
      /* Break when list end is reached */
      if(p_tcaphash_endcall->next_endcall == NULL) {
#ifdef DEBUG_TCAPSRT
        dbg(23,"End of Elist ");
#endif
        break;
      }
      p_tcaphash_endcall = p_tcaphash_endcall->next_endcall;
    } while (p_tcaphash_endcall != NULL) ;
  } else {
#ifdef DEBUG_TCAPSRT
    dbg(23,"Not in Ehash ");
#endif
  }
  return NULL;
}

/*
 * New record to create, to identify a new transaction
 */
static struct tcaphash_context_t *
new_tcaphash_context(struct tcaphash_context_key_t *p_tcaphash_context_key,
                     packet_info *pinfo)
{
  struct tcaphash_context_key_t *p_new_tcaphash_context_key;
  struct tcaphash_context_t *p_new_tcaphash_context = NULL;

  /* Register the transaction in the hash table
     with the tcap transaction Id as Main Key
     Once created, this entry will be updated later */

  p_new_tcaphash_context_key = wmem_new(wmem_file_scope(), struct tcaphash_context_key_t);
  p_new_tcaphash_context_key->session_id = p_tcaphash_context_key->session_id;

  p_new_tcaphash_context = wmem_new0(wmem_file_scope(), struct tcaphash_context_t);
  p_new_tcaphash_context->key = p_new_tcaphash_context_key;
  p_new_tcaphash_context->session_id = p_tcaphash_context_key->session_id;
  p_new_tcaphash_context->first_frame = pinfo->num;
#ifdef DEBUG_TCAPSRT
  dbg(10,"S%d ", p_new_tcaphash_context->session_id);
#endif
  /* store it */
  g_hash_table_insert(tcaphash_context, p_new_tcaphash_context_key, p_new_tcaphash_context);
  return p_new_tcaphash_context;
}

/*
 * New record to create, to identify a new transaction
 */
static struct tcaphash_begincall_t *
new_tcaphash_begin(struct tcaphash_begin_info_key_t *p_tcaphash_begin_key,
                   struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_begin_info_key_t *p_new_tcaphash_begin_key;
  struct tcaphash_begincall_t *p_new_tcaphash_begincall = NULL;

  /* Register the transaction in the hash table
     with the tcap transaction Id as Main Key
     Once created, this entry will be updated later */

  p_new_tcaphash_begin_key = wmem_new(wmem_file_scope(), struct tcaphash_begin_info_key_t);
  p_new_tcaphash_begin_key->hashKey = p_tcaphash_begin_key->hashKey;
  p_new_tcaphash_begin_key->tid = p_tcaphash_begin_key->tid;
  p_new_tcaphash_begin_key->pc_hash = p_tcaphash_begin_key->pc_hash;

 p_new_tcaphash_begincall = wmem_new0(wmem_file_scope(), struct tcaphash_begincall_t);
  p_new_tcaphash_begincall->beginkey=p_new_tcaphash_begin_key;
  p_new_tcaphash_begincall->context=p_tcaphash_context;
  p_tcaphash_context->begincall=p_new_tcaphash_begincall;
  p_new_tcaphash_begincall->father=TRUE;
  p_new_tcaphash_begincall->next_begincall=NULL;
  p_new_tcaphash_begincall->previous_begincall=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"B%d ", p_new_tcaphash_begincall->context->session_id);
#endif
  /* store it */
  g_hash_table_insert(tcaphash_begin, p_new_tcaphash_begin_key, p_new_tcaphash_begincall);
  return p_new_tcaphash_begincall;
}



/*
 * New record to create, to identify a new transaction
 */
static struct tcaphash_contcall_t *
new_tcaphash_cont(struct tcaphash_cont_info_key_t *p_tcaphash_cont_key,
                  struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_cont_info_key_t *p_new_tcaphash_cont_key;
  struct tcaphash_contcall_t *p_new_tcaphash_contcall = NULL;

  /* Register the transaction in the hash table
     with the tcap transaction Id as Main Key
     Once created, this entry will be updated later */

  p_new_tcaphash_cont_key = wmem_new(wmem_file_scope(), struct tcaphash_cont_info_key_t);
  p_new_tcaphash_cont_key->hashKey = p_tcaphash_cont_key->hashKey;
  p_new_tcaphash_cont_key->src_tid = p_tcaphash_cont_key->src_tid;
  p_new_tcaphash_cont_key->dst_tid = p_tcaphash_cont_key->dst_tid;
  p_new_tcaphash_cont_key->opc_hash = p_tcaphash_cont_key->opc_hash;
  p_new_tcaphash_cont_key->dpc_hash = p_tcaphash_cont_key->dpc_hash;

  p_new_tcaphash_contcall = wmem_new0(wmem_file_scope(), struct tcaphash_contcall_t);
  p_new_tcaphash_contcall->contkey=p_new_tcaphash_cont_key;
  p_new_tcaphash_contcall->context=p_tcaphash_context;
  p_tcaphash_context->contcall=p_new_tcaphash_contcall;
  p_new_tcaphash_contcall->father=TRUE;
  p_new_tcaphash_contcall->next_contcall=NULL;
  p_new_tcaphash_contcall->previous_contcall=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"C%d ", p_new_tcaphash_contcall->context->session_id);
#endif
  /* store it */
  g_hash_table_insert(tcaphash_cont, p_new_tcaphash_cont_key, p_new_tcaphash_contcall);
  return p_new_tcaphash_contcall;
}


/*
 * New record to create, to identify a new transaction
 */
static struct tcaphash_endcall_t *
new_tcaphash_end(struct tcaphash_end_info_key_t *p_tcaphash_end_key,
                 struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_end_info_key_t *p_new_tcaphash_end_key;
  struct tcaphash_endcall_t *p_new_tcaphash_endcall = NULL;

  /* Register the transaction in the hash table
     with the tcap transaction Id as Main Key
     Once created, this entry will be updated later */

  p_new_tcaphash_end_key = wmem_new(wmem_file_scope(), struct tcaphash_end_info_key_t);
  p_new_tcaphash_end_key->hashKey = p_tcaphash_end_key->hashKey;
  p_new_tcaphash_end_key->tid = p_tcaphash_end_key->tid;
  p_new_tcaphash_end_key->pc_hash = p_tcaphash_end_key->pc_hash;

  p_new_tcaphash_endcall = wmem_new0(wmem_file_scope(), struct tcaphash_endcall_t);
  p_new_tcaphash_endcall->endkey=p_new_tcaphash_end_key;
  p_new_tcaphash_endcall->context=p_tcaphash_context;
  p_tcaphash_context->endcall=p_new_tcaphash_endcall;
  p_new_tcaphash_endcall->father=TRUE;
  p_new_tcaphash_endcall->next_endcall=NULL;
  p_new_tcaphash_endcall->previous_endcall=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"E%d ", p_new_tcaphash_endcall->context->session_id);
#endif
  /* store it */
  g_hash_table_insert(tcaphash_end, p_new_tcaphash_end_key, p_new_tcaphash_endcall);
  return p_new_tcaphash_endcall;
}
/*
 * New record to create, to identify a new transaction
 */
static struct tcaphash_ansicall_t *
new_tcaphash_ansi(struct tcaphash_ansi_info_key_t *p_tcaphash_ansi_key,
                   struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_ansi_info_key_t *p_new_tcaphash_ansi_key;
  struct tcaphash_ansicall_t *p_new_tcaphash_ansicall = NULL;

  /* Register the transaction in the hash table
     with the tcap transaction Id as Main Key
     Once created, this entry will be updated later */

  p_new_tcaphash_ansi_key = wmem_new(wmem_file_scope(), struct tcaphash_ansi_info_key_t);
  p_new_tcaphash_ansi_key->hashKey = p_tcaphash_ansi_key->hashKey;
  p_new_tcaphash_ansi_key->tid = p_tcaphash_ansi_key->tid;
  p_new_tcaphash_ansi_key->opc_hash = p_tcaphash_ansi_key->opc_hash;
  p_new_tcaphash_ansi_key->dpc_hash = p_tcaphash_ansi_key->dpc_hash;

  p_new_tcaphash_ansicall = wmem_new0(wmem_file_scope(), struct tcaphash_ansicall_t);
  p_new_tcaphash_ansicall->ansikey=p_new_tcaphash_ansi_key;
  p_new_tcaphash_ansicall->context=p_tcaphash_context;
  p_tcaphash_context->ansicall=p_new_tcaphash_ansicall;
  p_new_tcaphash_ansicall->father=TRUE;
  p_new_tcaphash_ansicall->next_ansicall=NULL;
  p_new_tcaphash_ansicall->previous_ansicall=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"A%d ", p_new_tcaphash_ansicall->context->session_id);
#endif
  /* store it */
  g_hash_table_insert(tcaphash_ansi, p_new_tcaphash_ansi_key, p_new_tcaphash_ansicall);
  return p_new_tcaphash_ansicall;
}

static struct tcaphash_contcall_t *
create_tcaphash_cont(struct tcaphash_cont_info_key_t *p_tcaphash_cont_key,
                     struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_contcall_t *p_tcaphash_contcall1 = NULL;
  struct tcaphash_contcall_t *p_tcaphash_contcall = NULL;

  p_tcaphash_contcall1 = (struct tcaphash_contcall_t *)
    g_hash_table_lookup(tcaphash_cont, p_tcaphash_cont_key);

  if (p_tcaphash_contcall1) {
    /* Walk through list of transaction with identical keys */
    /* go the the end to insert new record */
    do {
      if (!p_tcaphash_contcall1->next_contcall) {
        p_tcaphash_contcall=append_tcaphash_contcall(p_tcaphash_contcall1,
                                                     p_tcaphash_context);
        break;
      }
      p_tcaphash_contcall1 = p_tcaphash_contcall1->next_contcall;
    } while (p_tcaphash_contcall1 != NULL );
  } else {
    p_tcaphash_contcall = new_tcaphash_cont(p_tcaphash_cont_key,
                                            p_tcaphash_context);
  }
  return p_tcaphash_contcall;
}


static struct tcaphash_endcall_t *
create_tcaphash_end(struct tcaphash_end_info_key_t *p_tcaphash_end_key,
                    struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_endcall_t *p_tcaphash_endcall1 = NULL;
  struct tcaphash_endcall_t *p_tcaphash_endcall = NULL;

  p_tcaphash_endcall1 = (struct tcaphash_endcall_t *)
    g_hash_table_lookup(tcaphash_end, p_tcaphash_end_key);

  if (p_tcaphash_endcall1) {
    /* Walk through list of transaction with identical keys */
    /* go the the end to insert new record */
    do {
      if (!p_tcaphash_endcall1->next_endcall) {
        p_tcaphash_endcall=append_tcaphash_endcall(p_tcaphash_endcall1,
                                                   p_tcaphash_context);
        break;
      }
      p_tcaphash_endcall1 = p_tcaphash_endcall1->next_endcall;
    } while (p_tcaphash_endcall1 != NULL );
  } else {
    p_tcaphash_endcall = new_tcaphash_end(p_tcaphash_end_key,
                                          p_tcaphash_context);
  }
  return p_tcaphash_endcall;
}


/*
 * Routine called when the TAP is initialized.
 * so hash table are (re)created
 */
void
tcapsrt_init_routine(void)
{

  /* free hash-table for SRT */
  if (tcaphash_context != NULL) {
#ifdef DEBUG_TCAPSRT
    dbg(16,"Destroy hash_context \n");
#endif
    g_hash_table_destroy(tcaphash_context);
  }

  if (tcaphash_begin != NULL) {
#ifdef DEBUG_TCAPSRT
    dbg(16,"Destroy hash_begin \n");
#endif
    g_hash_table_destroy(tcaphash_begin);
  }

  if (tcaphash_cont != NULL) {
#ifdef DEBUG_TCAPSRT
    dbg(16,"Destroy hash_cont \n");
#endif
    g_hash_table_destroy(tcaphash_cont);
  }

  if (tcaphash_end != NULL) {
#ifdef DEBUG_TCAPSRT
    dbg(16,"Destroy hash_end \n");
#endif
    g_hash_table_destroy(tcaphash_end);
  }

  if (tcaphash_ansi != NULL) {
#ifdef DEBUG_TCAPSRT
    dbg(16,"Destroy hash_ansi \n");
#endif
    g_hash_table_destroy(tcaphash_ansi);
  }

#ifdef DEBUG_TCAPSRT
  dbg(16,"Create hash \n");
#endif
  /* create new hash-tables for SRT */
  tcaphash_context = g_hash_table_new(tcaphash_context_calchash, tcaphash_context_equal);
  tcaphash_begin   = g_hash_table_new(tcaphash_begin_calchash, tcaphash_begin_equal);
  tcaphash_cont    = g_hash_table_new(tcaphash_cont_calchash, tcaphash_cont_equal);
  tcaphash_end     = g_hash_table_new(tcaphash_end_calchash, tcaphash_end_equal);
  tcaphash_ansi    = g_hash_table_new(tcaphash_ansi_calchash, tcaphash_ansi_equal);

  /* Reset the session counter */
  tcapsrt_global_SessionId=1;

  /* Display of SRT only if Persistent Stat */
  gtcap_DisplaySRT=gtcap_PersistentSRT || gtcap_HandleSRT&gtcap_StatSRT;
}

/*
 * Create the record identifiying the TCAP transaction
 * When the identifier for the transaction is reused, check
 * the following criteria before to append a new record:
 * - a timeout corresponding to a message retransmission is detected,
 * - a message hast been lost
 * - or the previous transaction has been  be closed
 */
static struct tcaphash_context_t *
tcaphash_begin_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        struct tcapsrt_info_t *p_tcapsrt_info)
{
  struct tcaphash_context_t *p_tcaphash_context=NULL;
  struct tcaphash_context_key_t tcaphash_context_key;
  struct tcaphash_begincall_t *p_tcaphash_begincall, *p_new_tcaphash_begincall=NULL;
  struct tcaphash_begin_info_key_t tcaphash_begin_key;
  proto_item *pi;
  proto_item *stat_item=NULL;
  proto_tree *stat_tree=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(51,"src %s srcTid %lx dst %s ", address_to_str(wmem_packet_scope(), &pinfo->src), p_tcapsrt_info->src_tid, address_to_str(wmem_packet_scope(), &pinfo->dst));
#endif

  /* prepare the key data */
  tcaphash_begin_key.tid = p_tcapsrt_info->src_tid;
  if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
  {
    /* We have MTP3 PCs (so we can safely do this cast) */
    tcaphash_begin_key.pc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
  } else {
    /* Don't have MTP3 PCs (have SCCP GT ?) */
    tcaphash_begin_key.pc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->src));
  }
  tcaphash_begin_key.hashKey=tcaphash_begin_calchash(&tcaphash_begin_key);

  /* look up the request */
#ifdef DEBUG_TCAPSRT
  dbg(10,"\n Hbegin #%u ", pinfo->num);
  dbg(11,"key %lx ",tcaphash_begin_key.hashKey);
  dbg(51,"addr %s ", address_to_str(wmem_packet_scope(), &pinfo->src));
  dbg(51,"Tid %lx \n",tcaphash_begin_key.tid);
#endif

  p_tcaphash_begincall = (struct tcaphash_begincall_t *)
  g_hash_table_lookup(tcaphash_begin, &tcaphash_begin_key);

  if (p_tcaphash_begincall) {
    /* Walk through list of transaction with identical keys */
    do {
      /* Check if the request with this reqSeqNum has been seen, with the same Message Type */
      if (pinfo->num == p_tcaphash_begincall->context->first_frame) {
        /* We have seen this request before -> do nothing */
#ifdef DEBUG_TCAPSRT
        dbg(22,"Already seen ");
#endif
        p_tcaphash_context=p_tcaphash_begincall->context;
        break;
      }
      /* If the last record for Tcap transaction with identifier has not been reached */
      if (!p_tcaphash_begincall->next_begincall) {
        /* check if we have to create a new record or not */
        /* if last request has been responded (response number is known)
           and this request appears after last response (has bigger frame number)
           and last request occurred after the timeout for repetition,
           or
           if last request hasn't been responded (so number unknown)
           and this request appears after last request (has bigger frame number)
           and this request occurred after the timeout for message lost */
        if ( ( p_tcaphash_begincall->context->last_frame != 0
               && pinfo->num > p_tcaphash_begincall->context->first_frame
               && (guint) pinfo->abs_ts.secs > (guint)(p_tcaphash_begincall->context->begin_time.secs + gtcap_RepetitionTimeout)
               ) ||
             ( p_tcaphash_begincall->context->last_frame == 0
               && pinfo->num > p_tcaphash_begincall->context->first_frame
               && (guint)pinfo->abs_ts.secs > (guint)(p_tcaphash_begincall->context->begin_time.secs + gtcap_LostTimeout)
               )
             )
          {
            /* we decide that we have a new request */
            /* Append new record to the list */
#ifdef DEBUG_TCAPSRT
            dbg(12,"(timeout) Append key %lx ",tcaphash_begin_key.hashKey);
            dbg(12,"Frame %u rsp %u ",pinfo->num,p_tcaphash_begincall->context->last_frame );
#endif
            tcaphash_context_key.session_id = tcapsrt_global_SessionId++;
            p_tcaphash_context = new_tcaphash_context(&tcaphash_context_key, pinfo);

            p_new_tcaphash_begincall = append_tcaphash_begincall(p_tcaphash_begincall,
                                                                 p_tcaphash_context,
                                                                 pinfo);
#ifdef DEBUG_TCAPSRT
            dbg(12,"Update key %lx ",tcaphash_begin_key.hashKey);
#endif
            update_tcaphash_begincall(p_new_tcaphash_begincall, pinfo);
          } else { /* timeout or message lost */

          /* If the Tid is reused for a closed Transaction */
          /* Or if we received an TC_BEGIN for a Transaction marked as "closed" */
          /* (this is the case, for pre-arranged END, the transaction is marked as closed */
          /* by the upper layer, thank to a callback method close) */
          if ( p_tcaphash_begincall->context->closed) {
#ifdef DEBUG_TCAPSRT
            dbg(12,"(closed) Append key %lu ",tcaphash_begin_key.hashKey);
            dbg(12,"Frame %u rsp %u ",pinfo->num,p_tcaphash_begincall->context->last_frame );
#endif
            tcaphash_context_key.session_id = tcapsrt_global_SessionId++;
            p_tcaphash_context = new_tcaphash_context(&tcaphash_context_key, pinfo);
            p_new_tcaphash_begincall = append_tcaphash_begincall(p_tcaphash_begincall,
                                                                 p_tcaphash_context,
                                                                 pinfo);

#ifdef DEBUG_TCAPSRT
            dbg(12,"Update key %lu ",tcaphash_begin_key.hashKey);
#endif
            update_tcaphash_begincall(p_new_tcaphash_begincall, pinfo);

          } else {
            /* the TCAP session is not closed, so, either messages have been lost */
            /* or it's a duplicate request. Mark it as such. */
#ifdef DEBUG_TCAPSRT
            dbg(21,"Display_duplicate %d ",p_tcaphash_begincall->context->first_frame);
#endif
            p_tcaphash_context=p_tcaphash_begincall->context;
            if (gtcap_DisplaySRT && tree) {
              stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
              PROTO_ITEM_SET_GENERATED(stat_item);
              pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_Duplicate, tvb, 0, 0,
                                              p_tcaphash_context->first_frame,
                                              "Duplicate with session %u in frame %u",
                                              p_tcaphash_context->session_id,p_tcaphash_context->first_frame);
              PROTO_ITEM_SET_GENERATED(pi);
            }
            return p_tcaphash_context;
          } /* Previous session closed */
        } /* test with Timeout or message Lost */
        break;
      } /* Next call is NULL */
      /* Repeat the tests for the next record with the same transaction identifier */
      p_tcaphash_begincall = p_tcaphash_begincall->next_begincall;
    } while (p_tcaphash_begincall != NULL );
    /*
     * End of analyze for the list be TC_BEGIN with same transaction ID
     */
  } else { /* p_tcaphash_begincall has not been found */
    /*
     * Create a new TCAP context
     */
#ifdef DEBUG_TCAPSRT
    dbg(10,"New key %lx ",tcaphash_begin_key.hashKey);
#endif

    tcaphash_context_key.session_id = tcapsrt_global_SessionId++;
    p_tcaphash_context = new_tcaphash_context(&tcaphash_context_key, pinfo);
    p_tcaphash_begincall = new_tcaphash_begin(&tcaphash_begin_key, p_tcaphash_context);

#ifdef DEBUG_TCAPSRT
    dbg(11,"Update key %lx ",tcaphash_begin_key.hashKey);
    dbg(11,"Frame reqlink #%u ", pinfo->num);
#endif
    update_tcaphash_begincall(p_tcaphash_begincall, pinfo);
  }

  /* display tcap session, if available */
  if ( gtcap_DisplaySRT && tree &&
       p_tcaphash_context &&
       p_tcaphash_context->session_id) {
    stat_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_tcap_stat, &stat_item, "Stat");
    PROTO_ITEM_SET_GENERATED(stat_item);
    pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
    PROTO_ITEM_SET_GENERATED(pi);

    /* add link to response frame, if available */
    /* p_tcaphash_begincall->context->last_frame) */
    if( p_tcaphash_context->last_frame != 0 ){
#ifdef DEBUG_TCAPSRT
      dbg(20,"Display_frameRsplink %d ",p_tcaphash_context->last_frame);
#endif
      pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_BeginSession, tvb, 0, 0,
                                      p_tcaphash_context->last_frame,
                                      "End of session in frame %u",
                                      p_tcaphash_context->last_frame);
      PROTO_ITEM_SET_GENERATED(pi);
    }
  }
  return p_tcaphash_context;
}

/*
* Try to find a TCAP session according to the source and destination
* Identifier given in the TC_CONT
* If nothing is found, it is probably a session in opening state, so try to find
* a tcap session registered with a TC_BEGIN "key", matching the destination Id of the TC_CONT
* Then associate the TC_CONT "key" to the TCAP context, and create a TC_END "key"
* and display the available info for the TCAP context
*/
static struct tcaphash_context_t *
tcaphash_cont_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       struct tcapsrt_info_t *p_tcapsrt_info)
{
  struct tcaphash_context_t *p_tcaphash_context=NULL;
  struct tcaphash_contcall_t *p_tcaphash_contcall;
  struct tcaphash_cont_info_key_t tcaphash_cont_key;
  struct tcaphash_begin_info_key_t tcaphash_begin_key;
  struct tcaphash_begincall_t *p_tcaphash_begincall;
  struct tcaphash_end_info_key_t tcaphash_end_key;
  proto_item *pi;
  proto_item *stat_item=NULL;
  proto_tree *stat_tree=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(51,"src %s srcTid %lx dst %s dstTid %lx ", address_to_str(wmem_packet_scope(), &pinfo->src), p_tcapsrt_info->src_tid, address_to_str(wmem_packet_scope(), &pinfo->dst), p_tcapsrt_info->dst_tid);
  dbg(10,"\n Hcont #%u ", pinfo->num);
#endif

  /* look only for matching request, if matching conversation is available. */
  tcaphash_cont_key.src_tid = p_tcapsrt_info->src_tid;
  tcaphash_cont_key.dst_tid = p_tcapsrt_info->dst_tid;
  if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
  {
    /* We have MTP3 PCs (so we can safely do this cast) */
    tcaphash_cont_key.opc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
    tcaphash_cont_key.dpc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
  } else {
    /* Don't have MTP3 PCs (have SCCP GT ?) */
    tcaphash_cont_key.opc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->src));
    tcaphash_cont_key.dpc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->dst));
  }
  tcaphash_cont_key.hashKey=tcaphash_cont_calchash(&tcaphash_cont_key);

#ifdef DEBUG_TCAPSRT
  dbg(11,"Ckey %lx ", tcaphash_cont_key.hashKey);
  dbg(51,"addr %s %s ", address_to_str(wmem_packet_scope(), &pinfo->src), address_to_str(wmem_packet_scope(), &pinfo->dst));
  dbg(51,"Tid %lx %lx \n",tcaphash_cont_key.src_tid, tcaphash_cont_key.dst_tid);
#endif
  p_tcaphash_contcall = find_tcaphash_cont(&tcaphash_cont_key, pinfo);
  if(p_tcaphash_contcall) {
#ifdef DEBUG_TCAPSRT
    dbg(12,"CFound ");
#endif
    p_tcaphash_context=p_tcaphash_contcall->context;
  } else { /* cont not found */
#ifdef DEBUG_TCAPSRT
    dbg(12,"CnotFound ");
#endif
    /* Find the TCAP transaction according to the TC_BEGIN (from dtid,dst) */
    tcaphash_begin_key.tid = p_tcapsrt_info->dst_tid;
    if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
    {
      /* We have MTP3 PCs (so we can safely do this cast) */
      tcaphash_begin_key.pc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
    } else {
      /* Don't have MTP3 PCs (have SCCP GT ?) */
      tcaphash_begin_key.pc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->dst));
    }
    tcaphash_begin_key.hashKey=tcaphash_begin_calchash(&tcaphash_begin_key);

#ifdef DEBUG_TCAPSRT
    dbg(11,"Bkey %lx ", tcaphash_begin_key.hashKey);
    dbg(51,"addr %s ", address_to_str(wmem_packet_scope(), &pinfo->dst));
    dbg(51,"Tid %lx \n",tcaphash_begin_key.tid);
#endif
    p_tcaphash_begincall = find_tcaphash_begin(&tcaphash_begin_key, pinfo, FALSE);
    if(!p_tcaphash_begincall){
/* can this actually happen? */
#ifdef DEBUG_TCAPSRT
        dbg(12,"BNotFound trying stid,src");
#endif
        /* Do we have a continue from the same source? (stid,src) */
        tcaphash_begin_key.tid = p_tcapsrt_info->src_tid;
        if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
        {
          /* We have MTP3 PCs (so we can safely do this cast) */
          tcaphash_begin_key.pc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
        } else {
          /* Don't have MTP3 PCs (have SCCP GT ?) */
          tcaphash_begin_key.pc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->src));
        }
        tcaphash_begin_key.hashKey=tcaphash_begin_calchash(&tcaphash_begin_key);
#ifdef DEBUG_TCAPSRT
        dbg(11,"Bkey %lx ", tcaphash_begin_key.hashKey);
        dbg(51,"addr %s ", address_to_str(wmem_packet_scope(), &pinfo->src));
        dbg(51,"Tid %lx \n",tcaphash_begin_key.tid);
#endif
        p_tcaphash_begincall = find_tcaphash_begin(&tcaphash_begin_key, pinfo,FALSE);
    }
    if(p_tcaphash_begincall &&
       !p_tcaphash_begincall->context->contcall ) {
#ifdef DEBUG_TCAPSRT
      dbg(12,"BFound \n");
#endif
      p_tcaphash_context=p_tcaphash_begincall->context;
      p_tcaphash_context->responded=TRUE;

#ifdef DEBUG_TCAPSRT
      dbg(10,"New Ckey %lx ",tcaphash_cont_key.hashKey);
      dbg(11,"Frame reqlink #%u \n", pinfo->num);
#endif
      create_tcaphash_cont(&tcaphash_cont_key,
                           p_tcaphash_begincall->context);

      /* Create END for (stid,src) */
      tcaphash_end_key.tid = p_tcapsrt_info->src_tid;
      if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
      {
        /* We have MTP3 PCs (so we can safely do this cast) */
        tcaphash_end_key.pc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
      } else {
        /* Don't have MTP3 PCs (have SCCP GT ?) */
        tcaphash_end_key.pc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->src));
      }
      tcaphash_end_key.hashKey=tcaphash_end_calchash(&tcaphash_end_key);

#ifdef DEBUG_TCAPSRT
      dbg(10,"New Ekey %lx ",tcaphash_end_key.hashKey);
      dbg(51,"addr %s ", address_to_str(wmem_packet_scope(), &pinfo->src));
      dbg(51,"Tid %lx ",tcaphash_end_key.tid);
      dbg(11,"Frame reqlink #%u ", pinfo->num);
#endif
      create_tcaphash_end(&tcaphash_end_key,
                          p_tcaphash_begincall->context);

    } else { /* Begin not found */
#ifdef DEBUG_TCAPSRT
      dbg(12,"BnotFound ");
#endif
    } /* begin found */
  } /* cont found */
    /* display tcap session, if available */
  if (gtcap_DisplaySRT && tree &&
      p_tcaphash_context &&
      p_tcaphash_context->session_id) {
    stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
    PROTO_ITEM_SET_GENERATED(stat_item);
    pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
    PROTO_ITEM_SET_GENERATED(pi);
  }

  return p_tcaphash_context;
}

/*
* Try to find a TCAP session according to the destination Identifier given in the TC_END/TC_ABORT
* If nothing is found,
* - either it is a session in opening state,
* - or the session is closed/aborted by the remote, ( so we switch the src and dst tid )
* so try to find a tcap session registered with a TC_BEGIN "key",
* matching the destination Id of the TC_END
* Then associate the TC_CONT "key" to the TCAP context
* and display the available info for the TCAP context
*/

static struct tcaphash_context_t *
tcaphash_end_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      struct tcapsrt_info_t *p_tcapsrt_info)
{
  struct tcaphash_context_t *p_tcaphash_context=NULL;

  struct tcaphash_end_info_key_t tcaphash_end_key;
  struct tcaphash_endcall_t *p_tcaphash_endcall=NULL;

  struct tcaphash_begin_info_key_t tcaphash_begin_key;
  struct tcaphash_begincall_t *p_tcaphash_begincall=NULL;
  proto_item *pi;
  nstime_t delta;
  proto_item *stat_item=NULL;
  proto_tree *stat_tree=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(51,"src %s dst %s dstTid %lx ", address_to_str(wmem_packet_scope(), &pinfo->src), address_to_str(wmem_packet_scope(), &pinfo->dst), p_tcapsrt_info->dst_tid);
  dbg(10,"\n Hend #%u ", pinfo->num);
#endif
  /* look only for matching request, if matching conversation is available. */
  tcaphash_end_key.tid = p_tcapsrt_info->dst_tid;
  if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
  {
    /* We have MTP3 PCs (so we can safely do this cast) */
    tcaphash_end_key.pc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
  } else {
    /* Don't have MTP3 PCs (have SCCP GT ?) */
    tcaphash_end_key.pc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->dst));
  }
  tcaphash_end_key.hashKey=tcaphash_end_calchash(&tcaphash_end_key);

#ifdef DEBUG_TCAPSRT
  dbg(11,"Ekey %lx ",tcaphash_end_key.hashKey);
  dbg(11,"addr %s ", address_to_str(wmem_packet_scope(), &pinfo->dst));
  dbg(51,"Tid %lx ",tcaphash_end_key.tid);
#endif
  p_tcaphash_endcall = find_tcaphash_end(&tcaphash_end_key, pinfo,TRUE);

  if(!p_tcaphash_endcall) {
#ifdef DEBUG_TCAPSRT
    dbg(12,"EnotFound ");
#endif
    tcaphash_begin_key.tid = p_tcapsrt_info->dst_tid;
    if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
    {
      /* We have MTP3 PCs (so we can safely do this cast) */
      tcaphash_begin_key.pc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
    } else {
      /* Don't have MTP3 PCs (have SCCP GT ?) */
      tcaphash_begin_key.pc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->dst));
    }
    tcaphash_begin_key.hashKey=tcaphash_begin_calchash(&tcaphash_begin_key);

#ifdef DEBUG_TCAPSRT
    dbg(11,"Bkey %lx ", tcaphash_begin_key.hashKey);
    dbg(51,"addr %s ", address_to_str(wmem_packet_scope(), &pinfo->dst));
    dbg(51,"Tid %lx ",tcaphash_begin_key.tid);
#endif
    p_tcaphash_begincall = find_tcaphash_begin(&tcaphash_begin_key, pinfo,FALSE);
    if(!p_tcaphash_begincall) {
#ifdef DEBUG_TCAPSRT
      dbg(12,"BnotFound ");
#endif
    }
  }
  if (p_tcaphash_endcall) {
    /* Use the TC_BEGIN Destination reference */
    p_tcaphash_context=p_tcaphash_endcall->context;
  } else if (p_tcaphash_begincall) {
    /* Use the TC_BEGIN Source reference */
    p_tcaphash_context=p_tcaphash_begincall->context;
  }

  if (p_tcaphash_context) {

#ifdef DEBUG_TCAPSRT
    dbg(12,"Found, req=%d ",p_tcaphash_context->first_frame);
#endif
    if (gtcap_DisplaySRT && tree) {
      stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
      PROTO_ITEM_SET_GENERATED(stat_item);

      pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
      PROTO_ITEM_SET_GENERATED(pi);
    }

#ifdef DEBUG_TCAPSRT
    dbg(20,"Display framereqlink %d ",p_tcaphash_context->first_frame);
#endif
    /* Indicate the frame to which this is a reply. */
    if (gtcap_DisplaySRT && stat_tree) {
      pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_EndSession, tvb, 0, 0,
                                      p_tcaphash_context->first_frame,
                                      "Begin of session in frame %u",
                                      p_tcaphash_context->first_frame);
      PROTO_ITEM_SET_GENERATED(pi);
      /* Calculate Service Response Time */
      nstime_delta(&delta, &pinfo->abs_ts, &p_tcaphash_context->begin_time);

      /* display Service Response Time and make it filterable */
      pi = proto_tree_add_time(stat_tree, hf_tcapsrt_SessionTime, tvb, 0, 0, &delta);
      PROTO_ITEM_SET_GENERATED(pi);
    }
    /* Close the context and remove it (if needed) */
    tcapsrt_close(p_tcaphash_context,pinfo);

  } else {/* context present */
#ifdef DEBUG_TCAPSRT
    dbg(12,"Context notFound ");
#endif
  }
  return p_tcaphash_context;
}

/*
 * ANSI PART
 * Create the record identifiying the TCAP transaction
 * When the identifier for the transaction is reused, check
 * the following criteria before to append a new record:
 * - a timeout corresponding to a message retransmission is detected,
 * - a message hast been lost
 * - or the previous transaction has been  be closed
 */
static struct tcaphash_context_t *
tcaphash_ansi_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       struct tcapsrt_info_t *p_tcapsrt_info)
{
  struct tcaphash_context_t *p_tcaphash_context=NULL;
  struct tcaphash_context_key_t tcaphash_context_key;
  struct tcaphash_ansicall_t *p_tcaphash_ansicall, *p_new_tcaphash_ansicall;
  struct tcaphash_ansi_info_key_t tcaphash_ansi_key;
  proto_item *pi;
  nstime_t delta;
  gboolean isResponse=FALSE;
  proto_tree * stat_tree=NULL;
  proto_item * stat_item=NULL;

  /* prepare the key data */
  tcaphash_ansi_key.tid = p_tcapsrt_info->src_tid;
  if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
  {
    /* We have MTP3 PCs (so we can safely do this cast) */
    tcaphash_ansi_key.opc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
    tcaphash_ansi_key.dpc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
  } else {
    /* Don't have MTP3 PCs (have SCCP GT ?) */
    tcaphash_ansi_key.opc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->src));
    tcaphash_ansi_key.dpc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->dst));
  }
  tcaphash_ansi_key.hashKey=tcaphash_ansi_calchash(&tcaphash_ansi_key);

  /* look up the request */
#ifdef DEBUG_TCAPSRT
  dbg(10,"\n Hansi #%u ", pinfo->num);
  dbg(11,"key %lx ",tcaphash_ansi_key.hashKey);
  dbg(51,"PC %s %s ",address_to_str(wmem_packet_scope(), &pinfo->src), address_to_str(wmem_packet_scope(), &pinfo->dst));
  dbg(51,"Tid %lx ",tcaphash_ansi_key.tid);
#endif
  p_tcaphash_ansicall = (struct tcaphash_ansicall_t *)
    g_hash_table_lookup(tcaphash_ansi, &tcaphash_ansi_key);

  if (p_tcaphash_ansicall) {
    /* Walk through list of transaction with identical keys */
    do {
      /* Check if the request with this reqSeqNum has been seen */
      if (pinfo->num == p_tcaphash_ansicall->context->first_frame) {
        /* We have seen this request before -> do nothing */
#ifdef DEBUG_TCAPSRT
        dbg(22,"Request already seen ");
#endif
        isResponse=FALSE;
        p_tcaphash_context=p_tcaphash_ansicall->context;
        break;
      }

      /* Check if the reponse with this reqSeqNum has been seen */
      if (pinfo->num == p_tcaphash_ansicall->context->last_frame) {
        /* We have seen this response before -> do nothing */
#ifdef DEBUG_TCAPSRT
        dbg(22,"Response already seen ");
#endif
        isResponse=TRUE;
        p_tcaphash_context=p_tcaphash_ansicall->context;
        break;
      }

      /* Check for the first Request without Response
       received before this frame */
      if ( pinfo->num > p_tcaphash_ansicall->context->first_frame &&
           p_tcaphash_ansicall->context->last_frame==0 ) {
        /* Take it, and update the context */

#ifdef DEBUG_TCAPSRT
        dbg(12,"Update key %lx ",tcaphash_ansi_key.hashKey);
#endif
        p_tcaphash_ansicall->context->last_frame = pinfo->num;
        p_tcaphash_ansicall->context->responded = TRUE;
        p_tcaphash_ansicall->context->closed = TRUE;
        p_tcaphash_context=p_tcaphash_ansicall->context;
        isResponse=TRUE;

        if (gtcap_DisplaySRT && tree) {
          stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
          PROTO_ITEM_SET_GENERATED(stat_item);

          pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
          PROTO_ITEM_SET_GENERATED(pi);

#ifdef DEBUG_TCAPSRT
          dbg(20,"Display framereqlink %d ",p_tcaphash_context->first_frame);
#endif
          /* Indicate the frame to which this is a reply. */
          pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_EndSession, tvb, 0, 0,
                                          p_tcaphash_context->first_frame,
                                          "Begin of session in frame %u",
                                          p_tcaphash_context->first_frame);
          PROTO_ITEM_SET_GENERATED(pi);
          /* Calculate Service Response Time */
          nstime_delta(&delta, &pinfo->abs_ts, &p_tcaphash_context->begin_time);

          /* display Service Response Time and make it filterable */
          pi = proto_tree_add_time(stat_tree, hf_tcapsrt_SessionTime, tvb, 0, 0, &delta);
          PROTO_ITEM_SET_GENERATED(pi);
        }
        break;
      } /* Lastframe=0, so take it */


      /* If the last record for Tcap transaction with identifier has been reached */
      if (!p_tcaphash_ansicall->next_ansicall) {
        /* check if we have to create a new record or not */
        /* if last request has been responded (response number in known)
           and this request appears after last response (has bigger frame number)
           and last request occurred after the timeout for repetition,
           or
           if last request hasn't been responded (so number unknown)
           and this request appears after last request (has bigger frame number)
           and this request occurred after the timeout for message lost */
        if ( ( p_tcaphash_ansicall->context->last_frame != 0
               && pinfo->num > p_tcaphash_ansicall->context->first_frame
               && (guint) pinfo->abs_ts.secs > (guint)(p_tcaphash_ansicall->context->begin_time.secs + gtcap_RepetitionTimeout)
               ) ||
             ( p_tcaphash_ansicall->context->last_frame == 0
               && pinfo->num > p_tcaphash_ansicall->context->first_frame
               && (guint)pinfo->abs_ts.secs > (guint)(p_tcaphash_ansicall->context->begin_time.secs + gtcap_LostTimeout)
               )
             )
          {
            /* we decide that we have a new request */
            /* Append new record to the list */
#ifdef DEBUG_TCAPSRT
            dbg(12,"(timeout) Append key %lx ",tcaphash_ansi_key.hashKey);
            dbg(12,"Frame %u rsp %u ",pinfo->num,p_tcaphash_ansicall->context->last_frame );
#endif
            tcaphash_context_key.session_id = tcapsrt_global_SessionId++;
            p_tcaphash_context = new_tcaphash_context(&tcaphash_context_key, pinfo);
            p_new_tcaphash_ansicall = append_tcaphash_ansicall(p_tcaphash_ansicall,
                                                                 p_tcaphash_context,
                                                                 pinfo);

#ifdef DEBUG_TCAPSRT
            dbg(12,"Update key %lx ",tcaphash_ansi_key.hashKey);
#endif
            update_tcaphash_ansicall(p_new_tcaphash_ansicall, pinfo);
            p_tcaphash_ansicall=p_new_tcaphash_ansicall;
          } else {

          /* If the Tid is reused for a closed Transaction */
          if ( p_tcaphash_ansicall->context->closed) {
#ifdef DEBUG_TCAPSRT
            dbg(12,"(closed) Append key %lu ",tcaphash_ansi_key.hashKey);
            dbg(12,"Frame %u rsp %u ",pinfo->num,p_tcaphash_ansicall->context->last_frame );
#endif
            tcaphash_context_key.session_id = tcapsrt_global_SessionId++;
            p_tcaphash_context = new_tcaphash_context(&tcaphash_context_key, pinfo);
            p_new_tcaphash_ansicall = append_tcaphash_ansicall(p_tcaphash_ansicall,
                                                                 p_tcaphash_context,
                                                                 pinfo);

#ifdef DEBUG_TCAPSRT
            dbg(12,"Update key %lu ",tcaphash_ansi_key.hashKey);
#endif
            update_tcaphash_ansicall(p_new_tcaphash_ansicall, pinfo);
            p_tcaphash_ansicall=p_new_tcaphash_ansicall;

          } else {
            /* the Tid is reused for an opened Transaction */
            /* so, this is the reply to the request of our context */
            p_tcaphash_context=p_tcaphash_ansicall->context;
#ifdef DEBUG_TCAPSRT
            dbg(12,"Found, req=%d ",p_tcaphash_context->first_frame);
#endif

            if (gtcap_DisplaySRT && tree) {
              stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
              PROTO_ITEM_SET_GENERATED(stat_item);

              pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
              PROTO_ITEM_SET_GENERATED(pi);

#ifdef DEBUG_TCAPSRT
              dbg(20,"Display framereqlink %d ",p_tcaphash_context->first_frame);
#endif
              /* Indicate the frame to which this is a reply. */
              pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_EndSession, tvb, 0, 0,
                                              p_tcaphash_context->first_frame,
                                              "Begin of session in frame %u",
                                              p_tcaphash_context->first_frame);
              PROTO_ITEM_SET_GENERATED(pi);
              /* Calculate Service Response Time */
              nstime_delta(&delta, &pinfo->abs_ts, &p_tcaphash_context->begin_time);

              /* display Service Response Time and make it filterable */
              pi = proto_tree_add_time(stat_tree, hf_tcapsrt_SessionTime, tvb, 0, 0, &delta);
              PROTO_ITEM_SET_GENERATED(pi);
            }
            p_tcaphash_context=p_tcaphash_ansicall->context;
          } /* test with Timeout */
        } /* closed */
        break;
      } /* Next call is NULL */
      p_tcaphash_ansicall = p_tcaphash_ansicall->next_ansicall;
    } while (p_tcaphash_ansicall != NULL );
    /*
     * New TCAP context
     */
  } else { /* p_tcaphash_ansicall has not been found */
#ifdef DEBUG_TCAPSRT
    dbg(10,"New key %lx ",tcaphash_ansi_key.hashKey);
#endif

    tcaphash_context_key.session_id = tcapsrt_global_SessionId++;
    p_tcaphash_context = new_tcaphash_context(&tcaphash_context_key, pinfo);
    p_tcaphash_ansicall = new_tcaphash_ansi(&tcaphash_ansi_key, p_tcaphash_context);

#ifdef DEBUG_TCAPSRT
    dbg(11,"Update key %lx ",tcaphash_ansi_key.hashKey);
    dbg(11,"Frame reqlink #%u ", pinfo->num);
#endif
    update_tcaphash_ansicall(p_tcaphash_ansicall, pinfo);
  }

  /* display tcap session, if available */
  if ( gtcap_DisplaySRT && tree &&
       p_tcaphash_context &&
       p_tcaphash_context->session_id) {
    stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
    PROTO_ITEM_SET_GENERATED(stat_item);
    pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
    PROTO_ITEM_SET_GENERATED(pi);
  }


  /* add link to response frame, if available */
  if( gtcap_DisplaySRT && stat_tree &&
      p_tcaphash_ansicall->context->last_frame != 0){
    if (!isResponse) { /* Request */
#ifdef DEBUG_TCAPSRT
      dbg(20,"Display_frameRsplink %d ",p_tcaphash_ansicall->context->last_frame);
#endif
      pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_BeginSession, tvb, 0, 0,
                                      p_tcaphash_ansicall->context->last_frame,
                                      "End of session in frame %u",
                                      p_tcaphash_ansicall->context->last_frame);
      PROTO_ITEM_SET_GENERATED(pi);
    } else { /* Response */
#ifdef DEBUG_TCAPSRT
      dbg(20,"Display framereqlink %d ",p_tcaphash_context->first_frame);
#endif
      /* Indicate the frame to which this is a reply. */
      if (gtcap_DisplaySRT) {
        pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_EndSession, tvb, 0, 0,
                                        p_tcaphash_context->first_frame,
                                        "Begin of session in frame %u",
                                        p_tcaphash_context->first_frame);
        PROTO_ITEM_SET_GENERATED(pi);
        /* Calculate Service Response Time */
        nstime_delta(&delta, &pinfo->abs_ts, &p_tcaphash_context->begin_time);

        /* display Service Response Time and make it filterable */
        pi = proto_tree_add_time(stat_tree, hf_tcapsrt_SessionTime, tvb, 0, 0, &delta);
        PROTO_ITEM_SET_GENERATED(pi);
      }
    } /* Request or Response */
  }
  return p_tcaphash_context;
}

/*
 * Service Response Time analyze
 * Called just after dissector call
 * Associate a TCAP context to a tcap session and display session related infomations
 * like the first frame, the last, the session duration,
 * and a uniq session identifier for the filtering
 *
 * For ETSI tcap, the TCAP context can be reached through three keys
 * - a key (BEGIN) identifying the session according to the tcap source identifier
 * - a key (CONT) identifying the established session (src_id and dst_id)
 * - a key (END) identifying the session according to the tcap destination identifier
 *
 * For ANSI tcap, the TCAP context is reached through a uniq key
 * - a key (ANSI) identifying the session according to the tcap identifier
*/
struct tcaphash_context_t *
tcapsrt_call_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      struct tcapsrt_info_t *p_tcapsrt_info)
{
  struct tcaphash_context_t *tcap_context=NULL;

  /* if this packet isn't loaded because of a read filter, don't output anything */
  if(pinfo == NULL || pinfo->num == 0) {
    return NULL;
  }

  switch (p_tcapsrt_info->ope) {

  case TC_BEGIN:
#ifdef DEBUG_TCAPSRT
    dbg(1,"\nTC_BEGIN ");
#endif
    tcap_context=tcaphash_begin_matching(tvb, pinfo, tree, p_tcapsrt_info);
    break;

  case TC_CONT:
#ifdef DEBUG_TCAPSRT
    dbg(1,"\nTC_CONT ");
#endif
    tcap_context=tcaphash_cont_matching(tvb, pinfo, tree, p_tcapsrt_info);
    break;

  case TC_ABORT:
#ifdef DEBUG_TCAPSRT
    dbg(1,"\nTC_ABORT ");
#endif
    tcap_context=tcaphash_end_matching(tvb, pinfo, tree, p_tcapsrt_info);
    break;

  case TC_END:
#ifdef DEBUG_TCAPSRT
    dbg(1,"\nTC_END ");
#endif
    tcap_context=tcaphash_end_matching(tvb, pinfo, tree, p_tcapsrt_info);
    break;

  case TC_ANSI_ALL:
  case TC_ANSI_ABORT:
#ifdef DEBUG_TCAPSRT
    dbg(1,"\nTC_ANSI ");
#endif
    tcap_context=tcaphash_ansi_matching(tvb, pinfo, tree, p_tcapsrt_info);
    break;

  default:
#ifdef DEBUG_TCAPSRT
    dbg(1,"\nUnknown %d ", p_tcapsrt_info->ope);
#endif
    break;
  } /* switch tcapop */
#ifdef DEBUG_TCAPSRT
  if (tcap_context)
    dbg(1,"session %d ", tcap_context->session_id);
#endif
  return tcap_context;
}

/*
 * Initialize the Message Info used by the main dissector
 * Data are linked to a TCAP transaction
 */
struct tcapsrt_info_t *
tcapsrt_razinfo(void)
{
  struct tcapsrt_info_t *p_tcapsrt_info ;

  /* Global buffer for packet extraction */
  tcapsrt_global_current++;
  if(tcapsrt_global_current==MAX_TCAP_INSTANCE){
    tcapsrt_global_current=0;
  }

  p_tcapsrt_info=&tcapsrt_global_info[tcapsrt_global_current];
  memset(p_tcapsrt_info,0,sizeof(struct tcapsrt_info_t));

  return p_tcapsrt_info;
}

void
tcapsrt_close(struct tcaphash_context_t *p_tcaphash_context,
              packet_info *pinfo)
{
#ifdef DEBUG_TCAPSRT
  dbg(60,"Force close ");
#endif
  if (p_tcaphash_context) {
    p_tcaphash_context->responded=TRUE;
    p_tcaphash_context->last_frame = pinfo->num;
    p_tcaphash_context->end_time = pinfo->abs_ts;
    p_tcaphash_context->closed=TRUE;

    /* If the endkey is present */
    if (p_tcaphash_context->endcall
        && !gtcap_PersistentSRT) {
      if (p_tcaphash_context->endcall->next_endcall) {
        if (p_tcaphash_context->endcall->previous_endcall ) {
#ifdef DEBUG_TCAPSRT
          dbg(20,"deplace Ehash ");
#endif
          p_tcaphash_context->endcall->previous_endcall->next_endcall
            = p_tcaphash_context->endcall->next_endcall;
          p_tcaphash_context->endcall->next_endcall->previous_endcall
            = p_tcaphash_context->endcall->previous_endcall;
          g_hash_table_remove(tcaphash_end, p_tcaphash_context->endcall->endkey);
        } else {
          /* cannot remove the father */
#ifdef DEBUG_TCAPSRT
          dbg(20,"father Ehash ");
#endif
        } /* no previous link, so father */
      } else if (!gtcap_PersistentSRT) {
#ifdef DEBUG_TCAPSRT
        dbg(20,"remove Ehash ");
#endif
        g_hash_table_remove(tcaphash_end, p_tcaphash_context->endcall->endkey);

      } /* endcall without chained string */
    } /* no endcall */


    /* If the contkey is present */
    if (p_tcaphash_context->contcall
        && !gtcap_PersistentSRT) {
      if (p_tcaphash_context->contcall->next_contcall) {
        if (p_tcaphash_context->contcall->previous_contcall ) {
#ifdef DEBUG_TCAPSRT
          dbg(20,"deplace Chash ");
#endif
          p_tcaphash_context->contcall->previous_contcall->next_contcall
            = p_tcaphash_context->contcall->next_contcall;
          p_tcaphash_context->contcall->next_contcall->previous_contcall
            = p_tcaphash_context->contcall->previous_contcall;
          g_hash_table_remove(tcaphash_cont, p_tcaphash_context->contcall->contkey);
        } else {
          /* cannot remove the father */
#ifdef DEBUG_TCAPSRT
          dbg(20,"father Chash ");
#endif
        } /* no previous link, so father */
      } else if (!gtcap_PersistentSRT) {
#ifdef DEBUG_TCAPSRT
        dbg(20,"remove Chash ");
#endif
        g_hash_table_remove(tcaphash_cont, p_tcaphash_context->contcall->contkey);
      } /* contcall without chained string */
    } /* no contcall */


    /* If the beginkey is present */
    if (p_tcaphash_context->begincall
        && !gtcap_PersistentSRT) {
      if (p_tcaphash_context->begincall->next_begincall) {
        if (p_tcaphash_context->begincall->previous_begincall ) {
#ifdef DEBUG_TCAPSRT
          dbg(20,"deplace Bhash ");
#endif
          p_tcaphash_context->begincall->previous_begincall->next_begincall
            = p_tcaphash_context->begincall->next_begincall;
          p_tcaphash_context->begincall->next_begincall->previous_begincall
            = p_tcaphash_context->begincall->previous_begincall;
          g_hash_table_remove(tcaphash_begin, p_tcaphash_context->begincall->beginkey);
        } else {
          /* cannot remove the father */
#ifdef DEBUG_TCAPSRT
          dbg(20,"father Bhash ");
#endif
        }
      } else  if (!gtcap_PersistentSRT) {
#ifdef DEBUG_TCAPSRT
        dbg(20,"remove Bhash ");
#endif
        g_hash_table_remove(tcaphash_begin, p_tcaphash_context->begincall->beginkey);
      } /* begincall without chained string */
    } /* no begincall */

    /* If the ansikey is present */
    if (p_tcaphash_context->ansicall
        && !gtcap_PersistentSRT) {
      if (p_tcaphash_context->ansicall->next_ansicall) {
        if (p_tcaphash_context->ansicall->previous_ansicall ) {
#ifdef DEBUG_TCAPSRT
          dbg(20,"deplace Ahash ");
#endif
          p_tcaphash_context->ansicall->previous_ansicall->next_ansicall
            = p_tcaphash_context->ansicall->next_ansicall;
          p_tcaphash_context->ansicall->next_ansicall->previous_ansicall
            = p_tcaphash_context->ansicall->previous_ansicall;
          g_hash_table_remove(tcaphash_ansi, p_tcaphash_context->ansicall->ansikey);
        } else {
          /* cannot remove the father */
#ifdef DEBUG_TCAPSRT
          dbg(20,"father Ahash ");
#endif
        }
      } else  if (!gtcap_PersistentSRT) {
#ifdef DEBUG_TCAPSRT
        dbg(20,"remove Ahash ");
#endif
        g_hash_table_remove(tcaphash_ansi, p_tcaphash_context->ansicall->ansikey);
      } /* ansicall without chained string */
    } /* no ansicall */

    if (!gtcap_PersistentSRT) {
#ifdef DEBUG_TCAPSRT
      dbg(20,"remove context ");
#endif
      g_hash_table_remove(tcaphash_context, p_tcaphash_context->key);
    }
  } else { /* no context */
#ifdef DEBUG_TCAPSRT
    dbg(20,"No context to remove ");
#endif
  }
}

const value_string tcap_component_type_str[] = {
  { TCAP_COMP_INVOKE, "Invoke" },
  { TCAP_COMP_RRL,    "Return Result(L)" },
  { TCAP_COMP_RE,     "Return Error" },
  { TCAP_COMP_REJECT, "Reject" },
  { TCAP_COMP_RRN,    "Return Result(NL)" },
  { 0,                NULL }
};

static int
dissect_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
  proto_item *item=NULL;
  proto_tree *tree=NULL;

  struct tcaphash_context_t * p_tcap_context;
  dissector_handle_t subdissector_handle;
  asn1_ctx_t asn1_ctx;
  gint8 ber_class;
  gboolean pc;
  gint tag;

  /* Check if ANSI TCAP and call the ANSI TCAP dissector if that's the case
   * PackageType ::= CHOICE { unidirectional            [PRIVATE 1] IMPLICIT UniTransactionPDU,
   *                          queryWithPerm             [PRIVATE 2] IMPLICIT TransactionPDU,
   *                          queryWithoutPerm          [PRIVATE 3] IMPLICIT TransactionPDU,
   *                          response                  [PRIVATE 4] IMPLICIT TransactionPDU,
   *                          conversationWithPerm      [PRIVATE 5] IMPLICIT TransactionPDU,
   *                          conversationWithoutPerm   [PRIVATE 6] IMPLICIT TransactionPDU,
   *                          abort                     [PRIVATE 22] IMPLICIT Abort
   *                          }
   *
   *
   */
  get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);

  if(ber_class == BER_CLASS_PRI){
    switch (tag){

    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 22:
      return call_dissector(ansi_tcap_handle, tvb, pinfo, parent_tree);

    default:
      return tvb_captured_length(tvb);
    }
  }

  /* ITU TCAP */
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  tcap_top_tree = parent_tree;
  tcap_stat_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCAP");

  /* create display subtree for the protocol */
  if(parent_tree){
    item = proto_tree_add_item(parent_tree, proto_tcap, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_tcap);
    tcap_stat_tree=tree;
  }
  cur_oid = NULL;
  tcapext_oid = NULL;
  raz_tcap_private(&tcap_private);

  asn1_ctx.value_ptr = &tcap_private;
  gp_tcapsrt_info=tcapsrt_razinfo();
  tcap_subdissector_used=FALSE;
  gp_tcap_context=NULL;
  dissect_tcap_TCMessage(FALSE, tvb, 0, &asn1_ctx, tree, -1);

  if (gtcap_HandleSRT && !tcap_subdissector_used ) {
    p_tcap_context=tcapsrt_call_matching(tvb, pinfo, tcap_stat_tree, gp_tcapsrt_info);
    tcap_private.context=p_tcap_context;

    /* If the current message is TCAP only,
     * save the Application Context Name for the next messages
     */
    if ( p_tcap_context && cur_oid && !p_tcap_context->oid_present ) {
      /* Save the application context and the sub dissector */
      g_strlcpy(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid));
      p_tcap_context->oid_present=TRUE;
      if ( (subdissector_handle = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
        p_tcap_context->subdissector_handle=subdissector_handle;
        p_tcap_context->subdissector_present=TRUE;
      }
    }
    if (gtcap_HandleSRT && p_tcap_context && p_tcap_context->callback) {
      /* Callback fonction for the upper layer */
      (p_tcap_context->callback)(tvb, pinfo, tcap_stat_tree, p_tcap_context);
    }
  }
  return tvb_captured_length(tvb);
}

void
proto_reg_handoff_tcap(void)
{

  data_handle = find_dissector("data");
  ansi_tcap_handle = find_dissector_add_dependency("ansi_tcap", proto_tcap);
  ber_oid_dissector_table = find_dissector_table("ber.oid");

  ss7pc_address_type = address_type_get_by_name("AT_SS7PC");


/*--- Included file: packet-tcap-dis-tab.c ---*/
#line 1 "./asn1/tcap/packet-tcap-dis-tab.c"
  register_ber_oid_dissector("0.0.17.773.1.1.1", dissect_DialoguePDU_PDU, proto_tcap, "id-as-dialogue");
  register_ber_oid_dissector("0.0.17.773.1.2.1", dissect_UniDialoguePDU_PDU, proto_tcap, "id-as-uniDialogue");


/*--- End of included file: packet-tcap-dis-tab.c ---*/
#line 1982 "./asn1/tcap/packet-tcap-template.c"
}

static void init_tcap(void);
static void cleanup_tcap(void);

void
proto_register_tcap(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_tcap_tag,
      { "Tag",
        "tcap.msgtype",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_tcap_length,
      { "Length",
        "tcap.len",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_tcap_data,
      { "Data",
        "tcap.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_tcap_tid,
      { "Transaction Id",
         "tcap.tid",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_tcap_constructor_eoc,
      { "CONSTRUCTOR EOC",
         "tcap.constructor_eoc",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    /* Tcap Service Response Time */
    { &hf_tcapsrt_SessionId,
      { "Session Id",
        "tcap.srt.session_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_tcapsrt_BeginSession,
      { "Begin Session",
        "tcap.srt.begin",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "SRT Begin of Session", HFILL }
    },
    { &hf_tcapsrt_EndSession,
      { "End Session",
        "tcap.srt.end",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "SRT End of Session", HFILL }
    },
    { &hf_tcapsrt_SessionTime,
      { "Session duration",
        "tcap.srt.sessiontime",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "Duration of the TCAP session", HFILL }
    },
    { &hf_tcapsrt_Duplicate,
      { "Session Duplicate",
        "tcap.srt.duplicate",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "SRT Duplicated with Session", HFILL }
    },

/*--- Included file: packet-tcap-hfarr.c ---*/
#line 1 "./asn1/tcap/packet-tcap-hfarr.c"
    { &hf_tcap_UniDialoguePDU_PDU,
      { "UniDialoguePDU", "tcap.UniDialoguePDU",
        FT_UINT32, BASE_DEC, VALS(tcap_UniDialoguePDU_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_DialoguePDU_PDU,
      { "DialoguePDU", "tcap.DialoguePDU",
        FT_UINT32, BASE_DEC, VALS(tcap_DialoguePDU_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_oid,
      { "oid", "tcap.oid",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_tcap_dialog,
      { "dialog", "tcap.dialog",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Dialog1", HFILL }},
    { &hf_tcap_unidirectional,
      { "unidirectional", "tcap.unidirectional_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcap_begin,
      { "begin", "tcap.begin_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcap_end,
      { "end", "tcap.end_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcap_continue,
      { "continue", "tcap.continue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcap_abort,
      { "abort", "tcap.abort_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcap_dialoguePortion,
      { "dialoguePortion", "tcap.dialoguePortion",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcap_components,
      { "components", "tcap.components",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ComponentPortion", HFILL }},
    { &hf_tcap_otid,
      { "otid", "tcap.otid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OrigTransactionID", HFILL }},
    { &hf_tcap_dtid,
      { "dtid", "tcap.dtid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DestTransactionID", HFILL }},
    { &hf_tcap_reason,
      { "reason", "tcap.reason",
        FT_UINT32, BASE_DEC, VALS(tcap_Reason_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_p_abortCause,
      { "p-abortCause", "tcap.p_abortCause",
        FT_UINT32, BASE_DEC, VALS(tcap_P_AbortCause_U_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_u_abortCause,
      { "u-abortCause", "tcap.u_abortCause",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DialoguePortion", HFILL }},
    { &hf_tcap__untag_item,
      { "Component", "tcap.Component",
        FT_UINT32, BASE_DEC, VALS(tcap_Component_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_invoke,
      { "invoke", "tcap.invoke_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcap_returnResultLast,
      { "returnResultLast", "tcap.returnResultLast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnResult", HFILL }},
    { &hf_tcap_returnError,
      { "returnError", "tcap.returnError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcap_reject,
      { "reject", "tcap.reject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcap_returnResultNotLast,
      { "returnResultNotLast", "tcap.returnResultNotLast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnResult", HFILL }},
    { &hf_tcap_invokeID,
      { "invokeID", "tcap.invokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeIdType", HFILL }},
    { &hf_tcap_linkedID,
      { "linkedID", "tcap.linkedID",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeIdType", HFILL }},
    { &hf_tcap_opCode,
      { "opCode", "tcap.opCode",
        FT_UINT32, BASE_DEC, VALS(tcap_OPERATION_vals), 0,
        "OPERATION", HFILL }},
    { &hf_tcap_parameter,
      { "parameter", "tcap.parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcap_resultretres,
      { "resultretres", "tcap.resultretres_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcap_errorCode,
      { "errorCode", "tcap.errorCode",
        FT_UINT32, BASE_DEC, VALS(tcap_ErrorCode_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_invokeIDRej,
      { "invokeIDRej", "tcap.invokeIDRej",
        FT_UINT32, BASE_DEC, VALS(tcap_T_invokeIDRej_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_derivable,
      { "derivable", "tcap.derivable",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeIdType", HFILL }},
    { &hf_tcap_not_derivable,
      { "not-derivable", "tcap.not_derivable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcap_problem,
      { "problem", "tcap.problem",
        FT_UINT32, BASE_DEC, VALS(tcap_T_problem_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_generalProblem,
      { "generalProblem", "tcap.generalProblem",
        FT_INT32, BASE_DEC, VALS(tcap_GeneralProblem_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_invokeProblem,
      { "invokeProblem", "tcap.invokeProblem",
        FT_INT32, BASE_DEC, VALS(tcap_InvokeProblem_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_returnResultProblem,
      { "returnResultProblem", "tcap.returnResultProblem",
        FT_INT32, BASE_DEC, VALS(tcap_ReturnResultProblem_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_returnErrorProblem,
      { "returnErrorProblem", "tcap.returnErrorProblem",
        FT_INT32, BASE_DEC, VALS(tcap_ReturnErrorProblem_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_localValue,
      { "localValue", "tcap.localValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_tcap_globalValue,
      { "globalValue", "tcap.globalValue",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_tcap_nationaler,
      { "nationaler", "tcap.nationaler",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_tcap_privateer,
      { "privateer", "tcap.privateer",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_tcap_unidialoguePDU,
      { "unidialoguePDU", "tcap.unidialoguePDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AUDT_apdu", HFILL }},
    { &hf_tcap_audt_protocol_version,
      { "protocol-version", "tcap.protocol_version",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AUDT_protocol_version", HFILL }},
    { &hf_tcap_audt_application_context_name,
      { "application-context-name", "tcap.application_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        "AUDT_application_context_name", HFILL }},
    { &hf_tcap_audt_user_information,
      { "user-information", "tcap.user_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AUDT_user_information", HFILL }},
    { &hf_tcap_audt_user_information_item,
      { "user-information item", "tcap.user_information_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_tcap_dialogueRequest,
      { "dialogueRequest", "tcap.dialogueRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AARQ_apdu", HFILL }},
    { &hf_tcap_dialogueResponse,
      { "dialogueResponse", "tcap.dialogueResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AARE_apdu", HFILL }},
    { &hf_tcap_dialogueAbort,
      { "dialogueAbort", "tcap.dialogueAbort_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ABRT_apdu", HFILL }},
    { &hf_tcap_aarq_protocol_version,
      { "protocol-version", "tcap.protocol_version",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AARQ_protocol_version", HFILL }},
    { &hf_tcap_aarq_application_context_name,
      { "application-context-name", "tcap.application_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        "AARQ_application_context_name", HFILL }},
    { &hf_tcap_aarq_user_information,
      { "user-information", "tcap.user_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AARQ_user_information", HFILL }},
    { &hf_tcap_aarq_user_information_item,
      { "user-information item", "tcap.user_information_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_tcap_aare_protocol_version,
      { "protocol-version", "tcap.protocol_version",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AARE_protocol_version", HFILL }},
    { &hf_tcap_aare_application_context_name,
      { "application-context-name", "tcap.application_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        "AARE_application_context_name", HFILL }},
    { &hf_tcap_result,
      { "result", "tcap.result",
        FT_INT32, BASE_DEC, VALS(tcap_Associate_result_vals), 0,
        "Associate_result", HFILL }},
    { &hf_tcap_result_source_diagnostic,
      { "result-source-diagnostic", "tcap.result_source_diagnostic",
        FT_UINT32, BASE_DEC, VALS(tcap_Associate_source_diagnostic_vals), 0,
        "Associate_source_diagnostic", HFILL }},
    { &hf_tcap_aare_user_information,
      { "user-information", "tcap.user_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AARE_user_information", HFILL }},
    { &hf_tcap_aare_user_information_item,
      { "user-information item", "tcap.user_information_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_tcap_abort_source,
      { "abort-source", "tcap.abort_source",
        FT_INT32, BASE_DEC, VALS(tcap_ABRT_source_vals), 0,
        "ABRT_source", HFILL }},
    { &hf_tcap_abrt_user_information,
      { "user-information", "tcap.user_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ABRT_user_information", HFILL }},
    { &hf_tcap_abrt_user_information_item,
      { "user-information item", "tcap.user_information_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_tcap_dialogue_service_user,
      { "dialogue-service-user", "tcap.dialogue_service_user",
        FT_INT32, BASE_DEC, VALS(tcap_T_dialogue_service_user_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_dialogue_service_provider,
      { "dialogue-service-provider", "tcap.dialogue_service_provider",
        FT_INT32, BASE_DEC, VALS(tcap_T_dialogue_service_provider_vals), 0,
        NULL, HFILL }},
    { &hf_tcap_AUDT_protocol_version_version1,
      { "version1", "tcap.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_tcap_AARQ_protocol_version_version1,
      { "version1", "tcap.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_tcap_AARE_protocol_version_version1,
      { "version1", "tcap.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

/*--- End of included file: packet-tcap-hfarr.c ---*/
#line 2055 "./asn1/tcap/packet-tcap-template.c"
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_tcap,
    &ett_param,
    &ett_otid,
    &ett_dtid,
    &ett_tcap_stat,

/*--- Included file: packet-tcap-ettarr.c ---*/
#line 1 "./asn1/tcap/packet-tcap-ettarr.c"
    &ett_tcap_ExternalPDU_U,
    &ett_tcap_TCMessage,
    &ett_tcap_Unidirectional,
    &ett_tcap_Begin,
    &ett_tcap_End,
    &ett_tcap_Continue,
    &ett_tcap_Abort,
    &ett_tcap_Reason,
    &ett_tcap_SEQUENCE_SIZE_1_MAX_OF_Component,
    &ett_tcap_Component,
    &ett_tcap_Invoke,
    &ett_tcap_ReturnResult,
    &ett_tcap_T_resultretres,
    &ett_tcap_ReturnError,
    &ett_tcap_Reject,
    &ett_tcap_T_invokeIDRej,
    &ett_tcap_T_problem,
    &ett_tcap_OPERATION,
    &ett_tcap_ErrorCode,
    &ett_tcap_UniDialoguePDU,
    &ett_tcap_AUDT_apdu_U,
    &ett_tcap_AUDT_protocol_version,
    &ett_tcap_AUDT_user_information,
    &ett_tcap_DialoguePDU,
    &ett_tcap_AARQ_apdu_U,
    &ett_tcap_AARQ_protocol_version,
    &ett_tcap_AARQ_user_information,
    &ett_tcap_AARE_apdu_U,
    &ett_tcap_AARE_protocol_version,
    &ett_tcap_AARE_user_information,
    &ett_tcap_ABRT_apdu_U,
    &ett_tcap_ABRT_user_information,
    &ett_tcap_Associate_source_diagnostic,

/*--- End of included file: packet-tcap-ettarr.c ---*/
#line 2065 "./asn1/tcap/packet-tcap-template.c"
  };

  /*static enum_val_t tcap_options[] = {
    { "itu", "ITU",  ITU_TCAP_STANDARD },
    { "ansi", "ANSI", ANSI_TCAP_STANDARD },
    { NULL, NULL, 0 }
  };*/

  module_t *tcap_module;

/* Register the protocol name and description */
  proto_tcap = proto_register_protocol(PNAME, PSNAME, PFNAME);

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_tcap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  tcap_module = prefs_register_protocol(proto_tcap, NULL);

#if 0
  prefs_register_enum_preference(tcap_module, "standard", "ITU TCAP standard",
                                 "The SS7 standard used in ITU TCAP packets",
                                 &tcap_standard, tcap_options, FALSE);
#else
  prefs_register_obsolete_preference(tcap_module, "standard");
#endif

#if 0
  prefs_register_bool_preference(tcap_module, "lock_info_col", "Lock Info column",
                                 "Always show TCAP in Info column",
                                 &lock_info_col);
#else
  prefs_register_obsolete_preference(tcap_module, "lock_info_col");
#endif

  /* Set default SSNs */
  range_convert_str(&global_ssn_range, "", MAX_SSN);

  prefs_register_range_preference(tcap_module, "ssn", "SCCP SSNs",
                                  "SCCP (and SUA) SSNs to decode as TCAP",
                                  &global_ssn_range, MAX_SSN);

  prefs_register_bool_preference(tcap_module, "srt",
                                 "Service Response Time Analyse",
                                 "Activate the analyse for Response Time",
                                 &gtcap_HandleSRT);

  prefs_register_bool_preference(tcap_module, "persistentsrt",
                                 "Persistent stats for SRT",
                                 "Statistics for Response Time",
                                 &gtcap_PersistentSRT);

  prefs_register_uint_preference(tcap_module, "repetitiontimeout",
                                 "Repetition timeout",
                                 "Maximal delay for message repetion",
                                 10, &gtcap_RepetitionTimeout);

  prefs_register_uint_preference(tcap_module, "losttimeout",
                                 "lost timeout",
                                 "Maximal delay for message lost",
                                 10, &gtcap_LostTimeout);

  ansi_sub_dissectors = g_hash_table_new(g_direct_hash,g_direct_equal);
  itu_sub_dissectors = g_hash_table_new(g_direct_hash,g_direct_equal);

  /* 'globally' register dissector */
  register_dissector("tcap", dissect_tcap, proto_tcap);

  tcap_handle = create_dissector_handle(dissect_tcap, proto_tcap);

  register_init_routine(&init_tcap);
  register_cleanup_routine(&cleanup_tcap);
}


static void range_delete_callback(guint32 ssn)
{
  if ( ssn && !get_ansi_tcap_subdissector(ssn) && !get_itu_tcap_subdissector(ssn) ) {
    dissector_delete_uint("sccp.ssn", ssn, tcap_handle);
  }
}

static void range_add_callback(guint32 ssn)
{
  if (ssn && !get_ansi_tcap_subdissector(ssn) && !get_itu_tcap_subdissector(ssn) ) {
    dissector_add_uint("sccp.ssn", ssn, tcap_handle);
  }
}


static void init_tcap(void)
{
  ssn_range = range_copy(global_ssn_range);
  range_foreach(ssn_range, range_add_callback);
  tcapsrt_init_routine();
}

static void cleanup_tcap(void)
{
  range_foreach(ssn_range, range_delete_callback);
  g_free(ssn_range);
}

static int
dissect_tcap_param(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset)
{
  gint tag_offset, saved_offset, len_offset;
  tvbuff_t *next_tvb;
  proto_tree *subtree;
  gint8 ber_class;
  gboolean pc;
  gint32 tag;
  guint32 len;
  guint32 tag_length;
  guint32 len_length;
  gboolean ind_field;

  while (tvb_reported_length_remaining(tvb, offset) > 0)
  {
    saved_offset = offset;

    offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
    tag_offset = offset;
    offset = get_ber_length(tvb, offset, &len, &ind_field);
    len_offset = offset;

    tag_length = tag_offset - saved_offset;
    len_length = len_offset - tag_offset;

    if (pc)
    {
      subtree = proto_tree_add_subtree(tree, tvb, saved_offset,
        len + (len_offset - saved_offset), ett_param, NULL,
        "CONSTRUCTOR");
      proto_tree_add_uint_format(subtree, hf_tcap_tag, tvb,
        saved_offset, tag_length, tag,
        "CONSTRUCTOR Tag");
      proto_tree_add_uint(subtree, hf_tcap_tag, tvb, saved_offset,
        tag_length, ber_class);

      proto_tree_add_uint(subtree, hf_tcap_length, tvb, tag_offset,
        len_length, len);

      if (len-(2*ind_field)) /*should always be positive unless we get an empty contructor pointless? */
      {
        next_tvb = tvb_new_subset_length(tvb, offset, len-(2*ind_field));
        dissect_tcap_param(actx, subtree,next_tvb,0);
      }

      if (ind_field)
        proto_tree_add_item(subtree, hf_tcap_constructor_eoc, tvb, offset+len-2, 2, ENC_BIG_ENDIAN);

      offset += len;
    }
    else
    {
      subtree = proto_tree_add_subtree_format(tree, tvb, saved_offset,
        len + (len_offset - saved_offset), ett_param, NULL,
        "Parameter (0x%.2x)", tag);

      proto_tree_add_uint(subtree, hf_tcap_tag, tvb, saved_offset,
        tag_length, tag);

      proto_tree_add_uint(subtree, hf_tcap_length, tvb,
        saved_offset+tag_length, len_length, len);

      if (len) /* check for NULLS */
      {
        next_tvb = tvb_new_subset_length(tvb, offset, len);
        dissect_ber_octet_string(TRUE, actx, tree, next_tvb, 0,
          hf_tcap_data, NULL);
      }

      offset += len;
    }
  }
  return offset;
}

static void raz_tcap_private(struct tcap_private_t * p_tcap_private)
{
  memset(p_tcap_private,0,sizeof(struct tcap_private_t) );
}

/*
 * Call ITU Subdissector to decode the Tcap Component
 */
static int
dissect_tcap_ITU_ComponentPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_)
{
  dissector_handle_t subdissector_handle=NULL;
  gboolean is_subdissector=FALSE;
  struct tcaphash_context_t * p_tcap_context=NULL;

  /*
   * ok lets look at the oid and ssn and try and find a dissector, otherwise lets decode it.
   */

  /*
   * Handle The TCAP Service Response Time
   */
  if ( gtcap_HandleSRT ) {
    if (!tcap_subdissector_used) {
      p_tcap_context=tcapsrt_call_matching(tvb, actx->pinfo, tcap_stat_tree, gp_tcapsrt_info);
      tcap_subdissector_used=TRUE;
      gp_tcap_context=p_tcap_context;
      tcap_private.context=p_tcap_context;
    } else {
      /* Take the last TCAP context */
      p_tcap_context = gp_tcap_context;
      tcap_private.context=p_tcap_context;
    }
  }
  if (p_tcap_context) {
    if (cur_oid) {
      if (p_tcap_context->oid_present) {
        /* We have already an Application Context, check if we have
           to fallback to a lower version */
        if ( strncmp(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid))!=0) {
          /* ACN, changed, Fallback to lower version
           * and update the subdissector (purely formal)
           */
          g_strlcpy(p_tcap_context->oid,cur_oid, sizeof(p_tcap_context->oid));
          if ( (subdissector_handle = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
            p_tcap_context->subdissector_handle=subdissector_handle;
            p_tcap_context->subdissector_present=TRUE;
          }
        }
      } else {
        /* We do not have the OID in the TCAP context, so store it */
        g_strlcpy(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid));
        p_tcap_context->oid_present=TRUE;
        /* Try to find a subdissector according to OID */
        if ( (subdissector_handle
          = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
          p_tcap_context->subdissector_handle=subdissector_handle;
          p_tcap_context->subdissector_present=TRUE;
        } else {
          /* Not found, so try to find a subdissector according to SSN */
          if ( (subdissector_handle = get_itu_tcap_subdissector(actx->pinfo->match_uint))) {
            /* Found according to SSN */
            p_tcap_context->subdissector_handle=subdissector_handle;
            p_tcap_context->subdissector_present=TRUE;
          }
        }
      } /* context OID */
    } else {
      /* Copy the OID from the TCAP context to the current oid */
      if (p_tcap_context->oid_present) {
        tcap_private.oid= (void*) p_tcap_context->oid;
        tcap_private.acv=TRUE;
      }
    } /* no OID */
  } /* no TCAP context */


  if ( p_tcap_context
       && p_tcap_context->subdissector_present) {
    /* Take the subdissector from the context */
    subdissector_handle=p_tcap_context->subdissector_handle;
    is_subdissector=TRUE;
  }

  /* Have SccpUsersTable protocol taking precedence over sccp.ssn table */
  if (!is_subdissector && requested_subdissector_handle) {
    is_subdissector = TRUE;
    subdissector_handle = requested_subdissector_handle;
  }

  if (!is_subdissector) {
    /*
     * If we do not currently know the subdissector, we have to find it
     * - first, according to the OID
     * - then according to the SSN
     * - and at least, take the default Data handler
     */
    if (ber_oid_dissector_table && cur_oid) {
      /* Search if we can find the sub protocol according to the A.C.N */
      if ( (subdissector_handle
        = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
        /* found */
        is_subdissector=TRUE;
      } else {
        /* Search if we can found the sub protocol according to the SSN table */
        if ( (subdissector_handle
          = get_itu_tcap_subdissector(actx->pinfo->match_uint))) {
          /* Found according to SSN */
          is_subdissector=TRUE;
        } else {
          /* Nothing found, take the Data handler */
          subdissector_handle = data_handle;
          is_subdissector=TRUE;
        } /* SSN */
      } /* ACN */
    } else {
      /* There is no A.C.N for this transaction, so search in the SSN table */
      if ( (subdissector_handle = get_itu_tcap_subdissector(actx->pinfo->match_uint))) {
        /* Found according to SSN */
        is_subdissector=TRUE;
      } else {
        subdissector_handle = data_handle;
        is_subdissector=TRUE;
      }
    } /* OID */
  } else {
    /* We have it already */
  }

  /* Call the sub dissector if present, and not already called */
  if (is_subdissector) {
    call_dissector_with_data(subdissector_handle, tvb, actx->pinfo, tree, actx->value_ptr);
    col_set_fence(actx->pinfo->cinfo, COL_INFO);
  }

  return offset;
}

void
call_tcap_dissector(dissector_handle_t handle, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
  requested_subdissector_handle = handle;

  TRY {
    dissect_tcap(tvb, pinfo, tree, NULL);
  } CATCH_ALL {
    requested_subdissector_handle = NULL;
    RETHROW;
  } ENDTRY;

  requested_subdissector_handle = NULL;
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
