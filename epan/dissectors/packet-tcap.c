/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-tcap.c                                                              */
/* ../../tools/asn2wrs.py -b -p tcap -c tcap.cnf -s packet-tcap-template tcap.asn UnidialoguePDUs.asn */

/* Input file: packet-tcap-template.c */

#line 1 "packet-tcap-template.c"
/* packet-tcap-template.c
 * Routines for  TCAP
 * Copyright 2004 - 2005, Tim Endean <endeant@hotmail.com>
 * Built from the gsm-map dissector Copyright 2004 - 2005, Anders Broman <anders.broman@ericsson.com>
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
 * References: ETSI 300 374
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/oids.h>
#include <epan/emem.h>
#include <epan/asn1.h>
#include <epan/strutil.h>

#include <stdio.h>
#include <string.h>
#include "packet-ber.h"
#include "packet-tcap.h"
#include "epan/tcap-persistentdata.h"

#define PNAME  "Transaction Capabilities Application Part"
#define PSNAME "TCAP"
#define PFNAME "tcap"

/* Initialize the protocol and registered fields */
int proto_tcap = -1;
static int hf_tcap_tag = -1;
static int hf_tcap_length = -1;
static int hf_tcap_data = -1;
static int hf_tcap_tid = -1;

int hf_tcapsrt_SessionId=-1;
int hf_tcapsrt_Duplicate=-1;
int hf_tcapsrt_BeginSession=-1;
int hf_tcapsrt_EndSession=-1;
int hf_tcapsrt_SessionTime=-1;


/*--- Included file: packet-tcap-hf.c ---*/
#line 1 "packet-tcap-hf.c"
static int hf_tcap_DialoguePDU_PDU = -1;          /* DialoguePDU */
static int hf_tcap_UniDialoguePDU_PDU = -1;       /* UniDialoguePDU */
static int hf_tcap_dialogueRequest = -1;          /* AARQ_apdu */
static int hf_tcap_dialogueResponse = -1;         /* AARE_apdu */
static int hf_tcap_dialogueAbort = -1;            /* ABRT_apdu */
static int hf_tcap_oid = -1;                      /* OBJECT_IDENTIFIER */
static int hf_tcap_dialog = -1;                   /* Dialog1 */
static int hf_tcap_useroid = -1;                  /* UserInfoOID */
static int hf_tcap_externuserinfo = -1;           /* ExternUserInfo */
static int hf_tcap_protocol_versionrq = -1;       /* T_protocol_versionrq */
static int hf_tcap_aarq_application_context_name = -1;  /* AARQ_application_context_name */
static int hf_tcap_aarq_user_information = -1;    /* AARQ_user_information */
static int hf_tcap_aarq_user_information_item = -1;  /* EXTERNAL */
static int hf_tcap_protocol_versionre = -1;       /* T_protocol_versionre */
static int hf_tcap_aare_application_context_name = -1;  /* AARE_application_context_name */
static int hf_tcap_result = -1;                   /* Associate_result */
static int hf_tcap_result_source_diagnostic = -1;  /* Associate_source_diagnostic */
static int hf_tcap_aare_user_information = -1;    /* AARE_user_information */
static int hf_tcap_abort_source = -1;             /* ABRT_source */
static int hf_tcap_abrt_user_information = -1;    /* ABRT_user_information */
static int hf_tcap_dialogue_service_user = -1;    /* T_dialogue_service_user */
static int hf_tcap_dialogue_service_provider = -1;  /* T_dialogue_service_provider */
static int hf_tcap_unidirectional = -1;           /* Unidirectional */
static int hf_tcap_begin = -1;                    /* Begin */
static int hf_tcap_end = -1;                      /* End */
static int hf_tcap_continue = -1;                 /* Continue */
static int hf_tcap_abort = -1;                    /* Abort */
static int hf_tcap_ansiunidirectional = -1;       /* UniTransactionPDU */
static int hf_tcap_ansiqueryWithPerm = -1;        /* T_ansiqueryWithPerm */
static int hf_tcap_ansiqueryWithoutPerm = -1;     /* T_ansiqueryWithoutPerm */
static int hf_tcap_ansiresponse = -1;             /* T_ansiresponse */
static int hf_tcap_ansiconversationWithPerm = -1;  /* T_ansiconversationWithPerm */
static int hf_tcap_ansiconversationWithoutPerm = -1;  /* T_ansiconversationWithoutPerm */
static int hf_tcap_ansiabort = -1;                /* AbortPDU */
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
static int hf_tcap_identifier = -1;               /* TransactionID */
static int hf_tcap_dialoguePortionansi = -1;      /* DialoguePortionANSI */
static int hf_tcap_componentPortion = -1;         /* ComponentSequence */
static int hf_tcap_causeInformation = -1;         /* T_causeInformation */
static int hf_tcap_abortCause = -1;               /* P_Abort_cause */
static int hf_tcap_userInformation = -1;          /* UserInformation */
static int hf_tcap_version = -1;                  /* ProtocolVersion */
static int hf_tcap_applicationContext = -1;       /* T_applicationContext */
static int hf_tcap_integerApplicationId = -1;     /* IntegerApplicationContext */
static int hf_tcap_objectApplicationId = -1;      /* ObjectIDApplicationContext */
static int hf_tcap_securityContext = -1;          /* T_securityContext */
static int hf_tcap_integerSecurityId = -1;        /* INTEGER */
static int hf_tcap_objectSecurityId = -1;         /* OBJECT_IDENTIFIER */
static int hf_tcap_confidentiality = -1;          /* Confidentiality */
static int hf_tcap_confidentialityId = -1;        /* T_confidentialityId */
static int hf_tcap_integerConfidentialityId = -1;  /* INTEGER */
static int hf_tcap_objectConfidentialityId = -1;  /* OBJECT_IDENTIFIER */
static int hf_tcap__untag_item_01 = -1;           /* ComponentPDU */
static int hf_tcap_invokeLastansi = -1;           /* InvokePDU */
static int hf_tcap_returnResultLastansi = -1;     /* ReturnResultPDU */
static int hf_tcap_returnErroransi = -1;          /* ReturnErrorPDU */
static int hf_tcap_rejectansi = -1;               /* RejectPDU */
static int hf_tcap_invokeNotLastansi = -1;        /* InvokePDU */
static int hf_tcap_returnResultNotLastansi = -1;  /* ReturnResultPDU */
static int hf_tcap_componentIDs = -1;             /* OCTET_STRING_SIZE_0_2 */
static int hf_tcap_operationCode = -1;            /* OperationCode */
static int hf_tcap_parameterinv = -1;             /* ANSIparamch */
static int hf_tcap_ansiparams = -1;               /* ANSIParameters */
static int hf_tcap_ansiparams1 = -1;              /* ANSIParameters */
static int hf_tcap_ansiparams2 = -1;              /* ANSIParameters */
static int hf_tcap_ansiparams3 = -1;              /* ANSIParameters */
static int hf_tcap_ansiparams4 = -1;              /* ANSIParameters */
static int hf_tcap_ansiparams5 = -1;              /* ANSIParameters */
static int hf_tcap_ansiparams6 = -1;              /* ANSIParameters */
static int hf_tcap_ansiparams7 = -1;              /* ANSIParameters */
static int hf_tcap_ansiparams8 = -1;              /* ANSIParameters */
static int hf_tcap_ansiparams9 = -1;              /* ANSIParameters */
static int hf_tcap_ansiparams10 = -1;             /* ANSIParameters */
static int hf_tcap_ansiparams11 = -1;             /* ANSIParameters */
static int hf_tcap_ansiparams12 = -1;             /* ANSIParameters */
static int hf_tcap_ansiparams13 = -1;             /* ANSIParameters */
static int hf_tcap_ansiparams14 = -1;             /* ANSIParameters */
static int hf_tcap_ansiparams15 = -1;             /* ANSIParameters */
static int hf_tcap_ansiparams16 = -1;             /* ANSIParameters */
static int hf_tcap_ansiparams17 = -1;             /* ANSIParameters */
static int hf_tcap_ansiparams18 = -1;             /* ANSIParameters */
static int hf_tcap_ansiparams19 = -1;             /* ANSIParameters */
static int hf_tcap_ansiparams20 = -1;             /* ANSIParameters */
static int hf_tcap_ansiparams21 = -1;             /* ANSIParameters */
static int hf_tcap_componentID = -1;              /* ComponentID */
static int hf_tcap_parameterrr = -1;              /* ANSIparamch */
static int hf_tcap_parameterre = -1;              /* ANSIparamch */
static int hf_tcap_rejectProblem = -1;            /* ProblemPDU */
static int hf_tcap_parameterrj = -1;              /* ANSIparamch */
static int hf_tcap_national = -1;                 /* INTEGER_M32768_32767 */
static int hf_tcap_private = -1;                  /* INTEGER */
static int hf_tcap_nationaler = -1;               /* INTEGER_M32768_32767 */
static int hf_tcap_privateer = -1;                /* INTEGER */
static int hf_tcap_unidialoguePDU = -1;           /* AUDT_apdu */
static int hf_tcap_protocol_version = -1;         /* T_protocol_version */
static int hf_tcap_audt_application_context_name = -1;  /* AUDT_application_context_name */
static int hf_tcap_audt_user_information = -1;    /* AUDT_user_information */
static int hf_tcap_audt_user_information_item = -1;  /* EXTERNAL */
/* named bits */
static int hf_tcap_T_protocol_versionrq_version1 = -1;
static int hf_tcap_T_protocol_versionre_version1 = -1;
static int hf_tcap_T_protocol_version_version1 = -1;

/*--- End of included file: packet-tcap-hf.c ---*/
#line 65 "packet-tcap-template.c"

/* Initialize the subtree pointers */
static gint ett_tcap = -1;
static gint ett_param = -1;

static gint ett_otid = -1;
static gint ett_dtid = -1;
gint ett_tcap_stat = -1;

static struct tcapsrt_info_t * gp_tcapsrt_info;
static gboolean tcap_subdissector_used=FALSE;
static dissector_handle_t requested_subdissector_handle = NULL;

static struct tcaphash_context_t * gp_tcap_context=NULL;


/*--- Included file: packet-tcap-ett.c ---*/
#line 1 "packet-tcap-ett.c"
static gint ett_tcap_DialoguePDU = -1;
static gint ett_tcap_ExternalPDU_U = -1;
static gint ett_tcap_UserInformation_U = -1;
static gint ett_tcap_AARQ_apdu_U = -1;
static gint ett_tcap_T_protocol_versionrq = -1;
static gint ett_tcap_AARQ_user_information = -1;
static gint ett_tcap_AARE_apdu_U = -1;
static gint ett_tcap_T_protocol_versionre = -1;
static gint ett_tcap_ABRT_apdu_U = -1;
static gint ett_tcap_Associate_source_diagnostic = -1;
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
static gint ett_tcap_ERROR = -1;
static gint ett_tcap_UniTransactionPDU = -1;
static gint ett_tcap_TransactionPDU = -1;
static gint ett_tcap_AbortPDU = -1;
static gint ett_tcap_T_causeInformation = -1;
static gint ett_tcap_DialoguePortionANSI_U = -1;
static gint ett_tcap_T_applicationContext = -1;
static gint ett_tcap_T_securityContext = -1;
static gint ett_tcap_Confidentiality = -1;
static gint ett_tcap_T_confidentialityId = -1;
static gint ett_tcap_SEQUENCE_OF_ComponentPDU = -1;
static gint ett_tcap_ComponentPDU = -1;
static gint ett_tcap_InvokePDU = -1;
static gint ett_tcap_ANSIparamch = -1;
static gint ett_tcap_ReturnResultPDU = -1;
static gint ett_tcap_ReturnErrorPDU = -1;
static gint ett_tcap_RejectPDU = -1;
static gint ett_tcap_OperationCode = -1;
static gint ett_tcap_ErrorCode = -1;
static gint ett_tcap_UniDialoguePDU = -1;
static gint ett_tcap_AUDT_apdu_U = -1;
static gint ett_tcap_T_protocol_version = -1;
static gint ett_tcap_AUDT_user_information = -1;

/*--- End of included file: packet-tcap-ett.c ---*/
#line 81 "packet-tcap-template.c"

#define MAX_SSN 254
static range_t *global_ssn_range;
static range_t *ssn_range;
struct tcap_private_t tcap_private;

gboolean gtcap_HandleSRT=FALSE;
extern gboolean gtcap_PersistentSRT;
extern gboolean gtcap_DisplaySRT;
extern guint gtcap_RepetitionTimeout;
extern guint gtcap_LostTimeout;

static dissector_handle_t	tcap_handle = NULL;
static dissector_table_t ber_oid_dissector_table=NULL;
static const char * cur_oid;
static const char * tcapext_oid;
static proto_tree * tcap_top_tree=NULL;
static proto_tree * tcap_stat_tree=NULL;

static dissector_handle_t data_handle;
static dissector_handle_t ansi_tcap_handle;

static void raz_tcap_private(struct tcap_private_t * p_tcap_private);
static int dissect_tcap_param(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_tcap_UserInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_);
static int dissect_tcap_ITU_ComponentPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_);
static int dissect_tcap_ANSI_ComponentPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_);
static int dissect_tcap_TheExternUserInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_);

static GHashTable* ansi_sub_dissectors = NULL;
static GHashTable* itu_sub_dissectors = NULL;

static void dissect_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree);

extern void add_ansi_tcap_subdissector(guint32 ssn, dissector_handle_t dissector) {
    g_hash_table_insert(ansi_sub_dissectors,GUINT_TO_POINTER(ssn),dissector);
    dissector_add("sccp.ssn",ssn,tcap_handle);
}

extern void add_itu_tcap_subdissector(guint32 ssn, dissector_handle_t dissector) {
    g_hash_table_insert(itu_sub_dissectors,GUINT_TO_POINTER(ssn),dissector);
    dissector_add("sccp.ssn",ssn,tcap_handle);
}

extern void delete_ansi_tcap_subdissector(guint32 ssn, dissector_handle_t dissector _U_) {
    g_hash_table_remove(ansi_sub_dissectors,GUINT_TO_POINTER(ssn));
    if (!get_itu_tcap_subdissector(ssn))
      dissector_delete("sccp.ssn",ssn,tcap_handle);
}
extern void delete_itu_tcap_subdissector(guint32 ssn, dissector_handle_t dissector _U_) {
    g_hash_table_remove(itu_sub_dissectors,GUINT_TO_POINTER(ssn));
    if (!get_ansi_tcap_subdissector(ssn))
      dissector_delete("sccp.ssn", ssn,tcap_handle);
}

dissector_handle_t get_ansi_tcap_subdissector(guint32 ssn) {
    return g_hash_table_lookup(ansi_sub_dissectors,GUINT_TO_POINTER(ssn));
}

dissector_handle_t get_itu_tcap_subdissector(guint32 ssn) {
    return g_hash_table_lookup(itu_sub_dissectors,GUINT_TO_POINTER(ssn));
}




/*--- Included file: packet-tcap-fn.c ---*/
#line 1 "packet-tcap-fn.c"

static const asn_namedbit T_protocol_versionrq_bits[] = {
  {  0, &hf_tcap_T_protocol_versionrq_version1, -1, -1, "version1", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_tcap_T_protocol_versionrq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_protocol_versionrq_bits, hf_index, ett_tcap_T_protocol_versionrq,
                                    NULL);

  return offset;
}



static int
dissect_tcap_AARQ_application_context_name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 104 "tcap.cnf"
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &cur_oid);

	tcap_private.oid= (void*) cur_oid;
	tcap_private.acv=TRUE;


  return offset;
}



static int
dissect_tcap_EXTERNAL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

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
  { &hf_tcap_protocol_versionrq, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcap_T_protocol_versionrq },
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


static const asn_namedbit T_protocol_versionre_bits[] = {
  {  0, &hf_tcap_T_protocol_versionre_version1, -1, -1, "version1", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_tcap_T_protocol_versionre(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_protocol_versionre_bits, hf_index, ett_tcap_T_protocol_versionre,
                                    NULL);

  return offset;
}



static int
dissect_tcap_AARE_application_context_name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 109 "tcap.cnf"
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &cur_oid);

	tcap_private.oid= (void*) cur_oid;
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



static int
dissect_tcap_User_information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 71 "tcap.cnf"

return dissect_tcap_UserInformation(FALSE, tvb, offset, actx, tree, -1);



  return offset;
}



static int
dissect_tcap_AARE_user_information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_tcap_User_information(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t AARE_apdu_U_sequence[] = {
  { &hf_tcap_protocol_versionre, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcap_T_protocol_versionre },
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



static int
dissect_tcap_ABRT_user_information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_tcap_User_information(implicit_tag, tvb, offset, actx, tree, hf_index);

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



static int
dissect_tcap_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_tcap_Dialog1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 61 "tcap.cnf"

return dissect_tcap_DialoguePDU(TRUE, tvb, offset, actx, tree, -1);



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
#line 56 "tcap.cnf"

  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_UNI, 8, TRUE, dissect_tcap_ExternalPDU_U);




  return offset;
}



static int
dissect_tcap_UserInfoOID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 117 "tcap.cnf"
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &tcapext_oid);




  return offset;
}



static int
dissect_tcap_ExternUserInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 121 "tcap.cnf"
tvbuff_t	*next_tvb;
gint8 class;
gboolean pc;
gint tag;
guint32 len, comp_offset;
gint ind_field;

comp_offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
comp_offset = dissect_ber_length(actx->pinfo, tree, tvb, comp_offset, &len, &ind_field);
/* we can believe the length now */
next_tvb = tvb_new_subset(tvb, offset, len+comp_offset-offset, len+comp_offset-offset);

if (!next_tvb)
  return comp_offset;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);


dissect_tcap_TheExternUserInfo(implicit_tag, next_tvb, 0, actx, tcap_top_tree, hf_index);

return comp_offset+len;



  return offset;
}


static const ber_sequence_t UserInformation_U_sequence[] = {
  { &hf_tcap_useroid        , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_tcap_UserInfoOID },
  { &hf_tcap_externuserinfo , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_tcap_ExternUserInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_UserInformation_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UserInformation_U_sequence, hf_index, ett_tcap_UserInformation_U);

  return offset;
}



static int
dissect_tcap_UserInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_UNI, 8, TRUE, dissect_tcap_UserInformation_U);

  return offset;
}



static int
dissect_tcap_Applicationcontext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_tcap_DialogueOC(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 51 "tcap.cnf"

return dissect_tcap_ExternalPDU(FALSE /*implicit_tag*/, tvb, offset, actx, tree, -1);



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
#line 66 "tcap.cnf"

return dissect_tcap_param(actx,tree,tvb,offset);



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
#line 76 "tcap.cnf"
tvbuff_t	*next_tvb;
gint8 class;
gboolean pc;
gint tag;
guint32 len, comp_offset;
gint ind_field;

comp_offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
comp_offset = dissect_ber_length(actx->pinfo, tree, tvb, comp_offset, &len, &ind_field);
/* we can believe the length now */
next_tvb = tvb_new_subset(tvb, offset, len+comp_offset-offset, len+comp_offset-offset);

if (!next_tvb)
  return comp_offset;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Component_choice, hf_index, ett_tcap_Component,
                                 NULL);


 dissect_tcap_ITU_ComponentPDU(implicit_tag, next_tvb, 0, actx, tcap_top_tree, hf_index);

/* return comp_offset+len; or return offset (will be automatically added */



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
#line 176 "tcap.cnf"
tvbuff_t *parameter_tvb;
guint8 len, i;
proto_item *tid_item;
proto_tree *subtree;
tid_item = proto_tree_add_text(tree, tvb, offset, -1, "Source Transaction ID");
subtree = proto_item_add_subtree(tid_item, ett_otid);

offset = dissect_ber_octet_string(implicit_tag, actx, subtree, tvb, offset, hf_tcap_tid,
                                    &parameter_tvb);

if (parameter_tvb){
	len = tvb_length_remaining(parameter_tvb, 0);
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

	if ((len)&&(check_col(actx->pinfo->cinfo, COL_INFO))){
		col_append_str(actx->pinfo->cinfo, COL_INFO, "otid(");
	   	for(i=0;i<len;i++)
        		  col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%02x",tvb_get_guint8(parameter_tvb,i));
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
#line 250 "tcap.cnf"
gp_tcapsrt_info->ope=TC_BEGIN;

/*  Do not change col_add_str() to col_append_str() here: we _want_ this call
 *  to overwrite whatever's currently in the INFO column (e.g., "UDT" from
 *  the SCCP dissector).
 *
 *  If there's something there that should not be overwritten, whoever
 *  put that info there should call col_set_fence() to protect it.
 */
if (check_col(actx->pinfo->cinfo, COL_INFO))
		col_set_str(actx->pinfo->cinfo, COL_INFO, "Begin ");

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Begin_sequence, hf_index, ett_tcap_Begin);

  return offset;
}



static int
dissect_tcap_DestTransactionID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 215 "tcap.cnf"
tvbuff_t *parameter_tvb;
guint8 len , i;
proto_item *tid_item;
proto_tree *subtree;
tid_item = proto_tree_add_text(tree, tvb, offset, -1, "Destination Transaction ID");
subtree = proto_item_add_subtree(tid_item, ett_otid);

offset = dissect_ber_octet_string(implicit_tag, actx, subtree, tvb, offset, hf_tcap_tid,
                                    &parameter_tvb);

if (parameter_tvb){
	len = tvb_length_remaining(parameter_tvb, 0);
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

	if ((len)&&(check_col(actx->pinfo->cinfo, COL_INFO))){
		col_append_str(actx->pinfo->cinfo, COL_INFO, "dtid(");
		for(i=0;i<len;i++)
          		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%02x",tvb_get_guint8(parameter_tvb,i));
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
#line 265 "tcap.cnf"
gp_tcapsrt_info->ope=TC_END;

if (check_col(actx->pinfo->cinfo, COL_INFO))
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
#line 273 "tcap.cnf"
gp_tcapsrt_info->ope=TC_CONT;

if (check_col(actx->pinfo->cinfo, COL_INFO))
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
#line 281 "tcap.cnf"
gp_tcapsrt_info->ope=TC_ABORT;

if (check_col(actx->pinfo->cinfo, COL_INFO))
		col_set_str(actx->pinfo->cinfo, COL_INFO, "Abort ");

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Abort_sequence, hf_index, ett_tcap_Abort);

  return offset;
}



static int
dissect_tcap_TransactionID_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 321 "tcap.cnf"

tvbuff_t *next_tvb;
guint8 len;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &next_tvb);


if(next_tvb) {
	tcap_private.TransactionID_str = tvb_bytes_to_str(next_tvb, 0,tvb_length(next_tvb));
	len = tvb_length_remaining(next_tvb, 0);
	switch(len) {
	case 1:
		gp_tcapsrt_info->src_tid=tvb_get_guint8(next_tvb, 0);
		break;
	case 2:
		gp_tcapsrt_info->src_tid=tvb_get_ntohs(next_tvb, 0);
		break;
	case 4:
		gp_tcapsrt_info->src_tid=tvb_get_ntohl(next_tvb, 0);
		break;
	default:
		gp_tcapsrt_info->src_tid=0;
		break;
	}
}



  return offset;
}



static int
dissect_tcap_TransactionID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 7, TRUE, dissect_tcap_TransactionID_U);

  return offset;
}



static int
dissect_tcap_OCTET_STRING_SIZE_1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_tcap_ProtocolVersion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 26, TRUE, dissect_tcap_OCTET_STRING_SIZE_1);

  return offset;
}



static int
dissect_tcap_IntegerApplicationContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 27, TRUE, dissect_tcap_INTEGER);

  return offset;
}



static int
dissect_tcap_ObjectIDApplicationContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 28, TRUE, dissect_tcap_OBJECT_IDENTIFIER);

  return offset;
}


static const value_string tcap_T_applicationContext_vals[] = {
  {  27, "integerApplicationId" },
  {  28, "objectApplicationId" },
  { 0, NULL }
};

static const ber_choice_t T_applicationContext_choice[] = {
  {  27, &hf_tcap_integerApplicationId, BER_CLASS_PRI, 27, BER_FLAGS_NOOWNTAG, dissect_tcap_IntegerApplicationContext },
  {  28, &hf_tcap_objectApplicationId, BER_CLASS_PRI, 28, BER_FLAGS_NOOWNTAG, dissect_tcap_ObjectIDApplicationContext },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_T_applicationContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_applicationContext_choice, hf_index, ett_tcap_T_applicationContext,
                                 NULL);

  return offset;
}


static const value_string tcap_T_securityContext_vals[] = {
  {   0, "integerSecurityId" },
  {   1, "objectSecurityId" },
  { 0, NULL }
};

static const ber_choice_t T_securityContext_choice[] = {
  {   0, &hf_tcap_integerSecurityId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_tcap_INTEGER },
  {   1, &hf_tcap_objectSecurityId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_tcap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_T_securityContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_securityContext_choice, hf_index, ett_tcap_T_securityContext,
                                 NULL);

  return offset;
}


static const value_string tcap_T_confidentialityId_vals[] = {
  {   0, "integerConfidentialityId" },
  {   1, "objectConfidentialityId" },
  { 0, NULL }
};

static const ber_choice_t T_confidentialityId_choice[] = {
  {   0, &hf_tcap_integerConfidentialityId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_tcap_INTEGER },
  {   1, &hf_tcap_objectConfidentialityId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_tcap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_T_confidentialityId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_confidentialityId_choice, hf_index, ett_tcap_T_confidentialityId,
                                 NULL);

  return offset;
}


static const ber_sequence_t Confidentiality_sequence[] = {
  { &hf_tcap_confidentialityId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tcap_T_confidentialityId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_Confidentiality(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Confidentiality_sequence, hf_index, ett_tcap_Confidentiality);

  return offset;
}


static const ber_sequence_t DialoguePortionANSI_U_sequence[] = {
  { &hf_tcap_version        , BER_CLASS_PRI, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ProtocolVersion },
  { &hf_tcap_applicationContext, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_tcap_T_applicationContext },
  { &hf_tcap_userInformation, BER_CLASS_UNI, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_UserInformation },
  { &hf_tcap_securityContext, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tcap_T_securityContext },
  { &hf_tcap_confidentiality, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcap_Confidentiality },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_DialoguePortionANSI_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DialoguePortionANSI_U_sequence, hf_index, ett_tcap_DialoguePortionANSI_U);

  return offset;
}



static int
dissect_tcap_DialoguePortionANSI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 25, TRUE, dissect_tcap_DialoguePortionANSI_U);

  return offset;
}



static int
dissect_tcap_OCTET_STRING_SIZE_0_2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string tcap_OperationCode_vals[] = {
  {  16, "national" },
  {  17, "private" },
  { 0, NULL }
};

static const ber_choice_t OperationCode_choice[] = {
  {  16, &hf_tcap_national       , BER_CLASS_PRI, 16, BER_FLAGS_IMPLTAG, dissect_tcap_INTEGER_M32768_32767 },
  {  17, &hf_tcap_private        , BER_CLASS_PRI, 17, BER_FLAGS_IMPLTAG, dissect_tcap_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_OperationCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 OperationCode_choice, hf_index, ett_tcap_OperationCode,
                                 NULL);

  return offset;
}



static int
dissect_tcap_ANSIParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 144 "tcap.cnf"
/* we are doing the ParamSet here so need to look at the tags*/
	guint32 len;
len = tvb_length_remaining(tvb, offset);
if (len > 2)  /* arghhh I dont know whether this is constructed or not! */
		offset = dissect_tcap_param(actx,tree,tvb,offset);
else
offset = dissect_ber_octet_string(TRUE, actx, tree, tvb, 0, hf_index,
                                    NULL);



  return offset;
}


static const ber_sequence_t ANSIparamch_sequence[] = {
  { &hf_tcap_ansiparams     , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams1    , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams2    , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams3    , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams4    , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams5    , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams6    , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams7    , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams8    , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams9    , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams10   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams11   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams12   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams13   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams14   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams15   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams16   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams17   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams18   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams19   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams20   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { &hf_tcap_ansiparams21   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_ANSIparamch(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ANSIparamch_sequence, hf_index, ett_tcap_ANSIparamch);

  return offset;
}


static const ber_sequence_t InvokePDU_sequence[] = {
  { &hf_tcap_componentIDs   , BER_CLASS_PRI, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcap_OCTET_STRING_SIZE_0_2 },
  { &hf_tcap_operationCode  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tcap_OperationCode },
  { &hf_tcap_parameterinv   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIparamch },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_InvokePDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InvokePDU_sequence, hf_index, ett_tcap_InvokePDU);

  return offset;
}



static int
dissect_tcap_ComponentID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 15, TRUE, dissect_tcap_OCTET_STRING_SIZE_1);

  return offset;
}


static const ber_sequence_t ReturnResultPDU_sequence[] = {
  { &hf_tcap_componentID    , BER_CLASS_PRI, 15, BER_FLAGS_NOOWNTAG, dissect_tcap_ComponentID },
  { &hf_tcap_parameterrr    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIparamch },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_ReturnResultPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnResultPDU_sequence, hf_index, ett_tcap_ReturnResultPDU);

  return offset;
}


static const ber_sequence_t ReturnErrorPDU_sequence[] = {
  { &hf_tcap_componentID    , BER_CLASS_PRI, 15, BER_FLAGS_NOOWNTAG, dissect_tcap_ComponentID },
  { &hf_tcap_errorCode      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tcap_ErrorCode },
  { &hf_tcap_parameterre    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIparamch },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_ReturnErrorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnErrorPDU_sequence, hf_index, ett_tcap_ReturnErrorPDU);

  return offset;
}


static const value_string tcap_ProblemPDU_vals[] = {
  { 257, "general-unrecognisedComponentType" },
  { 258, "general-incorrectComponentPortion" },
  { 259, "general-badlyStructuredCompPortion" },
  { 0, NULL }
};


static int
dissect_tcap_ProblemPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RejectPDU_sequence[] = {
  { &hf_tcap_componentID    , BER_CLASS_PRI, 15, BER_FLAGS_NOOWNTAG, dissect_tcap_ComponentID },
  { &hf_tcap_rejectProblem  , BER_CLASS_PRI, 21, BER_FLAGS_IMPLTAG, dissect_tcap_ProblemPDU },
  { &hf_tcap_parameterrj    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_tcap_ANSIparamch },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_RejectPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RejectPDU_sequence, hf_index, ett_tcap_RejectPDU);

  return offset;
}


static const value_string tcap_ComponentPDU_vals[] = {
  {   9, "invokeLastansi" },
  {  10, "returnResultLastansi" },
  {  11, "returnErroransi" },
  {  12, "rejectansi" },
  {  13, "invokeNotLastansi" },
  {  14, "returnResultNotLastansi" },
  { 0, NULL }
};

static const ber_choice_t ComponentPDU_choice[] = {
  {   9, &hf_tcap_invokeLastansi , BER_CLASS_PRI, 9, BER_FLAGS_IMPLTAG, dissect_tcap_InvokePDU },
  {  10, &hf_tcap_returnResultLastansi, BER_CLASS_PRI, 10, BER_FLAGS_IMPLTAG, dissect_tcap_ReturnResultPDU },
  {  11, &hf_tcap_returnErroransi, BER_CLASS_PRI, 11, BER_FLAGS_IMPLTAG, dissect_tcap_ReturnErrorPDU },
  {  12, &hf_tcap_rejectansi     , BER_CLASS_PRI, 12, BER_FLAGS_IMPLTAG, dissect_tcap_RejectPDU },
  {  13, &hf_tcap_invokeNotLastansi, BER_CLASS_PRI, 13, BER_FLAGS_IMPLTAG, dissect_tcap_InvokePDU },
  {  14, &hf_tcap_returnResultNotLastansi, BER_CLASS_PRI, 14, BER_FLAGS_IMPLTAG, dissect_tcap_ReturnResultPDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_ComponentPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 155 "tcap.cnf"
tvbuff_t	*next_tvb;
gint8 class;
gboolean pc;
gint tag;
guint32 len, comp_offset;
gint ind_field;

comp_offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
comp_offset = dissect_ber_length(actx->pinfo, tree, tvb, comp_offset, &len, &ind_field);
/* we can believe the length now */
next_tvb = tvb_new_subset(tvb, offset, len+comp_offset-offset, len+comp_offset-offset);

if (!next_tvb)
  return offset;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ComponentPDU_choice, hf_index, ett_tcap_ComponentPDU,
                                 NULL);


dissect_tcap_ANSI_ComponentPDU(implicit_tag, next_tvb, 0, actx, tcap_top_tree, hf_index);



  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ComponentPDU_sequence_of[1] = {
  { &hf_tcap__untag_item_01 , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tcap_ComponentPDU },
};

static int
dissect_tcap_SEQUENCE_OF_ComponentPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ComponentPDU_sequence_of, hf_index, ett_tcap_SEQUENCE_OF_ComponentPDU);

  return offset;
}



static int
dissect_tcap_ComponentSequence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 8, TRUE, dissect_tcap_SEQUENCE_OF_ComponentPDU);

  return offset;
}


static const ber_sequence_t UniTransactionPDU_sequence[] = {
  { &hf_tcap_identifier     , BER_CLASS_PRI, 7, BER_FLAGS_NOOWNTAG, dissect_tcap_TransactionID },
  { &hf_tcap_dialoguePortionansi, BER_CLASS_PRI, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_DialoguePortionANSI },
  { &hf_tcap_componentPortion, BER_CLASS_PRI, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ComponentSequence },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_UniTransactionPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UniTransactionPDU_sequence, hf_index, ett_tcap_UniTransactionPDU);

  return offset;
}


static const ber_sequence_t TransactionPDU_sequence[] = {
  { &hf_tcap_identifier     , BER_CLASS_PRI, 7, BER_FLAGS_NOOWNTAG, dissect_tcap_TransactionID },
  { &hf_tcap_dialoguePortionansi, BER_CLASS_PRI, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_DialoguePortionANSI },
  { &hf_tcap_componentPortion, BER_CLASS_PRI, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_ComponentSequence },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_TransactionPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TransactionPDU_sequence, hf_index, ett_tcap_TransactionPDU);

  return offset;
}



static int
dissect_tcap_T_ansiqueryWithPerm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 297 "tcap.cnf"
gp_tcapsrt_info->ope=TC_ANSI_ALL;
if (check_col(actx->pinfo->cinfo, COL_INFO))
				col_set_str(actx->pinfo->cinfo, COL_INFO, "QueryWithPerm ");

  offset = dissect_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_tcap_T_ansiqueryWithoutPerm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 301 "tcap.cnf"
gp_tcapsrt_info->ope=TC_ANSI_ALL;
if (check_col(actx->pinfo->cinfo, COL_INFO))
				col_set_str(actx->pinfo->cinfo, COL_INFO, "QueryWithOutPerm ");

  offset = dissect_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_tcap_T_ansiresponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 305 "tcap.cnf"
gp_tcapsrt_info->ope=TC_ANSI_ALL;
if (check_col(actx->pinfo->cinfo, COL_INFO))
				col_set_str(actx->pinfo->cinfo, COL_INFO, "Response ");

  offset = dissect_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_tcap_T_ansiconversationWithPerm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 309 "tcap.cnf"
gp_tcapsrt_info->ope=TC_ANSI_ALL;
if (check_col(actx->pinfo->cinfo, COL_INFO))
				col_set_str(actx->pinfo->cinfo, COL_INFO, "ConversationWithPerm ");

  offset = dissect_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_tcap_T_ansiconversationWithoutPerm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 313 "tcap.cnf"
gp_tcapsrt_info->ope=TC_ANSI_ALL;
if (check_col(actx->pinfo->cinfo, COL_INFO))
				col_set_str(actx->pinfo->cinfo, COL_INFO, "ConversationWithoutPerm ");


  offset = dissect_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string tcap_P_Abort_cause_U_vals[] = {
  {   1, "unrecognizedPackageType" },
  {   2, "incorrestTransactionPortion" },
  {   3, "badlyStructuredTransactionPortion" },
  {   4, "unassignedRespondingTransactionID" },
  {   5, "permissionToReleaseProblem" },
  {   6, "resourceUnavilable" },
  {   7, "unrecognizedDialoguePortionID" },
  {   8, "badlyStructuredDialoguePortion" },
  {   9, "missingDialoguePortion" },
  {  10, "inconsistentDialoguePortion" },
  { 0, NULL }
};


static int
dissect_tcap_P_Abort_cause_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_tcap_P_Abort_cause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 23, TRUE, dissect_tcap_P_Abort_cause_U);

  return offset;
}


static const value_string tcap_T_causeInformation_vals[] = {
  {   0, "abortCause" },
  {   1, "userInformation" },
  { 0, NULL }
};

static const ber_choice_t T_causeInformation_choice[] = {
  {   0, &hf_tcap_abortCause     , BER_CLASS_PRI, 23, BER_FLAGS_NOOWNTAG, dissect_tcap_P_Abort_cause },
  {   1, &hf_tcap_userInformation, BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_tcap_UserInformation },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_T_causeInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_causeInformation_choice, hf_index, ett_tcap_T_causeInformation,
                                 NULL);

  return offset;
}


static const ber_sequence_t AbortPDU_sequence[] = {
  { &hf_tcap_identifier     , BER_CLASS_PRI, 7, BER_FLAGS_NOOWNTAG, dissect_tcap_TransactionID },
  { &hf_tcap_dialoguePortionansi, BER_CLASS_PRI, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcap_DialoguePortionANSI },
  { &hf_tcap_causeInformation, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_tcap_T_causeInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_AbortPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 289 "tcap.cnf"
gp_tcapsrt_info->ope=TC_ANSI_ABORT;

if (check_col(actx->pinfo->cinfo, COL_INFO))
		col_set_str(actx->pinfo->cinfo, COL_INFO, "Abort ");

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AbortPDU_sequence, hf_index, ett_tcap_AbortPDU);

  return offset;
}


static const value_string tcap_TCMessage_vals[] = {
  {   0, "unidirectional" },
  {   1, "begin" },
  {   2, "end" },
  {   3, "continue" },
  {   4, "abort" },
  {   5, "ansiunidirectional" },
  {   6, "ansiqueryWithPerm" },
  {   7, "ansiqueryWithoutPerm" },
  {   8, "ansiresponse" },
  {   9, "ansiconversationWithPerm" },
  {  10, "ansiconversationWithoutPerm" },
  {  11, "ansiabort" },
  { 0, NULL }
};

static const ber_choice_t TCMessage_choice[] = {
  {   0, &hf_tcap_unidirectional , BER_CLASS_APP, 1, BER_FLAGS_IMPLTAG, dissect_tcap_Unidirectional },
  {   1, &hf_tcap_begin          , BER_CLASS_APP, 2, BER_FLAGS_IMPLTAG, dissect_tcap_Begin },
  {   2, &hf_tcap_end            , BER_CLASS_APP, 4, BER_FLAGS_IMPLTAG, dissect_tcap_End },
  {   3, &hf_tcap_continue       , BER_CLASS_APP, 5, BER_FLAGS_IMPLTAG, dissect_tcap_Continue },
  {   4, &hf_tcap_abort          , BER_CLASS_APP, 7, BER_FLAGS_IMPLTAG, dissect_tcap_Abort },
  {   5, &hf_tcap_ansiunidirectional, BER_CLASS_PRI, 1, BER_FLAGS_IMPLTAG, dissect_tcap_UniTransactionPDU },
  {   6, &hf_tcap_ansiqueryWithPerm, BER_CLASS_PRI, 2, BER_FLAGS_IMPLTAG, dissect_tcap_T_ansiqueryWithPerm },
  {   7, &hf_tcap_ansiqueryWithoutPerm, BER_CLASS_PRI, 3, BER_FLAGS_IMPLTAG, dissect_tcap_T_ansiqueryWithoutPerm },
  {   8, &hf_tcap_ansiresponse   , BER_CLASS_PRI, 4, BER_FLAGS_IMPLTAG, dissect_tcap_T_ansiresponse },
  {   9, &hf_tcap_ansiconversationWithPerm, BER_CLASS_PRI, 5, BER_FLAGS_IMPLTAG, dissect_tcap_T_ansiconversationWithPerm },
  {  10, &hf_tcap_ansiconversationWithoutPerm, BER_CLASS_PRI, 6, BER_FLAGS_IMPLTAG, dissect_tcap_T_ansiconversationWithoutPerm },
  {  11, &hf_tcap_ansiabort      , BER_CLASS_PRI, 22, BER_FLAGS_IMPLTAG, dissect_tcap_AbortPDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_TCMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TCMessage_choice, hf_index, ett_tcap_TCMessage,
                                 NULL);

  return offset;
}


static const value_string tcap_ERROR_vals[] = {
  {   0, "localValue" },
  {   1, "globalValue" },
  { 0, NULL }
};

static const ber_choice_t ERROR_choice[] = {
  {   0, &hf_tcap_localValue     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tcap_INTEGER },
  {   1, &hf_tcap_globalValue    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_tcap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_tcap_ERROR(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ERROR_choice, hf_index, ett_tcap_ERROR,
                                 NULL);

  return offset;
}


static const asn_namedbit T_protocol_version_bits[] = {
  {  0, &hf_tcap_T_protocol_version_version1, -1, -1, "version1", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_tcap_T_protocol_version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_protocol_version_bits, hf_index, ett_tcap_T_protocol_version,
                                    NULL);

  return offset;
}



static int
dissect_tcap_AUDT_application_context_name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 99 "tcap.cnf"
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &cur_oid);

	tcap_private.oid= (void*) cur_oid;
	tcap_private.acv=TRUE;


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
  { &hf_tcap_protocol_version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcap_T_protocol_version },
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

/*--- PDUs ---*/

static void dissect_DialoguePDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_tcap_DialoguePDU(FALSE, tvb, 0, &asn1_ctx, tree, hf_tcap_DialoguePDU_PDU);
}
static void dissect_UniDialoguePDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_tcap_UniDialoguePDU(FALSE, tvb, 0, &asn1_ctx, tree, hf_tcap_UniDialoguePDU_PDU);
}


/*--- End of included file: packet-tcap-fn.c ---*/
#line 147 "packet-tcap-template.c"



const value_string tcap_component_type_str[] = {
    { TCAP_COMP_INVOKE,		"Invoke" },
    { TCAP_COMP_RRL,		"Return Result(L)" },
    { TCAP_COMP_RE,			"Return Error" },
    { TCAP_COMP_REJECT,		"Reject" },
    { TCAP_COMP_RRN,		"Return Result(NL)" },
    { 0,			NULL } };


static void
dissect_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item		*item=NULL;
    proto_tree		*tree=NULL;

    struct tcaphash_context_t * p_tcap_context;
    dissector_handle_t subdissector_handle;
	asn1_ctx_t asn1_ctx;
	gint8 class;
	gboolean pc;
	gint tag;

	/* Check if ANSI TCAP and call the ANSI TCAP dissector if that's the case 
	 * PackageType ::= CHOICE { unidirectional			[PRIVATE 1] IMPLICIT UniTransactionPDU,
	 * 						 queryWithPerm				[PRIVATE 2] IMPLICIT TransactionPDU,
	 * 						 queryWithoutPerm			[PRIVATE 3] IMPLICIT TransactionPDU,
	 * 						 response					[PRIVATE 4] IMPLICIT TransactionPDU,
	 * 						 conversationWithPerm		[PRIVATE 5] IMPLICIT TransactionPDU,
	 * 						 conversationWithoutPerm	[PRIVATE 6] IMPLICIT TransactionPDU,
	 * 						 abort						[PRIVATE 22] IMPLICIT Abort 
	 * 						 }
	 * 	
	 * 
	 */
	get_ber_identifier(tvb, 0, &class, &pc, &tag);

	if(class == BER_CLASS_PRI){
		switch(tag){
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 22:
			call_dissector(ansi_tcap_handle, tvb, pinfo, parent_tree);
			return;
			break;
		default:
			return;
		}
	}

	/* ITU TCAP */
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    tcap_top_tree = parent_tree;
    tcap_stat_tree = NULL;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCAP");
    }

    /* create display subtree for the protocol */
    if(parent_tree){
      item = proto_tree_add_item(parent_tree, proto_tcap, tvb, 0, -1, FALSE);
      tree = proto_item_add_subtree(item, ett_tcap);
      tcap_stat_tree=tree;
    }
    cur_oid = NULL;
    tcapext_oid = NULL;
    raz_tcap_private(&tcap_private);

    pinfo->private_data = &tcap_private;
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
			ber_oid_dissector_table = find_dissector_table("ber.oid");
			g_strlcpy(p_tcap_context->oid,cur_oid, LENGTH_OID);
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
}

void
proto_reg_handoff_tcap(void)
{

    data_handle = find_dissector("data");
    ansi_tcap_handle = find_dissector("ansi_tcap");


/*--- Included file: packet-tcap-dis-tab.c ---*/
#line 1 "packet-tcap-dis-tab.c"
  register_ber_oid_dissector("0.0.17.773.1.1.1", dissect_DialoguePDU_PDU, proto_tcap, "dialogue-as-id");
  register_ber_oid_dissector("0.0.17.773.1.2.1", dissect_UniDialoguePDU_PDU, proto_tcap, "uniDialogue-as-id");


/*--- End of included file: packet-tcap-dis-tab.c ---*/
#line 262 "packet-tcap-template.c"
}

static void init_tcap(void);

void
proto_register_tcap(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
	{ &hf_tcap_tag,
		{ "Tag",           "tcap.msgtype",
		FT_UINT8, BASE_HEX, NULL, 0,
		"", HFILL }
	},
	{ &hf_tcap_length,
		{ "Length", "tcap.len",
		FT_UINT8, BASE_DEC, NULL, 0,
		"", HFILL }
	},
	{ &hf_tcap_data,
		{ "Data", "tcap.data",
		FT_BYTES, BASE_HEX, NULL, 0,
		"", HFILL }
	},
		{ &hf_tcap_tid,
		{ "Transaction Id", "tcap.tid",
		FT_BYTES, BASE_HEX, NULL, 0,
		"", HFILL }
	},
	/* Tcap Service Response Time */
	{ &hf_tcapsrt_SessionId,
	  { "Session Id",
	    "tcap.srt.session_id",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "", HFILL }
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
#line 1 "packet-tcap-hfarr.c"
    { &hf_tcap_DialoguePDU_PDU,
      { "DialoguePDU", "tcap.DialoguePDU",
        FT_UINT32, BASE_DEC, VALS(tcap_DialoguePDU_vals), 0,
        "tcap.DialoguePDU", HFILL }},
    { &hf_tcap_UniDialoguePDU_PDU,
      { "UniDialoguePDU", "tcap.UniDialoguePDU",
        FT_UINT32, BASE_DEC, VALS(tcap_UniDialoguePDU_vals), 0,
        "tcap.UniDialoguePDU", HFILL }},
    { &hf_tcap_dialogueRequest,
      { "dialogueRequest", "tcap.dialogueRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.AARQ_apdu", HFILL }},
    { &hf_tcap_dialogueResponse,
      { "dialogueResponse", "tcap.dialogueResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.AARE_apdu", HFILL }},
    { &hf_tcap_dialogueAbort,
      { "dialogueAbort", "tcap.dialogueAbort",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ABRT_apdu", HFILL }},
    { &hf_tcap_oid,
      { "oid", "tcap.oid",
        FT_OID, BASE_NONE, NULL, 0,
        "tcap.OBJECT_IDENTIFIER", HFILL }},
    { &hf_tcap_dialog,
      { "dialog", "tcap.dialog",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.Dialog1", HFILL }},
    { &hf_tcap_useroid,
      { "useroid", "tcap.useroid",
        FT_OID, BASE_NONE, NULL, 0,
        "tcap.UserInfoOID", HFILL }},
    { &hf_tcap_externuserinfo,
      { "externuserinfo", "tcap.externuserinfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.ExternUserInfo", HFILL }},
    { &hf_tcap_protocol_versionrq,
      { "protocol-versionrq", "tcap.protocol_versionrq",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.T_protocol_versionrq", HFILL }},
    { &hf_tcap_aarq_application_context_name,
      { "application-context-name", "tcap.application_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        "tcap.AARQ_application_context_name", HFILL }},
    { &hf_tcap_aarq_user_information,
      { "user-information", "tcap.user_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "tcap.AARQ_user_information", HFILL }},
    { &hf_tcap_aarq_user_information_item,
      { "Item", "tcap.user_information_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.EXTERNAL", HFILL }},
    { &hf_tcap_protocol_versionre,
      { "protocol-versionre", "tcap.protocol_versionre",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.T_protocol_versionre", HFILL }},
    { &hf_tcap_aare_application_context_name,
      { "application-context-name", "tcap.application_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        "tcap.AARE_application_context_name", HFILL }},
    { &hf_tcap_result,
      { "result", "tcap.result",
        FT_INT32, BASE_DEC, VALS(tcap_Associate_result_vals), 0,
        "tcap.Associate_result", HFILL }},
    { &hf_tcap_result_source_diagnostic,
      { "result-source-diagnostic", "tcap.result_source_diagnostic",
        FT_UINT32, BASE_DEC, VALS(tcap_Associate_source_diagnostic_vals), 0,
        "tcap.Associate_source_diagnostic", HFILL }},
    { &hf_tcap_aare_user_information,
      { "user-information", "tcap.user_information",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.AARE_user_information", HFILL }},
    { &hf_tcap_abort_source,
      { "abort-source", "tcap.abort_source",
        FT_INT32, BASE_DEC, VALS(tcap_ABRT_source_vals), 0,
        "tcap.ABRT_source", HFILL }},
    { &hf_tcap_abrt_user_information,
      { "user-information", "tcap.user_information",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.ABRT_user_information", HFILL }},
    { &hf_tcap_dialogue_service_user,
      { "dialogue-service-user", "tcap.dialogue_service_user",
        FT_INT32, BASE_DEC, VALS(tcap_T_dialogue_service_user_vals), 0,
        "tcap.T_dialogue_service_user", HFILL }},
    { &hf_tcap_dialogue_service_provider,
      { "dialogue-service-provider", "tcap.dialogue_service_provider",
        FT_INT32, BASE_DEC, VALS(tcap_T_dialogue_service_provider_vals), 0,
        "tcap.T_dialogue_service_provider", HFILL }},
    { &hf_tcap_unidirectional,
      { "unidirectional", "tcap.unidirectional",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.Unidirectional", HFILL }},
    { &hf_tcap_begin,
      { "begin", "tcap.begin",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.Begin", HFILL }},
    { &hf_tcap_end,
      { "end", "tcap.end",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.End", HFILL }},
    { &hf_tcap_continue,
      { "continue", "tcap.continue",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.Continue", HFILL }},
    { &hf_tcap_abort,
      { "abort", "tcap.abort",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.Abort", HFILL }},
    { &hf_tcap_ansiunidirectional,
      { "ansiunidirectional", "tcap.ansiunidirectional",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.UniTransactionPDU", HFILL }},
    { &hf_tcap_ansiqueryWithPerm,
      { "ansiqueryWithPerm", "tcap.ansiqueryWithPerm",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.T_ansiqueryWithPerm", HFILL }},
    { &hf_tcap_ansiqueryWithoutPerm,
      { "ansiqueryWithoutPerm", "tcap.ansiqueryWithoutPerm",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.T_ansiqueryWithoutPerm", HFILL }},
    { &hf_tcap_ansiresponse,
      { "ansiresponse", "tcap.ansiresponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.T_ansiresponse", HFILL }},
    { &hf_tcap_ansiconversationWithPerm,
      { "ansiconversationWithPerm", "tcap.ansiconversationWithPerm",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.T_ansiconversationWithPerm", HFILL }},
    { &hf_tcap_ansiconversationWithoutPerm,
      { "ansiconversationWithoutPerm", "tcap.ansiconversationWithoutPerm",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.T_ansiconversationWithoutPerm", HFILL }},
    { &hf_tcap_ansiabort,
      { "ansiabort", "tcap.ansiabort",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.AbortPDU", HFILL }},
    { &hf_tcap_dialoguePortion,
      { "dialoguePortion", "tcap.dialoguePortion",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.DialoguePortion", HFILL }},
    { &hf_tcap_components,
      { "components", "tcap.components",
        FT_UINT32, BASE_DEC, NULL, 0,
        "tcap.ComponentPortion", HFILL }},
    { &hf_tcap_otid,
      { "otid", "tcap.otid",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.OrigTransactionID", HFILL }},
    { &hf_tcap_dtid,
      { "dtid", "tcap.dtid",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.DestTransactionID", HFILL }},
    { &hf_tcap_reason,
      { "reason", "tcap.reason",
        FT_UINT32, BASE_DEC, VALS(tcap_Reason_vals), 0,
        "tcap.Reason", HFILL }},
    { &hf_tcap_p_abortCause,
      { "p-abortCause", "tcap.p_abortCause",
        FT_UINT32, BASE_DEC, VALS(tcap_P_AbortCause_U_vals), 0,
        "tcap.P_AbortCause", HFILL }},
    { &hf_tcap_u_abortCause,
      { "u-abortCause", "tcap.u_abortCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.DialoguePortion", HFILL }},
    { &hf_tcap__untag_item,
      { "Item", "tcap._untag_item",
        FT_UINT32, BASE_DEC, VALS(tcap_Component_vals), 0,
        "tcap.Component", HFILL }},
    { &hf_tcap_invoke,
      { "invoke", "tcap.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.Invoke", HFILL }},
    { &hf_tcap_returnResultLast,
      { "returnResultLast", "tcap.returnResultLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ReturnResult", HFILL }},
    { &hf_tcap_returnError,
      { "returnError", "tcap.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ReturnError", HFILL }},
    { &hf_tcap_reject,
      { "reject", "tcap.reject",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.Reject", HFILL }},
    { &hf_tcap_returnResultNotLast,
      { "returnResultNotLast", "tcap.returnResultNotLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ReturnResult", HFILL }},
    { &hf_tcap_invokeID,
      { "invokeID", "tcap.invokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "tcap.InvokeIdType", HFILL }},
    { &hf_tcap_linkedID,
      { "linkedID", "tcap.linkedID",
        FT_INT32, BASE_DEC, NULL, 0,
        "tcap.InvokeIdType", HFILL }},
    { &hf_tcap_opCode,
      { "opCode", "tcap.opCode",
        FT_UINT32, BASE_DEC, VALS(tcap_OPERATION_vals), 0,
        "tcap.OPERATION", HFILL }},
    { &hf_tcap_parameter,
      { "parameter", "tcap.parameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.Parameter", HFILL }},
    { &hf_tcap_resultretres,
      { "resultretres", "tcap.resultretres",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.T_resultretres", HFILL }},
    { &hf_tcap_errorCode,
      { "errorCode", "tcap.errorCode",
        FT_UINT32, BASE_DEC, VALS(tcap_ErrorCode_vals), 0,
        "tcap.ErrorCode", HFILL }},
    { &hf_tcap_invokeIDRej,
      { "invokeIDRej", "tcap.invokeIDRej",
        FT_UINT32, BASE_DEC, VALS(tcap_T_invokeIDRej_vals), 0,
        "tcap.T_invokeIDRej", HFILL }},
    { &hf_tcap_derivable,
      { "derivable", "tcap.derivable",
        FT_INT32, BASE_DEC, NULL, 0,
        "tcap.InvokeIdType", HFILL }},
    { &hf_tcap_not_derivable,
      { "not-derivable", "tcap.not_derivable",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.NULL", HFILL }},
    { &hf_tcap_problem,
      { "problem", "tcap.problem",
        FT_UINT32, BASE_DEC, VALS(tcap_T_problem_vals), 0,
        "tcap.T_problem", HFILL }},
    { &hf_tcap_generalProblem,
      { "generalProblem", "tcap.generalProblem",
        FT_INT32, BASE_DEC, VALS(tcap_GeneralProblem_vals), 0,
        "tcap.GeneralProblem", HFILL }},
    { &hf_tcap_invokeProblem,
      { "invokeProblem", "tcap.invokeProblem",
        FT_INT32, BASE_DEC, VALS(tcap_InvokeProblem_vals), 0,
        "tcap.InvokeProblem", HFILL }},
    { &hf_tcap_returnResultProblem,
      { "returnResultProblem", "tcap.returnResultProblem",
        FT_INT32, BASE_DEC, VALS(tcap_ReturnResultProblem_vals), 0,
        "tcap.ReturnResultProblem", HFILL }},
    { &hf_tcap_returnErrorProblem,
      { "returnErrorProblem", "tcap.returnErrorProblem",
        FT_INT32, BASE_DEC, VALS(tcap_ReturnErrorProblem_vals), 0,
        "tcap.ReturnErrorProblem", HFILL }},
    { &hf_tcap_localValue,
      { "localValue", "tcap.localValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "tcap.INTEGER", HFILL }},
    { &hf_tcap_globalValue,
      { "globalValue", "tcap.globalValue",
        FT_OID, BASE_NONE, NULL, 0,
        "tcap.OBJECT_IDENTIFIER", HFILL }},
    { &hf_tcap_identifier,
      { "identifier", "tcap.identifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.TransactionID", HFILL }},
    { &hf_tcap_dialoguePortionansi,
      { "dialoguePortionansi", "tcap.dialoguePortionansi",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.DialoguePortionANSI", HFILL }},
    { &hf_tcap_componentPortion,
      { "componentPortion", "tcap.componentPortion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "tcap.ComponentSequence", HFILL }},
    { &hf_tcap_causeInformation,
      { "causeInformation", "tcap.causeInformation",
        FT_UINT32, BASE_DEC, VALS(tcap_T_causeInformation_vals), 0,
        "tcap.T_causeInformation", HFILL }},
    { &hf_tcap_abortCause,
      { "abortCause", "tcap.abortCause",
        FT_INT32, BASE_DEC, VALS(tcap_P_Abort_cause_U_vals), 0,
        "tcap.P_Abort_cause", HFILL }},
    { &hf_tcap_userInformation,
      { "userInformation", "tcap.userInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.UserInformation", HFILL }},
    { &hf_tcap_version,
      { "version", "tcap.version",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.ProtocolVersion", HFILL }},
    { &hf_tcap_applicationContext,
      { "applicationContext", "tcap.applicationContext",
        FT_UINT32, BASE_DEC, VALS(tcap_T_applicationContext_vals), 0,
        "tcap.T_applicationContext", HFILL }},
    { &hf_tcap_integerApplicationId,
      { "integerApplicationId", "tcap.integerApplicationId",
        FT_INT32, BASE_DEC, NULL, 0,
        "tcap.IntegerApplicationContext", HFILL }},
    { &hf_tcap_objectApplicationId,
      { "objectApplicationId", "tcap.objectApplicationId",
        FT_OID, BASE_NONE, NULL, 0,
        "tcap.ObjectIDApplicationContext", HFILL }},
    { &hf_tcap_securityContext,
      { "securityContext", "tcap.securityContext",
        FT_UINT32, BASE_DEC, VALS(tcap_T_securityContext_vals), 0,
        "tcap.T_securityContext", HFILL }},
    { &hf_tcap_integerSecurityId,
      { "integerSecurityId", "tcap.integerSecurityId",
        FT_INT32, BASE_DEC, NULL, 0,
        "tcap.INTEGER", HFILL }},
    { &hf_tcap_objectSecurityId,
      { "objectSecurityId", "tcap.objectSecurityId",
        FT_OID, BASE_NONE, NULL, 0,
        "tcap.OBJECT_IDENTIFIER", HFILL }},
    { &hf_tcap_confidentiality,
      { "confidentiality", "tcap.confidentiality",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.Confidentiality", HFILL }},
    { &hf_tcap_confidentialityId,
      { "confidentialityId", "tcap.confidentialityId",
        FT_UINT32, BASE_DEC, VALS(tcap_T_confidentialityId_vals), 0,
        "tcap.T_confidentialityId", HFILL }},
    { &hf_tcap_integerConfidentialityId,
      { "integerConfidentialityId", "tcap.integerConfidentialityId",
        FT_INT32, BASE_DEC, NULL, 0,
        "tcap.INTEGER", HFILL }},
    { &hf_tcap_objectConfidentialityId,
      { "objectConfidentialityId", "tcap.objectConfidentialityId",
        FT_OID, BASE_NONE, NULL, 0,
        "tcap.OBJECT_IDENTIFIER", HFILL }},
    { &hf_tcap__untag_item_01,
      { "Item", "tcap._untag_item",
        FT_UINT32, BASE_DEC, VALS(tcap_ComponentPDU_vals), 0,
        "tcap.ComponentPDU", HFILL }},
    { &hf_tcap_invokeLastansi,
      { "invokeLastansi", "tcap.invokeLastansi",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.InvokePDU", HFILL }},
    { &hf_tcap_returnResultLastansi,
      { "returnResultLastansi", "tcap.returnResultLastansi",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ReturnResultPDU", HFILL }},
    { &hf_tcap_returnErroransi,
      { "returnErroransi", "tcap.returnErroransi",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ReturnErrorPDU", HFILL }},
    { &hf_tcap_rejectansi,
      { "rejectansi", "tcap.rejectansi",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.RejectPDU", HFILL }},
    { &hf_tcap_invokeNotLastansi,
      { "invokeNotLastansi", "tcap.invokeNotLastansi",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.InvokePDU", HFILL }},
    { &hf_tcap_returnResultNotLastansi,
      { "returnResultNotLastansi", "tcap.returnResultNotLastansi",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ReturnResultPDU", HFILL }},
    { &hf_tcap_componentIDs,
      { "componentIDs", "tcap.componentIDs",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.OCTET_STRING_SIZE_0_2", HFILL }},
    { &hf_tcap_operationCode,
      { "operationCode", "tcap.operationCode",
        FT_UINT32, BASE_DEC, VALS(tcap_OperationCode_vals), 0,
        "tcap.OperationCode", HFILL }},
    { &hf_tcap_parameterinv,
      { "parameterinv", "tcap.parameterinv",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIparamch", HFILL }},
    { &hf_tcap_ansiparams,
      { "ansiparams", "tcap.ansiparams",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams1,
      { "ansiparams1", "tcap.ansiparams1",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams2,
      { "ansiparams2", "tcap.ansiparams2",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams3,
      { "ansiparams3", "tcap.ansiparams3",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams4,
      { "ansiparams4", "tcap.ansiparams4",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams5,
      { "ansiparams5", "tcap.ansiparams5",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams6,
      { "ansiparams6", "tcap.ansiparams6",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams7,
      { "ansiparams7", "tcap.ansiparams7",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams8,
      { "ansiparams8", "tcap.ansiparams8",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams9,
      { "ansiparams9", "tcap.ansiparams9",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams10,
      { "ansiparams10", "tcap.ansiparams10",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams11,
      { "ansiparams11", "tcap.ansiparams11",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams12,
      { "ansiparams12", "tcap.ansiparams12",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams13,
      { "ansiparams13", "tcap.ansiparams13",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams14,
      { "ansiparams14", "tcap.ansiparams14",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams15,
      { "ansiparams15", "tcap.ansiparams15",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams16,
      { "ansiparams16", "tcap.ansiparams16",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams17,
      { "ansiparams17", "tcap.ansiparams17",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams18,
      { "ansiparams18", "tcap.ansiparams18",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams19,
      { "ansiparams19", "tcap.ansiparams19",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams20,
      { "ansiparams20", "tcap.ansiparams20",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_ansiparams21,
      { "ansiparams21", "tcap.ansiparams21",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIParameters", HFILL }},
    { &hf_tcap_componentID,
      { "componentID", "tcap.componentID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.ComponentID", HFILL }},
    { &hf_tcap_parameterrr,
      { "parameterrr", "tcap.parameterrr",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIparamch", HFILL }},
    { &hf_tcap_parameterre,
      { "parameterre", "tcap.parameterre",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIparamch", HFILL }},
    { &hf_tcap_rejectProblem,
      { "rejectProblem", "tcap.rejectProblem",
        FT_INT32, BASE_DEC, VALS(tcap_ProblemPDU_vals), 0,
        "tcap.ProblemPDU", HFILL }},
    { &hf_tcap_parameterrj,
      { "parameterrj", "tcap.parameterrj",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.ANSIparamch", HFILL }},
    { &hf_tcap_national,
      { "national", "tcap.national",
        FT_INT32, BASE_DEC, NULL, 0,
        "tcap.INTEGER_M32768_32767", HFILL }},
    { &hf_tcap_private,
      { "private", "tcap.private",
        FT_INT32, BASE_DEC, NULL, 0,
        "tcap.INTEGER", HFILL }},
    { &hf_tcap_nationaler,
      { "nationaler", "tcap.nationaler",
        FT_INT32, BASE_DEC, NULL, 0,
        "tcap.INTEGER_M32768_32767", HFILL }},
    { &hf_tcap_privateer,
      { "privateer", "tcap.privateer",
        FT_INT32, BASE_DEC, NULL, 0,
        "tcap.INTEGER", HFILL }},
    { &hf_tcap_unidialoguePDU,
      { "unidialoguePDU", "tcap.unidialoguePDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.AUDT_apdu", HFILL }},
    { &hf_tcap_protocol_version,
      { "protocol-version", "tcap.protocol_version",
        FT_BYTES, BASE_HEX, NULL, 0,
        "tcap.T_protocol_version", HFILL }},
    { &hf_tcap_audt_application_context_name,
      { "application-context-name", "tcap.application_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        "tcap.AUDT_application_context_name", HFILL }},
    { &hf_tcap_audt_user_information,
      { "user-information", "tcap.user_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "tcap.AUDT_user_information", HFILL }},
    { &hf_tcap_audt_user_information_item,
      { "Item", "tcap.user_information_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "tcap.EXTERNAL", HFILL }},
    { &hf_tcap_T_protocol_versionrq_version1,
      { "version1", "tcap.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_tcap_T_protocol_versionre_version1,
      { "version1", "tcap.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_tcap_T_protocol_version_version1,
      { "version1", "tcap.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},

/*--- End of included file: packet-tcap-hfarr.c ---*/
#line 324 "packet-tcap-template.c"
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_tcap,
	&ett_param,
	&ett_otid,
	&ett_dtid,
	&ett_tcap_stat,

/*--- Included file: packet-tcap-ettarr.c ---*/
#line 1 "packet-tcap-ettarr.c"
    &ett_tcap_DialoguePDU,
    &ett_tcap_ExternalPDU_U,
    &ett_tcap_UserInformation_U,
    &ett_tcap_AARQ_apdu_U,
    &ett_tcap_T_protocol_versionrq,
    &ett_tcap_AARQ_user_information,
    &ett_tcap_AARE_apdu_U,
    &ett_tcap_T_protocol_versionre,
    &ett_tcap_ABRT_apdu_U,
    &ett_tcap_Associate_source_diagnostic,
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
    &ett_tcap_ERROR,
    &ett_tcap_UniTransactionPDU,
    &ett_tcap_TransactionPDU,
    &ett_tcap_AbortPDU,
    &ett_tcap_T_causeInformation,
    &ett_tcap_DialoguePortionANSI_U,
    &ett_tcap_T_applicationContext,
    &ett_tcap_T_securityContext,
    &ett_tcap_Confidentiality,
    &ett_tcap_T_confidentialityId,
    &ett_tcap_SEQUENCE_OF_ComponentPDU,
    &ett_tcap_ComponentPDU,
    &ett_tcap_InvokePDU,
    &ett_tcap_ANSIparamch,
    &ett_tcap_ReturnResultPDU,
    &ett_tcap_ReturnErrorPDU,
    &ett_tcap_RejectPDU,
    &ett_tcap_OperationCode,
    &ett_tcap_ErrorCode,
    &ett_tcap_UniDialoguePDU,
    &ett_tcap_AUDT_apdu_U,
    &ett_tcap_T_protocol_version,
    &ett_tcap_AUDT_user_information,

/*--- End of included file: packet-tcap-ettarr.c ---*/
#line 334 "packet-tcap-template.c"
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
    ssn_range = range_empty();

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
}


static void range_delete_callback(guint32 ssn)
{
    if ( ssn && !get_ansi_tcap_subdissector(ssn) && !get_itu_tcap_subdissector(ssn) ) {
        dissector_delete("sccp.ssn", ssn, tcap_handle);
    }
}

static void range_add_callback(guint32 ssn)
{
    if (ssn && !get_ansi_tcap_subdissector(ssn) && !get_itu_tcap_subdissector(ssn) ) {
        dissector_add("sccp.ssn", ssn, tcap_handle);
    }
}


static void init_tcap(void) {
    if (ssn_range) {
        range_foreach(ssn_range, range_delete_callback);
        g_free(ssn_range);
    }

    ssn_range = range_copy(global_ssn_range);
    range_foreach(ssn_range, range_add_callback);
    tcapsrt_init_routine();
}

static int
dissect_tcap_param(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset)
{
    gint tag_offset, saved_offset, len_offset;
    tvbuff_t	*next_tvb;
    proto_tree *subtree;
    proto_item *pi;
    gint8 class;
    gboolean pc;
    gint32 tag;
    guint32 len;
    guint32 tag_length;
    guint32 len_length;
    gboolean ind_field;

    while (tvb_reported_length_remaining(tvb, offset) > 0)
    {
	saved_offset = offset;

	offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
	tag_offset = offset;
	offset = get_ber_length(tvb, offset, &len, &ind_field);
	len_offset = offset;

	tag_length = tag_offset - saved_offset;
	len_length = len_offset - tag_offset;

	if (pc)
	{
	    pi = proto_tree_add_text(tree, tvb, saved_offset,
				     len + (len_offset - saved_offset),
				     "CONSTRUCTOR");
	    subtree = proto_item_add_subtree(pi, ett_param);
	    proto_tree_add_uint_format(subtree, hf_tcap_tag, tvb,
				       saved_offset, tag_length, tag,
				       "CONSTRUCTOR Tag");
	    proto_tree_add_uint(subtree, hf_tcap_tag, tvb, saved_offset,
				tag_length, class);

	    proto_tree_add_uint(subtree, hf_tcap_length, tvb, tag_offset,
				len_length, len);

	    if (len-(2*ind_field)) /*should always be positive unless we get an empty contructor pointless? */
	    {
		next_tvb = tvb_new_subset(tvb, offset, len-(2*ind_field),
					  len-(2*ind_field));
		dissect_tcap_param(actx, subtree,next_tvb,0);
	    }

	    if (ind_field)
		    proto_tree_add_text(subtree, tvb, offset+len-2, 2, "CONSTRUCTOR EOC");

	    offset += len;
	}
	else
	{
	    pi = proto_tree_add_text(tree, tvb, saved_offset,
				     len + (len_offset - saved_offset),
				     "Parameter (0x%.2x)", tag);

	    subtree = proto_item_add_subtree(pi, ett_param);

	    proto_tree_add_uint(subtree, hf_tcap_tag, tvb, saved_offset,
			        tag_length, tag);

	    proto_tree_add_uint(subtree, hf_tcap_length, tvb,
				saved_offset+tag_length, len_length, len);

	    if (len) /* check for NULLS */
	    {
		next_tvb = tvb_new_subset(tvb, offset, len, len);
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
  ber_oid_dissector_table = find_dissector_table("ber.oid");

  /*
   * Handle The TCAP Service Response Time
   */
  if ( gtcap_HandleSRT ) {
	  if (!tcap_subdissector_used) {
	    p_tcap_context=tcapsrt_call_matching(tvb, actx->pinfo, tcap_stat_tree, gp_tcapsrt_info);
	    tcap_subdissector_used=TRUE;
	    gp_tcap_context=p_tcap_context;
	    tcap_private.context=p_tcap_context;
	  }else{
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
			  if ( strncmp(p_tcap_context->oid,cur_oid, LENGTH_OID)!=0) {
				  /* ACN, changed, Fallback to lower version
				   * and update the subdissector (purely formal)
				   */
				  g_strlcpy(p_tcap_context->oid,cur_oid, LENGTH_OID);
				  if ( (subdissector_handle = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
					  p_tcap_context->subdissector_handle=subdissector_handle;
					  p_tcap_context->subdissector_present=TRUE;
				  }
			  }
		  } else {
			  /* We do not have the OID in the TCAP context, so store it */
			  g_strlcpy(p_tcap_context->oid,cur_oid, LENGTH_OID);
			  p_tcap_context->oid_present=TRUE;
			  /* Try to find a subdissector according to OID */
			  if ( (subdissector_handle
				  = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
				  p_tcap_context->subdissector_handle=subdissector_handle;
				  p_tcap_context->subdissector_present=TRUE;
			  } else {
			    /* Not found, so try to find a subdissector according to SSN */
			    if ( (subdissector_handle = get_itu_tcap_subdissector(actx->pinfo->match_port))) {
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
			  = get_itu_tcap_subdissector(actx->pinfo->match_port))) {
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
		if ( (subdissector_handle = get_itu_tcap_subdissector(actx->pinfo->match_port))) {
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
  if (is_subdissector)
    call_dissector(subdissector_handle, tvb, actx->pinfo, tree);

  return offset;
}

/*
 * Call ANSI Subdissector to decode the Tcap Component
 */
static int
dissect_tcap_ANSI_ComponentPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_)
{
  dissector_handle_t subdissector_handle;
  gboolean is_subdissector=FALSE;
  struct tcaphash_context_t * p_tcap_context=NULL;

  gchar str[20];


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
    /* tcap_private.TransactionID_str =  bytes_to_str(&(p_tcap_context->session_id),4); */
    g_snprintf(str, sizeof(str), "(%d)",p_tcap_context->session_id);
    tcap_private.TransactionID_str = str;
  }

  if ( (subdissector_handle
	= get_ansi_tcap_subdissector(actx->pinfo->match_port))) {
    /* Found according to SSN */
    is_subdissector=TRUE;
  } else {
    /* Nothing found, take the Data handler */
    subdissector_handle = data_handle;
    is_subdissector=TRUE;
  } /* SSN */

  /* Call the sub dissector if present, and not already called */
  if (is_subdissector)
    call_dissector(subdissector_handle, tvb, actx->pinfo, tree);

  return offset;
}

static int
dissect_tcap_TheExternUserInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_)
{
  /*
   * ok lets look at the oid and ssn and try and find a dissector, otherwise lets decode it.
   */
  ber_oid_dissector_table = find_dissector_table("ber.oid");

  if (ber_oid_dissector_table && tcapext_oid){
    if(!dissector_try_string(ber_oid_dissector_table, tcapext_oid, tvb, actx->pinfo, tree))
      {
	return dissect_tcap_param(actx,tree,tvb,0);
      }
  }
  return offset;
}


void call_tcap_dissector(dissector_handle_t handle, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree) {

	requested_subdissector_handle = handle;

	TRY {
		dissect_tcap(tvb, pinfo, tree);
	} CATCH_ALL {
		requested_subdissector_handle = NULL;
		RETHROW;
	} ENDTRY;

	requested_subdissector_handle = NULL;

}


