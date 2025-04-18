/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-idmp.c                                                              */
/* asn2wrs.py -b -q -L -p idmp -c ./idmp.cnf -s ./packet-idmp-template -D . -O ../.. IDMProtocolSpecification.asn CommonProtocolSpecification.asn */

/* packet-idmp.c
 * Routines for X.519 Internet Directly Mapped Procotol (IDMP) packet dissection
 * Graeme Lunt 2010
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/ipproto.h>
#include <epan/strutil.h>

#include <wsutil/str_util.h>
#include <wsutil/array.h>

#include "packet-tcp.h"

#include "packet-ber.h"
#include "packet-ros.h"
#include "packet-x509ce.h"


#define PNAME  "X.519 Internet Directly Mapped Protocol"
#define PSNAME "IDMP"
#define PFNAME "idmp"

void proto_register_idmp(void);
void proto_reg_handoff_idm(void);
void register_idmp_protocol_info(const char *oid, const ros_info_t *rinfo, int proto _U_, const char *name);

static bool           idmp_desegment       = true;
#define IDMP_TCP_PORT     1102 /* made up for now - not IANA registered */
static bool           idmp_reassemble      = true;
static dissector_handle_t idmp_handle;

static proto_tree *top_tree;
static const char *protocolID;
static const char *saved_protocolID;
static uint32_t    opcode           = -1;

/* Initialize the protocol and registered fields */
int proto_idmp;

static int hf_idmp_version;
static int hf_idmp_final;
static int hf_idmp_length;
static int hf_idmp_PDU;

static reassembly_table idmp_reassembly_table;

static int hf_idmp_fragments;
static int hf_idmp_fragment;
static int hf_idmp_fragment_overlap;
static int hf_idmp_fragment_overlap_conflicts;
static int hf_idmp_fragment_multiple_tails;
static int hf_idmp_fragment_too_long_fragment;
static int hf_idmp_fragment_error;
static int hf_idmp_fragment_count;
static int hf_idmp_reassembled_in;
static int hf_idmp_reassembled_length;
static int hf_idmp_segment_data;

static int ett_idmp_fragment;
static int ett_idmp_fragments;

static const fragment_items idmp_frag_items = {
    /* Fragment subtrees */
    &ett_idmp_fragment,
    &ett_idmp_fragments,
    /* Fragment fields */
    &hf_idmp_fragments,
    &hf_idmp_fragment,
    &hf_idmp_fragment_overlap,
    &hf_idmp_fragment_overlap_conflicts,
    &hf_idmp_fragment_multiple_tails,
    &hf_idmp_fragment_too_long_fragment,
    &hf_idmp_fragment_error,
    &hf_idmp_fragment_count,
    /* Reassembled in field */
    &hf_idmp_reassembled_in,
    /* Reassembled length field */
    &hf_idmp_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "IDMP fragments"
};


static int call_idmp_oid_callback(tvbuff_t *tvb, int offset, packet_info *pinfo, int op, proto_tree *tree, struct SESSION_DATA_STRUCTURE *session)
{
    if(session != NULL) {

        /* XXX saved_protocolID should be part of session data */
        if (!saved_protocolID) {
            saved_protocolID = "[ unknown ]";
        }

        /* mimic ROS! */
        session->ros_op = op;
        offset = call_ros_oid_callback(saved_protocolID, tvb, offset, pinfo, tree, session);
    }

    return offset;

}

static int hf_idmp_bind;                          /* IdmBind */
static int hf_idmp_bindResult;                    /* IdmBindResult */
static int hf_idmp_bindError;                     /* IdmBindError */
static int hf_idmp_request;                       /* Request */
static int hf_idmp_idm_result;                    /* IdmResult */
static int hf_idmp_idm_error;                     /* Error */
static int hf_idmp_reject;                        /* IdmReject */
static int hf_idmp_unbind;                        /* Unbind */
static int hf_idmp_abort;                         /* Abort */
static int hf_idmp_startTLS;                      /* StartTLS */
static int hf_idmp_tLSResponse;                   /* TLSResponse */
static int hf_idmp_protocolID;                    /* OBJECT_IDENTIFIER */
static int hf_idmp_callingAETitle;                /* GeneralName */
static int hf_idmp_calledAETitle;                 /* GeneralName */
static int hf_idmp_bind_argument;                 /* Bind_argument */
static int hf_idmp_respondingAETitle;             /* GeneralName */
static int hf_idmp_bind_result;                   /* Bind_result */
static int hf_idmp_bind_errcode;                  /* Bind_errcode */
static int hf_idmp_aETitleError;                  /* T_aETitleError */
static int hf_idmp_bind_error;                    /* Bind_error */
static int hf_idmp_invokeID;                      /* INTEGER */
static int hf_idmp_opcode;                        /* Code */
static int hf_idmp_argument;                      /* T_argument */
static int hf_idmp_idm_invokeID;                  /* InvokeId */
static int hf_idmp_result;                        /* T_result */
static int hf_idmp_errcode;                       /* T_errcode */
static int hf_idmp_error;                         /* T_error */
static int hf_idmp_reason;                        /* T_reason */
static int hf_idmp_local;                         /* T_local */
static int hf_idmp_global;                        /* OBJECT_IDENTIFIER */
static int hf_idmp_present;                       /* INTEGER */
static int hf_idmp_absent;                        /* NULL */

/* Initialize the subtree pointers */
static int ett_idmp;
static int ett_idmp_IDM_PDU;
static int ett_idmp_IdmBind;
static int ett_idmp_IdmBindResult;
static int ett_idmp_IdmBindError;
static int ett_idmp_Request;
static int ett_idmp_IdmResult;
static int ett_idmp_Error;
static int ett_idmp_IdmReject;
static int ett_idmp_Code;
static int ett_idmp_InvokeId;



static int
dissect_idmp_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &protocolID);

  return offset;
}



static int
dissect_idmp_Bind_argument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct SESSION_DATA_STRUCTURE *session = (struct SESSION_DATA_STRUCTURE*)actx->private_data;
  offset = call_idmp_oid_callback(tvb, offset, actx->pinfo, (ROS_OP_BIND | ROS_OP_ARGUMENT), top_tree, session);


  return offset;
}


static const ber_sequence_t IdmBind_sequence[] = {
  { &hf_idmp_protocolID     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_idmp_OBJECT_IDENTIFIER },
  { &hf_idmp_callingAETitle , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509ce_GeneralName },
  { &hf_idmp_calledAETitle  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509ce_GeneralName },
  { &hf_idmp_bind_argument  , BER_CLASS_CON, 2, 0, dissect_idmp_Bind_argument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_idmp_IdmBind(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  protocolID = saved_protocolID = NULL;
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IdmBind_sequence, hf_index, ett_idmp_IdmBind);

  if (protocolID) {
    saved_protocolID = wmem_strdup(wmem_epan_scope(), protocolID);
  }
  return offset;
}



static int
dissect_idmp_Bind_result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct SESSION_DATA_STRUCTURE *session = (struct SESSION_DATA_STRUCTURE*)actx->private_data;
  offset = call_idmp_oid_callback(tvb, offset, actx->pinfo, (ROS_OP_BIND | ROS_OP_RESULT), top_tree, session);


  return offset;
}


static const ber_sequence_t IdmBindResult_sequence[] = {
  { &hf_idmp_protocolID     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_idmp_OBJECT_IDENTIFIER },
  { &hf_idmp_respondingAETitle, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509ce_GeneralName },
  { &hf_idmp_bind_result    , BER_CLASS_CON, 1, 0, dissect_idmp_Bind_result },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_idmp_IdmBindResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IdmBindResult_sequence, hf_index, ett_idmp_IdmBindResult);

  return offset;
}



static int
dissect_idmp_Bind_errcode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {


  return offset;
}


static const value_string idmp_T_aETitleError_vals[] = {
  {   0, "callingAETitleNotAccepted" },
  {   1, "calledAETitleNotRecognized" },
  { 0, NULL }
};


static int
dissect_idmp_T_aETitleError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_idmp_Bind_error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct SESSION_DATA_STRUCTURE *session = (struct SESSION_DATA_STRUCTURE*)actx->private_data;
  offset = call_idmp_oid_callback(tvb, offset, actx->pinfo, (ROS_OP_BIND| ROS_OP_ERROR), top_tree, session);


  return offset;
}


static const ber_sequence_t IdmBindError_sequence[] = {
  { &hf_idmp_protocolID     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_idmp_OBJECT_IDENTIFIER },
  { &hf_idmp_bind_errcode   , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_idmp_Bind_errcode },
  { &hf_idmp_respondingAETitle, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509ce_GeneralName },
  { &hf_idmp_aETitleError   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_idmp_T_aETitleError },
  { &hf_idmp_bind_error     , BER_CLASS_CON, 1, 0, dissect_idmp_Bind_error },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_idmp_IdmBindError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IdmBindError_sequence, hf_index, ett_idmp_IdmBindError);

  return offset;
}



static int
dissect_idmp_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_idmp_T_local(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &opcode);

  return offset;
}


static const value_string idmp_Code_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const ber_choice_t Code_choice[] = {
  {   0, &hf_idmp_local          , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_idmp_T_local },
  {   1, &hf_idmp_global         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_idmp_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_idmp_Code(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Code_choice, hf_index, ett_idmp_Code,
                                 NULL);

  return offset;
}



static int
dissect_idmp_T_argument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct SESSION_DATA_STRUCTURE *session = (struct SESSION_DATA_STRUCTURE*)actx->private_data;
  offset = call_idmp_oid_callback(tvb, offset, actx->pinfo, (ROS_OP_INVOKE | ROS_OP_ARGUMENT | opcode), top_tree, session);


  return offset;
}


static const ber_sequence_t Request_sequence[] = {
  { &hf_idmp_invokeID       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_idmp_INTEGER },
  { &hf_idmp_opcode         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_idmp_Code },
  { &hf_idmp_argument       , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_idmp_T_argument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_idmp_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Request_sequence, hf_index, ett_idmp_Request);

  return offset;
}



static int
dissect_idmp_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string idmp_InvokeId_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};

static const ber_choice_t InvokeId_choice[] = {
  {   0, &hf_idmp_present        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_idmp_INTEGER },
  {   1, &hf_idmp_absent         , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_idmp_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_idmp_InvokeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InvokeId_choice, hf_index, ett_idmp_InvokeId,
                                 NULL);

  return offset;
}



static int
dissect_idmp_T_result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct SESSION_DATA_STRUCTURE *session = (struct SESSION_DATA_STRUCTURE*)actx->private_data;
  offset = call_idmp_oid_callback(tvb, offset, actx->pinfo, (ROS_OP_INVOKE | ROS_OP_RESULT | opcode), top_tree, session);


  return offset;
}


static const ber_sequence_t IdmResult_sequence[] = {
  { &hf_idmp_idm_invokeID   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_idmp_InvokeId },
  { &hf_idmp_opcode         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_idmp_Code },
  { &hf_idmp_result         , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_idmp_T_result },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_idmp_IdmResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IdmResult_sequence, hf_index, ett_idmp_IdmResult);

  return offset;
}



static int
dissect_idmp_T_errcode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {


  return offset;
}



static int
dissect_idmp_T_error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {


  return offset;
}


static const ber_sequence_t Error_sequence[] = {
  { &hf_idmp_invokeID       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_idmp_INTEGER },
  { &hf_idmp_errcode        , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_idmp_T_errcode },
  { &hf_idmp_error          , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_idmp_T_error },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_idmp_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Error_sequence, hf_index, ett_idmp_Error);

  return offset;
}


static const value_string idmp_T_reason_vals[] = {
  {   0, "mistypedPDU" },
  {   1, "duplicateInvokeIDRequest" },
  {   2, "unsupportedOperationRequest" },
  {   3, "unknownOperationRequest" },
  {   4, "mistypedArgumentRequest" },
  {   5, "resourceLimitationRequest" },
  {   6, "unknownInvokeIDResult" },
  {   7, "mistypedResultRequest" },
  {   8, "unknownInvokeIDError" },
  {   9, "unknownError" },
  {  10, "mistypedParameterError" },
  { 0, NULL }
};


static int
dissect_idmp_T_reason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t IdmReject_sequence[] = {
  { &hf_idmp_invokeID       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_idmp_INTEGER },
  { &hf_idmp_reason         , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_idmp_T_reason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_idmp_IdmReject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IdmReject_sequence, hf_index, ett_idmp_IdmReject);

  return offset;
}



static int
dissect_idmp_Unbind(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string idmp_Abort_vals[] = {
  {   0, "mistypedPDU" },
  {   1, "unboundRequest" },
  {   2, "invalidPDU" },
  {   3, "resourceLimitation" },
  {   4, "connectionFailed" },
  {   5, "invalidProtocol" },
  {   6, "reasonNotSpecified" },
  { 0, NULL }
};


static int
dissect_idmp_Abort(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_idmp_StartTLS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string idmp_TLSResponse_vals[] = {
  {   0, "success" },
  {   1, "operationsError" },
  {   2, "protocolError" },
  {   3, "unavailable" },
  { 0, NULL }
};


static int
dissect_idmp_TLSResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string idmp_IDM_PDU_vals[] = {
  {   0, "bind" },
  {   1, "bindResult" },
  {   2, "bindError" },
  {   3, "request" },
  {   4, "result" },
  {   5, "error" },
  {   6, "reject" },
  {   7, "unbind" },
  {   8, "abort" },
  {   9, "startTLS" },
  {  10, "tLSResponse" },
  { 0, NULL }
};

static const ber_choice_t IDM_PDU_choice[] = {
  {   0, &hf_idmp_bind           , BER_CLASS_CON, 0, 0, dissect_idmp_IdmBind },
  {   1, &hf_idmp_bindResult     , BER_CLASS_CON, 1, 0, dissect_idmp_IdmBindResult },
  {   2, &hf_idmp_bindError      , BER_CLASS_CON, 2, 0, dissect_idmp_IdmBindError },
  {   3, &hf_idmp_request        , BER_CLASS_CON, 3, 0, dissect_idmp_Request },
  {   4, &hf_idmp_idm_result     , BER_CLASS_CON, 4, 0, dissect_idmp_IdmResult },
  {   5, &hf_idmp_idm_error      , BER_CLASS_CON, 5, 0, dissect_idmp_Error },
  {   6, &hf_idmp_reject         , BER_CLASS_CON, 6, 0, dissect_idmp_IdmReject },
  {   7, &hf_idmp_unbind         , BER_CLASS_CON, 7, 0, dissect_idmp_Unbind },
  {   8, &hf_idmp_abort          , BER_CLASS_CON, 8, 0, dissect_idmp_Abort },
  {   9, &hf_idmp_startTLS       , BER_CLASS_CON, 9, 0, dissect_idmp_StartTLS },
  {  10, &hf_idmp_tLSResponse    , BER_CLASS_CON, 10, 0, dissect_idmp_TLSResponse },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_idmp_IDM_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IDM_PDU_choice, hf_index, ett_idmp_IDM_PDU,
                                 NULL);

  return offset;
}


void
register_idmp_protocol_info(const char *oid, const ros_info_t *rinfo, int proto _U_, const char *name)
{
    /* just register with ROS for now */
    register_ros_protocol_info(oid, rinfo, proto, name, false);
}


static int dissect_idmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    int offset = 0;

    proto_item                    *item;
    proto_tree                    *tree;
    asn1_ctx_t                     asn1_ctx;
    struct SESSION_DATA_STRUCTURE  session;
    bool                           idmp_final;
    uint32_t                       idmp_length;
    fragment_head                 *fd_head;
    conversation_t                *conv;
    uint32_t                       dst_ref = 0;

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

    conv = find_conversation_pinfo(pinfo, 0);
    if (conv) {
        /* Found a conversation, also use index for the generated dst_ref */
        dst_ref = conv->conv_index;
    }

    /* save parent_tree so subdissectors can create new top nodes */
    top_tree=parent_tree;

    item = proto_tree_add_item(parent_tree, proto_idmp, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_idmp);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IDMP");

    /* now check the segment fields */

    proto_tree_add_item(tree, hf_idmp_version, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
    proto_tree_add_item(tree, hf_idmp_final, tvb, offset, 1, ENC_BIG_ENDIAN);
    idmp_final = tvb_get_uint8(tvb, offset); offset++;
    proto_tree_add_item(tree, hf_idmp_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    idmp_length = tvb_get_ntohl(tvb, offset); offset += 4;

    asn1_ctx.private_data = &session;

    if(idmp_reassemble) {

        pinfo->fragmented = !idmp_final;

        col_append_fstr(pinfo->cinfo, COL_INFO, " [%sIDMP fragment, %u byte%s]",
                            idmp_final ? "Final " : "" ,
                            idmp_length, plurality(idmp_length, "", "s"));

        fd_head = fragment_add_seq_next(&idmp_reassembly_table, tvb, offset,
                                        pinfo, dst_ref, NULL,
                                        idmp_length, !idmp_final);

        if(fd_head && fd_head->next) {
            proto_tree_add_item(tree, hf_idmp_segment_data, tvb, offset, (idmp_length) ? -1 : 0, ENC_NA);

            if (idmp_final) {
                /* This is the last segment */
                tvb = process_reassembled_data (tvb, offset, pinfo,
                                                "Reassembled IDMP", fd_head, &idmp_frag_items, NULL, tree);
                offset = 0;
            } else if (pinfo->num != fd_head->reassembled_in) {
                /* Add a "Reassembled in" link if not reassembled in this frame */
                proto_tree_add_uint (tree, hf_idmp_reassembled_in,
                                     tvb, 0, 0, fd_head->reassembled_in);
            }
        }

    } else {
        if(!idmp_final) {

            col_append_fstr(pinfo->cinfo, COL_INFO, " [IDMP fragment, %u byte%s, IDMP reassembly not enabled]",
                                idmp_length, plurality(idmp_length, "", "s"));

            proto_tree_add_bytes_format_value(tree, hf_idmp_segment_data, tvb, offset, (idmp_length) ? -1 : 0,
                                NULL, "(IDMP reassembly not enabled)");
        }
    }
    /* not reassembling - just dissect */
    if(idmp_final) {
        asn1_ctx.private_data = &session;
        dissect_idmp_IDM_PDU(false, tvb, offset, &asn1_ctx, tree, hf_idmp_PDU);
    }

    return tvb_captured_length(tvb);
}

static unsigned get_idmp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                              int offset, void *data _U_)
{
    uint32_t len;

    len = tvb_get_ntohl(tvb, offset + 2);

    return len + 6;
}

static int dissect_idmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, parent_tree, idmp_desegment, 0, get_idmp_pdu_len, dissect_idmp, data);
	return tvb_captured_length(tvb);
}

static void idmp_reassemble_cleanup(void)
{
    protocolID = NULL; // packet scoped
    saved_protocolID = NULL; // epan scoped copy of protocolID
    opcode = -1;
}

/*--- proto_register_idmp -------------------------------------------*/
void proto_register_idmp(void)
{
    /* List of fields */
    static hf_register_info hf[] = {
        { &hf_idmp_version,
          { "version", "idmp.version",
            FT_INT8, BASE_DEC, NULL, 0,
            "idmp.INTEGER", HFILL }},
        { &hf_idmp_final,
          { "final", "idmp.final",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            "idmp.BOOLEAN", HFILL }},
        { &hf_idmp_length,
          { "length", "idmp.length",
            FT_INT32, BASE_DEC, NULL, 0,
            "idmp.INTEGER", HFILL }},
        { &hf_idmp_PDU,
          { "IDM-PDU", "idmp.pdu",
            FT_UINT32, BASE_DEC, VALS(idmp_IDM_PDU_vals), 0,
            "idmp.PDU", HFILL }},
        /* Fragment entries */
        { &hf_idmp_fragments,
          { "IDMP fragments", "idmp.fragments", FT_NONE, BASE_NONE,
            NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment,
          { "IDMP fragment", "idmp.fragment", FT_FRAMENUM, BASE_NONE,
            NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment_overlap,
          { "IDMP fragment overlap", "idmp.fragment.overlap", FT_BOOLEAN,
            BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment_overlap_conflicts,
          { "IDMP fragment overlapping with conflicting data",
            "idmp.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE,
            NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment_multiple_tails,
          { "IDMP has multiple tail fragments",
            "idmp.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
            NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment_too_long_fragment,
          { "IDMP fragment too long", "idmp.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment_error,
          { "IDMP defragmentation error", "idmp.fragment.error", FT_FRAMENUM,
            BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment_count,
          { "IDMP fragment count", "idmp.fragment.count", FT_UINT32, BASE_DEC,
            NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_reassembled_in,
          { "Reassembled IDMP in frame", "idmp.reassembled.in", FT_FRAMENUM, BASE_NONE,
            NULL, 0x00, "This IDMP packet is reassembled in this frame", HFILL } },
        { &hf_idmp_reassembled_length,
          { "Reassembled IDMP length", "idmp.reassembled.length", FT_UINT32, BASE_DEC,
            NULL, 0x00, "The total length of the reassembled payload", HFILL } },
        { &hf_idmp_segment_data,
          { "IDMP segment data", "idmp.segment_data", FT_BYTES, BASE_NONE,
            NULL, 0x00, NULL, HFILL } },

    { &hf_idmp_bind,
      { "bind", "idmp.bind_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IdmBind", HFILL }},
    { &hf_idmp_bindResult,
      { "bindResult", "idmp.bindResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IdmBindResult", HFILL }},
    { &hf_idmp_bindError,
      { "bindError", "idmp.bindError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IdmBindError", HFILL }},
    { &hf_idmp_request,
      { "request", "idmp.request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_idmp_idm_result,
      { "result", "idmp.idm_result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IdmResult", HFILL }},
    { &hf_idmp_idm_error,
      { "error", "idmp.idm_error_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_idmp_reject,
      { "reject", "idmp.reject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IdmReject", HFILL }},
    { &hf_idmp_unbind,
      { "unbind", "idmp.unbind_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_idmp_abort,
      { "abort", "idmp.abort",
        FT_UINT32, BASE_DEC, VALS(idmp_Abort_vals), 0,
        NULL, HFILL }},
    { &hf_idmp_startTLS,
      { "startTLS", "idmp.startTLS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_idmp_tLSResponse,
      { "tLSResponse", "idmp.tLSResponse",
        FT_UINT32, BASE_DEC, VALS(idmp_TLSResponse_vals), 0,
        NULL, HFILL }},
    { &hf_idmp_protocolID,
      { "protocolID", "idmp.protocolID",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_idmp_callingAETitle,
      { "callingAETitle", "idmp.callingAETitle",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralName", HFILL }},
    { &hf_idmp_calledAETitle,
      { "calledAETitle", "idmp.calledAETitle",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralName", HFILL }},
    { &hf_idmp_bind_argument,
      { "argument", "idmp.bind_argument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Bind_argument", HFILL }},
    { &hf_idmp_respondingAETitle,
      { "respondingAETitle", "idmp.respondingAETitle",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralName", HFILL }},
    { &hf_idmp_bind_result,
      { "result", "idmp.bind_result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Bind_result", HFILL }},
    { &hf_idmp_bind_errcode,
      { "errcode", "idmp.bind_errcode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Bind_errcode", HFILL }},
    { &hf_idmp_aETitleError,
      { "aETitleError", "idmp.aETitleError",
        FT_UINT32, BASE_DEC, VALS(idmp_T_aETitleError_vals), 0,
        NULL, HFILL }},
    { &hf_idmp_bind_error,
      { "error", "idmp.bind_error_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Bind_error", HFILL }},
    { &hf_idmp_invokeID,
      { "invokeID", "idmp.invokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_idmp_opcode,
      { "opcode", "idmp.opcode",
        FT_UINT32, BASE_DEC, VALS(idmp_Code_vals), 0,
        "Code", HFILL }},
    { &hf_idmp_argument,
      { "argument", "idmp.argument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_idmp_idm_invokeID,
      { "invokeID", "idmp.idmResult.invokeID",
        FT_UINT32, BASE_DEC, VALS(idmp_InvokeId_vals), 0,
        NULL, HFILL }},
    { &hf_idmp_result,
      { "result", "idmp.result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_idmp_errcode,
      { "errcode", "idmp.errcode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_idmp_error,
      { "error", "idmp.error_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_idmp_reason,
      { "reason", "idmp.reason",
        FT_UINT32, BASE_DEC, VALS(idmp_T_reason_vals), 0,
        NULL, HFILL }},
    { &hf_idmp_local,
      { "local", "idmp.local",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_idmp_global,
      { "global", "idmp.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_idmp_present,
      { "present", "idmp.present",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_idmp_absent,
      { "absent", "idmp.absent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    };

    /* List of subtrees */
    static int *ett[] = {
        &ett_idmp,
        &ett_idmp_fragment,
        &ett_idmp_fragments,
    &ett_idmp_IDM_PDU,
    &ett_idmp_IdmBind,
    &ett_idmp_IdmBindResult,
    &ett_idmp_IdmBindError,
    &ett_idmp_Request,
    &ett_idmp_IdmResult,
    &ett_idmp_Error,
    &ett_idmp_IdmReject,
    &ett_idmp_Code,
    &ett_idmp_InvokeId,
    };
    module_t *idmp_module;

    /* Register protocol */
    proto_idmp = proto_register_protocol(PNAME, PSNAME, PFNAME);

    /* Register fields and subtrees */
    proto_register_field_array(proto_idmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    idmp_handle = register_dissector("idmp", dissect_idmp_tcp, proto_idmp);

    register_cleanup_routine (&idmp_reassemble_cleanup);
    reassembly_table_register (&idmp_reassembly_table,
                           &addresses_reassembly_table_functions);


    /* Register our configuration options for IDMP, particularly our port */

    idmp_module = prefs_register_protocol_subtree("OSI/X.500", proto_idmp, NULL);

    prefs_register_bool_preference(idmp_module, "desegment_idmp_messages",
                                   "Reassemble IDMP messages spanning multiple TCP segments",
                                   "Whether the IDMP dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &idmp_desegment);

    prefs_register_bool_preference(idmp_module, "reassemble",
                                   "Reassemble segmented IDMP datagrams",
                                   "Whether segmented IDMP datagrams should be reassembled."
                                   " To use this option, you must also enable"
                                   " \"Allow subdissectors to reassemble TCP streams\""
                                   " in the TCP protocol settings.", &idmp_reassemble);
}


/*--- proto_reg_handoff_idm --- */
void proto_reg_handoff_idm(void) {
    dissector_add_uint_with_preference("tcp.port", IDMP_TCP_PORT, idmp_handle);
}
