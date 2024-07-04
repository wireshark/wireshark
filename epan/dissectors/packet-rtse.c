/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-rtse.c                                                              */
/* asn2wrs.py -b -q -L -p rtse -c ./rtse.cnf -s ./packet-rtse-template -D . -O ../.. rtse.asn */

/* packet-rtse-template.c
 * Routines for RTSE packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include <wsutil/str_util.h>

#include "packet-ber.h"
#include "packet-pres.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"

#define PNAME  "X.228 OSI Reliable Transfer Service"
#define PSNAME "RTSE"
#define PFNAME "rtse"

void proto_register_rtse(void);
void proto_reg_handoff_rtse(void);

/* Initialize the protocol and registered fields */
static int proto_rtse;

static bool open_request=false;
static uint32_t app_proto=0;

static proto_tree *top_tree;

/* Preferences */
static bool rtse_reassemble = true;

static int hf_rtse_rtorq_apdu;                    /* RTORQapdu */
static int hf_rtse_rtoac_apdu;                    /* RTOACapdu */
static int hf_rtse_rtorj_apdu;                    /* RTORJapdu */
static int hf_rtse_rttp_apdu;                     /* RTTPapdu */
static int hf_rtse_rttr_apdu;                     /* RTTRapdu */
static int hf_rtse_rtab_apdu;                     /* RTABapdu */
static int hf_rtse_checkpointSize;                /* INTEGER */
static int hf_rtse_windowSize;                    /* INTEGER */
static int hf_rtse_dialogueMode;                  /* T_dialogueMode */
static int hf_rtse_connectionDataRQ;              /* ConnectionData */
static int hf_rtse_applicationProtocol;           /* T_applicationProtocol */
static int hf_rtse_connectionDataAC;              /* ConnectionData */
static int hf_rtse_refuseReason;                  /* RefuseReason */
static int hf_rtse_userDataRJ;                    /* T_userDataRJ */
static int hf_rtse_abortReason;                   /* AbortReason */
static int hf_rtse_reflectedParameter;            /* BIT_STRING */
static int hf_rtse_userdataAB;                    /* T_userdataAB */
static int hf_rtse_open;                          /* T_open */
static int hf_rtse_recover;                       /* SessionConnectionIdentifier */
static int hf_rtse_callingSSuserReference;        /* CallingSSuserReference */
static int hf_rtse_commonReference;               /* CommonReference */
static int hf_rtse_additionalReferenceInformation;  /* AdditionalReferenceInformation */
static int hf_rtse_t61String;                     /* T_t61String */
static int hf_rtse_octetString;                   /* T_octetString */

/* Initialize the subtree pointers */
static int ett_rtse;
static int ett_rtse_RTSE_apdus;
static int ett_rtse_RTORQapdu;
static int ett_rtse_RTOACapdu;
static int ett_rtse_RTORJapdu;
static int ett_rtse_RTABapdu;
static int ett_rtse_ConnectionData;
static int ett_rtse_SessionConnectionIdentifier;
static int ett_rtse_CallingSSuserReference;

static expert_field ei_rtse_dissector_oid_not_implemented;
static expert_field ei_rtse_unknown_rtse_pdu;
static expert_field ei_rtse_abstract_syntax;

static dissector_table_t rtse_oid_dissector_table;
static dissector_handle_t rtse_handle;
static int ett_rtse_unknown;

static reassembly_table rtse_reassembly_table;

static int hf_rtse_segment_data;
static int hf_rtse_fragments;
static int hf_rtse_fragment;
static int hf_rtse_fragment_overlap;
static int hf_rtse_fragment_overlap_conflicts;
static int hf_rtse_fragment_multiple_tails;
static int hf_rtse_fragment_too_long_fragment;
static int hf_rtse_fragment_error;
static int hf_rtse_fragment_count;
static int hf_rtse_reassembled_in;
static int hf_rtse_reassembled_length;

static int ett_rtse_fragment;
static int ett_rtse_fragments;

static const fragment_items rtse_frag_items = {
    /* Fragment subtrees */
    &ett_rtse_fragment,
    &ett_rtse_fragments,
    /* Fragment fields */
    &hf_rtse_fragments,
    &hf_rtse_fragment,
    &hf_rtse_fragment_overlap,
    &hf_rtse_fragment_overlap_conflicts,
    &hf_rtse_fragment_multiple_tails,
    &hf_rtse_fragment_too_long_fragment,
    &hf_rtse_fragment_error,
    &hf_rtse_fragment_count,
    /* Reassembled in field */
    &hf_rtse_reassembled_in,
    /* Reassembled length field */
    &hf_rtse_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "RTSE fragments"
};

void
register_rtse_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto, const char *name, bool uses_ros)
{
/* XXX: Note that this fcn is called from proto_reg_handoff in *other* dissectors ... */

  static  dissector_handle_t ros_handle = NULL;

  if (ros_handle == NULL)
    ros_handle = find_dissector("ros");

  /* register RTSE with the BER (ACSE) */
  register_ber_oid_dissector_handle(oid, rtse_handle, proto, name);

  if (uses_ros) {
    /* make sure we call ROS ... */
    dissector_add_string("rtse.oid", oid, ros_handle);

    /* and then tell ROS how to dissect the AS*/
    if (dissector != NULL)
      register_ros_oid_dissector_handle(oid, dissector, proto, name, true);

  } else {
    /* otherwise we just remember how to dissect the AS */
    dissector_add_string("rtse.oid", oid, dissector);
  }
}

static int
call_rtse_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data)
{
    tvbuff_t *next_tvb;
    int len;

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    if ((len = dissector_try_string(rtse_oid_dissector_table, oid, next_tvb, pinfo, tree, data)) == 0) {
        proto_item *item;
        proto_tree *next_tree;

        next_tree = proto_tree_add_subtree_format(tree, next_tvb, 0, -1, ett_rtse_unknown, &item,
                "RTSE: Dissector for OID:%s not implemented. Contact Wireshark developers if you want this supported", oid);

        expert_add_info_format(pinfo, item, &ei_rtse_dissector_oid_not_implemented,
                                       "RTSE: Dissector for OID %s not implemented", oid);
        len = dissect_unknown_ber(pinfo, next_tvb, offset, next_tree);
    }

    offset += len;

    return offset;
}

static int
call_rtse_external_type_callback(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_)
{
    const char    *oid = NULL;

    if (actx->external.indirect_ref_present) {

        oid = (const char *)find_oid_by_pres_ctx_id(actx->pinfo, actx->external.indirect_reference);

        if (!oid)
            proto_tree_add_expert_format(tree, actx->pinfo, &ei_rtse_abstract_syntax, tvb, offset, tvb_captured_length_remaining(tvb, offset),
                    "Unable to determine abstract syntax for indirect reference: %d.", actx->external.indirect_reference);
    } else if (actx->external.direct_ref_present) {
        oid = actx->external.direct_reference;
    }

    if (oid)
        offset = call_rtse_oid_callback(oid, tvb, offset, actx->pinfo, top_tree ? top_tree : tree, actx->private_data);

    return offset;
}



static int
dissect_rtse_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string rtse_T_dialogueMode_vals[] = {
  {   0, "monologue" },
  {   1, "twa" },
  { 0, NULL }
};


static int
dissect_rtse_T_dialogueMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_rtse_T_open(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

        struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE*)actx->private_data;
        const char *oid = NULL;

        switch(app_proto)  {
        case 1:         /* mts-transfer-protocol-1984 */
                oid = "applicationProtocol.1";
                break;
        case 12:        /* mts-transfer-protocol */
                oid = "applicationProtocol.12";
                break;
        default:
                if(session && session->pres_ctx_id)
                        oid = find_oid_by_pres_ctx_id(actx->pinfo, session->pres_ctx_id);
                break;
        }

        if(!oid) /* XXX: problem here is we haven't decoded the applicationProtocol yet - so we make assumptions! */
                oid = "applicationProtocol.12";

        if(oid) {

                offset = call_rtse_oid_callback(oid, tvb, offset, actx->pinfo, top_tree ? top_tree : tree, session);
        }

        /* else XXX: need to flag we can't find the presentation context */


  return offset;
}



static int
dissect_rtse_T_t61String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *string = NULL;
    offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            &string);

  if(open_request && string)
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", tvb_get_string_enc(actx->pinfo->pool, string, 0,
                                                                            tvb_reported_length(string), ENC_T61));


  return offset;
}



static int
dissect_rtse_T_octetString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *string = NULL;
    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &string);

  if(open_request && string)
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", tvb_format_text(actx->pinfo->pool, string, 0, tvb_reported_length(string)));


  return offset;
}


static const value_string rtse_CallingSSuserReference_vals[] = {
  {   0, "t61String" },
  {   1, "octetString" },
  { 0, NULL }
};

static const ber_choice_t CallingSSuserReference_choice[] = {
  {   0, &hf_rtse_t61String      , BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_rtse_T_t61String },
  {   1, &hf_rtse_octetString    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_rtse_T_octetString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_rtse_CallingSSuserReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CallingSSuserReference_choice, hf_index, ett_rtse_CallingSSuserReference,
                                 NULL);

  return offset;
}



static int
dissect_rtse_CommonReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *string = NULL;
    offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index, NULL, NULL);

  if(open_request && string)
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", tvb_format_text(actx->pinfo->pool, string, 0, tvb_reported_length(string)));


  return offset;
}



static int
dissect_rtse_AdditionalReferenceInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t SessionConnectionIdentifier_sequence[] = {
  { &hf_rtse_callingSSuserReference, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_rtse_CallingSSuserReference },
  { &hf_rtse_commonReference, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_rtse_CommonReference },
  { &hf_rtse_additionalReferenceInformation, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_AdditionalReferenceInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_rtse_SessionConnectionIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if(open_request){
    col_append_str(actx->pinfo->cinfo, COL_INFO, "Recover");
  }
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SessionConnectionIdentifier_sequence, hf_index, ett_rtse_SessionConnectionIdentifier);



  return offset;
}


static const value_string rtse_ConnectionData_vals[] = {
  {   0, "open" },
  {   1, "recover" },
  { 0, NULL }
};

static const ber_choice_t ConnectionData_choice[] = {
  {   0, &hf_rtse_open           , BER_CLASS_CON, 0, 0, dissect_rtse_T_open },
  {   1, &hf_rtse_recover        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_rtse_SessionConnectionIdentifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_rtse_ConnectionData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ConnectionData_choice, hf_index, ett_rtse_ConnectionData,
                                 NULL);

  return offset;
}


static const value_string rtse_T_applicationProtocol_vals[] = {
  {  12, "mts-transfer-protocol" },
  {   1, "mts-transfer-protocol-1984" },
  { 0, NULL }
};


static int
dissect_rtse_T_applicationProtocol(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_ber_integer(true, actx, tree, tvb, offset, hf_index, &app_proto);


  return offset;
}


static const ber_sequence_t RTORQapdu_set[] = {
  { &hf_rtse_checkpointSize , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_INTEGER },
  { &hf_rtse_windowSize     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_INTEGER },
  { &hf_rtse_dialogueMode   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_T_dialogueMode },
  { &hf_rtse_connectionDataRQ, BER_CLASS_CON, 3, BER_FLAGS_NOTCHKTAG, dissect_rtse_ConnectionData },
  { &hf_rtse_applicationProtocol, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_T_applicationProtocol },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_rtse_RTORQapdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE*)actx->private_data;

  if(session != NULL)
        session->ros_op = (ROS_OP_BIND | ROS_OP_ARGUMENT);
  open_request=true;
    offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RTORQapdu_set, hf_index, ett_rtse_RTORQapdu);

  open_request=false;


  return offset;
}


static const ber_sequence_t RTOACapdu_set[] = {
  { &hf_rtse_checkpointSize , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_INTEGER },
  { &hf_rtse_windowSize     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_INTEGER },
  { &hf_rtse_connectionDataAC, BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_rtse_ConnectionData },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_rtse_RTOACapdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE*)actx->private_data;

  if(session != NULL)
        session->ros_op = (ROS_OP_BIND | ROS_OP_RESULT);

    offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RTOACapdu_set, hf_index, ett_rtse_RTOACapdu);



  return offset;
}


static const value_string rtse_RefuseReason_vals[] = {
  {   0, "rtsBusy" },
  {   1, "cannotRecover" },
  {   2, "validationFailure" },
  {   3, "unacceptableDialogueMode" },
  { 0, NULL }
};


static int
dissect_rtse_RefuseReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int reason = -1;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &reason);


  if(reason != -1)
   col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%s)", val_to_str(reason, rtse_RefuseReason_vals, "reason(%d)"));


  return offset;
}



static int
dissect_rtse_T_userDataRJ(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE*)actx->private_data;
        const char *oid = NULL;

        switch(app_proto)  {
        case 1:         /* mts-transfer-protocol-1984 */
                oid = "applicationProtocol.1";
                break;
        case 12:        /* mts-transfer-protocol */
                oid = "applicationProtocol.12";
                break;
        default:
                if(session && session->pres_ctx_id)
                        oid = find_oid_by_pres_ctx_id(actx->pinfo, session->pres_ctx_id);
                break;
        }

        if(!oid) /* XXX: problem here is we haven't decoded the applicationProtocol yet - so we make assumptions! */
                oid = "applicationProtocol.12";

        if(oid) {
          if(session != NULL)
                session->ros_op = (ROS_OP_BIND | ROS_OP_ERROR);

          offset = call_rtse_oid_callback(oid, tvb, offset, actx->pinfo, top_tree ? top_tree : tree, session);
        }


  return offset;
}


static const ber_sequence_t RTORJapdu_set[] = {
  { &hf_rtse_refuseReason   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_RefuseReason },
  { &hf_rtse_userDataRJ     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_rtse_T_userDataRJ },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_rtse_RTORJapdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_str(actx->pinfo->cinfo, COL_INFO, "Refuse");

    offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RTORJapdu_set, hf_index, ett_rtse_RTORJapdu);



  return offset;
}



static int
dissect_rtse_RTTPapdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int priority = -1;

  col_append_str(actx->pinfo->cinfo, COL_INFO, "Turn-Please");

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &priority);


  if(priority != -1)
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%d)", priority);


  return offset;
}



static int
dissect_rtse_RTTRapdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
        tvbuff_t *next_tvb = NULL;
    struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE*)actx->private_data;

        offset = dissect_ber_octet_string(false, actx, tree, tvb, offset, hf_index, &next_tvb);

        if(next_tvb) {

                /* XXX: we should check is this is an EXTERNAL first */

                /* ROS won't do this for us */
                if(session)
                        session->ros_op = (ROS_OP_INVOKE | ROS_OP_ARGUMENT);

                offset = dissect_ber_external_type(false, tree, next_tvb, 0, actx,  -1, call_rtse_external_type_callback);
        }



  return offset;
}


static const value_string rtse_AbortReason_vals[] = {
  {   0, "localSystemProblem" },
  {   1, "invalidParameter" },
  {   2, "unrecognizedActivity" },
  {   3, "temporaryProblem" },
  {   4, "protocolError" },
  {   5, "permanentProblem" },
  {   6, "userError" },
  {   7, "transferCompleted" },
  { 0, NULL }
};


static int
dissect_rtse_AbortReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int reason = -1;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &reason);


  if(reason != -1)
   col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%s)", val_to_str(reason, rtse_AbortReason_vals, "reason(%d)"));


  return offset;
}



static int
dissect_rtse_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_rtse_T_userdataAB(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/*XXX not implemented yet */


  return offset;
}


static const ber_sequence_t RTABapdu_set[] = {
  { &hf_rtse_abortReason    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_AbortReason },
  { &hf_rtse_reflectedParameter, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_BIT_STRING },
  { &hf_rtse_userdataAB     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_rtse_T_userdataAB },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_rtse_RTABapdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_str(actx->pinfo->cinfo, COL_INFO, "Abort");

    offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RTABapdu_set, hf_index, ett_rtse_RTABapdu);



  return offset;
}


static const ber_choice_t RTSE_apdus_choice[] = {
  {   0, &hf_rtse_rtorq_apdu     , BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_rtse_RTORQapdu },
  {   1, &hf_rtse_rtoac_apdu     , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_rtse_RTOACapdu },
  {   2, &hf_rtse_rtorj_apdu     , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_rtse_RTORJapdu },
  {   3, &hf_rtse_rttp_apdu      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_rtse_RTTPapdu },
  {   4, &hf_rtse_rttr_apdu      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_rtse_RTTRapdu },
  {   5, &hf_rtse_rtab_apdu      , BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_rtse_RTABapdu },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_rtse_RTSE_apdus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RTSE_apdus_choice, hf_index, ett_rtse_RTSE_apdus,
                                 NULL);

  return offset;
}


/*
* Dissect RTSE PDUs inside a PPDU.
*/
static int
dissect_rtse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
    int offset = 0;
    int old_offset;
    proto_item *item;
    proto_tree *tree;
    proto_tree *next_tree=NULL;
    tvbuff_t *next_tvb = NULL;
    tvbuff_t *data_tvb = NULL;
    fragment_head *frag_msg = NULL;
    uint32_t fragment_length;
    uint32_t rtse_id = 0;
    bool data_handled = false;
    struct SESSION_DATA_STRUCTURE* session;
    conversation_t *conversation = NULL;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

    /* do we have application context from the acse dissector? */
    if (data == NULL)
        return 0;
    session = (struct SESSION_DATA_STRUCTURE*)data;

    /* save parent_tree so subdissectors can create new top nodes */
    top_tree=parent_tree;

    asn1_ctx.private_data = session;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTSE");
    col_clear(pinfo->cinfo, COL_INFO);

    if (rtse_reassemble &&
        ((session->spdu_type == SES_DATA_TRANSFER) ||
         (session->spdu_type == SES_MAJOR_SYNC_POINT)))
    {
        /* Use conversation index as fragment id */
        conversation  = find_conversation_pinfo(pinfo, 0);
        if (conversation != NULL) {
            rtse_id = conversation->conv_index;
        }
        session->rtse_reassemble = true;
    }
    if (rtse_reassemble && session->spdu_type == SES_MAJOR_SYNC_POINT) {
        frag_msg = fragment_end_seq_next (&rtse_reassembly_table,
                          pinfo, rtse_id, NULL);
        next_tvb = process_reassembled_data (tvb, offset, pinfo, "Reassembled RTSE",
                             frag_msg, &rtse_frag_items, NULL, parent_tree);
    }

    item = proto_tree_add_item(parent_tree, proto_rtse, next_tvb ? next_tvb : tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_rtse);

    if (rtse_reassemble && session->spdu_type == SES_DATA_TRANSFER) {
        /* strip off the OCTET STRING encoding - including any CONSTRUCTED OCTET STRING */
        dissect_ber_octet_string(false, &asn1_ctx, tree, tvb, offset, hf_rtse_segment_data, &data_tvb);

        if (data_tvb) {
            fragment_length = tvb_captured_length_remaining (data_tvb, 0);
            proto_item_append_text(asn1_ctx.created_item, " (%u byte%s)", fragment_length,
                                        plurality(fragment_length, "", "s"));
            frag_msg = fragment_add_seq_next (&rtse_reassembly_table,
                              data_tvb, 0, pinfo,
                              rtse_id, NULL,
                              fragment_length, true);
            if (frag_msg && pinfo->num != frag_msg->reassembled_in) {
                /* Add a "Reassembled in" link if not reassembled in this frame */
                proto_tree_add_uint (tree, *(rtse_frag_items.hf_reassembled_in),
                             data_tvb, 0, 0, frag_msg->reassembled_in);
            }
            pinfo->fragmented = true;
            data_handled = true;
        } else {
            fragment_length = tvb_captured_length_remaining (tvb, offset);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, "[RTSE fragment, %u byte%s]",
                    fragment_length, plurality(fragment_length, "", "s"));
    } else if (rtse_reassemble && session->spdu_type == SES_MAJOR_SYNC_POINT) {
        if (next_tvb) {
            /* ROS won't do this for us */
            session->ros_op = (ROS_OP_INVOKE | ROS_OP_ARGUMENT);
            /*offset=*/dissect_ber_external_type(false, tree, next_tvb, 0, &asn1_ctx, -1, call_rtse_external_type_callback);
            top_tree = NULL;
            /* Return other than 0 to indicate that we handled this packet */
            return 1;
        } else {
            offset = tvb_captured_length (tvb);
        }
        pinfo->fragmented = false;
        data_handled = true;
    }

    if (!data_handled) {
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            old_offset=offset;
            offset=dissect_rtse_RTSE_apdus(true, tvb, offset, &asn1_ctx, tree, -1);
            if (offset == old_offset) {
                next_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                ett_rtse_unknown, &item, "Unknown RTSE PDU");
                expert_add_info (pinfo, item, &ei_rtse_unknown_rtse_pdu);
                dissect_unknown_ber(pinfo, tvb, offset, next_tree);
                break;
            }
        }
    }

    top_tree = NULL;
    return tvb_captured_length(tvb);
}

/*--- proto_register_rtse -------------------------------------------*/
void proto_register_rtse(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
    /* Fragment entries */
    { &hf_rtse_segment_data,
      { "RTSE segment data", "rtse.segment", FT_NONE, BASE_NONE,
    NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_fragments,
      { "RTSE fragments", "rtse.fragments", FT_NONE, BASE_NONE,
    NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_fragment,
      { "RTSE fragment", "rtse.fragment", FT_FRAMENUM, BASE_NONE,
    NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_fragment_overlap,
      { "RTSE fragment overlap", "rtse.fragment.overlap", FT_BOOLEAN,
    BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_rtse_fragment_overlap_conflicts,
      { "RTSE fragment overlapping with conflicting data",
    "rtse.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE,
    NULL, 0x0, NULL, HFILL } },
    { &hf_rtse_fragment_multiple_tails,
      { "RTSE has multiple tail fragments",
    "rtse.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
    NULL, 0x0, NULL, HFILL } },
    { &hf_rtse_fragment_too_long_fragment,
      { "RTSE fragment too long", "rtse.fragment.too_long_fragment",
    FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_rtse_fragment_error,
      { "RTSE defragmentation error", "rtse.fragment.error", FT_FRAMENUM,
    BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_fragment_count,
      { "RTSE fragment count", "rtse.fragment.count", FT_UINT32, BASE_DEC,
    NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_reassembled_in,
      { "Reassembled RTSE in frame", "rtse.reassembled.in", FT_FRAMENUM, BASE_NONE,
    NULL, 0x00, "This RTSE packet is reassembled in this frame", HFILL } },
    { &hf_rtse_reassembled_length,
      { "Reassembled RTSE length", "rtse.reassembled.length", FT_UINT32, BASE_DEC,
    NULL, 0x00, "The total length of the reassembled payload", HFILL } },

    { &hf_rtse_rtorq_apdu,
      { "rtorq-apdu", "rtse.rtorq_apdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTORQapdu", HFILL }},
    { &hf_rtse_rtoac_apdu,
      { "rtoac-apdu", "rtse.rtoac_apdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTOACapdu", HFILL }},
    { &hf_rtse_rtorj_apdu,
      { "rtorj-apdu", "rtse.rtorj_apdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTORJapdu", HFILL }},
    { &hf_rtse_rttp_apdu,
      { "rttp-apdu", "rtse.rttp_apdu",
        FT_INT32, BASE_DEC, NULL, 0,
        "RTTPapdu", HFILL }},
    { &hf_rtse_rttr_apdu,
      { "rttr-apdu", "rtse.rttr_apdu",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RTTRapdu", HFILL }},
    { &hf_rtse_rtab_apdu,
      { "rtab-apdu", "rtse.rtab_apdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTABapdu", HFILL }},
    { &hf_rtse_checkpointSize,
      { "checkpointSize", "rtse.checkpointSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_rtse_windowSize,
      { "windowSize", "rtse.windowSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_rtse_dialogueMode,
      { "dialogueMode", "rtse.dialogueMode",
        FT_INT32, BASE_DEC, VALS(rtse_T_dialogueMode_vals), 0,
        NULL, HFILL }},
    { &hf_rtse_connectionDataRQ,
      { "connectionDataRQ", "rtse.connectionDataRQ",
        FT_UINT32, BASE_DEC, VALS(rtse_ConnectionData_vals), 0,
        "ConnectionData", HFILL }},
    { &hf_rtse_applicationProtocol,
      { "applicationProtocol", "rtse.applicationProtocol",
        FT_INT32, BASE_DEC, VALS(rtse_T_applicationProtocol_vals), 0,
        NULL, HFILL }},
    { &hf_rtse_connectionDataAC,
      { "connectionDataAC", "rtse.connectionDataAC",
        FT_UINT32, BASE_DEC, VALS(rtse_ConnectionData_vals), 0,
        "ConnectionData", HFILL }},
    { &hf_rtse_refuseReason,
      { "refuseReason", "rtse.refuseReason",
        FT_INT32, BASE_DEC, VALS(rtse_RefuseReason_vals), 0,
        NULL, HFILL }},
    { &hf_rtse_userDataRJ,
      { "userDataRJ", "rtse.userDataRJ_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rtse_abortReason,
      { "abortReason", "rtse.abortReason",
        FT_INT32, BASE_DEC, VALS(rtse_AbortReason_vals), 0,
        NULL, HFILL }},
    { &hf_rtse_reflectedParameter,
      { "reflectedParameter", "rtse.reflectedParameter",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_rtse_userdataAB,
      { "userdataAB", "rtse.userdataAB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rtse_open,
      { "open", "rtse.open_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rtse_recover,
      { "recover", "rtse.recover_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SessionConnectionIdentifier", HFILL }},
    { &hf_rtse_callingSSuserReference,
      { "callingSSuserReference", "rtse.callingSSuserReference",
        FT_UINT32, BASE_DEC, VALS(rtse_CallingSSuserReference_vals), 0,
        NULL, HFILL }},
    { &hf_rtse_commonReference,
      { "commonReference", "rtse.commonReference",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rtse_additionalReferenceInformation,
      { "additionalReferenceInformation", "rtse.additionalReferenceInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rtse_t61String,
      { "t61String", "rtse.t61String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rtse_octetString,
      { "octetString", "rtse.octetString",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_rtse,
    &ett_rtse_unknown,
    &ett_rtse_fragment,
    &ett_rtse_fragments,
    &ett_rtse_RTSE_apdus,
    &ett_rtse_RTORQapdu,
    &ett_rtse_RTOACapdu,
    &ett_rtse_RTORJapdu,
    &ett_rtse_RTABapdu,
    &ett_rtse_ConnectionData,
    &ett_rtse_SessionConnectionIdentifier,
    &ett_rtse_CallingSSuserReference,
  };

  static ei_register_info ei[] = {
     { &ei_rtse_dissector_oid_not_implemented, { "rtse.dissector_oid_not_implemented", PI_UNDECODED, PI_WARN, "RTSE: Dissector for OID not implemented", EXPFILL }},
     { &ei_rtse_unknown_rtse_pdu, { "rtse.unknown_rtse_pdu", PI_UNDECODED, PI_WARN, "Unknown RTSE PDU", EXPFILL }},
     { &ei_rtse_abstract_syntax, { "rtse.bad_abstract_syntax", PI_PROTOCOL, PI_WARN, "Unable to determine abstract syntax for indirect reference", EXPFILL }},
  };

  expert_module_t* expert_rtse;
  module_t *rtse_module;

  /* Register protocol */
  proto_rtse = proto_register_protocol(PNAME, PSNAME, PFNAME);
  rtse_handle = register_dissector("rtse", dissect_rtse, proto_rtse);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rtse, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_rtse = expert_register_protocol(proto_rtse);
  expert_register_field_array(expert_rtse, ei, array_length(ei));

  reassembly_table_register (&rtse_reassembly_table,
                   &addresses_reassembly_table_functions);

  rtse_module = prefs_register_protocol_subtree("OSI", proto_rtse, NULL);

  prefs_register_bool_preference(rtse_module, "reassemble",
                 "Reassemble segmented RTSE datagrams",
                 "Whether segmented RTSE datagrams should be reassembled."
                 " To use this option, you must also enable"
                 " \"Allow subdissectors to reassemble TCP streams\""
                 " in the TCP protocol settings.", &rtse_reassemble);

  rtse_oid_dissector_table = register_dissector_table("rtse.oid", "RTSE OID Dissectors", proto_rtse, FT_STRING, STRING_CASE_SENSITIVE);
}


/*--- proto_reg_handoff_rtse --- */
void proto_reg_handoff_rtse(void) {


}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
