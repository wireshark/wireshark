/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ros.c                                                               */
/* asn2wrs.py -b -q -L -p ros -c ./ros.cnf -s ./packet-ros-template -D . -O ../.. ros.asn Remote-Operations-Information-Objects.asn */

/* packet-ros_asn1.c
 * Routines for ROS packet dissection
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
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-pres.h"
#include "packet-ros.h"

#define PNAME  "X.880 OSI Remote Operations Service"
#define PSNAME "ROS"
#define PFNAME "ros"

void proto_register_ros(void);
void proto_reg_handoff_ros(void);

/* Initialize the protocol and registered fields */
static int proto_ros;

static proto_tree *top_tree;
static uint32_t opcode;
static uint32_t invokeid;

static  dissector_handle_t ros_handle;

typedef struct ros_conv_info_t {
  wmem_map_t *unmatched; /* unmatched operations */
  wmem_map_t *matched;   /* matched operations */
} ros_conv_info_t;

typedef struct ros_call_response {
  bool is_request;
  uint32_t req_frame;
  nstime_t req_time;
  uint32_t rep_frame;
  unsigned invokeId;
} ros_call_response_t;

static int hf_ros_response_in;
static int hf_ros_response_to;
static int hf_ros_time;


static int hf_ros_invoke;                         /* Invoke */
static int hf_ros_returnResult;                   /* ReturnResult */
static int hf_ros_returnError;                    /* ReturnError */
static int hf_ros_reject;                         /* T_reject */
static int hf_ros_bind_invoke;                    /* T_bind_invoke */
static int hf_ros_bind_result;                    /* T_bind_result */
static int hf_ros_bind_error;                     /* T_bind_error */
static int hf_ros_unbind_invoke;                  /* T_unbind_invoke */
static int hf_ros_unbind_result;                  /* T_unbind_result */
static int hf_ros_unbind_error;                   /* T_unbind_error */
static int hf_ros_invokeId;                       /* InvokeId */
static int hf_ros_linkedId;                       /* INTEGER */
static int hf_ros_opcode;                         /* OperationCode */
static int hf_ros_argument;                       /* T_argument */
static int hf_ros_result;                         /* T_result */
static int hf_ros_operationResult;                /* OperationResult */
static int hf_ros_errcode;                        /* ErrorCode */
static int hf_ros_parameter;                      /* T_parameter */
static int hf_ros_problem;                        /* T_problem */
static int hf_ros_general;                        /* GeneralProblem */
static int hf_ros_invokeProblem;                  /* InvokeProblem */
static int hf_ros_rejectResult;                   /* ReturnResultProblem */
static int hf_ros_rejectError;                    /* ReturnErrorProblem */
static int hf_ros_present;                        /* T_present */
static int hf_ros_absent;                         /* NULL */
static int hf_ros_local;                          /* INTEGER */
static int hf_ros_global;                         /* OBJECT_IDENTIFIER */

/* Initialize the subtree pointers */
static int ett_ros;
static int ett_ros_unknown;
static int ett_ros_invoke_argument;
static int ett_ros_return_result;
static int ett_ros_bind_invoke;
static int ett_ros_bind_result;
static int ett_ros_bind_error;
static int ett_ros_unbind_invoke;
static int ett_ros_unbind_result;
static int ett_ros_unbind_error;
static int ett_ros_ROS;
static int ett_ros_Invoke;
static int ett_ros_ReturnResult;
static int ett_ros_T_result;
static int ett_ros_ReturnError;
static int ett_ros_Reject;
static int ett_ros_T_problem;
static int ett_ros_InvokeId;
static int ett_ros_Code;

static expert_field ei_ros_dissector_oid_not_implemented;
static expert_field ei_ros_unknown_ros_pdu;

static dissector_table_t ros_oid_dissector_table;

static wmem_map_t *protocol_table;

void
register_ros_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto _U_, const char *name, bool uses_rtse)
{
	dissector_add_string("ros.oid", oid, dissector);

	if(!uses_rtse)
	  /* if we are not using RTSE, then we must register ROS with BER (ACSE) */
	  register_ber_oid_dissector_handle(oid, ros_handle, proto, name);
}

void
register_ros_protocol_info(const char *oid, const ros_info_t *rinfo, int proto _U_, const char *name, bool uses_rtse)
{
	wmem_map_insert(protocol_table, (void *)oid, (void *)rinfo);

	if(!uses_rtse)
	  /* if we are not using RTSE, then we must register ROS with BER (ACSE) */
	  register_ber_oid_dissector_handle(oid, ros_handle, proto, name);
}

static dissector_t ros_lookup_opr_dissector(int32_t opcode_lcl, const ros_opr_t *operations, bool argument)
{
	/* we don't know what order asn2wrs/module definition is, so ... */
	if(operations) {
		for(;operations->arg_pdu != (dissector_t)(-1); operations++)
			if(operations->opcode == opcode_lcl)
				return argument ? operations->arg_pdu : operations->res_pdu;

	}
	return NULL;
}

static dissector_t ros_lookup_err_dissector(int32_t errcode, const ros_err_t *errors)
{
	/* we don't know what order asn2wrs/module definition is, so ... */
	if(errors) {
		for(;errors->err_pdu != (dissector_t) (-1); errors++) {
			if(errors->errcode == errcode)
				return errors->err_pdu;
		}
	}
	return NULL;
}


static int
ros_try_string(const char *oid, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct SESSION_DATA_STRUCTURE* session)
{
	ros_info_t *rinfo;
	int32_t    opcode_lcl = 0;
	const char *opname = NULL;
	const char *suffix = NULL;
	dissector_t opdissector = NULL;
	const value_string *lookup;
	proto_item *item=NULL;
	proto_tree *ros_tree=NULL;

	if((session != NULL) && (oid != NULL) && ((rinfo = (ros_info_t*)wmem_map_lookup(protocol_table, oid)) != NULL)) {

		if(tree){
			item = proto_tree_add_item(tree, *(rinfo->proto), tvb, 0, -1, ENC_NA);
			ros_tree = proto_item_add_subtree(item, *(rinfo->ett_proto));
		}

		col_set_str(pinfo->cinfo, COL_PROTOCOL, rinfo->name);

		/* if this is a bind operation */
		if((session->ros_op & ROS_OP_TYPE_MASK) == ROS_OP_BIND) {
			/* use the in-built operation codes */
			if((session->ros_op & ROS_OP_PDU_MASK) ==  ROS_OP_ERROR)
				opcode_lcl = err_ros_bind;
			else
				opcode_lcl = op_ros_bind;
		} else
			/* otherwise just take the opcode */
			opcode_lcl = session->ros_op & ROS_OP_OPCODE_MASK;

		/* default lookup in the operations */
		lookup = rinfo->opr_code_strings;

		switch(session->ros_op & ROS_OP_PDU_MASK) {
		case ROS_OP_ARGUMENT:
			opdissector = ros_lookup_opr_dissector(opcode_lcl, rinfo->opr_code_dissectors, true);
			suffix = "_argument";
			break;
		case ROS_OP_RESULT:
			opdissector = ros_lookup_opr_dissector(opcode_lcl, rinfo->opr_code_dissectors, false);
			suffix = "_result";
			break;
		case ROS_OP_ERROR:
			opdissector = ros_lookup_err_dissector(opcode_lcl, rinfo->err_code_dissectors);
			lookup = rinfo->err_code_strings;
			break;
		default:
			break;
		}

		if(opdissector) {

			opname = val_to_str(opcode_lcl, lookup, "Unknown opcode (%d)");

			col_set_str(pinfo->cinfo, COL_INFO, opname);
			if(suffix)
				col_append_str(pinfo->cinfo, COL_INFO, suffix);

			return (*opdissector)(tvb, pinfo, ros_tree, NULL);
		}
	}

	return 0;
}

int
call_ros_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, struct SESSION_DATA_STRUCTURE* session)
{
	tvbuff_t *next_tvb;
	int len;

	next_tvb = tvb_new_subset_remaining(tvb, offset);

	if(((len = ros_try_string(oid, next_tvb, pinfo, tree, session)) == 0) &&
	   ((len = dissector_try_string(ros_oid_dissector_table, oid, next_tvb, pinfo, tree, session)) == 0)) {
		proto_item *item;
		proto_tree *next_tree;

		next_tree = proto_tree_add_subtree_format(tree, next_tvb, 0, -1, ett_ros_unknown, &item,
				"ROS: Dissector for OID:%s not implemented. Contact Wireshark developers if you want this supported", oid);

		expert_add_info_format(pinfo, item, &ei_ros_dissector_oid_not_implemented,
				       "ROS: Dissector for OID %s not implemented", oid);
		len = dissect_unknown_ber(pinfo, next_tvb, offset, next_tree);
	}

	offset += len;

	return offset;
}


static unsigned
ros_info_hash_matched(const void *k)
{
  const ros_call_response_t *key = (const ros_call_response_t *)k;

  return key->invokeId;
}

static int
ros_info_equal_matched(const void *k1, const void *k2)
{
  const ros_call_response_t *key1 = (const ros_call_response_t *)k1;
  const ros_call_response_t *key2 = (const ros_call_response_t *)k2;

  if( key1->req_frame && key2->req_frame && (key1->req_frame!=key2->req_frame) ){
    return 0;
  }
  /* a response may span multiple frames
  if( key1->rep_frame && key2->rep_frame && (key1->rep_frame!=key2->rep_frame) ){
    return 0;
  }
  */

  return key1->invokeId==key2->invokeId;
}

static unsigned
ros_info_hash_unmatched(const void *k)
{
  const ros_call_response_t *key = (const ros_call_response_t *)k;

  return key->invokeId;
}

static int
ros_info_equal_unmatched(const void *k1, const void *k2)
{
  const ros_call_response_t *key1 = (const ros_call_response_t *)k1;
  const ros_call_response_t *key2 = (const ros_call_response_t *)k2;

  return key1->invokeId==key2->invokeId;
}

static ros_call_response_t *
ros_match_call_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned invokeId, bool isInvoke)
{
  ros_call_response_t rcr, *rcrp=NULL;
  ros_conv_info_t *ros_info;
  conversation_t *conversation;

  /* first see if we have already matched this */
  conversation = find_conversation_pinfo(pinfo, 0);
  if (conversation == NULL)
    return NULL;

  ros_info = (ros_conv_info_t *)conversation_get_proto_data(conversation, proto_ros);
  if (ros_info == NULL)
    return NULL;

  rcr.invokeId=invokeId;
  rcr.is_request = isInvoke;

  if(isInvoke) {
    rcr.req_frame=pinfo->num;
    rcr.rep_frame=0;
  } else {
    rcr.req_frame=0;
    rcr.rep_frame=pinfo->num;
  }

  rcrp=(ros_call_response_t *)wmem_map_lookup(ros_info->matched, &rcr);

  if(rcrp) {
    /* we have found a match */
    rcrp->is_request=rcr.is_request;

  } else {

    /* we haven't found a match - try and match it up */

    if(isInvoke) {
      /* this is a request - add it to the unmatched list */

      /* check that we don't already have one of those in the
	 unmatched list and if so remove it */

      rcr.invokeId=invokeId;

      rcrp=(ros_call_response_t *)wmem_map_lookup(ros_info->unmatched, &rcr);

      if(rcrp){
	wmem_map_remove(ros_info->unmatched, rcrp);
      }

      /* if we can't reuse the old one, grab a new chunk */
      if(!rcrp){
	rcrp=wmem_new(wmem_file_scope(), ros_call_response_t);
      }
      rcrp->invokeId=invokeId;
      rcrp->req_frame=pinfo->num;
      rcrp->req_time=pinfo->abs_ts;
      rcrp->rep_frame=0;
      rcrp->is_request=true;
      wmem_map_insert(ros_info->unmatched, rcrp, rcrp);
      return NULL;

    } else {

      /* this is a result - it should be in our unmatched list */

      rcr.invokeId=invokeId;
      rcrp=(ros_call_response_t *)wmem_map_lookup(ros_info->unmatched, &rcr);

      if(rcrp){

	if(!rcrp->rep_frame){
	  wmem_map_remove(ros_info->unmatched, rcrp);
	  rcrp->rep_frame=pinfo->num;
	  rcrp->is_request=false;
	  wmem_map_insert(ros_info->matched, rcrp, rcrp);
	}
      }
    }
  }

  if(rcrp){ /* we have found a match */
    proto_item *item = NULL;

    if(rcrp->is_request){
      item=proto_tree_add_uint(tree, hf_ros_response_in, tvb, 0, 0, rcrp->rep_frame);
      proto_item_set_generated (item);
    } else {
      nstime_t ns;
      item=proto_tree_add_uint(tree, hf_ros_response_to, tvb, 0, 0, rcrp->req_frame);
      proto_item_set_generated (item);
      nstime_delta(&ns, &pinfo->abs_ts, &rcrp->req_time);
      item=proto_tree_add_time(tree, hf_ros_time, tvb, 0, 0, &ns);
      proto_item_set_generated (item);
    }
  }

  return rcrp;
}



static int
dissect_ros_T_present(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &invokeid);

  return offset;
}



static int
dissect_ros_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


const value_string ros_InvokeId_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};

static const ber_choice_t InvokeId_choice[] = {
  {   0, &hf_ros_present         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ros_T_present },
  {   1, &hf_ros_absent          , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_ros_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_ros_InvokeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InvokeId_choice, hf_index, ett_ros_InvokeId,
                                 NULL);

  return offset;
}



static int
dissect_ros_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ros_OperationCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &opcode);

  return offset;
}



static int
dissect_ros_T_argument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  char *oid;
  proto_tree* subtree;
  struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE *)actx->private_data;

  /* not sure what the length should be - -1 for now */
  subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_ros_invoke_argument, NULL, "invoke argument");

  ros_match_call_response(tvb, actx->pinfo, subtree, invokeid, true);

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(actx->pinfo, session->pres_ctx_id))) {
	/* this should be ROS! */
	session->ros_op = (ROS_OP_INVOKE | ROS_OP_ARGUMENT);
	/* now add the opcode */
	session->ros_op |= opcode;
	offset = call_ros_oid_callback(oid, tvb, offset, actx->pinfo, top_tree, session);
  }


  return offset;
}


static const ber_sequence_t Invoke_sequence[] = {
  { &hf_ros_invokeId        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ros_InvokeId },
  { &hf_ros_linkedId        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ros_INTEGER },
  { &hf_ros_opcode          , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ros_OperationCode },
  { &hf_ros_argument        , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ros_T_argument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ros_Invoke(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_ros_Invoke);

  return offset;
}



static int
dissect_ros_OperationResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  char *oid;
  proto_tree* subtree;
  struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE *)actx->private_data;

  /* not sure what the length should be - -1 for now */
  subtree = proto_tree_add_subtree(tree, tvb, offset,-1, ett_ros_return_result, NULL, "return result");

  ros_match_call_response(tvb, actx->pinfo, subtree, invokeid, false);

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(actx->pinfo, session->pres_ctx_id))) {
	/* this should be ROS! */
	session->ros_op = (ROS_OP_INVOKE | ROS_OP_RESULT);
	/* now add the opcode */
	session->ros_op |= opcode;
	offset = call_ros_oid_callback(oid, tvb, offset, actx->pinfo, top_tree, session);
  }


  return offset;
}


static const ber_sequence_t T_result_sequence[] = {
  { &hf_ros_opcode          , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ros_OperationCode },
  { &hf_ros_operationResult , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_ros_OperationResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ros_T_result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_result_sequence, hf_index, ett_ros_T_result);

  return offset;
}


static const ber_sequence_t ReturnResult_sequence[] = {
  { &hf_ros_invokeId        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ros_InvokeId },
  { &hf_ros_result          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ros_T_result },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ros_ReturnResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_ros_ReturnResult);

  return offset;
}



static int
dissect_ros_ErrorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &opcode);

  return offset;
}



static int
dissect_ros_T_parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  char *oid;
  proto_tree* subtree;
  struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE *)actx->private_data;

  /* not sure what the length should be - -1 for now */
  subtree = proto_tree_add_subtree(tree, tvb, offset,-1, ett_ros_return_result, NULL, "return result");

  ros_match_call_response(tvb, actx->pinfo, subtree, invokeid, false);

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(actx->pinfo, session->pres_ctx_id))) {
	/* this should be ROS! */
	session->ros_op = (ROS_OP_INVOKE | ROS_OP_ERROR);
	/* now add the opcode  (really the error code) */
	session->ros_op |= opcode;
	offset = call_ros_oid_callback(oid, tvb, offset, actx->pinfo, top_tree, session);
  }


  return offset;
}


static const ber_sequence_t ReturnError_sequence[] = {
  { &hf_ros_invokeId        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ros_InvokeId },
  { &hf_ros_errcode         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ros_ErrorCode },
  { &hf_ros_parameter       , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ros_T_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ros_ReturnError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnError_sequence, hf_index, ett_ros_ReturnError);

  return offset;
}


static const value_string ros_GeneralProblem_vals[] = {
  {   0, "unrecognizedPDU" },
  {   1, "mistypedPDU" },
  {   2, "badlyStructuredPDU" },
  { 0, NULL }
};


static int
dissect_ros_GeneralProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t problem;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, ros_GeneralProblem_vals, "GeneralProblem(%d)"));


  return offset;
}


static const value_string ros_InvokeProblem_vals[] = {
  {   0, "duplicateInvocation" },
  {   1, "unrecognizedOperation" },
  {   2, "mistypedArgument" },
  {   3, "resourceLimitation" },
  {   4, "releaseInProgress" },
  {   5, "unrecognizedLinkedId" },
  {   6, "linkedResponseUnexpected" },
  {   7, "unexpectedLinkedOperation" },
  { 0, NULL }
};


static int
dissect_ros_InvokeProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t problem;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, ros_InvokeProblem_vals, "InvokeProblem(%d)"));


  return offset;
}


static const value_string ros_ReturnResultProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "resultResponseUnexpected" },
  {   2, "mistypedResult" },
  { 0, NULL }
};


static int
dissect_ros_ReturnResultProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t problem;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, ros_ReturnResultProblem_vals, "ReturnResultProblem(%d)"));


  return offset;
}


static const value_string ros_ReturnErrorProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "errorResponseUnexpected" },
  {   2, "unrecognizedError" },
  {   3, "unexpectedError" },
  {   4, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_ros_ReturnErrorProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t problem;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, ros_ReturnErrorProblem_vals, "ReturnErrorProblem(%d)"));


  return offset;
}


static const value_string ros_T_problem_vals[] = {
  {   0, "general" },
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  { 0, NULL }
};

static const ber_choice_t T_problem_choice[] = {
  {   0, &hf_ros_general         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ros_GeneralProblem },
  {   1, &hf_ros_invokeProblem   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ros_InvokeProblem },
  {   2, &hf_ros_rejectResult    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ros_ReturnResultProblem },
  {   3, &hf_ros_rejectError     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ros_ReturnErrorProblem },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ros_T_problem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_problem_choice, hf_index, ett_ros_T_problem,
                                 NULL);

  return offset;
}


static const ber_sequence_t Reject_sequence[] = {
  { &hf_ros_invokeId        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ros_InvokeId },
  { &hf_ros_problem         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ros_T_problem },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ros_Reject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Reject_sequence, hf_index, ett_ros_Reject);

  return offset;
}



static int
dissect_ros_T_reject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	col_set_str(actx->pinfo->cinfo, COL_INFO, "Reject");
	  offset = dissect_ros_Reject(implicit_tag, tvb, offset, actx, tree, hf_index);



  return offset;
}



static int
dissect_ros_T_bind_invoke(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  char *oid;
  struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE *)actx->private_data;

  /* not sure what the length should be - -1 for now */
  proto_tree_add_subtree(tree, tvb, offset,-1, ett_ros_bind_result, NULL, "bind-invoke");

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(actx->pinfo, session->pres_ctx_id))) {
    /* this should be ROS! */
    session->ros_op = (ROS_OP_BIND | ROS_OP_ARGUMENT);
    offset = call_ros_oid_callback(oid, tvb, offset, actx->pinfo, top_tree, session);
  }


  return offset;
}



static int
dissect_ros_T_bind_result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  char *oid;
  struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE *)actx->private_data;

  /* not sure what the length should be - -1 for now */
  proto_tree_add_subtree(tree, tvb, offset,-1, ett_ros_bind_result, NULL, "bind-result");

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(actx->pinfo, session->pres_ctx_id))) {
    /* this should be ROS! */
    session->ros_op = (ROS_OP_BIND | ROS_OP_RESULT);
    offset = call_ros_oid_callback(oid, tvb, offset, actx->pinfo, top_tree, session);
  }


  return offset;
}



static int
dissect_ros_T_bind_error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  char *oid;
  struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE *)actx->private_data;

  /* not sure what the length should be - -1 for now */
  proto_tree_add_subtree(tree, tvb, offset,-1, ett_ros_bind_error, NULL, "bind-error");

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(actx->pinfo, session->pres_ctx_id))) {
    /* this should be ROS! */
    session->ros_op = (ROS_OP_BIND | ROS_OP_ERROR);
    offset = call_ros_oid_callback(oid, tvb, offset, actx->pinfo, top_tree, session);
  }



  return offset;
}



static int
dissect_ros_T_unbind_invoke(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  char *oid;
  struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE *)actx->private_data;

  /* not sure what the length should be - -1 for now */
  proto_tree_add_subtree(tree, tvb, offset,-1, ett_ros_unbind_invoke, NULL, "unbind-invoke");

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(actx->pinfo, session->pres_ctx_id))) {
    /* this should be ROS! */
    session->ros_op = (ROS_OP_UNBIND | ROS_OP_ARGUMENT);
    offset = call_ros_oid_callback(oid, tvb, offset, actx->pinfo, top_tree, session);
  }



  return offset;
}



static int
dissect_ros_T_unbind_result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  char *oid;
  struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE *)actx->private_data;

  /* not sure what the length should be - -1 for now */
  proto_tree_add_subtree(tree, tvb, offset,-1, ett_ros_unbind_result, NULL, "unbind-result");

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(actx->pinfo, session->pres_ctx_id))) {
    /* this should be ROS! */
    session->ros_op = (ROS_OP_UNBIND | ROS_OP_RESULT);
    offset = call_ros_oid_callback(oid, tvb, offset, actx->pinfo, top_tree, session);
  }


  return offset;
}



static int
dissect_ros_T_unbind_error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  char *oid;
  struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE *)actx->private_data;

  /* not sure what the length should be - -1 for now */
  proto_tree_add_subtree(tree, tvb, offset,-1, ett_ros_unbind_error, NULL, "unbind-error");

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(actx->pinfo, session->pres_ctx_id))) {
    /* this should be ROS! */
    session->ros_op = (ROS_OP_UNBIND | ROS_OP_ERROR);
    offset = call_ros_oid_callback(oid, tvb, offset, actx->pinfo, top_tree, session);
  }


  return offset;
}


const value_string ros_ROS_vals[] = {
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  {   4, "reject" },
  {  16, "bind-invoke" },
  {  17, "bind-result" },
  {  18, "bind-error" },
  {  19, "unbind-invoke" },
  {  20, "unbind-result" },
  {  21, "unbind-error" },
  { 0, NULL }
};

static const ber_choice_t ROS_choice[] = {
  {   1, &hf_ros_invoke          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ros_Invoke },
  {   2, &hf_ros_returnResult    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ros_ReturnResult },
  {   3, &hf_ros_returnError     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ros_ReturnError },
  {   4, &hf_ros_reject          , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ros_T_reject },
  {  16, &hf_ros_bind_invoke     , BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_ros_T_bind_invoke },
  {  17, &hf_ros_bind_result     , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_ros_T_bind_result },
  {  18, &hf_ros_bind_error      , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_ros_T_bind_error },
  {  19, &hf_ros_unbind_invoke   , BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_ros_T_unbind_invoke },
  {  20, &hf_ros_unbind_result   , BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_ros_T_unbind_result },
  {  21, &hf_ros_unbind_error    , BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_ros_T_unbind_error },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_ros_ROS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ROS_choice, hf_index, ett_ros_ROS,
                                 NULL);

  return offset;
}



static int
dissect_ros_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


const value_string ros_Code_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const ber_choice_t Code_choice[] = {
  {   0, &hf_ros_local           , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ros_INTEGER },
  {   1, &hf_ros_global          , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ros_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_ros_Code(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Code_choice, hf_index, ett_ros_Code,
                                 NULL);

  return offset;
}


/*
* Dissect ROS PDUs inside a PPDU.
*/
static int
dissect_ros(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
	int offset = 0;
	int old_offset;
	proto_item *item;
	proto_tree *tree;
	proto_tree *next_tree=NULL;
	conversation_t *conversation;
	ros_conv_info_t *ros_info = NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	/* do we have application context from the acse dissector? */
	if (data == NULL)
		return 0;
	asn1_ctx.private_data = data;

	/* save parent_tree so subdissectors can create new top nodes */
	top_tree=parent_tree;

	conversation = find_or_create_conversation(pinfo);

	/*
	 * Do we already have our info
	 */
	ros_info = (ros_conv_info_t *)conversation_get_proto_data(conversation, proto_ros);
	if (ros_info == NULL) {

	  /* No.  Attach that information to the conversation. */

	  ros_info = (ros_conv_info_t *)wmem_new0(wmem_file_scope(), ros_conv_info_t);
	  ros_info->matched=wmem_map_new(wmem_file_scope(), ros_info_hash_matched, ros_info_equal_matched);
	  ros_info->unmatched=wmem_map_new(wmem_file_scope(), ros_info_hash_unmatched, ros_info_equal_unmatched);

	  conversation_add_proto_data(conversation, proto_ros, ros_info);
	}

	item = proto_tree_add_item(parent_tree, proto_ros, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_ros);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ROS");
  	col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=dissect_ros_ROS(false, tvb, offset, &asn1_ctx , tree, -1);
		if(offset == old_offset){
			next_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_ros_unknown, &item, "Unknown ROS PDU");

			expert_add_info(pinfo, item, &ei_ros_unknown_ros_pdu);
			dissect_unknown_ber(pinfo, tvb, offset, next_tree);
			break;
		}
	}

	return tvb_captured_length(tvb);
}

/*--- proto_register_ros -------------------------------------------*/
void proto_register_ros(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
    { &hf_ros_response_in,
      { "Response In", "ros.response_in",
	FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	"The response to this remote operation invocation is in this frame", HFILL }},
    { &hf_ros_response_to,
      { "Response To", "ros.response_to",
	FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	"This is a response to the remote operation invocation in this frame", HFILL }},
    { &hf_ros_time,
      { "Time", "ros.time",
	FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
	"The time between the Invoke and the Response", HFILL }},

    { &hf_ros_invoke,
      { "invoke", "ros.invoke_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_returnResult,
      { "returnResult", "ros.returnResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_returnError,
      { "returnError", "ros.returnError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_reject,
      { "reject", "ros.reject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_bind_invoke,
      { "bind-invoke", "ros.bind_invoke_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_bind_result,
      { "bind-result", "ros.bind_result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_bind_error,
      { "bind-error", "ros.bind_error_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_unbind_invoke,
      { "unbind-invoke", "ros.unbind_invoke_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_unbind_result,
      { "unbind-result", "ros.unbind_result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_unbind_error,
      { "unbind-error", "ros.unbind_error_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_invokeId,
      { "invokeId", "ros.invokeId",
        FT_UINT32, BASE_DEC, VALS(ros_InvokeId_vals), 0,
        NULL, HFILL }},
    { &hf_ros_linkedId,
      { "linkedId", "ros.linkedId",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ros_opcode,
      { "opcode", "ros.opcode",
        FT_INT32, BASE_DEC, NULL, 0,
        "OperationCode", HFILL }},
    { &hf_ros_argument,
      { "argument", "ros.argument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_result,
      { "result", "ros.result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_operationResult,
      { "result", "ros.result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OperationResult", HFILL }},
    { &hf_ros_errcode,
      { "errcode", "ros.errcode",
        FT_INT32, BASE_DEC, NULL, 0,
        "ErrorCode", HFILL }},
    { &hf_ros_parameter,
      { "parameter", "ros.parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_problem,
      { "problem", "ros.problem",
        FT_UINT32, BASE_DEC, VALS(ros_T_problem_vals), 0,
        NULL, HFILL }},
    { &hf_ros_general,
      { "general", "ros.general",
        FT_INT32, BASE_DEC, VALS(ros_GeneralProblem_vals), 0,
        "GeneralProblem", HFILL }},
    { &hf_ros_invokeProblem,
      { "invoke", "ros.invoke",
        FT_INT32, BASE_DEC, VALS(ros_InvokeProblem_vals), 0,
        "InvokeProblem", HFILL }},
    { &hf_ros_rejectResult,
      { "returnResult", "ros.returnResult",
        FT_INT32, BASE_DEC, VALS(ros_ReturnResultProblem_vals), 0,
        "ReturnResultProblem", HFILL }},
    { &hf_ros_rejectError,
      { "returnError", "ros.returnError",
        FT_INT32, BASE_DEC, VALS(ros_ReturnErrorProblem_vals), 0,
        "ReturnErrorProblem", HFILL }},
    { &hf_ros_present,
      { "present", "ros.present",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_absent,
      { "absent", "ros.absent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ros_local,
      { "local", "ros.local",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ros_global,
      { "global", "ros.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_ros,
    &ett_ros_unknown,
    &ett_ros_invoke_argument,
    &ett_ros_return_result,
    &ett_ros_bind_invoke,
    &ett_ros_bind_result,
    &ett_ros_bind_error,
    &ett_ros_unbind_invoke,
    &ett_ros_unbind_result,
    &ett_ros_unbind_error,

    &ett_ros_ROS,
    &ett_ros_Invoke,
    &ett_ros_ReturnResult,
    &ett_ros_T_result,
    &ett_ros_ReturnError,
    &ett_ros_Reject,
    &ett_ros_T_problem,
    &ett_ros_InvokeId,
    &ett_ros_Code,
  };

  static ei_register_info ei[] = {
     { &ei_ros_dissector_oid_not_implemented, { "ros.dissector_oid_not_implemented", PI_UNDECODED, PI_WARN, "ROS: Dissector for OID not implemented", EXPFILL }},
     { &ei_ros_unknown_ros_pdu, { "ros.unknown_ros_pdu", PI_UNDECODED, PI_WARN, "Unknown ROS PDU", EXPFILL }},
  };

  expert_module_t* expert_ros;

  /* Register protocol */
  proto_ros = proto_register_protocol(PNAME, PSNAME, PFNAME);
  ros_handle = register_dissector("ros", dissect_ros, proto_ros);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ros, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_ros = expert_register_protocol(proto_ros);
  expert_register_field_array(expert_ros, ei, array_length(ei));

  ros_oid_dissector_table = register_dissector_table("ros.oid", "ROS OID Dissectors", proto_ros, FT_STRING, STRING_CASE_SENSITIVE);
  protocol_table = wmem_map_new(wmem_epan_scope(), wmem_str_hash, g_str_equal);
}


/*--- proto_reg_handoff_ros --- */
void proto_reg_handoff_ros(void) {


}
