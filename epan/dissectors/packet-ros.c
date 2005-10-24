/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-ros.c                                                             */
/* ../../tools/asn2eth.py -X -b -e -p ros -c ros.cnf -s packet-ros-template ros.asn */

/* Input file: packet-ros-template.c */

/* packet-ros_asn1.c
 * Routines for ROS packet dissection
 * Graeme Lunt 2005
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-pres.h"
#include "packet-ros.h"

#define PNAME  "X.880 OSI Remote Operations Service"
#define PSNAME "ROS"
#define PFNAME "ros"

/* Initialize the protocol and registered fields */
int proto_ros = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;

static proto_tree *top_tree=NULL;
static guint32 opcode;

static  dissector_handle_t ros_handle = NULL;


/*--- Included file: packet-ros-hf.c ---*/

static int hf_ros_invoke = -1;                    /* Invoke */
static int hf_ros_returnResult = -1;              /* ReturnResult */
static int hf_ros_returnError = -1;               /* ReturnError */
static int hf_ros_reject = -1;                    /* Reject */
static int hf_ros_bind_invoke = -1;               /* T_bind_invoke */
static int hf_ros_bind_result = -1;               /* T_bind_result */
static int hf_ros_bind_error = -1;                /* T_bind_error */
static int hf_ros_unbind_invoke = -1;             /* T_unbind_invoke */
static int hf_ros_unbind_result = -1;             /* T_unbind_result */
static int hf_ros_unbind_error = -1;              /* T_unbind_error */
static int hf_ros_invokeId = -1;                  /* InvokeId */
static int hf_ros_linkedId = -1;                  /* INTEGER */
static int hf_ros_opcode = -1;                    /* OperationCode */
static int hf_ros_argument = -1;                  /* T_argument */
static int hf_ros_result = -1;                    /* T_result */
static int hf_ros_operationResult = -1;           /* OperationResult */
static int hf_ros_errcode = -1;                   /* ErrorCode */
static int hf_ros_parameter = -1;                 /* T_parameter */
static int hf_ros_problem = -1;                   /* T_problem */
static int hf_ros_general = -1;                   /* GeneralProblem */
static int hf_ros_invokeProblem = -1;             /* InvokeProblem */
static int hf_ros_rejectResult = -1;              /* ReturnResultProblem */
static int hf_ros_rejectError = -1;               /* ReturnErrorProblem */
static int hf_ros_present = -1;                   /* INTEGER */
static int hf_ros_absent = -1;                    /* NULL */
static int hf_ros_local = -1;                     /* INTEGER */
static int hf_ros_global = -1;                    /* OBJECT_IDENTIFIER */

/*--- End of included file: packet-ros-hf.c ---*/


/* Initialize the subtree pointers */
static gint ett_ros = -1;

/*--- Included file: packet-ros-ett.c ---*/

static gint ett_ros_ROS = -1;
static gint ett_ros_Invoke = -1;
static gint ett_ros_ReturnResult = -1;
static gint ett_ros_T_result = -1;
static gint ett_ros_ReturnError = -1;
static gint ett_ros_Reject = -1;
static gint ett_ros_T_problem = -1;
static gint ett_ros_InvokeId = -1;
static gint ett_ros_Code = -1;

/*--- End of included file: packet-ros-ett.c ---*/


static dissector_table_t ros_oid_dissector_table=NULL;
static GHashTable *oid_table=NULL;
static gint ett_ros_unknown = -1;

void
register_ros_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto _U_, const char *name, gboolean uses_rtse)
{
	dissector_add_string("ros.oid", oid, dissector);
	g_hash_table_insert(oid_table, (gpointer)oid, (gpointer)name);

	if(!uses_rtse)
	  /* if we are not using RTSE, then we must register ROS with BER (ACSE) */
	  register_ber_oid_dissector_handle(oid, ros_handle, proto, name);
}

static int
call_ros_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;

	next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), tvb_reported_length_remaining(tvb, offset));
	if(!dissector_try_string(ros_oid_dissector_table, oid, next_tvb, pinfo, tree)){
		proto_item *item=NULL;
		proto_tree *next_tree=NULL;

		item=proto_tree_add_text(tree, next_tvb, 0, tvb_length_remaining(tvb, offset), "ROS: Dissector for OID:%s not implemented. Contact Ethereal developers if you want this supported", oid);
		if(item){
			next_tree=proto_item_add_subtree(item, ett_ros_unknown);
		}
		dissect_unknown_ber(pinfo, next_tvb, offset, next_tree);
	}

	/*XXX until we change the #.REGISTER signature for _PDU()s 
	 * into new_dissector_t   we have to do this kludge with
	 * manually step past the content in the ANY type.
	 */
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}


/*--- Included file: packet-ros-fn.c ---*/

/*--- Fields for imported types ---*/




static int
dissect_ros_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_linkedId_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_ros_linkedId);
}
static int dissect_present(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_ros_present);
}
static int dissect_local(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_ros_local);
}



static int
dissect_ros_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_absent(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_NULL(FALSE, tvb, offset, pinfo, tree, hf_ros_absent);
}


const value_string ros_InvokeId_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};

static const ber_choice_t InvokeId_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_present },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_absent },
  { 0, 0, 0, 0, NULL }
};

int
dissect_ros_InvokeId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 InvokeId_choice, hf_index, ett_ros_InvokeId,
                                 NULL);

  return offset;
}
static int dissect_invokeId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_InvokeId(FALSE, tvb, offset, pinfo, tree, hf_ros_invokeId);
}



static int
dissect_ros_OperationCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

  offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_index,
                                  &opcode);


  return offset;
}
static int dissect_opcode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_OperationCode(FALSE, tvb, offset, pinfo, tree, hf_ros_opcode);
}



static int
dissect_ros_T_argument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  char *oid;
  /* not sure what the length should be - -1 for now */
  proto_tree_add_text(tree, tvb, offset,-1, "invoke argument");
	
  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(pinfo, session->pres_ctx_id))) {
	/* this should be ROS! */
	session->ros_op = (ROS_OP_INVOKE | ROS_OP_ARGUMENT);
	/* now add the opcode */
	session->ros_op |= opcode;
	offset = call_ros_oid_callback(oid, tvb, offset, pinfo, top_tree);
  }


  return offset;
}
static int dissect_argument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_T_argument(FALSE, tvb, offset, pinfo, tree, hf_ros_argument);
}


static const ber_sequence_t Invoke_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_linkedId_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_opcode },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_argument },
  { 0, 0, 0, NULL }
};

static int
dissect_ros_Invoke(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_ros_Invoke);

  return offset;
}
static int dissect_invoke_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_Invoke(TRUE, tvb, offset, pinfo, tree, hf_ros_invoke);
}



static int
dissect_ros_OperationResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  char *oid;
  /* not sure what the length should be - -1 for now */
  proto_tree_add_text(tree, tvb, offset,-1, "return result");
	
  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(pinfo, session->pres_ctx_id))) {
	/* this should be ROS! */
	session->ros_op = (ROS_OP_INVOKE | ROS_OP_RESULT);
	/* now add the opcode */
	session->ros_op |= opcode;
	offset = call_ros_oid_callback(oid, tvb, offset, pinfo, top_tree);
  }


  return offset;
}
static int dissect_operationResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_OperationResult(FALSE, tvb, offset, pinfo, tree, hf_ros_operationResult);
}


static const ber_sequence_t T_result_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_opcode },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_operationResult },
  { 0, 0, 0, NULL }
};

static int
dissect_ros_T_result(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_result_sequence, hf_index, ett_ros_T_result);

  return offset;
}
static int dissect_result(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_T_result(FALSE, tvb, offset, pinfo, tree, hf_ros_result);
}


static const ber_sequence_t ReturnResult_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_result },
  { 0, 0, 0, NULL }
};

static int
dissect_ros_ReturnResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_ros_ReturnResult);

  return offset;
}
static int dissect_returnResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_ReturnResult(TRUE, tvb, offset, pinfo, tree, hf_ros_returnResult);
}



static int
dissect_ros_ErrorCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

  offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_index,
                                  &opcode);


  return offset;
}
static int dissect_errcode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_ErrorCode(FALSE, tvb, offset, pinfo, tree, hf_ros_errcode);
}



static int
dissect_ros_T_parameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  char *oid;
  /* not sure what the length should be - -1 for now */
  proto_tree_add_text(tree, tvb, offset,-1, "return result");
	
  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(pinfo, session->pres_ctx_id))) {
	/* this should be ROS! */
	session->ros_op = (ROS_OP_INVOKE | ROS_OP_ERROR);
	/* now add the opcode  (really the errode) */
	session->ros_op |= opcode;
	offset = call_ros_oid_callback(oid, tvb, offset, pinfo, top_tree);
  }



  return offset;
}
static int dissect_parameter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_T_parameter(FALSE, tvb, offset, pinfo, tree, hf_ros_parameter);
}


static const ber_sequence_t ReturnError_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_errcode },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_parameter },
  { 0, 0, 0, NULL }
};

static int
dissect_ros_ReturnError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReturnError_sequence, hf_index, ett_ros_ReturnError);

  return offset;
}
static int dissect_returnError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_ReturnError(TRUE, tvb, offset, pinfo, tree, hf_ros_returnError);
}


static const value_string ros_GeneralProblem_vals[] = {
  {   0, "unrecognizedPDU" },
  {   1, "mistypedPDU" },
  {   2, "badlyStructuredPDU" },
  { 0, NULL }
};


static int
dissect_ros_GeneralProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_general_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_GeneralProblem(TRUE, tvb, offset, pinfo, tree, hf_ros_general);
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
dissect_ros_InvokeProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_invokeProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_InvokeProblem(TRUE, tvb, offset, pinfo, tree, hf_ros_invokeProblem);
}


static const value_string ros_ReturnResultProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "resultResponseUnexpected" },
  {   2, "mistypedResult" },
  { 0, NULL }
};


static int
dissect_ros_ReturnResultProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_rejectResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_ReturnResultProblem(TRUE, tvb, offset, pinfo, tree, hf_ros_rejectResult);
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
dissect_ros_ReturnErrorProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_rejectError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_ReturnErrorProblem(TRUE, tvb, offset, pinfo, tree, hf_ros_rejectError);
}


static const value_string ros_T_problem_vals[] = {
  {   0, "general" },
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  { 0, NULL }
};

static const ber_choice_t T_problem_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_general_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_invokeProblem_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_rejectResult_impl },
  {   3, BER_CLASS_CON, 3, 0, dissect_rejectError_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ros_T_problem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_problem_choice, hf_index, ett_ros_T_problem,
                                 NULL);

  return offset;
}
static int dissect_problem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_T_problem(FALSE, tvb, offset, pinfo, tree, hf_ros_problem);
}


static const ber_sequence_t Reject_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_problem },
  { 0, 0, 0, NULL }
};

static int
dissect_ros_Reject(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Reject_sequence, hf_index, ett_ros_Reject);

  return offset;
}
static int dissect_reject_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_Reject(TRUE, tvb, offset, pinfo, tree, hf_ros_reject);
}



static int
dissect_ros_T_bind_invoke(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  char *oid;
  /* not sure what the length should be - -1 for now */
  proto_tree_add_text(tree, tvb, offset,-1, "bind-invoke");

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(pinfo, session->pres_ctx_id))) {
    /* this should be ROS! */
    session->ros_op = (ROS_OP_BIND | ROS_OP_ARGUMENT);
    offset = call_ros_oid_callback(oid, tvb, offset, pinfo, top_tree);
  }


  return offset;
}
static int dissect_bind_invoke_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_T_bind_invoke(TRUE, tvb, offset, pinfo, tree, hf_ros_bind_invoke);
}



static int
dissect_ros_T_bind_result(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  char *oid;
  /* not sure what the length should be - -1 for now */
  proto_tree_add_text(tree, tvb, offset,-1, "bind-result");

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(pinfo, session->pres_ctx_id))) {
    /* this should be ROS! */
    session->ros_op = (ROS_OP_BIND | ROS_OP_RESULT);
    offset = call_ros_oid_callback(oid, tvb, offset, pinfo, top_tree);
  }


  return offset;
}
static int dissect_bind_result_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_T_bind_result(TRUE, tvb, offset, pinfo, tree, hf_ros_bind_result);
}



static int
dissect_ros_T_bind_error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  char *oid;
  /* not sure what the length should be - -1 for now */
  proto_tree_add_text(tree, tvb, offset,-1, "bind-error");

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(pinfo, session->pres_ctx_id))) {
    /* this should be ROS! */
    session->ros_op = (ROS_OP_BIND | ROS_OP_ERROR);
    offset = call_ros_oid_callback(oid, tvb, offset, pinfo, top_tree);
  }



  return offset;
}
static int dissect_bind_error_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_T_bind_error(TRUE, tvb, offset, pinfo, tree, hf_ros_bind_error);
}



static int
dissect_ros_T_unbind_invoke(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  char *oid;
  /* not sure what the length should be - -1 for now */
  proto_tree_add_text(tree, tvb, offset,-1, "unbind-invoke");

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(pinfo, session->pres_ctx_id))) {
    /* this should be ROS! */
    session->ros_op = (ROS_OP_UNBIND | ROS_OP_ARGUMENT);
    offset = call_ros_oid_callback(oid, tvb, offset, pinfo, top_tree);
  }



  return offset;
}
static int dissect_unbind_invoke_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_T_unbind_invoke(TRUE, tvb, offset, pinfo, tree, hf_ros_unbind_invoke);
}



static int
dissect_ros_T_unbind_result(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  char *oid;
  /* not sure what the length should be - -1 for now */
  proto_tree_add_text(tree, tvb, offset,-1, "unbind-result");

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(pinfo, session->pres_ctx_id))) {
    /* this should be ROS! */
    session->ros_op = (ROS_OP_UNBIND | ROS_OP_RESULT);
    offset = call_ros_oid_callback(oid, tvb, offset, pinfo, top_tree);
  }


  return offset;
}
static int dissect_unbind_result_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_T_unbind_result(TRUE, tvb, offset, pinfo, tree, hf_ros_unbind_result);
}



static int
dissect_ros_T_unbind_error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  char *oid;
  /* not sure what the length should be - -1 for now */
  proto_tree_add_text(tree, tvb, offset,-1, "unbind-error");

  if(session && session->pres_ctx_id && (oid = find_oid_by_pres_ctx_id(pinfo, session->pres_ctx_id))) {
    /* this should be ROS! */
    session->ros_op = (ROS_OP_UNBIND | ROS_OP_ERROR);
    offset = call_ros_oid_callback(oid, tvb, offset, pinfo, top_tree);
  }

  return offset;
}
static int dissect_unbind_error_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_T_unbind_error(TRUE, tvb, offset, pinfo, tree, hf_ros_unbind_error);
}


static const value_string ros_ROS_vals[] = {
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
  {   1, BER_CLASS_CON, 1, 0, dissect_invoke_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_returnResult_impl },
  {   3, BER_CLASS_CON, 3, 0, dissect_returnError_impl },
  {   4, BER_CLASS_CON, 4, 0, dissect_reject_impl },
  {  16, BER_CLASS_CON, 16, 0, dissect_bind_invoke_impl },
  {  17, BER_CLASS_CON, 17, 0, dissect_bind_result_impl },
  {  18, BER_CLASS_CON, 18, 0, dissect_bind_error_impl },
  {  19, BER_CLASS_CON, 19, 0, dissect_unbind_invoke_impl },
  {  20, BER_CLASS_CON, 20, 0, dissect_unbind_result_impl },
  {  21, BER_CLASS_CON, 21, 0, dissect_unbind_error_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ros_ROS(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ROS_choice, hf_index, ett_ros_ROS,
                                 NULL);

  return offset;
}


static const value_string ros_RejectProblem_vals[] = {
  {   0, "general-unrecognizedPDU" },
  {   1, "general-mistypedPDU" },
  {   2, "general-badlyStructuredPDU" },
  {  10, "invoke-duplicateInvocation" },
  {  11, "invoke-unrecognizedOperation" },
  {  12, "invoke-mistypedArgument" },
  {  13, "invoke-resourceLimitation" },
  {  14, "invoke-releaseInProgress" },
  {  15, "invoke-unrecognizedLinkedId" },
  {  16, "invoke-linkedResponseUnexpected" },
  {  17, "invoke-unexpectedLinkedOperation" },
  {  20, "returnResult-unrecognizedInvocation" },
  {  21, "returnResult-resultResponseUnexpected" },
  {  22, "returnResult-mistypedResult" },
  {  30, "returnError-unrecognizedInvocation" },
  {  31, "returnError-errorResponseUnexpected" },
  {  32, "returnError-unrecognizedError" },
  {  33, "returnError-unexpectedError" },
  {  34, "returnError-mistypedParameter" },
  { 0, NULL }
};


static int
dissect_ros_RejectProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ros_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_global(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_ros_global);
}


const value_string ros_Code_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const ber_choice_t Code_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_local },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_global },
  { 0, 0, 0, 0, NULL }
};

int
dissect_ros_Code(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Code_choice, hf_index, ett_ros_Code,
                                 NULL);

  return offset;
}



static int
dissect_ros_Priority(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


/*--- End of included file: packet-ros-fn.c ---*/



/*
* Dissect ROS PDUs inside a PPDU.
*/
static void
dissect_ros(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	/* save parent_tree so subdissectors can create new top nodes */
	top_tree=parent_tree;

	/* do we have application context from the acse dissector?  */
	if( !pinfo->private_data ){
		if(parent_tree){
			proto_tree_add_text(parent_tree, tvb, offset, -1,
				"Internal error:can't get application context from ACSE dissector.");
		} 
		return  ;
	} else {
		session  = ( (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data) );

	}

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_ros, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_ros);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ROS");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=dissect_ros_ROS(FALSE, tvb, offset, pinfo , tree, -1);
		if(offset == old_offset){
			proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte ROS PDU");
			offset = tvb_length(tvb);
			break;
		}
	}
}


/*--- proto_register_ros -------------------------------------------*/
void proto_register_ros(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-ros-hfarr.c ---*/

    { &hf_ros_invoke,
      { "invoke", "ros.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/invoke", HFILL }},
    { &hf_ros_returnResult,
      { "returnResult", "ros.returnResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/returnResult", HFILL }},
    { &hf_ros_returnError,
      { "returnError", "ros.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/returnError", HFILL }},
    { &hf_ros_reject,
      { "reject", "ros.reject",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/reject", HFILL }},
    { &hf_ros_bind_invoke,
      { "bind-invoke", "ros.bind_invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/bind-invoke", HFILL }},
    { &hf_ros_bind_result,
      { "bind-result", "ros.bind_result",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/bind-result", HFILL }},
    { &hf_ros_bind_error,
      { "bind-error", "ros.bind_error",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/bind-error", HFILL }},
    { &hf_ros_unbind_invoke,
      { "unbind-invoke", "ros.unbind_invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/unbind-invoke", HFILL }},
    { &hf_ros_unbind_result,
      { "unbind-result", "ros.unbind_result",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/unbind-result", HFILL }},
    { &hf_ros_unbind_error,
      { "unbind-error", "ros.unbind_error",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/unbind-error", HFILL }},
    { &hf_ros_invokeId,
      { "invokeId", "ros.invokeId",
        FT_UINT32, BASE_DEC, VALS(ros_InvokeId_vals), 0,
        "", HFILL }},
    { &hf_ros_linkedId,
      { "linkedId", "ros.linkedId",
        FT_INT32, BASE_DEC, NULL, 0,
        "Invoke/linkedId", HFILL }},
    { &hf_ros_opcode,
      { "opcode", "ros.opcode",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ros_argument,
      { "argument", "ros.argument",
        FT_NONE, BASE_NONE, NULL, 0,
        "Invoke/argument", HFILL }},
    { &hf_ros_result,
      { "result", "ros.result",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnResult/result", HFILL }},
    { &hf_ros_operationResult,
      { "result", "ros.result",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnResult/result/result", HFILL }},
    { &hf_ros_errcode,
      { "errcode", "ros.errcode",
        FT_INT32, BASE_DEC, NULL, 0,
        "ReturnError/errcode", HFILL }},
    { &hf_ros_parameter,
      { "parameter", "ros.parameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnError/parameter", HFILL }},
    { &hf_ros_problem,
      { "problem", "ros.problem",
        FT_UINT32, BASE_DEC, VALS(ros_T_problem_vals), 0,
        "Reject/problem", HFILL }},
    { &hf_ros_general,
      { "general", "ros.general",
        FT_INT32, BASE_DEC, VALS(ros_GeneralProblem_vals), 0,
        "Reject/problem/general", HFILL }},
    { &hf_ros_invokeProblem,
      { "invoke", "ros.invoke",
        FT_INT32, BASE_DEC, VALS(ros_InvokeProblem_vals), 0,
        "Reject/problem/invoke", HFILL }},
    { &hf_ros_rejectResult,
      { "returnResult", "ros.returnResult",
        FT_INT32, BASE_DEC, VALS(ros_ReturnResultProblem_vals), 0,
        "Reject/problem/returnResult", HFILL }},
    { &hf_ros_rejectError,
      { "returnError", "ros.returnError",
        FT_INT32, BASE_DEC, VALS(ros_ReturnErrorProblem_vals), 0,
        "Reject/problem/returnError", HFILL }},
    { &hf_ros_present,
      { "present", "ros.present",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeId/present", HFILL }},
    { &hf_ros_absent,
      { "absent", "ros.absent",
        FT_NONE, BASE_NONE, NULL, 0,
        "InvokeId/absent", HFILL }},
    { &hf_ros_local,
      { "local", "ros.local",
        FT_INT32, BASE_DEC, NULL, 0,
        "Code/local", HFILL }},
    { &hf_ros_global,
      { "global", "ros.global",
        FT_STRING, BASE_NONE, NULL, 0,
        "Code/global", HFILL }},

/*--- End of included file: packet-ros-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ros,
    &ett_ros_unknown,

/*--- Included file: packet-ros-ettarr.c ---*/

    &ett_ros_ROS,
    &ett_ros_Invoke,
    &ett_ros_ReturnResult,
    &ett_ros_T_result,
    &ett_ros_ReturnError,
    &ett_ros_Reject,
    &ett_ros_T_problem,
    &ett_ros_InvokeId,
    &ett_ros_Code,

/*--- End of included file: packet-ros-ettarr.c ---*/

  };

  /* Register protocol */
  proto_ros = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("ros", dissect_ros, proto_ros);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ros, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ros_oid_dissector_table = register_dissector_table("ros.oid", "ROS OID Dissectors", FT_STRING, BASE_NONE);
  oid_table=g_hash_table_new(g_str_hash, g_str_equal);
}


/*--- proto_reg_handoff_ros --- */
void proto_reg_handoff_ros(void) {

  ros_handle = find_dissector("ros");

}
