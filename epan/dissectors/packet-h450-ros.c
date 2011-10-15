/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-h450-ros.c                                                          */
/* ../../tools/asn2wrs.py -p h450.ros -c ./h450-ros.cnf -s ./packet-h450-ros-template -D . -O ../../epan/dissectors ../ros/Remote-Operations-Information-Objects.asn Remote-Operations-Apdus.asn */

/* Input file: packet-h450-ros-template.c */

#line 1 "../../asn1/h450-ros/packet-h450-ros-template.c"
/* packet-h450-ros.c
 * Routines for H.450 packet dissection
 * 2007  Tomas Kukosa
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-per.h"

#define PNAME  "H.450 Remote Operations Apdus"
#define PSNAME "H450.ROS"
#define PFNAME "h450.ros"

/* Initialize the protocol and registered fields */
static int proto_h450_ros = -1;

/*--- Included file: packet-h450-ros-hf.c ---*/
#line 1 "../../asn1/h450-ros/packet-h450-ros-hf.c"
static int hf_h450_ros_local = -1;                /* T_local */
static int hf_h450_ros_global = -1;               /* T_global */
static int hf_h450_ros_invoke = -1;               /* Invoke */
static int hf_h450_ros_returnResult = -1;         /* ReturnResult */
static int hf_h450_ros_returnError = -1;          /* ReturnError */
static int hf_h450_ros_reject = -1;               /* Reject */
static int hf_h450_ros_invokeIdConstrained = -1;  /* T_invokeIdConstrained */
static int hf_h450_ros_linkedId = -1;             /* InvokeId */
static int hf_h450_ros_opcode = -1;               /* Code */
static int hf_h450_ros_argument = -1;             /* InvokeArgument */
static int hf_h450_ros_invokeId = -1;             /* InvokeId */
static int hf_h450_ros_result = -1;               /* T_result */
static int hf_h450_ros_resultArgument = -1;       /* ResultArgument */
static int hf_h450_ros_errcode = -1;              /* Code */
static int hf_h450_ros_parameter = -1;            /* T_parameter */
static int hf_h450_ros_problem = -1;              /* T_problem */
static int hf_h450_ros_general = -1;              /* GeneralProblem */
static int hf_h450_ros_invokeProblem = -1;        /* InvokeProblem */
static int hf_h450_ros_returnResultProblem = -1;  /* ReturnResultProblem */
static int hf_h450_ros_returnErrorProblem = -1;   /* ReturnErrorProblem */

/*--- End of included file: packet-h450-ros-hf.c ---*/
#line 44 "../../asn1/h450-ros/packet-h450-ros-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-h450-ros-ett.c ---*/
#line 1 "../../asn1/h450-ros/packet-h450-ros-ett.c"
static gint ett_h450_ros_Code = -1;
static gint ett_h450_ros_ROS = -1;
static gint ett_h450_ros_Invoke = -1;
static gint ett_h450_ros_ReturnResult = -1;
static gint ett_h450_ros_T_result = -1;
static gint ett_h450_ros_ReturnError = -1;
static gint ett_h450_ros_Reject = -1;
static gint ett_h450_ros_T_problem = -1;

/*--- End of included file: packet-h450-ros-ett.c ---*/
#line 47 "../../asn1/h450-ros/packet-h450-ros-template.c"

/* Preferences */

/* Subdissectors */
static dissector_handle_t data_handle = NULL; 

/* Gloabl variables */
static gint32 problem_val;
static gchar problem_str[64];
static tvbuff_t *arg_next_tvb, *res_next_tvb, *err_next_tvb;

static void
argument_cb(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_) {
  arg_next_tvb = tvb;
}

static void
result_cb(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_) {
  res_next_tvb = tvb;
}

static void
error_cb(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_) {
  err_next_tvb = tvb;
}


/*--- Included file: packet-h450-ros-fn.c ---*/
#line 1 "../../asn1/h450-ros/packet-h450-ros-fn.c"


static int
dissect_h450_ros_T_local(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, &actx->rose_ctx->d.code_local);

  return offset;
}



static int
dissect_h450_ros_T_global(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier_str(tvb, offset, actx, tree, hf_index, &actx->rose_ctx->d.code_global);

  return offset;
}


static const value_string h450_ros_Code_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t Code_choice[] = {
  {   0, &hf_h450_ros_local      , ASN1_NO_EXTENSIONS     , dissect_h450_ros_T_local },
  {   1, &hf_h450_ros_global     , ASN1_NO_EXTENSIONS     , dissect_h450_ros_T_global },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_ros_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_ros_Code, Code_choice,
                                 &actx->rose_ctx->d.code);

#line 40 "../../asn1/h450-ros/h450-ros.cnf"
  actx->rose_ctx->d.code_item = actx->created_item;

  return offset;
}



static int
dissect_h450_ros_InvokeId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_h450_ros_T_invokeIdConstrained(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 68 "../../asn1/h450-ros/h450-ros.cnf"
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                           0U, 65535U, NULL, TRUE);


  return offset;
}



static int
dissect_h450_ros_InvokeArgument(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu(tvb, offset, actx, tree, hf_index, argument_cb);

  return offset;
}


static const per_sequence_t Invoke_sequence[] = {
  { &hf_h450_ros_invokeIdConstrained, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_ros_T_invokeIdConstrained },
  { &hf_h450_ros_linkedId   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h450_ros_InvokeId },
  { &hf_h450_ros_opcode     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_ros_Code },
  { &hf_h450_ros_argument   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h450_ros_InvokeArgument },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_ros_Invoke(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 8 "../../asn1/ros/ros-inv.cnf"
  dissector_handle_t arg_handle = NULL;
  const gchar *descr = "";

  arg_next_tvb = NULL;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_ros_Invoke, Invoke_sequence);

#line 13 "../../asn1/ros/ros-inv.cnf"
  actx->rose_ctx->d.pdu = 1;

  if ((actx->rose_ctx->d.code == 0) && actx->rose_ctx->arg_local_dissector_table) {
    arg_handle = dissector_get_uint_handle(actx->rose_ctx->arg_local_dissector_table, actx->rose_ctx->d.code_local);
  } else if ((actx->rose_ctx->d.code == 1) && actx->rose_ctx->arg_global_dissector_table) {
    arg_handle = dissector_get_string_handle(actx->rose_ctx->arg_global_dissector_table, actx->rose_ctx->d.code_global);
  } else {
    arg_handle = NULL;
  }

  if (!arg_handle || 
      !proto_is_protocol_enabled(find_protocol_by_id(dissector_handle_get_protocol_index(arg_handle)))) {
    if (actx->rose_ctx->d.code == 0)
      descr = ep_strdup_printf("INV: %d", actx->rose_ctx->d.code_local);
    else if (actx->rose_ctx->d.code == 1)
      descr = ep_strdup_printf("INV: %s", actx->rose_ctx->d.code_global);
  } else {
    descr = ep_strdup_printf("INV:");
  }

  if (actx->rose_ctx->apdu_depth >= 0)
    proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), actx->rose_ctx->apdu_depth), "  %s", descr);
  if (actx->rose_ctx->fillin_info && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_str(actx->pinfo->cinfo, COL_INFO, descr);
  if (actx->rose_ctx->fillin_ptr)
    g_strlcat(actx->rose_ctx->fillin_ptr, descr, actx->rose_ctx->fillin_buf_size);

  if (!arg_next_tvb) {  /* empty argument */
    arg_next_tvb = tvb_new_subset(tvb, (actx->encoding==ASN1_ENC_PER)?offset>>3:offset, 0, 0);
  }
  actx->pinfo->private_data = actx->rose_ctx;
  call_dissector((arg_handle)?arg_handle:data_handle, arg_next_tvb, actx->pinfo, tree);
  if (!arg_handle) {
    expert_add_info_format(actx->pinfo, tree, PI_UNDECODED, PI_WARN, "Undecoded %s", descr);
  }

  return offset;
}



static int
dissect_h450_ros_ResultArgument(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu(tvb, offset, actx, tree, hf_index, result_cb);

  return offset;
}


static const per_sequence_t T_result_sequence[] = {
  { &hf_h450_ros_opcode     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_ros_Code },
  { &hf_h450_ros_resultArgument, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_ros_ResultArgument },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_ros_T_result(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_ros_T_result, T_result_sequence);

  return offset;
}


static const per_sequence_t ReturnResult_sequence[] = {
  { &hf_h450_ros_invokeId   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_ros_InvokeId },
  { &hf_h450_ros_result     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h450_ros_T_result },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_ros_ReturnResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 7 "../../asn1/ros/ros-res.cnf"
  dissector_handle_t res_handle = NULL;
  const gchar *descr = "";

  actx->rose_ctx->d.code = -1;
  res_next_tvb = NULL;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_ros_ReturnResult, ReturnResult_sequence);

#line 13 "../../asn1/ros/ros-res.cnf"
  actx->rose_ctx->d.pdu = 2;

  if ((actx->rose_ctx->d.code == 0) && actx->rose_ctx->res_local_dissector_table) {
    res_handle = dissector_get_uint_handle(actx->rose_ctx->res_local_dissector_table, actx->rose_ctx->d.code_local);
  } else if ((actx->rose_ctx->d.code == 1) && actx->rose_ctx->res_global_dissector_table) {
    res_handle = dissector_get_string_handle(actx->rose_ctx->res_global_dissector_table, actx->rose_ctx->d.code_global);
  } else {
    res_handle = NULL;
  }

  if (!res_handle || 
      !proto_is_protocol_enabled(find_protocol_by_id(dissector_handle_get_protocol_index(res_handle)))) {
    if (actx->rose_ctx->d.code == 0)
      descr = ep_strdup_printf("RES: %d", actx->rose_ctx->d.code_local);
    else if (actx->rose_ctx->d.code == 1)
      descr = ep_strdup_printf("RES: %s", actx->rose_ctx->d.code_global);
  } else {
    descr = ep_strdup_printf("RES:");
  }

  if (actx->rose_ctx->apdu_depth >= 0)
    proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), actx->rose_ctx->apdu_depth), "  %s", descr);
  if (actx->rose_ctx->fillin_info && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_str(actx->pinfo->cinfo, COL_INFO, descr);
  if (actx->rose_ctx->fillin_ptr)
    g_strlcat(actx->rose_ctx->fillin_ptr, descr, actx->rose_ctx->fillin_buf_size);

  if (actx->rose_ctx->d.code != -1) {
    if (!res_next_tvb) {  /* empty result */
      res_next_tvb = tvb_new_subset(tvb, (actx->encoding==ASN1_ENC_PER)?offset>>3:offset, 0, 0);
    }
    actx->pinfo->private_data = actx->rose_ctx;
    call_dissector((res_handle)?res_handle:data_handle, res_next_tvb, actx->pinfo, tree); 
    if (!res_handle) {
      expert_add_info_format(actx->pinfo, tree, PI_UNDECODED, PI_WARN, "Undecoded %s", descr);
    }
  }

  return offset;
}



static int
dissect_h450_ros_T_parameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu(tvb, offset, actx, tree, hf_index, error_cb);

  return offset;
}


static const per_sequence_t ReturnError_sequence[] = {
  { &hf_h450_ros_invokeId   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_ros_InvokeId },
  { &hf_h450_ros_errcode    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_ros_Code },
  { &hf_h450_ros_parameter  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h450_ros_T_parameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_ros_ReturnError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 7 "../../asn1/ros/ros-err.cnf"
  dissector_handle_t err_handle = NULL;
  const gchar *descr = "";

  err_next_tvb = NULL;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_ros_ReturnError, ReturnError_sequence);

#line 12 "../../asn1/ros/ros-err.cnf"
  actx->rose_ctx->d.pdu = 3;

  if ((actx->rose_ctx->d.code == 0) && actx->rose_ctx->err_local_dissector_table) {
    err_handle = dissector_get_uint_handle(actx->rose_ctx->err_local_dissector_table, actx->rose_ctx->d.code_local);
  } else if ((actx->rose_ctx->d.code == 1) && actx->rose_ctx->err_global_dissector_table) {
    err_handle = dissector_get_string_handle(actx->rose_ctx->err_global_dissector_table, actx->rose_ctx->d.code_global);
  } else {
    err_handle = NULL;
  }

  if (!err_handle || 
      !proto_is_protocol_enabled(find_protocol_by_id(dissector_handle_get_protocol_index(err_handle)))) {
    if (actx->rose_ctx->d.code == 0)
      descr = ep_strdup_printf("ERR: %d", actx->rose_ctx->d.code_local);
    else if (actx->rose_ctx->d.code == 1)
      descr = ep_strdup_printf("ERR: %s", actx->rose_ctx->d.code_global);
  } else {
    descr = ep_strdup_printf("ERR:");
  }

  if (actx->rose_ctx->apdu_depth >= 0)
    proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), actx->rose_ctx->apdu_depth), "  %s", descr);
  if (actx->rose_ctx->fillin_info && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_str(actx->pinfo->cinfo, COL_INFO, descr);
  if (actx->rose_ctx->fillin_ptr)
    g_strlcat(actx->rose_ctx->fillin_ptr, descr, actx->rose_ctx->fillin_buf_size);

  if (!err_next_tvb) {  /* empty error */
    err_next_tvb = tvb_new_subset(tvb, (actx->encoding==ASN1_ENC_PER)?offset>>3:offset, 0, 0);
  }
  actx->pinfo->private_data = actx->rose_ctx;
  call_dissector((err_handle)?err_handle:data_handle, err_next_tvb, actx->pinfo, tree); 
  if (!err_handle) {
    expert_add_info_format(actx->pinfo, tree, PI_UNDECODED, PI_WARN, "Undecoded %s", descr);
  }

  return offset;
}


static const value_string h450_ros_GeneralProblem_vals[] = {
  {   0, "unrecognizedComponent" },
  {   1, "mistypedComponent" },
  {   2, "badlyStructuredComponent" },
  { 0, NULL }
};


static int
dissect_h450_ros_GeneralProblem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, &problem_val);

#line 51 "../../asn1/h450-ros/h450-ros.cnf"
  g_strlcpy(problem_str, val_to_str(problem_val, VALS(h450_ros_GeneralProblem_vals), ""), 64);
  problem_str[64-1] = '\0';

  return offset;
}


static const value_string h450_ros_InvokeProblem_vals[] = {
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
dissect_h450_ros_InvokeProblem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, &problem_val);

#line 54 "../../asn1/h450-ros/h450-ros.cnf"
  g_strlcpy(problem_str, val_to_str(problem_val, VALS(h450_ros_InvokeProblem_vals), ""), 64);
  problem_str[64-1] = '\0';

  return offset;
}


static const value_string h450_ros_ReturnResultProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "resultResponseUnexpected" },
  {   2, "mistypedResult" },
  { 0, NULL }
};


static int
dissect_h450_ros_ReturnResultProblem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, &problem_val);

#line 57 "../../asn1/h450-ros/h450-ros.cnf"
  g_strlcpy(problem_str, val_to_str(problem_val, VALS(h450_ros_ReturnResultProblem_vals), ""), 64);
  problem_str[64-1] = '\0';

  return offset;
}


static const value_string h450_ros_ReturnErrorProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "errorResponseUnexpected" },
  {   2, "unrecognizedError" },
  {   3, "unexpectedError" },
  {   4, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_h450_ros_ReturnErrorProblem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, &problem_val);

#line 60 "../../asn1/h450-ros/h450-ros.cnf"
  g_strlcpy(problem_str, val_to_str(problem_val, VALS(h450_ros_ReturnErrorProblem_vals), ""), 64);
  problem_str[64-1] = '\0';

  return offset;
}


static const value_string h450_ros_T_problem_vals[] = {
  {   0, "general" },
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  { 0, NULL }
};

static const per_choice_t T_problem_choice[] = {
  {   0, &hf_h450_ros_general    , ASN1_NO_EXTENSIONS     , dissect_h450_ros_GeneralProblem },
  {   1, &hf_h450_ros_invokeProblem, ASN1_NO_EXTENSIONS     , dissect_h450_ros_InvokeProblem },
  {   2, &hf_h450_ros_returnResultProblem, ASN1_NO_EXTENSIONS     , dissect_h450_ros_ReturnResultProblem },
  {   3, &hf_h450_ros_returnErrorProblem, ASN1_NO_EXTENSIONS     , dissect_h450_ros_ReturnErrorProblem },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_ros_T_problem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_ros_T_problem, T_problem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Reject_sequence[] = {
  { &hf_h450_ros_invokeId   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_ros_InvokeId },
  { &hf_h450_ros_problem    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h450_ros_T_problem },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_ros_Reject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 7 "../../asn1/ros/ros-rej.cnf"
  const gchar *descr = "";

  problem_str[0] = '\0';

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_ros_Reject, Reject_sequence);

#line 11 "../../asn1/ros/ros-rej.cnf"
  descr = ep_strdup_printf("REJ: %s", problem_str);

  if (actx->rose_ctx->apdu_depth >= 0)
    proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), actx->rose_ctx->apdu_depth), "  %s", descr);
  if (actx->rose_ctx->fillin_info && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_str(actx->pinfo->cinfo, COL_INFO, descr);
  if (actx->rose_ctx->fillin_ptr)
    g_strlcat(actx->rose_ctx->fillin_ptr, descr, actx->rose_ctx->fillin_buf_size);

  return offset;
}


const value_string h450_ros_ROS_vals[] = {
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  {   4, "reject" },
  { 0, NULL }
};

static const per_choice_t ROS_choice[] = {
  {   1, &hf_h450_ros_invoke     , ASN1_NO_EXTENSIONS     , dissect_h450_ros_Invoke },
  {   2, &hf_h450_ros_returnResult, ASN1_NO_EXTENSIONS     , dissect_h450_ros_ReturnResult },
  {   3, &hf_h450_ros_returnError, ASN1_NO_EXTENSIONS     , dissect_h450_ros_ReturnError },
  {   4, &hf_h450_ros_reject     , ASN1_NO_EXTENSIONS     , dissect_h450_ros_Reject },
  { 0, NULL, 0, NULL }
};

int
dissect_h450_ros_ROS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 29 "../../asn1/h450-ros/h450-ros.cnf"
  DISSECTOR_ASSERT(actx->rose_ctx);
  rose_ctx_clean_data(actx->rose_ctx);

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_ros_ROS, ROS_choice,
                                 NULL);

  return offset;
}


/*--- End of included file: packet-h450-ros-fn.c ---*/
#line 74 "../../asn1/h450-ros/packet-h450-ros-template.c"

/*--- proto_register_h450_ros -----------------------------------------------*/
void proto_register_h450_ros(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-h450-ros-hfarr.c ---*/
#line 1 "../../asn1/h450-ros/packet-h450-ros-hfarr.c"
    { &hf_h450_ros_local,
      { "local", "h450.ros.local",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_ros_global,
      { "global", "h450.ros.global",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_ros_invoke,
      { "invoke", "h450.ros.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_ros_returnResult,
      { "returnResult", "h450.ros.returnResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_ros_returnError,
      { "returnError", "h450.ros.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_ros_reject,
      { "reject", "h450.ros.reject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_ros_invokeIdConstrained,
      { "invokeId", "h450.ros.invokeId",
        FT_INT32, BASE_DEC, NULL, 0,
        "T_invokeIdConstrained", HFILL }},
    { &hf_h450_ros_linkedId,
      { "linkedId", "h450.ros.linkedId",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeId", HFILL }},
    { &hf_h450_ros_opcode,
      { "opcode", "h450.ros.opcode",
        FT_UINT32, BASE_DEC, VALS(h450_ros_Code_vals), 0,
        "Code", HFILL }},
    { &hf_h450_ros_argument,
      { "argument", "h450.ros.argument",
        FT_BYTES, BASE_NONE, NULL, 0,
        "InvokeArgument", HFILL }},
    { &hf_h450_ros_invokeId,
      { "invokeId", "h450.ros.invokeId",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_ros_result,
      { "result", "h450.ros.result",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_ros_resultArgument,
      { "result", "h450.ros.result",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ResultArgument", HFILL }},
    { &hf_h450_ros_errcode,
      { "errcode", "h450.ros.errcode",
        FT_UINT32, BASE_DEC, VALS(h450_ros_Code_vals), 0,
        "Code", HFILL }},
    { &hf_h450_ros_parameter,
      { "parameter", "h450.ros.parameter",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h450_ros_problem,
      { "problem", "h450.ros.problem",
        FT_UINT32, BASE_DEC, VALS(h450_ros_T_problem_vals), 0,
        NULL, HFILL }},
    { &hf_h450_ros_general,
      { "general", "h450.ros.general",
        FT_INT32, BASE_DEC, VALS(h450_ros_GeneralProblem_vals), 0,
        "GeneralProblem", HFILL }},
    { &hf_h450_ros_invokeProblem,
      { "invoke", "h450.ros.invoke",
        FT_INT32, BASE_DEC, VALS(h450_ros_InvokeProblem_vals), 0,
        "InvokeProblem", HFILL }},
    { &hf_h450_ros_returnResultProblem,
      { "returnResult", "h450.ros.returnResult",
        FT_INT32, BASE_DEC, VALS(h450_ros_ReturnResultProblem_vals), 0,
        "ReturnResultProblem", HFILL }},
    { &hf_h450_ros_returnErrorProblem,
      { "returnError", "h450.ros.returnError",
        FT_INT32, BASE_DEC, VALS(h450_ros_ReturnErrorProblem_vals), 0,
        "ReturnErrorProblem", HFILL }},

/*--- End of included file: packet-h450-ros-hfarr.c ---*/
#line 81 "../../asn1/h450-ros/packet-h450-ros-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-h450-ros-ettarr.c ---*/
#line 1 "../../asn1/h450-ros/packet-h450-ros-ettarr.c"
    &ett_h450_ros_Code,
    &ett_h450_ros_ROS,
    &ett_h450_ros_Invoke,
    &ett_h450_ros_ReturnResult,
    &ett_h450_ros_T_result,
    &ett_h450_ros_ReturnError,
    &ett_h450_ros_Reject,
    &ett_h450_ros_T_problem,

/*--- End of included file: packet-h450-ros-ettarr.c ---*/
#line 86 "../../asn1/h450-ros/packet-h450-ros-template.c"
  };

  /* Register protocol and dissector */
  proto_h450_ros = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_set_cant_toggle(proto_h450_ros);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h450_ros, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

/*--- proto_reg_handoff_h450_ros --------------------------------------------*/
void proto_reg_handoff_h450_ros(void) {
  data_handle = find_dissector("data");
}

/*---------------------------------------------------------------------------*/
