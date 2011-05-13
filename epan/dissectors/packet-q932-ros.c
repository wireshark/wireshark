/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-q932-ros.c                                                          */
/* ../../tools/asn2wrs.py -b -p q932.ros -c ./q932-ros.cnf -s ./packet-q932-ros-template -D . ../ros/Remote-Operations-Information-Objects.asn Facility-Information-Element-Components.asn */

/* Input file: packet-q932-ros-template.c */

#line 1 "../../asn1/q932-ros/packet-q932-ros-template.c"
/* packet-q932-ros.c
 * Routines for Q.932 packet dissection
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

#include "packet-ber.h"

#define PNAME  "Q.932 Operations Service Element"
#define PSNAME "Q932.ROS"
#define PFNAME "q932.ros"

/* Initialize the protocol and registered fields */
static int proto_q932_ros = -1;

/*--- Included file: packet-q932-ros-hf.c ---*/
#line 1 "../../asn1/q932-ros/packet-q932-ros-hf.c"
static int hf_q932_ros_ROS_PDU = -1;              /* ROS */
static int hf_q932_ros_local = -1;                /* T_local */
static int hf_q932_ros_global = -1;               /* T_global */
static int hf_q932_ros_invoke = -1;               /* Invoke */
static int hf_q932_ros_returnResult = -1;         /* ReturnResult */
static int hf_q932_ros_returnError = -1;          /* ReturnError */
static int hf_q932_ros_reject = -1;               /* Reject */
static int hf_q932_ros_invokeId = -1;             /* InvokeId */
static int hf_q932_ros_linkedId = -1;             /* T_linkedId */
static int hf_q932_ros_linkedIdPresent = -1;      /* T_linkedIdPresent */
static int hf_q932_ros_absent = -1;               /* NULL */
static int hf_q932_ros_opcode = -1;               /* Code */
static int hf_q932_ros_argument = -1;             /* InvokeArgument */
static int hf_q932_ros_result = -1;               /* T_result */
static int hf_q932_ros_resultArgument = -1;       /* ResultArgument */
static int hf_q932_ros_errcode = -1;              /* Code */
static int hf_q932_ros_parameter = -1;            /* T_parameter */
static int hf_q932_ros_problem = -1;              /* T_problem */
static int hf_q932_ros_general = -1;              /* GeneralProblem */
static int hf_q932_ros_invokeProblem = -1;        /* InvokeProblem */
static int hf_q932_ros_returnResultProblem = -1;  /* ReturnResultProblem */
static int hf_q932_ros_returnErrorProblem = -1;   /* ReturnErrorProblem */
static int hf_q932_ros_present = -1;              /* INTEGER */
static int hf_q932_ros_InvokeId_present = -1;     /* InvokeId_present */

/*--- End of included file: packet-q932-ros-hf.c ---*/
#line 44 "../../asn1/q932-ros/packet-q932-ros-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-q932-ros-ett.c ---*/
#line 1 "../../asn1/q932-ros/packet-q932-ros-ett.c"
static gint ett_q932_ros_Code = -1;
static gint ett_q932_ros_ROS = -1;
static gint ett_q932_ros_Invoke = -1;
static gint ett_q932_ros_T_linkedId = -1;
static gint ett_q932_ros_ReturnResult = -1;
static gint ett_q932_ros_T_result = -1;
static gint ett_q932_ros_ReturnError = -1;
static gint ett_q932_ros_Reject = -1;
static gint ett_q932_ros_T_problem = -1;
static gint ett_q932_ros_InvokeId = -1;

/*--- End of included file: packet-q932-ros-ett.c ---*/
#line 47 "../../asn1/q932-ros/packet-q932-ros-template.c"

/* Preferences */

/* Subdissectors */
static dissector_handle_t data_handle = NULL; 

/* Gloabl variables */
static rose_ctx_t *rose_ctx_tmp;

static guint32 problem_val;
static gchar problem_str[64];
static tvbuff_t *arg_next_tvb, *res_next_tvb, *err_next_tvb;



/*--- Included file: packet-q932-ros-fn.c ---*/
#line 1 "../../asn1/q932-ros/packet-q932-ros-fn.c"


static int
dissect_q932_ros_T_local(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &actx->rose_ctx->d.code_local);

  return offset;
}



static int
dissect_q932_ros_T_global(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->rose_ctx->d.code_global);

  return offset;
}


static const value_string q932_ros_Code_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const ber_choice_t Code_choice[] = {
  {   0, &hf_q932_ros_local      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_q932_ros_T_local },
  {   1, &hf_q932_ros_global     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_q932_ros_T_global },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_ros_Code(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Code_choice, hf_index, ett_q932_ros_Code,
                                 &actx->rose_ctx->d.code);

#line 43 "../../asn1/q932-ros/q932-ros.cnf"
  actx->rose_ctx->d.code_item = actx->created_item;

  return offset;
}



static int
dissect_q932_ros_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_q932_ros_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string q932_ros_InvokeId_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};

static const ber_choice_t InvokeId_choice[] = {
  {   0, &hf_q932_ros_present    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_q932_ros_INTEGER },
  {   1, &hf_q932_ros_absent     , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_q932_ros_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_ros_InvokeId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InvokeId_choice, hf_index, ett_q932_ros_InvokeId,
                                 NULL);

  return offset;
}



static int
dissect_q932_ros_InvokeId_present(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_q932_ros_T_linkedIdPresent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_q932_ros_InvokeId_present(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string q932_ros_T_linkedId_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};

static const ber_choice_t T_linkedId_choice[] = {
  {   0, &hf_q932_ros_linkedIdPresent, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_q932_ros_T_linkedIdPresent },
  {   1, &hf_q932_ros_absent     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_q932_ros_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_ros_T_linkedId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_linkedId_choice, hf_index, ett_q932_ros_T_linkedId,
                                 NULL);

  return offset;
}



static int
dissect_q932_ros_InvokeArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 69 "../../asn1/q932-ros/q932-ros.cnf"
  gint len;

  len = tvb_length_remaining(tvb, offset);
  if (len)
    proto_tree_add_item(tree, hf_index, tvb, offset, len, FALSE);
  arg_next_tvb = tvb_new_subset(tvb, offset, len, len);

  offset += tvb_length_remaining(tvb, offset);


  return offset;
}


static const ber_sequence_t Invoke_sequence[] = {
  { &hf_q932_ros_invokeId   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_ros_InvokeId },
  { &hf_q932_ros_linkedId   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_ros_T_linkedId },
  { &hf_q932_ros_opcode     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_ros_Code },
  { &hf_q932_ros_argument   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_q932_ros_InvokeArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_ros_Invoke(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 8 "../../asn1/ros/ros-inv.cnf"
  dissector_handle_t arg_handle = NULL;
  const gchar *descr = "";

  arg_next_tvb = NULL;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_q932_ros_Invoke);

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
dissect_q932_ros_ResultArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 87 "../../asn1/q932-ros/q932-ros.cnf"
  gint len;

  len = tvb_length_remaining(tvb, offset);
  if (len)
    proto_tree_add_item(tree, hf_index, tvb, offset, len, FALSE);
  res_next_tvb = tvb_new_subset(tvb, offset, len, len);

  offset += tvb_length_remaining(tvb, offset);



  return offset;
}


static const ber_sequence_t T_result_sequence[] = {
  { &hf_q932_ros_opcode     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_ros_Code },
  { &hf_q932_ros_resultArgument, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_q932_ros_ResultArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_ros_T_result(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_result_sequence, hf_index, ett_q932_ros_T_result);

  return offset;
}


static const ber_sequence_t ReturnResult_sequence[] = {
  { &hf_q932_ros_invokeId   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_ros_InvokeId },
  { &hf_q932_ros_result     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_q932_ros_T_result },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_ros_ReturnResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 7 "../../asn1/ros/ros-res.cnf"
  dissector_handle_t res_handle = NULL;
  const gchar *descr = "";

  actx->rose_ctx->d.code = -1;
  res_next_tvb = NULL;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_q932_ros_ReturnResult);

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
dissect_q932_ros_T_parameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 106 "../../asn1/q932-ros/q932-ros.cnf"

  gint len;

  len = tvb_length_remaining(tvb, offset);
  if (len)
    proto_tree_add_item(tree, hf_index, tvb, offset, len, FALSE);
  err_next_tvb = tvb_new_subset(tvb, offset, len, len);

  offset += tvb_length_remaining(tvb, offset);


  return offset;
}


static const ber_sequence_t ReturnError_sequence[] = {
  { &hf_q932_ros_invokeId   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_ros_InvokeId },
  { &hf_q932_ros_errcode    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_ros_Code },
  { &hf_q932_ros_parameter  , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_q932_ros_T_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_ros_ReturnError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 7 "../../asn1/ros/ros-err.cnf"
  dissector_handle_t err_handle = NULL;
  const gchar *descr = "";

  err_next_tvb = NULL;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnError_sequence, hf_index, ett_q932_ros_ReturnError);

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


static const value_string q932_ros_GeneralProblem_vals[] = {
  {   0, "unrecognizedComponent" },
  {   1, "mistypedComponent" },
  {   2, "badlyStructuredComponent" },
  { 0, NULL }
};


static int
dissect_q932_ros_GeneralProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem_val);

#line 54 "../../asn1/q932-ros/q932-ros.cnf"
  g_strlcpy(problem_str, val_to_str(problem_val, VALS(q932_ros_GeneralProblem_vals), ""), 64);

  return offset;
}


static const value_string q932_ros_InvokeProblem_vals[] = {
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
dissect_q932_ros_InvokeProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem_val);

#line 56 "../../asn1/q932-ros/q932-ros.cnf"
  g_strlcpy(problem_str, val_to_str(problem_val, VALS(q932_ros_InvokeProblem_vals), ""), 64);

  return offset;
}


static const value_string q932_ros_ReturnResultProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "resultResponseUnexpected" },
  {   2, "mistypedResult" },
  { 0, NULL }
};


static int
dissect_q932_ros_ReturnResultProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem_val);

#line 58 "../../asn1/q932-ros/q932-ros.cnf"
  g_strlcpy(problem_str, val_to_str(problem_val, VALS(q932_ros_ReturnResultProblem_vals), ""), 64);

  return offset;
}


static const value_string q932_ros_ReturnErrorProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "errorResponseUnexpected" },
  {   2, "unrecognizedError" },
  {   3, "unexpectedError" },
  {   4, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_q932_ros_ReturnErrorProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem_val);

#line 60 "../../asn1/q932-ros/q932-ros.cnf"
  g_strlcpy(problem_str, val_to_str(problem_val, VALS(q932_ros_ReturnErrorProblem_vals), ""), 64);

  return offset;
}


static const value_string q932_ros_T_problem_vals[] = {
  {   0, "general" },
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  { 0, NULL }
};

static const ber_choice_t T_problem_choice[] = {
  {   0, &hf_q932_ros_general    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_q932_ros_GeneralProblem },
  {   1, &hf_q932_ros_invokeProblem, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_q932_ros_InvokeProblem },
  {   2, &hf_q932_ros_returnResultProblem, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_q932_ros_ReturnResultProblem },
  {   3, &hf_q932_ros_returnErrorProblem, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_q932_ros_ReturnErrorProblem },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_ros_T_problem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_problem_choice, hf_index, ett_q932_ros_T_problem,
                                 NULL);

  return offset;
}


static const ber_sequence_t Reject_sequence[] = {
  { &hf_q932_ros_invokeId   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_ros_InvokeId },
  { &hf_q932_ros_problem    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_ros_T_problem },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_ros_Reject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 7 "../../asn1/ros/ros-rej.cnf"
  const gchar *descr = "";

  problem_str[0] = '\0';

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Reject_sequence, hf_index, ett_q932_ros_Reject);

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


static const value_string q932_ros_ROS_vals[] = {
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  {   4, "reject" },
  { 0, NULL }
};

static const ber_choice_t ROS_choice[] = {
  {   1, &hf_q932_ros_invoke     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_q932_ros_Invoke },
  {   2, &hf_q932_ros_returnResult, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_q932_ros_ReturnResult },
  {   3, &hf_q932_ros_returnError, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_q932_ros_ReturnError },
  {   4, &hf_q932_ros_reject     , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_q932_ros_Reject },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_ros_ROS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 31 "../../asn1/q932-ros/q932-ros.cnf"
  /* will be moved to ROS_PDU when PDU function can be alternated from conformance file */
  actx->rose_ctx = rose_ctx_tmp;
  rose_ctx_clean_data(actx->rose_ctx);

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ROS_choice, hf_index, ett_q932_ros_ROS,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_ROS_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_q932_ros_ROS(FALSE, tvb, offset, &asn1_ctx, tree, hf_q932_ros_ROS_PDU);
  return offset;
}


/*--- End of included file: packet-q932-ros-fn.c ---*/
#line 62 "../../asn1/q932-ros/packet-q932-ros-template.c"

/*--- dissect_q932_ros -----------------------------------------------------*/
static int dissect_q932_ros(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  rose_ctx_tmp = get_rose_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(rose_ctx_tmp);
  return dissect_ROS_PDU(tvb, pinfo, tree);
}

/*--- proto_register_q932_ros -----------------------------------------------*/
void proto_register_q932_ros(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-q932-ros-hfarr.c ---*/
#line 1 "../../asn1/q932-ros/packet-q932-ros-hfarr.c"
    { &hf_q932_ros_ROS_PDU,
      { "ROS", "q932.ros.ROS",
        FT_UINT32, BASE_DEC, VALS(q932_ros_ROS_vals), 0,
        NULL, HFILL }},
    { &hf_q932_ros_local,
      { "local", "q932.ros.local",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_ros_global,
      { "global", "q932.ros.global",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_ros_invoke,
      { "invoke", "q932.ros.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_ros_returnResult,
      { "returnResult", "q932.ros.returnResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_ros_returnError,
      { "returnError", "q932.ros.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_ros_reject,
      { "reject", "q932.ros.reject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_ros_invokeId,
      { "invokeId", "q932.ros.invokeId",
        FT_UINT32, BASE_DEC, VALS(q932_ros_InvokeId_vals), 0,
        NULL, HFILL }},
    { &hf_q932_ros_linkedId,
      { "linkedId", "q932.ros.linkedId",
        FT_UINT32, BASE_DEC, VALS(q932_ros_T_linkedId_vals), 0,
        NULL, HFILL }},
    { &hf_q932_ros_linkedIdPresent,
      { "present", "q932.ros.present",
        FT_INT32, BASE_DEC, NULL, 0,
        "T_linkedIdPresent", HFILL }},
    { &hf_q932_ros_absent,
      { "absent", "q932.ros.absent",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_ros_opcode,
      { "opcode", "q932.ros.opcode",
        FT_UINT32, BASE_DEC, VALS(q932_ros_Code_vals), 0,
        "Code", HFILL }},
    { &hf_q932_ros_argument,
      { "argument", "q932.ros.argument",
        FT_BYTES, BASE_NONE, NULL, 0,
        "InvokeArgument", HFILL }},
    { &hf_q932_ros_result,
      { "result", "q932.ros.result",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_ros_resultArgument,
      { "result", "q932.ros.result",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ResultArgument", HFILL }},
    { &hf_q932_ros_errcode,
      { "errcode", "q932.ros.errcode",
        FT_UINT32, BASE_DEC, VALS(q932_ros_Code_vals), 0,
        "Code", HFILL }},
    { &hf_q932_ros_parameter,
      { "parameter", "q932.ros.parameter",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_ros_problem,
      { "problem", "q932.ros.problem",
        FT_UINT32, BASE_DEC, VALS(q932_ros_T_problem_vals), 0,
        NULL, HFILL }},
    { &hf_q932_ros_general,
      { "general", "q932.ros.general",
        FT_INT32, BASE_DEC, VALS(q932_ros_GeneralProblem_vals), 0,
        "GeneralProblem", HFILL }},
    { &hf_q932_ros_invokeProblem,
      { "invoke", "q932.ros.invoke",
        FT_INT32, BASE_DEC, VALS(q932_ros_InvokeProblem_vals), 0,
        "InvokeProblem", HFILL }},
    { &hf_q932_ros_returnResultProblem,
      { "returnResult", "q932.ros.returnResult",
        FT_INT32, BASE_DEC, VALS(q932_ros_ReturnResultProblem_vals), 0,
        "ReturnResultProblem", HFILL }},
    { &hf_q932_ros_returnErrorProblem,
      { "returnError", "q932.ros.returnError",
        FT_INT32, BASE_DEC, VALS(q932_ros_ReturnErrorProblem_vals), 0,
        "ReturnErrorProblem", HFILL }},
    { &hf_q932_ros_present,
      { "present", "q932.ros.present",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_q932_ros_InvokeId_present,
      { "InvokeId.present", "q932.ros.InvokeId_present",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeId_present", HFILL }},

/*--- End of included file: packet-q932-ros-hfarr.c ---*/
#line 76 "../../asn1/q932-ros/packet-q932-ros-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-q932-ros-ettarr.c ---*/
#line 1 "../../asn1/q932-ros/packet-q932-ros-ettarr.c"
    &ett_q932_ros_Code,
    &ett_q932_ros_ROS,
    &ett_q932_ros_Invoke,
    &ett_q932_ros_T_linkedId,
    &ett_q932_ros_ReturnResult,
    &ett_q932_ros_T_result,
    &ett_q932_ros_ReturnError,
    &ett_q932_ros_Reject,
    &ett_q932_ros_T_problem,
    &ett_q932_ros_InvokeId,

/*--- End of included file: packet-q932-ros-ettarr.c ---*/
#line 81 "../../asn1/q932-ros/packet-q932-ros-template.c"
  };

  /* Register protocol and dissector */
  proto_q932_ros = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_set_cant_toggle(proto_q932_ros);

  /* Register fields and subtrees */
  proto_register_field_array(proto_q932_ros, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  new_register_dissector(PFNAME, dissect_q932_ros, proto_q932_ros);
}

/*--- proto_reg_handoff_q932_ros --------------------------------------------*/
void proto_reg_handoff_q932_ros(void) {
  data_handle = find_dissector("data");
}

/*---------------------------------------------------------------------------*/
