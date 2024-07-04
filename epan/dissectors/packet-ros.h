/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ros.h                                                               */
/* asn2wrs.py -b -q -L -p ros -c ./ros.cnf -s ./packet-ros-template -D . -O ../.. ros.asn Remote-Operations-Information-Objects.asn */

/* packet-ros.h
 * Routines for ROS packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_ROS_H
#define PACKET_ROS_H

extern const value_string ros_ROS_vals[];
extern const value_string ros_InvokeId_vals[];
extern const value_string ros_Code_vals[];
int dissect_ros_ROS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_ros_InvokeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_ros_Code(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

# include "packet-ses.h"

/* for use in the SESSION_DATA_STRUCTURE ros_op argument
   top byte indicates ROS invocation
   bottom three bytes indicate operation code */

# define ROS_OP_MASK    0xff000000

# define ROS_OP_PDU_MASK  0xf0000000
# define ROS_OP_ARGUMENT  0x10000000
# define ROS_OP_RESULT  0x20000000
# define ROS_OP_ERROR   0x30000000
# define ROS_OP_REJECT  0x40000000

# define ROS_OP_TYPE_MASK 0x0f000000
# define ROS_OP_BIND    0x01000000
# define ROS_OP_UNBIND  0x02000000
# define ROS_OP_INVOKE  0x03000000

# define ROS_OP_OPCODE_MASK (~ROS_OP_MASK)

# define op_ros_bind   (-1) /* pseudo operation code for asn2wrs generated binds */
# define err_ros_bind  (-2) /* pseudo error code for asn2wrs generated binds */

typedef struct _ros_opr_t {
  int32_t opcode;
  dissector_t arg_pdu;
  dissector_t res_pdu;
} ros_opr_t;

typedef struct _ros_err_t {
  int32_t errcode;
  dissector_t err_pdu;
} ros_err_t;

typedef struct _ros_info_t {
  const char          *name;
  int                 *proto;
  int                 *ett_proto;
  const value_string  *opr_code_strings;
  const ros_opr_t     *opr_code_dissectors;
  const value_string  *err_code_strings;
  const ros_err_t     *err_code_dissectors;
} ros_info_t;

void register_ros_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto _U_, const char *name, bool uses_rtse);
void register_ros_protocol_info(const char *oid, const ros_info_t *rinfo, int proto _U_, const char *name, bool uses_rtse);
int call_ros_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, struct SESSION_DATA_STRUCTURE* session);

#endif  /* PACKET_ROS_H */
