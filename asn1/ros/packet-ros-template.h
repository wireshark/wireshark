/* packet-ros.h
 * Routines for ROS packet dissection
 * Graeme Lunt 2005
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
 */

#ifndef PACKET_ROS_H
#define PACKET_ROS_H

#include "packet-ros-exp.h"

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
# define err_ros_bind  (-1) /* pseudo eror code for asn2wrs generated binds */

typedef struct _ros_opr_t {
  gint32 opcode;
  new_dissector_t arg_pdu;
  new_dissector_t res_pdu;
} ros_opr_t;

typedef struct _ros_err_t {
  gint32 errcode;
  new_dissector_t err_pdu;
} ros_err_t;

typedef struct _ros_info_t {
  const gchar         *name;
  int                 *proto;
  gint                *ett_proto;
  const value_string  *opr_code_strings;
  const ros_opr_t     *opr_code_dissectors;
  const value_string  *err_code_strings;
  const ros_err_t     *err_code_dissectors;
} ros_info_t;

void register_ros_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto _U_, const char *name, gboolean uses_rtse);
void register_ros_protocol_info(const char *oid, const ros_info_t *rinfo, int proto _U_, const char *name, gboolean uses_rtse);
int call_ros_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, struct SESSION_DATA_STRUCTURE* session);

#endif  /* PACKET_ROS_H */
