/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-ros.h                                                             */
/* ../../tools/asn2eth.py -X -b -e -p ros -c ros.cnf -s packet-ros-template ros.asn */

/* Input file: packet-ros-template.h */

#line 1 "packet-ros-template.h"
/* packet-ros.h
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

#ifndef PACKET_ROS_H
#define PACKET_ROS_H


/*--- Included file: packet-ros-exp.h ---*/
#line 1 "packet-ros-exp.h"
extern const value_string ros_InvokeId_vals[];
extern const value_string ros_Code_vals[];
int dissect_ros_InvokeId(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_ros_Code(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

/*--- End of included file: packet-ros-exp.h ---*/
#line 30 "packet-ros-template.h"

# include "packet-ses.h"

/* for use in the SESSION_DATA_STRUCTURE ros_op argument
   top byte indicates ROS invocation 
   bottom three bytes indicate operation code */

# define ROS_OP_MASK    0xff000000

# define ROS_OP_ARGUMENT  0x10000000
# define ROS_OP_RESULT  0x20000000
# define ROS_OP_ERROR   0x30000000
# define ROS_OP_REJECT  0x40000000

# define ROS_OP_BIND    0x01000000
# define ROS_OP_UNBIND  0x02000000
# define ROS_OP_INVOKE  0x03000000

# define ROS_OP_OPCODE_MASK (~ROS_OP_MASK)

void register_ros_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto _U_, const char *name, gboolean uses_rtse);

#endif  /* PACKET_ROS_H */
