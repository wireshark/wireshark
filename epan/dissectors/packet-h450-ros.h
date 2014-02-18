/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-h450-ros.h                                                          */
/* ../../tools/asn2wrs.py -p h450.ros -c ./h450-ros.cnf -s ./packet-h450-ros-template -D . -O ../../epan/dissectors ../ros/Remote-Operations-Information-Objects.asn Remote-Operations-Apdus.asn */

/* Input file: packet-h450-ros-template.h */

#line 1 "../../asn1/h450-ros/packet-h450-ros-template.h"
/* packet-h450-ros.h
 * Routines for H.450 packet dissection
 * 2007  Tomas Kukosa
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

#ifndef PACKET_H450_ROS_H
#define PACKET_H450_ROS_H


/*--- Included file: packet-h450-ros-exp.h ---*/
#line 1 "../../asn1/h450-ros/packet-h450-ros-exp.h"
extern const value_string h450_ros_ROS_vals[];
int dissect_h450_ros_ROS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-h450-ros-exp.h ---*/
#line 28 "../../asn1/h450-ros/packet-h450-ros-template.h"

#endif  /* PACKET_H450_ROS_H */

