/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-h450-ros.h                                                          */
/* asn2wrs.py -q -L -p h450.ros -c ./h450-ros.cnf -s ./packet-h450-ros-template -D . -O ../.. ../ros/Remote-Operations-Information-Objects.asn Remote-Operations-Apdus.asn */

/* packet-h450-ros.h
 * Routines for H.450 packet dissection
 * 2007  Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_H450_ROS_H
#define PACKET_H450_ROS_H

extern const value_string h450_ros_ROS_vals[];
int dissect_h450_ros_ROS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#endif  /* PACKET_H450_ROS_H */

