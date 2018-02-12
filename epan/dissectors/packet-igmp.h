/* packet-igmp.h   2001 Ronnie Sahlberg <See AUTHORS for email>
 * Declarations of routines for IGMP packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_IGMP_H__
#define __PACKET_IGMP_H__

#define IGMP_V0_CREATE_GROUP_REQUEST	0x01
#define IGMP_V0_CREATE_GROUP_REPLY	0x02
#define IGMP_V0_JOIN_GROUP_REQUEST	0x03
#define IGMP_V0_JOIN_GROUP_REPLY	0x04
#define IGMP_V0_LEAVE_GROUP_REQUEST	0x05
#define IGMP_V0_LEAVE_GROUP_REPLY	0x06
#define IGMP_V0_CONFIRM_GROUP_REQUEST	0x07
#define IGMP_V0_CONFIRM_GROUP_REPLY	0x08
#define IGMP_V1_HOST_MEMBERSHIP_QUERY	0x11
#define IGMP_V1_HOST_MEMBERSHIP_REPORT	0x12
#define IGMP_DVMRP			0x13
#define IGMP_V1_PIM_ROUTING_MESSAGE	0x14
#define IGMP_V2_MEMBERSHIP_REPORT	0x16
#define IGMP_V2_LEAVE_GROUP		0x17
#define IGMP_TRACEROUTE_RESPONSE		0x1e
#define IGMP_TRACEROUTE_QUERY_REQ		0x1f
#define IGMP_V3_MEMBERSHIP_REPORT	0x22
#define IGMP_TYPE_0x23			0x23
#define IGMP_TYPE_0x24			0x24
#define IGMP_TYPE_0x25			0x25
#define IGMP_TYPE_0x26			0x26

#define IGMP_IGAP_JOIN  0x40
#define IGMP_IGAP_QUERY 0x41
#define IGMP_IGAP_LEAVE 0x42

#define IGMP_RGMP_LEAVE 0xFC
#define IGMP_RGMP_JOIN  0xFD
#define IGMP_RGMP_BYE   0xFE
#define IGMP_RGMP_HELLO 0xFF

void igmp_checksum(proto_tree *tree, tvbuff_t *tvb, int hf_index,
    int hf_index_status, expert_field* ei_checksum, packet_info *pinfo, guint len);

#endif

