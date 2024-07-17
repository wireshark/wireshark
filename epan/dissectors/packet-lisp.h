/* packet-lisp.h
 * Routines for Locator/ID Separation Protocol (LISP) Control Message dissection
 * Copyright 2018 Lorand Jakab <ljakab@ac.upc.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_LISP_H__
#define __PACKET_LISP_H__

#include <epan/packet.h>

#define INET_ADDRLEN        4
#define INET6_ADDRLEN       16
#define EUI48_ADDRLEN       6
#define LISP_XTRID_LEN      16
#define LISP_SITEID_LEN     8

#define LISP_CONTROL_PORT   4342

const char * get_addr_str(tvbuff_t *tvb, packet_info *pinfo, int offset, uint16_t afi, uint16_t *addr_len);
int dissect_lcaf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_item *tip);
int dissect_lisp_mapping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree,
        uint8_t rec_cnt, int rec, bool referral, int offset, proto_item *tim);
int dissect_lisp_map_register(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree,
        int offset, proto_item *tim, bool keep_going);

#endif /* __PACKET_LISP_H__ */
