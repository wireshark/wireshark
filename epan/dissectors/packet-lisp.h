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

const gchar * get_addr_str(tvbuff_t *tvb, gint offset, guint16 afi, guint16 *addr_len);
int dissect_lcaf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, proto_item *tip);
int dissect_lisp_mapping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree,
        guint8 rec_cnt, int rec, gboolean referral, gint offset, proto_item *tim);
gint dissect_lisp_map_register(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lisp_tree,
        gint offset, proto_item *tim, gboolean keep_going);

#endif /* __PACKET_LISP_H__ */
