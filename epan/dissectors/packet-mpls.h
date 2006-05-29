/* packet-mpls.h
 * Declarations of exported routines from MPLS dissector
 * Author: Carlos Pignataro <cpignata@cisco.com>
 * Copyright 2005, cisco Systems, Inc.
 *
 * (c) Copyright 2006, _FF_ Francesco Fondelli <francesco.fondelli@gmail.com>  
 *                     added MPLS OAM support, ITU-T Y.1711
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

#ifndef __PACKET_MPLS_H_
#define __PACKET_MPLS_H__

/* Special labels in MPLS */
enum {
    LABEL_IP4_EXPLICIT_NULL = 0,
    LABEL_ROUTER_ALERT,
    LABEL_IP6_EXPLICIT_NULL,
    LABEL_IMPLICIT_NULL,
    LABEL_OAM_ALERT = 14,
    LABEL_MAX_RESERVED = 15
};

extern const value_string special_labels[];
extern void decode_mpls_label(tvbuff_t *tvb, int offset,
                              guint32 *label, guint8 *exp,
                              guint8 *bos, guint8 *ttl);

#endif
