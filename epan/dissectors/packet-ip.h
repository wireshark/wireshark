/* packet-ip.h
 * Definitions for IP packet disassembly structures and routines
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


#ifndef __PACKET_IP_H__
#define __PACKET_IP_H__

#include "ws_symbol_export.h"

extern int proto_ip;

typedef struct _ws_ip
{
    guint8  ip_v_hl; /* combines ip_v and ip_hl */
    guint8  ip_tos;
    guint16 ip_len;
    guint16 ip_id;
    guint16 ip_off;
    guint8  ip_ttl;
    guint8  ip_p;
    guint16 ip_sum;
    address ip_src;
    address ip_dst;
} ws_ip;

void capture_ip(const guchar *, int, int, packet_counts *);
guint16 ip_checksum(const guint8 *ptr, int len);

/* Export the DSCP extended value-string table for other protocols */
WS_DLL_PUBLIC value_string_ext dscp_vals_ext;

#endif
