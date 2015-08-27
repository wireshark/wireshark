/* packet-icmp.h
 * Definitions for ICMP: http://tools.ietf.org/html/rfc792.
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

#ifndef __PACKET_ICMP_H__
#define __PACKET_ICMP_H__

extern int proto_icmp;

/* ICMP echo request/reply transaction statistics ... used by ICMP tap(s) */
typedef struct _icmp_transaction_t {
    guint32 rqst_frame;
    guint32 resp_frame;
    nstime_t rqst_time;
    nstime_t resp_time;
} icmp_transaction_t;

/* ICMP info ... used by sequence analysis tap and stored in pinfo with p_add_proto_data */
typedef struct {
    guint8 type;
    guint8 code;
} icmp_info_t;

#endif
