/* packet-dccp.h
 * Definitions for Datagram Congestion Control Protocol, "DCCP" dissection:
 * it should be conformance to draft-ietf-dccp-spec-11.txt
 *
 * Copyright 2005 _FF_
 *
 * Francesco Fondelli <francesco dot fondelli, gmail dot com>
 *
 * $Id$
 *
 * template taken from packet-udp.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __PACKET_DCCP_H__
#define __PACKET_DCCP_H__

/* DCCP structs and definitions */
typedef struct _e_dccphdr
{
    guint16 sport;
    guint16 dport;
    guint8 data_offset;
    guint8 cscov;         /* 4 bits */
    guint8 ccval;         /* 4 bits */
    guint16 checksum;
    guint8 reserved1;     /* 3 bits */
    guint8 type;          /* 4 bits */
    gboolean x;           /* 1 bits */
    guint8 reserved2;     /* if x == 1 */
    guint64 seq;          /* 48 or 24 bits sequence number */

    guint16 ack_reserved; /*
                           * for all defined packet types except DCCP-Request
                           * and DCCP-Data
                           */
    guint64 ack;           /* 48 or 24 bits acknowledgement sequence number */

    guint32 service_code;
    guint8 reset_code;
    guint8 data1;
    guint8 data2;
    guint8 data3;

    address ip_src;
    address ip_dst;
} e_dccphdr;

#endif /* __PACKET_DCCP_H__ */
