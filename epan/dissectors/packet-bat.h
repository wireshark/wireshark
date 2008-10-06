/* packet-bat.h
 * Routines for B.A.T.M.A.N. Layer 3 dissection
 * Copyright (C) 2007-2008 B.A.T.M.A.N. contributors:
 * Marek Lindner
 *
 * $Id$
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#ifndef _PACKET_BAT_H
#define _PACKET_BAT_H

#define BAT_BATMAN_PORT  4305
#define BAT_GW_PORT  4306
#define BAT_VIS_PORT  4307

#define UNIDIRECTIONAL 0x80
#define DIRECTLINK 0x40

struct batman_packet_v5 {
	guint8  version;  /* batman version field */
	guint8  flags;    /* 0x80: UNIDIRECTIONAL link, 0x40: DIRECTLINK flag, ... */
	guint8  ttl;
	guint8  gwflags;  /* flags related to gateway functions: gateway class */
	guint16 seqno;
	guint16 gwport;
	address orig;
	address old_orig;
	guint8 tq;
	guint8 hna_len;
};
#define BATMAN_PACKET_V5_SIZE 18

struct gw_packet {
	guint8  type;
};
#define GW_PACKET_SIZE 1

#define TUNNEL_DATA 0x01
#define TUNNEL_IP_REQUEST 0x02
#define TUNNEL_IP_INVALID 0x03
#define TUNNEL_KEEPALIVE_REQUEST 0x04
#define TUNNEL_KEEPALIVE_REPLY 0x05

#define DATA_TYPE_NEIGH 1
#define DATA_TYPE_SEC_IF 2
#define DATA_TYPE_HNA 3



struct vis_packet_v22 {
	address sender_ip;
	guint8 version;
	guint8 gw_class;
	guint16 tq_max;
};
#define VIS_PACKET_V22_SIZE 8

struct vis_data_v22 {
	guint8 type;
	guint16 data;
	address ip;
};
#define VIS_PACKET_V22_DATA_SIZE 7

struct vis_packet_v23 {
	address sender_ip;
	guint8 version;
	guint8 gw_class;
	guint8 tq_max;
};
#define VIS_PACKET_V23_SIZE 7

struct vis_data_v23 {
	guint8 type;
	guint8 data;
	address ip;
};
#define VIS_PACKET_V23_DATA_SIZE 6

#endif /* _PACKET_BAT_H */
