/* packet-rip.h
 *
 * $Id: packet-rip.h,v 1.6 2000/08/11 13:34:02 deniel Exp $
 *
 * (c) 1998 Hannes Boehm
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __PACKET_RIP_H__
#define __PACKET_RIP_H__

#define	RIPv1	1
#define	RIPv2	2

#define RIP_HEADER_LENGTH 4
#define RIP_ENTRY_LENGTH 20

typedef struct _e_riphdr {
    guint8	command;
    guint8	version;
    guint16	domain;
} e_riphdr;

typedef struct _e_rip_vektor {
    guint16	family;
    guint16	tag;
    guint32	ip;
    guint32	mask;
    guint32	next_hop;
    guint32	metric;
} e_rip_vektor;

typedef struct _e_rip_authentication {
    guint16	family;
    guint16	authtype;
    guint8	authentication[16];
} e_rip_authentication;

typedef union _e_rip_entry {
    e_rip_vektor	vektor;
    e_rip_authentication authentication;
} e_rip_entry;

#endif
