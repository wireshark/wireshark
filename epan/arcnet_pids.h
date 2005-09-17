/* arcnet_pids.h
 * ARCNET protocol ID values
 * Copyright 2001-2002, Peter Fales <ethereal@fales-lorenz.net>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

/* RFC 1051 */
#define ARCNET_PROTO_IP_1051	240
#define ARCNET_PROTO_ARP_1051	241

/* RFC 1201 */
#define ARCNET_PROTO_IP_1201	212
#define ARCNET_PROTO_ARP_1201	213
#define ARCNET_PROTO_RARP_1201	214

#define ARCNET_PROTO_IPX	250
#define ARCNET_PROTO_NOVELL_EC	236

#define ARCNET_PROTO_IPv6	196	/* or so BSD's arcnet.h claims */

/*
 * Raw Ethernet over ARCNET - Linux's "if_arcnet.h" calls this
 * "MS LanMan/WfWg 'NDIS' encapsuation".
 */
#define ARCNET_PROTO_ETHERNET	232

#define ARCNET_PROTO_DATAPOINT_BOOT	0
#define ARCNET_PROTO_DATAPOINT_MOUNT	1
#define ARCNET_PROTO_POWERLAN_BEACON	8
#define ARCNET_PROTO_POWERLAN_BEACON2	243
#define ARCNET_PROTO_LANSOFT	251

#define ARCNET_PROTO_APPLETALK	221
#define ARCNET_PROTO_BANYAN	247	/* Banyan VINES */

#define ARCNET_PROTO_DIAGNOSE	128	/* as per ANSI/ATA 878.1 */

#define ARCNET_PROTO_BACNET	205
