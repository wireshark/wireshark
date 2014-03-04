/* packet-portmap.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PACKET_PORTMAP_H
#define PACKET_PORTMAP_H

#define PORTMAP_PROGRAM  100000

#define PORTMAPPROC_NULL     0
#define PORTMAPPROC_SET      1
#define PORTMAPPROC_UNSET    2
#define PORTMAPPROC_GETPORT  3
#define PORTMAPPROC_DUMP     4
#define PORTMAPPROC_CALLIT   5

/* RFC 1833, Page 7 */
#define RPCBPROC_NULL		0
#define RPCBPROC_SET		1
#define RPCBPROC_UNSET		2
#define RPCBPROC_GETADDR	3
#define RPCBPROC_DUMP		4
#define RPCBPROC_CALLIT		5
#define RPCBPROC_GETTIME	6
#define RPCBPROC_UADDR2TADDR	7
#define RPCBPROC_TADDR2UADDR	8

/* RFC 1833, Page 8 */
#define RPCBPROC_BCAST		RPCBPROC_CALLIT
#define RPCBPROC_GETVERSADDR	9
#define RPCBPROC_INDIRECT	10
#define RPCBPROC_GETADDRLIST	11
#define RPCBPROC_GETSTAT	12

struct pmap {
        guint32 pm_prog;
        guint32 pm_vers;
        guint32 pm_prot;
        guint32 pm_port;
};

#endif
