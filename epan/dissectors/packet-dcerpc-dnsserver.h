/* packet-dcerpc-dnsserver.h
 * Routines for SMB \PIPE\DNSSERVER packet disassembly
 * Copyright 2002, Tim Potter <tpot@samba.org>
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

#ifndef __PACKET_DCERPC_DNSSERVER_H
#define __PACKET_DCERPC_DNSSERVER_H

/* Functions available on the DNSSERVER pipe */

#define DNSSERVER_DNSSRV_OPERATION 		0x00
#define DNSSERVER_DNSSRV_QUERY 			0x01
#define DNSSERVER_DNSSRV_COMPLEX_OPERATION	0x02
#define DNSSERVER_DNSSRV_ENUM_RECORDS 		0x03
#define DNSSERVER_DNSSRV_UPDATE_RECORD	 	0x04
#define DNSSERVER_DNSSRV_OPERATION_2 		0x05
#define DNSSERVER_DNSSRV_QUERY_2 		0x06
#define DNSSERVER_DNSSRV_COMPLEX_OPERATION_2	0x07
#define DNSSERVER_DNSSRV_ENUM_RECORDS_2 	0x08
#define DNSSERVER_DNSSRV_UPDATE_RECORD_2 	0x09

#endif /* packet-dcerpc-dnsserver.h */
