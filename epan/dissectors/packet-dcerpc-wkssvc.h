/* packet-dcerpc-wkssvc.h
 * Routines for SMB \PIPE\wkssvc packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 * Copyright 2002, Richard Sharpe <rsharpe@richardsharpe.org>
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

#ifndef __PACKET_DCERPC_WKSSVC_H
#define __PACKET_DCERPC_WKSSVC_H

/* Functions available on the WKSSVC pipe.  From Samba, include/rpc_wkssvc.h */

#define WKS_NETRWKSTAGETINFO    		0x00
#define WKS_NETRWKSTASETINFO       		0x01
#define WKS_NETRWKSTAUSERENUM     		0x02
#define WKS_NETRWKSTAUSERGETINFO		0x03
#define WKS_NETRWKSTAUSERSETINFO		0x04
#define WKS_NETRWKSTATRANSPORTENUM 		0x05
#define WKS_NETRWKSTATRANSPORTADD		0x06
#define WKS_NETRWKSTATRANSPORTDEL		0x07
#define WKS_NETRUSEADD				0x08
#define WKS_NETRUSEGETINFO			0x09
#define WKS_NETRUSEDEL				0x0a
#define WKS_NETRUSEENUM 			0x0b
#define WKS_NETRMESSAGEBUFFERSEND		0x0c
#define WKS_NETRWORKSTATIONSTATISTICSGET 	0x0d
#define WKS_NETRLOGONDOMAINNAMEADD		0x0e
#define WKS_NETRLOGONDOMAINNAMEDEL		0x0f
#define WKS_NETRJOINDOMAIN			0x10
#define WKS_NETRUNJOINDOMAIN			0x11
#define WKS_NETRRENAMEMACHINEINDOMAIN		0x12
#define WKS_NETRVALIDATENAME			0x13
#define WKS_NETRGETJOININFORMATION		0x14
#define WKS_NETRGETJOINABLEOUS			0x15
#define WKS_NETRJOINDOMAIN2			0x16
#define WKS_NETRUNJOINDOMAIN2			0x17
#define WKS_NETRRENAMEMACHINEINDOMAIN2		0x18
#define WKS_NETRVALIDATENAME2			0x19
#define WKS_NETRGETJOINABLEOUS2 		0x1a
#define WKS_NETRADDALTERNATECOMPUTERNAME 	0x1b
#define WKS_NETRREMOVEALTERNATECOMPUTERNAME 	0x1c
#define WKS_NETRSETPRIMARYCOMPUTERNAME		0x1d
#define WKS_NETRENUMERATECOMPUTERNAMES		0x1e



#endif /* packet-dcerpc-wkssvc.h */
