/* packet-dcerpc-netlogon.h
 * Routines for SMB \PIPE\NETLOGON packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-netlogon.h,v 1.4 2002/03/12 08:16:41 sahlberg Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_DCERPC_NETLOGON_H
#define __PACKET_DCERPC_NETLOGON_H

#define NETLOGON_FUNCTION_00				0x00
#define NETLOGON_FUNCTION_01				0x01
#define NETLOGON_NETLOGONSAMLOGON			0x02
#define NETLOGON_NETLOGONSAMLOGOFF			0x03
#define NETLOGON_NETSERVERREQCHALLENGE			0x04
#define NETLOGON_NETSERVERAUTHENTICATE			0x05
#define NETLOGON_NETSERVERPASSWORDSET			0x06
#define NETLOGON_NETSAMDELTAS				0x07
#define NETLOGON_FUNCTION_08				0x08
#define NETLOGON_FUNCTION_09				0x09
#define NETLOGON_FUNCTION_0A				0x0a
#define NETLOGON_FUNCTION_0B				0x0b
#define NETLOGON_NETLOGONCONTROL			0x0c
#define NETLOGON_FUNCTION_0D				0x0d
#define NETLOGON_NETLOGONCONTROL2			0x0e
#define NETLOGON_NETSERVERAUTHENTICATE2			0x0f
#define NETLOGON_NETDATABASESYNC2			0x10
#define NETLOGON_FUNCTION_11				0x11
#define NETLOGON_FUNCTION_12				0x12
#define NETLOGON_NETTRUSTEDDOMAINLIST			0x13
#define NETLOGON_DSRGETDCNAME2				0x14
#define NETLOGON_FUNCTION_15				0x15
#define NETLOGON_FUNCTION_16				0x16
#define NETLOGON_FUNCTION_17				0x17
#define NETLOGON_FUNCTION_18				0x18
#define NETLOGON_FUNCTION_19				0x19
#define NETLOGON_NETSERVERAUTHENTICATE3			0x1a
#define NETLOGON_DSRGETDCNAME				0x1b
#define NETLOGON_DSRGETSITENAME				0x1c
#define NETLOGON_FUNCTION_1D				0x1d
#define NETLOGON_FUNCTION_1E				0x1e
#define NETLOGON_NETSERVERPASSWORDSET2			0x1f
#define NETLOGON_FUNCTION_20				0x20
#define NETLOGON_FUNCTION_21				0x21
#define NETLOGON_FUNCTION_22				0x22
#define NETLOGON_FUNCTION_23				0x23
#define NETLOGON_FUNCTION_24				0x24
#define NETLOGON_FUNCTION_25				0x25
#define NETLOGON_FUNCTION_26				0x26
#define NETLOGON_FUNCTION_27				0x27
#define NETLOGON_DSRROLEGETPRIMARYDOMAININFORMATION	0x28
#define NETLOGON_DSRDEREGISTERDNSHOSTRECORDS		0x29

#endif /* packet-dcerpc-netlogon.h */
