/* packet-dcerpc-netlogon.h
 * Routines for SMB \PIPE\NETLOGON packet disassembly
 * Copyright 2001,2003 Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-netlogon.h,v 1.15 2003/09/12 10:32:21 sahlberg Exp $
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

#define NETLOGON_NETRLOGONUASLOGON			0x00
#define NETLOGON_NETRLOGONUASLOGOFF			0x01
#define NETLOGON_NETRLOGONSAMLOGON			0x02
#define NETLOGON_NETRLOGONSAMLOGOFF			0x03
#define NETLOGON_NETRSERVERREQCHALLENGE			0x04
#define NETLOGON_NETRSERVERAUTHENTICATE			0x05
#define NETLOGON_NETRSERVERPASSWORDSET			0x06
#define NETLOGON_NETRDATABASEDELTAS			0x07
#define NETLOGON_NETRDATABASESYNC			0x08
#define NETLOGON_NETRACCOUNTDELTAS			0x09
#define NETLOGON_NETRACCOUNTSYNC			0x0a
#define NETLOGON_NETRGETDCNAME				0x0b
#define NETLOGON_NETRLOGONCONTROL			0x0c
#define NETLOGON_NETRGETANYDCNAME			0x0d
#define NETLOGON_NETRLOGONCONTROL2			0x0e
#define NETLOGON_NETRSERVERAUTHENTICATE2		0x0f
#define NETLOGON_NETRDATABASESYNC2			0x10
#define NETLOGON_NETRDATABASEREDO			0x11
#define NETLOGON_FUNCTION_12				0x12
#define NETLOGON_NETRENUMERATETRUSTEDDOMAINS		0x13
#define NETLOGON_DSRGETDCNAMEEX2			0x14
#define NETLOGON_FUNCTION_15				0x15
#define NETLOGON_FUNCTION_16				0x16
#define NETLOGON_NETRLOGONGETTRUSTRID			0x17
#define NETLOGON_NETRLOGONCOMPUTERSERVERDIGEST		0x18
#define NETLOGON_FUNCTION_19				0x19
#define NETLOGON_NETRSERVERAUTHENTICATE3		0x1a
#define NETLOGON_DSRGETDCNAME				0x1b
#define NETLOGON_DSRGETSITENAME				0x1c
#define NETLOGON_NETRLOGONGETDOMAININFO			0x1d
#define NETLOGON_FUNCTION_1E				0x1e
#define NETLOGON_NETRSERVERPASSWORDSET2			0x1f
#define NETLOGON_FUNCTION_20				0x20
#define NETLOGON_FUNCTION_21				0x21
#define NETLOGON_FUNCTION_22				0x22
#define NETLOGON_FUNCTION_23				0x23
#define NETLOGON_FUNCTION_24				0x24
#define NETLOGON_FUNCTION_25				0x25
#define NETLOGON_DSRGETDCSITECOVERAGE			0x26
#define NETLOGON_LOGONSAMLOGONEX			0x27
#define NETLOGON_DSRENUMERATEDOMAINTRUSTS		0x28
#define NETLOGON_DSRDEREGISTERDNSHOSTRECORDS		0x29

/* Secure channel types */

#define SEC_CHAN_WKSTA   2
#define SEC_CHAN_DOMAIN  4
#define SEC_CHAN_BDC     6

#endif /* packet-dcerpc-netlogon.h */
