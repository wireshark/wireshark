/* packet-dcerpc-spoolss.h
 * Routines for SMB \PIPE\spoolss packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-spoolss.h,v 1.4 2002/03/22 10:03:35 guy Exp $
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

#ifndef __PACKET_DCERPC_SPOOLSS_H
#define __PACKET_DCERPC_SPOOLSS_H

/* Functions available on the SPOOLSS pipe.  From Samba, 
   include/rpc_spoolss.h */

#define SPOOLSS_ENUMPRINTERS				0x00
#define SPOOLSS_OPENPRINTER				0x01
#define SPOOLSS_SETJOB					0x02
#define SPOOLSS_GETJOB					0x03
#define SPOOLSS_ENUMJOBS				0x04
#define SPOOLSS_ADDPRINTER				0x05
#define SPOOLSS_DELETEPRINTER				0x06
#define SPOOLSS_SETPRINTER				0x07
#define SPOOLSS_GETPRINTER				0x08
#define SPOOLSS_ADDPRINTERDRIVER			0x09
#define SPOOLSS_ENUMPRINTERDRIVERS			0x0a
#define SPOOLSS_GETPRINTERDRIVER			0x0b
#define SPOOLSS_GETPRINTERDRIVERDIRECTORY		0x0c
#define SPOOLSS_DELETEPRINTERDRIVER			0x0d
#define SPOOLSS_ADDPRINTPROCESSOR			0x0e
#define SPOOLSS_ENUMPRINTPROCESSORS			0x0f
#define SPOOLSS_GETPRINTPROCESSORDIRECTORY		0x10
#define SPOOLSS_STARTDOCPRINTER				0x11
#define SPOOLSS_STARTPAGEPRINTER			0x12
#define SPOOLSS_WRITEPRINTER				0x13
#define SPOOLSS_ENDPAGEPRINTER				0x14
#define SPOOLSS_ABORTPRINTER				0x15
#define SPOOLSS_READPRINTER				0x16
#define SPOOLSS_ENDDOCPRINTER				0x17
#define SPOOLSS_ADDJOB					0x18
#define SPOOLSS_SCHEDULEJOB				0x19
#define SPOOLSS_GETPRINTERDATA				0x1a
#define SPOOLSS_SETPRINTERDATA				0x1b
#define SPOOLSS_WAITFORPRINTERCHANGE			0x1c
#define SPOOLSS_CLOSEPRINTER				0x1d
#define SPOOLSS_ADDFORM					0x1e
#define SPOOLSS_DELETEFORM				0x1f
#define SPOOLSS_GETFORM					0x20
#define SPOOLSS_SETFORM					0x21
#define SPOOLSS_ENUMFORMS				0x22
#define SPOOLSS_ENUMPORTS				0x23
#define SPOOLSS_ENUMMONITORS				0x24
#define SPOOLSS_ADDPORT					0x25
#define SPOOLSS_CONFIGUREPORT				0x26
#define SPOOLSS_DELETEPORT				0x27
#define SPOOLSS_CREATEPRINTERIC				0x28
#define SPOOLSS_PLAYGDISCRIPTONPRINTERIC		0x29
#define SPOOLSS_DELETEPRINTERIC				0x2a
#define SPOOLSS_ADDPRINTERCONNECTION			0x2b
#define SPOOLSS_DELETEPRINTERCONNECTION			0x2c
#define SPOOLSS_PRINTERMESSAGEBOX			0x2d
#define SPOOLSS_ADDMONITOR				0x2e
#define SPOOLSS_DELETEMONITOR				0x2f
#define SPOOLSS_DELETEPRINTPROCESSOR			0x30
#define SPOOLSS_ADDPRINTPROVIDOR			0x31
#define SPOOLSS_DELETEPRINTPROVIDOR			0x32
#define SPOOLSS_ENUMPRINTPROCDATATYPES			0x33
#define SPOOLSS_RESETPRINTER				0x34
#define SPOOLSS_GETPRINTERDRIVER2			0x35
#define SPOOLSS_FINDFIRSTPRINTERCHANGENOTIFICATION	0x36
#define SPOOLSS_FINDNEXTPRINTERCHANGENOTIFICATION	0x37
#define SPOOLSS_FCPN					0x38
#define SPOOLSS_ROUTERFINDFIRSTPRINTERNOTIFICATIONOLD	0x39
#define SPOOLSS_REPLYOPENPRINTER			0x3a
#define SPOOLSS_ROUTERREPLYPRINTER			0x3b
#define SPOOLSS_REPLYCLOSEPRINTER			0x3c
#define SPOOLSS_ADDPORTEX				0x3d
#define SPOOLSS_REMOTEFINDFIRSTPRINTERCHANGENOTIFICATION 0x3e
#define SPOOLSS_SPOOLERINIT				0x3f
#define SPOOLSS_RESETPRINTEREX				0x40
#define SPOOLSS_RFFPCNEX				0x41
#define SPOOLSS_RRPCN					0x42
#define SPOOLSS_RFNPCNEX				0x43
#define SPOOLSS_OPENPRINTEREX				0x45
#define SPOOLSS_ADDPRINTEREX				0x46
#define SPOOLSS_ENUMPRINTERDATA				0x48
#define SPOOLSS_DELETEPRINTERDATA			0x49
#define SPOOLSS_SETPRINTERDATAEX			0x4d
#define SPOOLSS_GETPRINTERDATAEX			0x4e
#define SPOOLSS_ENUMPRINTERDATAEX			0x4f
#define SPOOLSS_ENUMPRINTERKEY				0x50
#define SPOOLSS_DELETEPRINTERDATAEX			0x51
#define SPOOLSS_DELETEPRINTERDRIVEREX			0x54
#define SPOOLSS_ADDPRINTERDRIVEREX			0x59
#endif /* packet-dcerpc-spoolss.h */







