/* packet-dcerpc-srvsvc.h
 * Routines for SMB \PIPE\srvsvc packet disassembly
 * initial version
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * 2002, Ronnie Sahlberg.
 *  Rewrote entire file with a complete and correct list of all
 *  function names.  Ronnie Sahlberg
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

#ifndef __PACKET_DCERPC_SRVSVC_H
#define __PACKET_DCERPC_SRVSVC_H

#define SRV_NETRCHARDEVENUM		0x00
#define SRV_NETRCHARDEVGETINFO		0x01
#define SRV_NETRCHARDEVCONTROL		0x02
#define SRV_NETRCHARDEVQENUM		0x03
#define SRV_NETRCHARDEVQGETINFO		0x04
#define SRV_NETRCHARDEVQSETINFO		0x05
#define SRV_NETRCHARDEVQPURGE		0x06
#define SRV_NETRCHARDEVQPURGESELF	0x07
#define SRV_NETRCONNECTIONENUM		0x08
#define SRV_NETRFILEENUM		0x09
#define SRV_NETRFILEGETINFO		0x0a
#define SRV_NETRFILECLOSE		0x0b
#define SRV_NETRSESSIONENUM		0x0c
#define SRV_NETRSESSIONDEL		0x0d
#define SRV_NETRSHAREADD		0x0e
#define SRV_NETRSHAREENUM		0x0f
#define SRV_NETRSHAREGETINFO		0x10
#define SRV_NETRSHARESETINFO		0x11
#define SRV_NETRSHAREDEL		0x12
#define SRV_NETRSHAREDELSTICKY		0x13
#define SRV_NETRSHARECHECK		0x14
#define SRV_NETRSERVERGETINFO		0x15
#define SRV_NETRSERVERSETINFO		0x16
#define SRV_NETRSERVERDISKENUM		0x17
#define SRV_NETRSERVERSTATISTICSGET	0x18
#define SRV_NETRSERVERTRANSPORTADD	0x19
#define SRV_NETRSERVERTRANSPORTENUM	0x1a
#define SRV_NETRSERVERTRANSPORTDEL	0x1b
#define SRV_NETRREMOTETOD		0x1c
#define SRV_NETRSERVERSETSERVICEBITS	0x1d
#define SRV_NETRPRPATHTYPE		0x1e
#define SRV_NETRPRPATHCANONICALIZE	0x1f
#define SRV_NETRPRPATHCOMPARE		0x20
#define SRV_NETRPRNAMEVALIDATE		0x21
#define SRV_NETRPRNAMECANONICALIZE	0x22
#define SRV_NETRPRNAMECOMPARE		0x23
#define SRV_NETRSHAREENUMSTICKY		0x24
#define SRV_NETRSHAREDELSTART		0x25
#define SRV_NETRSHAREDELCOMMIT		0x26
#define SRV_NETRPGETFILESECURITY	0x27
#define SRV_NETRPSETFILESECURITY	0x28
#define SRV_NETRSERVERTRANSPORTADDEX	0x29
#define SRV_NETRSERVERSETSERVICEBITSEX	0x2a
#define SRV_NETRDFSGETVERSION 		0x2b
#define SRV_NETRDFSCREATELOCALPARTITION 0x2c
#define SRV_NETRDFSDELETELOCALPARTITION 0x2d
#define SRV_NETRDFSSETLOCALVOLUMESTATE  0x2e
#define SRV_NETRDFSSETSERVERINFO	0x2f
#define SRV_NETRDFSCREATEEXITPOINT	0x30
#define SRV_NETRDFSDELETEEXITPOINT	0x31
#define SRV_NETRDFSMODIFYPREFIX		0x32
#define SRV_NETRDFSFIXLOCALVOLUME	0x33
#define SRV_NETRDFSMANAGERREPORTSITEINFO 0x34
#define SRV_NETRSERVERTRANSPORTDELEX	0x35

#endif
