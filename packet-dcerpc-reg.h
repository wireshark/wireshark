/* packet-dcerpc-reg.h
 * Routines for SMB \PIPE\winreg packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-reg.h,v 1.2 2001/12/09 00:07:37 guy Exp $
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

#ifndef __PACKET_MSRPC_REG_H
#define __PACKET_MSRPC_REG_H

/* Functions available on the WINREG pipe.  From Samba, include/rpc_reg.h */

#define REG_OPEN_HKCR		0x00
#define _REG_UNK_01		0x01
#define REG_OPEN_HKLM		0x02
#define _REG_UNK_03		0x03
#define REG_OPEN_HKU		0x04
#define REG_CLOSE		0x05
#define REG_CREATE_KEY		0x06
#define REG_DELETE_KEY		0x07
#define REG_DELETE_VALUE	0x08
#define REG_ENUM_KEY		0x09
#define REG_ENUM_VALUE		0x0a
#define REG_FLUSH_KEY		0x0b
#define REG_GET_KEY_SEC		0x0c
#define	_REG_UNK_0D		0x0d
#define _REG_UNK_0E		0x0e
#define REG_OPEN_ENTRY		0x0f
#define REG_QUERY_KEY		0x10
#define REG_INFO		0x11
#define	_REG_UNK_12		0x12
#define _REG_UNK_13		0x13
#define	_REG_UNK_14		0x14
#define REG_SET_KEY_SEC		0x15
#define REG_CREATE_VALUE	0x16
#define	_REG_UNK_17		0x17
#define REG_SHUTDOWN		0x18
#define REG_ABORT_SHUTDOWN	0x19
#define REG_UNK_1A		0x1a

#endif /* packet-dcerpc-reg.h */
