/* packet-dcerpc-reg.h
 * Routines for SMB \PIPE\winreg packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-reg.h,v 1.8 2003/09/28 11:35:20 tpot Exp $
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

#ifndef __PACKET_DCERPC_REG_H
#define __PACKET_DCERPC_REG_H

/* Functions available on the WINREG pipe.  From Samba, include/rpc_reg.h */

#define REG_OPEN_HKCR			0x00
#define REG_OPEN_HKCU			0x01
#define REG_OPEN_HKLM			0x02
#define REG_OPEN_HKPD			0x03
#define REG_OPEN_HKU			0x04
#define REG_CLOSE_KEY			0x05
#define REG_CREATE_KEY			0x06
#define REG_DELETE_KEY			0x07
#define REG_DELETE_VALUE		0x08
#define REG_ENUM_KEY			0x09
#define REG_ENUM_VALUE			0x0a
#define REG_FLUSH_KEY			0x0b
#define REG_GET_KEY_SEC 		0x0c
#define REG_LOAD_KEY			0x0d
#define REG_NOTIFY_CHANGE_KEY_VALUE 	0x0e
#define REG_OPEN_KEY			0x0f
#define REG_QUERY_INFO_KEY		0x10
#define REG_QUERY_VALUE 		0x11
#define REG_REPLACE_KEY 		0x12
#define REG_RESTORE_KEY 		0x13
#define REG_SAVE_KEY 			0x14
#define REG_SET_KEY_SEC 		0x15
#define REG_SET_VALUE			0x16
#define REG_UNLOAD_KEY 		0x17
#define REG_INITIATE_SYSTEM_SHUTDOWN 	0x18
#define REG_ABORT_SYSTEM_SHUTDOWN	0x19
#define REG_GET_VERSION 		0x1a
#define REG_OPEN_HKCC			0x1b
#define REG_OPEN_HKDD			0x1c
#define REG_QUERY_MULTIPLE_VALUES	0x1d
#define REG_INITIATE_SYSTEM_SHUTDOWN_EX 0x1e
#define REG_SAVE_KEY_EX 		0x1f
#define REG_OPEN_HKPT			0x20
#define REG_OPEN_HKPN			0x21
#define REG_QUERY_MULTIPLE_VALUES_2	0x22

/* Registry data types */

#define DCERPC_REG_NONE                       0
#define DCERPC_REG_SZ		               1
#define DCERPC_REG_EXPAND_SZ                  2
#define DCERPC_REG_BINARY 	               3
#define DCERPC_REG_DWORD	               4
#define DCERPC_REG_DWORD_LE	               4	/* DWORD, little endian */
#define DCERPC_REG_DWORD_BE	               5	/* DWORD, big endian */
#define DCERPC_REG_LINK                       6
#define DCERPC_REG_MULTI_SZ  	               7
#define DCERPC_REG_RESOURCE_LIST              8
#define DCERPC_REG_FULL_RESOURCE_DESCRIPTOR   9
#define DCERPC_REG_RESOURCE_REQUIREMENTS_LIST 10

extern const value_string reg_datatypes[];

#endif /* packet-dcerpc-reg.h */
