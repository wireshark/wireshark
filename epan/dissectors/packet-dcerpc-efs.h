/* packet-dcerpc-efs.h
 * Routines for the efsrpc MSRPC interface
 * Copyright 2004 Ronnie Sahlberg, Jean-Baptiste Marchand 
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_DCERPC_EFS_H
#define __PACKET_DCERPC_EFS_H

/* MSRPC functions available in the efsrpc interface */

#define EFS_RPC_OPEN_FILE_RAW 			0x00
#define EFS_RPC_READ_FILE_RAW			0x01
#define EFS_RPC_WRITE_FILE_RAW			0x02
#define EFS_RPC_CLOSE_RAW			0x03
#define EFS_RPC_ENCRYPT_FILE_SRV 		0x04
#define EFS_RPC_DECRYPT_FILE_SRV		0x05
#define EFS_RPC_QUERY_USERS_ON_FILE		0x06
#define EFS_RPC_QUERY_RECOVERY_AGENTS		0x07
#define EFS_RPC_REMOVE_USERS_FROM_FILE		0x08
#define EFS_RPC_ADD_USERS_TO_FILE		0x09
#define EFS_RPC_SET_FILE_ENCRYPTION_KEY 	0x0a
#define EFS_RPC_NOT_SUPPORTED			0x0b
#define EFS_RPC_FILE_KEY_INFO			0x0c
#define EFS_RPC_DUPLICATE_ENCRYPTION_INFO_FILE 	0x0d

#endif /* packet-dcerpc-efs.h */
