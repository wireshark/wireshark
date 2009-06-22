/* packet-dcerpc-frsrpc.h
 * Routines for the frs (File Replication Service) MSRPC interface 
 * Copyright 2004 Jean-Baptiste Marchand <jbm@hsc.fr>
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

#ifndef __PACKET_DCERPC_FRSRPC_H
#define __PACKET_DCERPC_FRSRPC_H

/* MSRPC functions available in the frsrpc interface */

#define FRSRPC_SEND_COMM_PKT 			0x00
#define FRSRPC_VERIFY_PROMOTION_PARENT		0x01
#define FRSRPC_START_PROMOTION_PARENT 		0x02
#define FRSRPC_NOP				0x03
#define FRSRPC_BACKUP_COMPLETE			0x04
#define FRSRPC_BACKUP_COMPLETE_5		0x05
#define FRSRPC_BACKUP_COMPLETE_6		0x06
#define FRSRPC_BACKUP_COMPLETE_7		0x07
#define FRSRPC_BACKUP_COMPLETE_8		0x08
#define FRSRPC_BACKUP_COMPLETE_9		0x09
#define FRSRPC_VERIFY_PROMOTION_PARENT_EX 	0x0a

#endif /* packet-dcerpc-frsrpc.h */
