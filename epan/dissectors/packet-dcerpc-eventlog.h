/* packet-dcerpc-eventlog.h
 * Routines for SMB \pipe\eventlog packet disassembly
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

#ifndef __PACKET_DCERPC_EVENTLOG_H
#define __PACKET_DCERPC_EVENTLOG_H

/* MSRPC functions available in the eventlog interface */

#define EVENTLOG_CLEAR 			0x00
#define EVENTLOG_BACKUP 		0x01
#define EVENTLOG_CLOSE 			0x02
#define EVENTLOG_DEREGISTER_EVT_SRC 	0x03
#define EVENTLOG_NUMOFRECORDS 		0x04
#define EVENTLOG_GET_OLDEST_RECORD 	0x05
#define EVENTLOG_NOTIFY_CHANGE 		0x06
#define EVENTLOG_OPEN 			0x07
#define EVENTLOG_REGISTER_EVT_SRC 	0x08
#define EVENTLOG_OPEN_BACKUP 		0x09
#define EVENTLOG_READ 			0x0a
#define EVENTLOG_REPORT 		0x0b
#define EVENTLOG_CLEAR_ASCII 		0x0c
#define EVENTLOG_BACKUP_ASCII 		0x0d
#define EVENTLOG_OPEN_ASCII 		0x0e
#define EVENTLOG_REGISTER_EVT_SRC_ASCII 0x0f
#define EVENTLOG_OPEN_BACKUP_ASCII 	0x10
#define EVENTLOG_READ_ASCII 		0x11
#define EVENTLOG_REPORT_ASCII 		0x12
#define EVENTLOG_REGISTER_CLUSTER_SVC 	0x13
#define EVENTLOG_DEREGISTER_CLUSTER_SVC	0x14
#define EVENTLOG_WRITE_CLUSTER_EVENTS	0x15
#define EVENTLOG_GET_INFO 		0x16
#define EVENTLOG_FLUSH 			0x17

#endif /* packet-dcerpc-eventlog.h */

