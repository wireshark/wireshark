/* packet-dcerpc-svcctl.h
 * Routines for SMB \PIPE\svcctl packet disassembly
 * Copyright 2003, Tim Potter <tpot@samba.org>
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

#ifndef __PACKET_DCERPC_SVCCTL_H
#define __PACKET_DCERPC_SVCCTL_H

#define SVC_CLOSE_SERVICE_HANDLE 		0x00
#define SVC_CONTROL_SERVICE      		0x01
#define SVC_DELETE_SERVICE 			0x02
#define SVC_LOCK_SERVICE_DATABASE 		0x03
#define SVC_QUERY_SERVICE_OBJECT_SECURITY  	0x04
#define SVC_SET_SERVICE_OBJECT_SECURITY		0x05
#define SVC_QUERY_SERVICE_STATUS		0x06 
#define SVC_SET_SERVICE_STATUS			0x07
#define SVC_UNLOCK_SERVICE_DATABASE 		0x08
#define SVC_NOTIFY_BOOT_CONFIG_STATUS		0x09
#define SVC_SC_SET_SERVICE_BITS_W		0x0a
#define SVC_CHANGE_SERVICE_CONFIG_W 		0x0b
#define SVC_CREATE_SERVICE_W			0x0c
#define SVC_ENUM_DEPENDENT_SERVICES_W		0x0d
#define SVC_ENUM_SERVICES_STATUS_W 		0x0e
#define SVC_OPEN_SC_MANAGER_W      		0x0f
#define SVC_OPEN_SERVICE_W 			0x10
#define SVC_QUERY_SERVICE_CONFIG_W 		0x11
#define SVC_QUERY_SERVICE_LOCK_STATUS_W		0x12
#define SVC_START_SERVICE_W    			0x13
#define SVC_GET_SERVICE_DISPLAY_NAME_W 		0x14
#define SVC_GET_SERVICE_KEY_NAME_W 		0x15
#define SVC_SC_SET_SERVICE_BITS_A		0x16
#define SVC_CHANGE_SERVICE_CONFIG_A		0x17
#define SVC_CREATE_SERVICE_A			0x18
#define SVC_ENUM_DEPENDENT_SERVICES_A		0x19
#define SVC_ENUM_SERVICES_STATUS_A		0x1a
#define SVC_OPEN_SC_MANAGER_A 			0x1b
#define SVC_OPEN_SERVICE_A    			0x1c
#define SVC_QUERY_SERVICE_CONFIG_A 		0x1d
#define SVC_QUERY_SERVICE_LOCK_STATUS_A		0x1e
#define SVC_START_SERVICE_A			0x1f
#define SVC_GET_SERVICE_DISPLAY_NAME_A 		0x20
#define SVC_GET_SERVICE_KEY_NAME_A 		0x21
#define SVC_SC_GET_CURRENT_GROUPE_STATE_W	0x22
#define SVC_ENUM_SERVICE_GROUP_W		0x23
#define SVC_CHANGE_SERVICE_CONFIG2_A		0x24
#define SVC_CHANGE_SERVICE_CONFIG2_W		0x25
#define SVC_QUERY_SERVICE_CONFIG2_A 		0x26
#define SVC_QUERY_SERVICE_CONFIG2_W 		0x27
#define SVC_QUERY_SERVICE_STATUS_EX		0x28
#define SVC_ENUM_SERVICES_STATUS_EX_A 		0x29
#define SVC_ENUM_SERVICES_STATUS_EX_W 		0x2a
#define SVC_SC_SEND_TS_MESSAGE			0x2b

#endif
