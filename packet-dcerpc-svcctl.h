/* packet-dcerpc-svcctl.h
 * Routines for SMB \PIPE\svcctl packet disassembly
 * Copyright 2003, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-svcctl.h,v 1.5 2003/04/27 06:05:43 sahlberg Exp $
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

#ifndef __PACKET_DCERPC_SVCCTL_H
#define __PACKET_DCERPC_SVCCTL_H

#define SVC_CLOSE_SERVICE_HANDLE 0x00
#define SVC_STOP_SERVICE      0x01
#define SVC_DELETE            0x02
#define SVC_LOCK_SERVICE_DATABASE 0x03
#define SVC_GET_SVC_SEC       0x04
#define SVC_UNLOCK_SERVICE_DATABASE 0x08
#define SVC_CHANGE_SVC_CONFIG 0x0b
#define SVC_ENUM_SVCS_STATUS  0x0e
#define SVC_OPEN_SC_MAN       0x0f
#define SVC_OPEN_SERVICE      0x10
#define SVC_QUERY_SVC_CONFIG  0x11
#define SVC_START_SERVICE     0x13
#define SVC_QUERY_DISP_NAME   0x14
#define SVC_ENUM_SERVICES_STATUS	0x1a
#define SVC_OPEN_SC_MANAGER     0x1b
#define SVC_OPEN_SERVICE_A    0x1c
#define SVC_QUERY_SERVICE_LOCK_STATUS	0x1e

#endif
