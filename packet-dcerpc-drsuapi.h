/* packet-dcerpc-drsuapi.h
 * Routines for the drsuapi (Directory Replication Service) MSRPC interface 
 * Copyright 2003 Jean-Baptiste Marchand <jbm@hsc.fr>
 *
 * $Id: packet-dcerpc-drsuapi.h,v 1.1 2003/09/20 08:56:56 guy Exp $
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

#ifndef __PACKET_DCERPC_DRSUAPI_H
#define __PACKET_DCERPC_DRSUAPI_H

/* MSRPC functions available in the drsuapi interface */

#define DRSUAPI_BIND 			0x00
#define DRSUAPI_UNBIND			0x01
#define DRSUAPI_REPLICA_SYNC		0x02
#define DRSUAPI_GET_NC_CHANGES		0x03
#define DRSUAPI_UPDATE_REFS 		0x04
#define DRSUAPI_REPLICA_ADD		0x05	
#define DRSUAPI_REPLICA_DEL		0x06
#define DRSUAPI_REPLICA_MODIFY		0x07
#define DRSUAPI_VERIFY_NAMES		0x08
#define DRSUAPI_GET_MEMBERSHIPS		0x09
#define DRSUAPI_INTER_DOMAIN_MOVE	0x0a
#define DRSUAPI_GET_NT4_CHANGELOG	0x0b
#define DRSUAPI_CRACKNAMES		0x0c
#define DRSUAPI_WRITE_SPN		0x0d
#define DRSUAPI_REMOVE_DS_SERVER	0x0e
#define DRSUAPI_REMOVE_DS_DOMAIN	0x0f
#define DRSUAPI_DOMAIN_CONTROLLER_INFO	0x10
#define DRSUAPI_ADD_ENTRY		0x11
#define DRSUAPI_EXECUTE_KCC		0x12
#define DRSUAPI_GET_REPL_INFO		0x13
#define DRSUAPI_ADD_SID_HISTORY		0x14
#define DRSUAPI_GET_MEMBERSHIPS2	0x15
#define DRSUAPI_REPLICA_VERIFY_OBJECTS	0x16
#define DRSUAPI_GET_OBJECT_EXISTENCE	0x17
#define DRSUAPI_QUERY_SITES_BY_COST	0x18

#endif /* packet-dcerpc-drsuapi.h */



