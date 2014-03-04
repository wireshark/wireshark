/* packet-dcerpc-frsapi.h
 * Routines for the frs API (File Replication Service) MSRPC interface
 * Copyright 2004 Jean-Baptiste Marchand <jbm@hsc.fr>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_DCERPC_FRSAPI_H
#define __PACKET_DCERPC_FRSAPI_H

/* MSRPC functions available in the frsapi interface */

#define FRSAPI_VERIFY_PROMOTION			0x00
#define FRSAPI_PROMOTION_STATUS			0x01
#define FRSAPI_START_DEMOTION			0x02
#define FRSAPI_COMMIT_DEMOTION			0x03
#define FRSAPI_SET_DS_POLLING_INTERVAL_W	0x04
#define FRSAPI_GET_DS_POLLING_INTERVAL_W	0x05
#define FRSAPI_VERIFY_PROMOTION_W		0x06
#define FRSAPI_INFO_W				0x07
#define FRSAPI_IS_PATH_REPLICATED		0x08
#define FRSAPI_WRITER_COMMAND			0x09

#endif /* packet-dcerpc-frsapi.h */
