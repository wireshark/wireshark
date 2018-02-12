/* packet-dcerpc-frsapi.h
 * Routines for the frs API (File Replication Service) MSRPC interface
 * Copyright 2004 Jean-Baptiste Marchand <jbm@hsc.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
