/* packet-ipx.h
 * Routines for NetWare's IPX
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-ipx.h,v 1.2 1998/10/14 05:18:31 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
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

/*
 *  ipxlib.h
 *
 *  Copyright (C) 1995 by Volker Lendecke
 *
 */

#define IPX_NODE_LEN	6

typedef guint32	IPXNet;
typedef guint16	IPXPort;
typedef guint8	IPXNode[IPX_NODE_LEN];
typedef const guint8	CIPXNode[IPX_NODE_LEN];

#define IPX_USER_PTYPE (0x00)
#define IPX_RIP_PTYPE (0x01)
#define IPX_SAP_PTYPE (0x04)
#define IPX_AUTO_PORT (0x0000)
#define IPX_SAP_PORT  (0x0452)
#define IPX_RIP_PORT  (0x0453)

#define IPX_SAP_GENERAL_QUERY (0x0001)
#define IPX_SAP_GENERAL_RESPONSE (0x0002)
#define IPX_SAP_NEAREST_QUERY (0x0003)
#define IPX_SAP_NEAREST_RESPONSE (0x0004)

#define IPX_SAP_FILE_SERVER (0x0004)

struct sap_query
{
	guint16	query_type;	/* net order */
	guint16	server_type;	/* net order */
};

struct sap_server_ident
{
	guint16	server_type ;
	char		server_name[48] ;
	IPXNet		server_network ;
	IPXNode		server_node ;
	IPXPort		server_port ;
	guint16	intermediate_network ;
};

#define IPX_RIP_REQUEST (0x1)
#define IPX_RIP_RESPONSE (0x2)

struct ipx_rip_packet
{
	guint16 operation ;
	struct ipx_rt_def
	{
		guint32 network ;
		guint16 hops ;
		guint16 ticks ;
	}
	rt[1] ;
};

#define IPX_BROADCAST_NODE ("\xff\xff\xff\xff\xff\xff")
#define IPX_THIS_NODE      ("\0\0\0\0\0\0")
#define IPX_THIS_NET (0)

#ifndef IPX_NODE_LEN
#define IPX_NODE_LEN (6)
#endif

gchar*
ipxnet_to_string(const guint8 *ad);
