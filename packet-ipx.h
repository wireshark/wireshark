/* packet-ipx.h
 * Routines for NetWare's IPX
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-ipx.h,v 1.12 2001/02/27 07:28:47 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

#ifndef __PACKET_IPX_H__
#define __PACKET_IPX_H__

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

/*
 * From:
 *
 *	http://alr.base2co.com:457/netguide/dipxD.ipx_packet_struct.html
 *
 * which is part of SCO's "Network Programmer's Guide and Reference".
 *
 * It calls type 20 "NetBIOS name packet".  Microsoft Network Monitor
 * calls it "WAN Broadcast"; it's also used for SMB browser announcements,
 * i.e. NetBIOS (broadcast) datagrams.
 */
#define IPX_PACKET_TYPE_IPX		0
#define IPX_PACKET_TYPE_RIP		1
#define	IPX_PACKET_TYPE_ECHO		2
#define	IPX_PACKET_TYPE_ERROR		3
#define IPX_PACKET_TYPE_PEP		4
#define IPX_PACKET_TYPE_SPX		5
#define IPX_PACKET_TYPE_NCP		17
#define IPX_PACKET_TYPE_WANBCAST	20	/* propagated NetBIOS packet? */

/* info on these sockets can be found in this listing from Novell:

	http://developer.novell.com/engsup/sample/tids/dsoc1b/dsoc1b.htm
*/

#define IPX_SOCKET_PING_CISCO           0x0002 /* In cisco this is set with: ipx ping-default cisco */
#define IPX_SOCKET_NCP			0x0451
#define IPX_SOCKET_SAP			0x0452
#define IPX_SOCKET_IPXRIP		0x0453
#define IPX_SOCKET_NETBIOS		0x0455
#define IPX_SOCKET_DIAGNOSTIC		0x0456
#define IPX_SOCKET_SERIALIZATION	0x0457
#define IPX_SOCKET_NWLINK_SMB_SERVER	0x0550
#define IPX_SOCKET_NWLINK_SMB_NAMEQUERY	0x0551
#define IPX_SOCKET_NWLINK_SMB_REDIR	0x0552
#define IPX_SOCKET_NWLINK_SMB_MAILSLOT	0x0553
#define IPX_SOCKET_NWLINK_SMB_MESSENGER	0x0554
#define IPX_SOCKET_NWLINK_SMB_BROWSE	0x0555 /* ? not sure on this
	but I guessed based on the content of the packet I saw */
#define IPX_SOCKET_ATTACHMATE_GW	0x055d
#define IPX_SOCKET_IPX_MESSAGE		0x4001
#define IPX_SOCKET_ADSM                 0x8522 /* www.tivoli.com */
#define IPX_SOCKET_EIGRP                0x85be /* cisco ipx eigrp */
#define IPX_SOCKET_WIDE_AREA_ROUTER	0x9001
#define IPX_SOCKET_SNMP_AGENT           0x900F /* RFC 1906 */
#define IPX_SOCKET_SNMP_SINK            0x9010 /* RFC 1906 */
#define IPX_SOCKET_PING_NOVELL          0x9086 /* In cisco this is set with: ipx ping-default novell */
#define IPX_SOCKET_TCP_TUNNEL           0x9091 /* RFC 1791 */
#define IPX_SOCKET_UDP_TUNNEL           0x9092 /* RFC 1791 */

gchar* ipxnet_to_string(const guint8 *ad);
gchar* ipxnet_to_str_punct(const guint32 ad, char punct);

void capture_ipx(const u_char *, int, packet_counts *);

#endif
