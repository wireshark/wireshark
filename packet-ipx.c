/* packet-ipx.c
 * Routines for NetWare's IPX
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-ipx.c,v 1.15 1999/03/05 05:20:12 gram Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "packet-ipx.h"

/* The information in this module (IPX, SPX, NCP) comes from:
	NetWare LAN Analysis, Second Edition
	Laura A. Chappell and Dan E. Hakes
	(c) 1994 Novell, Inc.
	Novell Press, San Jose.
	ISBN: 0-7821-1362-1

  And from the ncpfs source code by Volker Lendecke

*/

static void
dissect_spx(const u_char *pd, int offset, frame_data *fd, GtkTree *tree);

static void
dissect_ipxrip(const u_char *pd, int offset, frame_data *fd, GtkTree *tree);

static void
dissect_sap(const u_char *pd, int offset, frame_data *fd, GtkTree *tree);

struct port_info {
	guint16	port;
	void	(*func) (const u_char *, int, frame_data *, GtkTree *);
	char	*text;
};

struct conn_info {
	guint8	ctrl;
	char	*text;
};

struct server_info {
	guint16	type;
	char	*text;
};

/* ================================================================= */
/* IPX                                                               */
/* ================================================================= */
static struct port_info	ports[] = {
	{ 0x0451, dissect_ncp,		"NCP" },
	{ 0x0452, dissect_sap,		"SAP" },
	{ 0x0453, dissect_ipxrip, 	"RIP" },
	{ 0x0455, NULL,				"NetBIOS" },
	{ 0x0456, NULL,				"Diagnostic" },
	{ 0x0457, NULL,				"Serialization" },
	{ 0x0551, NULL,				"NWLink SMB Name Query" },
	{ 0x0553, dissect_nwlink_dg,"NWLink SMB Datagram" },
	{ 0x055d, NULL,				"Attachmate Gateway" },
	{ 0x4001, NULL,				"IPX Message" },
	{ 0x0000, NULL,				NULL }
};

static char*
port_text(guint16 port) {
	int i=0;

	while (ports[i].text != NULL) {
		if (ports[i].port == port) {
			return ports[i].text;
		}
		i++;
	}
	return "Unknown";
}

static void*
port_func(guint16 port) {
	int i=0;

	while (ports[i].text != NULL) {
		if (ports[i].port == port) {
			return ports[i].func;
		}
		i++;
	}
	return NULL;
}

char *
ipx_packet_type(u_char val)
{
	if (val == 0) {
		return "IPX";
	}
	else if (val == 5) {
		return "SPX";
	}
	else if (val == 17) {
		return "NCP";
	}
	else if (val == 20) {
		return "NetBIOS Broadcast";
	}
	else if (val >= 16 && val <= 31) {
		return "Experimental Protocol";
	}
	else {
		return "Unknown";
	}
}

gchar*
ipxnet_to_string(const guint8 *ad)
{
	static gchar	str[3][12];
	static gchar	*cur;

	if (cur == &str[0][0]) {
		cur = &str[1][0];
	} else if (cur == &str[1][0]) {
		cur = &str[2][0];
	} else {
		cur = &str[0][0];
	}

	sprintf(cur, "%02X %02X %02X %02X", ad[0], ad[1], ad[2], ad[3]);
	return cur;
}

void
dissect_ipx(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {

	GtkWidget	*ipx_tree, *ti;
	u_char		ipx_type;

	char		*dnet, *snet;
	guint16		dsocket, ssocket;
	void		(*dissect) (const u_char *, int, frame_data *, GtkTree *);

	/* Calculate here for use in pinfo and in tree */
	dnet = ipxnet_to_string((guint8*)&pd[offset+6]);
	snet = ipxnet_to_string((guint8*)&pd[offset+18]);
	dsocket = pntohs(&pd[offset+16]);
	ssocket = pntohs(&pd[offset+28]);

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "IPX");
	if (check_col(fd, COL_INFO))
		col_add_fstr(fd, COL_INFO, "%s (0x%04X)", port_text(dsocket), dsocket);

	ipx_type = pd[offset+5];

	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), offset, 30,
			"Internetwork Packet Exchange");
		ipx_tree = gtk_tree_new();
		add_subtree(ti, ipx_tree, ETT_IPX);
		add_item_to_tree(ipx_tree, offset,      2, "Checksum: 0x%04X",
			(pd[offset] << 8) | pd[offset+1]);
		add_item_to_tree(ipx_tree, offset+2,    2, "Length: %d bytes",
			(pd[offset+2] << 8) | pd[offset+3]);
		add_item_to_tree(ipx_tree, offset+4,    1, "Transport Control: %d hops",
			pd[offset+4]);
		add_item_to_tree(ipx_tree, offset+5,    1, "Packet Type: %s",
			ipx_packet_type(ipx_type));
		add_item_to_tree(ipx_tree, offset+6,    4, "Destination Network: %s",
			dnet);
		add_item_to_tree(ipx_tree, offset+10,   6, "Destination Node: %s",
			ether_to_str((guint8*)&pd[offset+10]));
		/*dsocket = ntohs(*((guint16*)&pd[offset+16]));*/
		add_item_to_tree(ipx_tree, offset+16,   2,
			"Destination Socket: %s (0x%04X)", port_text(dsocket), dsocket);
		add_item_to_tree(ipx_tree, offset+18,   4, "Source Network: %s",
			snet);
		add_item_to_tree(ipx_tree, offset+22,   6, "Source Node: %s",
			ether_to_str((guint8*)&pd[offset+22]));
		add_item_to_tree(ipx_tree, offset+28,   2,
			"Source Socket: %s (0x%04X)", port_text(ssocket), ssocket);
	}
	offset += 30;

	switch (ipx_type) {
		case 5: /* SPX */
			dissect_spx(pd, offset, fd, tree);
			break;

		case 17: /* NCP */
			dissect_ncp(pd, offset, fd, tree);
			break;

		case 20: /* NetBIOS */
			if (dsocket == 0x0455) {
				dissect_nbipx_ns(pd, offset, fd, tree);
				break;
			}
			/* else fall through */

		case 0: /* IPX, fall through to default */
		default:
			dissect = port_func(dsocket);
			if (dissect) {
				dissect(pd, offset, fd, tree);
			}
			else {
				dissect = port_func(ssocket);
				if (dissect) {
					dissect(pd, offset, fd, tree);
				}
				else {
					dissect_data(pd, offset, fd, tree);
				}
			}
			break;
	}
}


/* ================================================================= */
/* SPX                                                               */
/* ================================================================= */
static char*
spx_conn_ctrl(u_char ctrl)
{
	int i=0;

	static struct conn_info	conns[] = {
		{ 0x10, "End-of-Message" },
		{ 0x20, "Attention" },
		{ 0x40, "Acknowledgment Required"},
		{ 0x80, "System Packet"}
	};

	while (conns[i].text != NULL) {
		if (conns[i].ctrl == ctrl) {
			return conns[i].text;
		}
		i++;
	}
	return "Unknown";
}

static char*
datastream(u_char type)
{
	switch (type) {
		case 0xfe:
			return "End-of-Connection";
		case 0xff:
			return "End-of-Connection Acknowledgment";
		default:
			return "Client-Defined";
	}
}

static void
dissect_spx(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {

	GtkWidget	*spx_tree, *ti;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "SPX");
	if (check_col(fd, COL_INFO))
		col_add_str(fd, COL_INFO, "SPX");

	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), offset, 12,
			"Sequenced Packet Exchange");
		spx_tree = gtk_tree_new();
		add_subtree(ti, spx_tree, ETT_SPX);

		add_item_to_tree(spx_tree, offset,      1,
			"Connection Control: %s (0x%02X)",
			spx_conn_ctrl(pd[offset]), pd[offset]);

		add_item_to_tree(spx_tree, offset+1,     1,
			"Datastream Type: %s (0x%02X)",
			datastream(pd[offset+1]), pd[offset+1]);

		add_item_to_tree(spx_tree, offset+2,     2,
			"Source Connection ID: %d", pntohs( &pd[offset+2] ) );

		add_item_to_tree(spx_tree, offset+4,     2,
			"Destination Connection ID: %d", pntohs( &pd[offset+4] ) );

		add_item_to_tree(spx_tree, offset+6,     2,
			"Sequence Number: %d", pntohs( &pd[offset+6] ) );

		add_item_to_tree(spx_tree, offset+8,     2,
			"Acknowledgment Number: %d", pntohs( &pd[offset+8] ) );

		add_item_to_tree(spx_tree, offset+10,     2,
			"Allocation Number: %d", pntohs( &pd[offset+10] ) );

		offset += 12;
		dissect_data(pd, offset, fd, tree);
	}
}

/* ================================================================= */
/* IPX RIP                                                           */
/* ================================================================= */
static void
dissect_ipxrip(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {

	GtkWidget	*rip_tree, *ti;
	guint16		operation;
	struct ipx_rt_def route;
	int			cursor;

	char		*rip_type[2] = { "Request", "Response" };

	operation = pntohs(&pd[offset]) - 1;

	if (check_col(fd, COL_PROTOCOL))
	 col_add_str(fd, COL_PROTOCOL, "IPX RIP");
	if (check_col(fd, COL_PROTOCOL)) {
	 if (operation < 2) {
		 col_add_str(fd, COL_INFO, rip_type[operation]);
	 }
	 else {
		 col_add_str(fd, COL_INFO, "Unknown Packet Type");
	 }
	}

	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), offset, END_OF_FRAME,
			"IPX Routing Information Protocol");
		rip_tree = gtk_tree_new();
		add_subtree(ti, rip_tree, ETT_IPXRIP);

		if (operation < 2) {
			add_item_to_tree(rip_tree, offset, 2,
			"RIP packet type: %s", rip_type[operation]);
		}
		else {
			add_item_to_tree(rip_tree, offset, 2, "Unknown RIP packet type");
		}

		for (cursor = offset + 2; cursor < fd->cap_len; cursor += 8) {
			memcpy(&route.network, &pd[cursor], 4);
			route.hops = pntohs(&pd[cursor+4]);
			route.ticks = pntohs(&pd[cursor+6]);

			if (operation == IPX_RIP_REQUEST - 1) {
				add_item_to_tree(rip_tree, cursor,      8,
					"Route Vector: %s, %d hop%s, %d tick%s",
					ipxnet_to_string((guint8*)&route.network),
					route.hops,  route.hops  == 1 ? "" : "s",
					route.ticks, route.ticks == 1 ? "" : "s");
			}
			else {
				add_item_to_tree(rip_tree, cursor,      8,
					"Route Vector: %s, %d hop%s, %d tick%s (%d ms)",
					ipxnet_to_string((guint8*)&route.network),
					route.hops,  route.hops  == 1 ? "" : "s",
					route.ticks, route.ticks == 1 ? "" : "s",
					route.ticks * 1000 / 18);
			}
		}
	}
}



/* ================================================================= */
/* SAP																 */
/* ================================================================= */
static char*
server_type(guint16 type)
{
	int i=0;

	/* some of these are from ncpfs, others are from the book */
	static struct server_info	servers[] = {
		{ 0x0001,	"User" },
		{ 0x0002,	"User Group" },
		{ 0x0003,	"Print Queue" },
		{ 0x0004,	"File server" },
		{ 0x0005,	"Job server" },
		{ 0x0007,	"Print server" },
		{ 0x0008,	"Archive server" },
		{ 0x0009,	"Archive server" },
		{ 0x000a,	"Job queue" },
		{ 0x000b,	"Administration" },
		{ 0x0021,	"NAS SNA gateway" },
		{ 0x0024,	"Remote bridge" },
		{ 0x0026,	"Bridge server" },
		{ 0x0027,	"TCP/IP gateway" },
		{ 0x002d,	"Time Synchronization VAP" },
		{ 0x002e,	"Archive Server Dynamic SAP" },
		{ 0x0047,	"Advertising print server" },
		{ 0x004b,	"Btrieve VAP 5.0" },
		{ 0x004c,	"SQL VAP" },
		{ 0x0050,	"Btrieve VAP" },
		{ 0x0053,	"Print Queue VAP" },
		{ 0x007a,	"TES NetWare for VMS" },
		{ 0x0098,	"NetWare access server" },
		{ 0x009a,	"Named Pipes server" },
		{ 0x009e,	"Portable NetWare Unix" },
		{ 0x0107,	"NetWare 386" },
		{ 0x0111,	"Test server" },
		{ 0x0133,	"NetWare Name Service" },
		{ 0x0166,	"NetWare management" },
		{ 0x026a,	"NetWare management" },
		{ 0x026b,	"Time synchronization" },
		{ 0x0278,	"NetWare Directory server" },
		{ 0x055d,	"Attachmate SNA gateway" },
		{ 0x0000,	NULL }
	};

	while (servers[i].text != NULL) {
		if (servers[i].type == type) {
			return servers[i].text;
		}
		i++;
	}
	return "Unknown";
}

static void
dissect_sap(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {

	GtkWidget	*sap_tree, *s_tree, *ti;
	int			cursor;
	struct sap_query query;
	struct sap_server_ident server;

	char		*sap_type[4] = { "General Query", "General Response",
		"Nearest Query", "Nearest Response" };

	query.query_type = pntohs(&pd[offset]);
	query.server_type = pntohs(&pd[offset+2]);

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "SAP");
	if (check_col(fd, COL_INFO)) {
		if (query.query_type < 4) {
			col_add_str(fd, COL_INFO, sap_type[query.query_type - 1]);
		}
		else {
			col_add_str(fd, COL_INFO, "Unknown Packet Type");
		}
	}

	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), offset, END_OF_FRAME,
			"Service Advertising Protocol");
		sap_tree = gtk_tree_new();
		add_subtree(ti, sap_tree, ETT_IPXSAP);

		if (query.query_type < 4) {
			add_item_to_tree(sap_tree, offset, 2, sap_type[query.query_type - 1]);
		}
		else {
			add_item_to_tree(sap_tree, offset, 2,
					"Unknown SAP Packet Type %d", query.query_type);
		}

		if (query.query_type == IPX_SAP_GENERAL_RESPONSE ||
				query.query_type == IPX_SAP_NEAREST_RESPONSE) { /* responses */

			for (cursor = offset + 2; (cursor + 64) <= fd->cap_len; cursor += 64) {
				server.server_type = pntohs(&pd[cursor]);
				memcpy(server.server_name, &pd[cursor+2], 48);
				memcpy(&server.server_network, &pd[cursor+50], 4);
				memcpy(&server.server_node, &pd[cursor+54], 6);
				server.server_port = pntohs(&pd[cursor+60]);
				server.intermediate_network = pntohs(&pd[cursor+62]);

				ti = add_item_to_tree(GTK_WIDGET(sap_tree), cursor+2, 48,
					"Server Name: %s", server.server_name);
				s_tree = gtk_tree_new();
				add_subtree(ti, s_tree, ETT_IPXSAP_SERVER);

				add_item_to_tree(s_tree, cursor, 2, "Server Type: %s (0x%04X)",
						server_type(server.server_type), server.server_type);
				add_item_to_tree(s_tree, cursor+50, 4, "Network: %s",
						ipxnet_to_string((guint8*)&pd[cursor+50]));
				add_item_to_tree(s_tree, cursor+54, 6, "Node: %s",
						ether_to_str((guint8*)&pd[cursor+54]));
				add_item_to_tree(s_tree, cursor+60, 2, "Socket: %s (0x%04X)",
						port_text(server.server_port), server.server_port);
				add_item_to_tree(s_tree, cursor+62, 2,
						"Intermediate Networks: %d",
						server.intermediate_network);
			}
		}
		else {  /* queries */
			add_item_to_tree(sap_tree, offset+2, 2, "Server Type: %s (0x%04X)",
					server_type(query.server_type), query.server_type);
		}
	}
}

