/* packet-ipx.c
 * Routines for NetWare's IPX
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-ipx.c,v 1.3 1998/09/23 05:25:09 gram Exp $
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
#include <pcap.h>

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
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

struct port_info {
	guint16	port;
	void	(*func) (const u_char *, int, frame_data *, GtkTree *);
	char	*text;
};

struct conn_info {
	guint8	ctrl;
	char	*text;
};

/* ================================================================= */
/* IPX                                                               */
/* ================================================================= */
static struct port_info	ports[] = {
	{ 0x0451, dissect_ncp,		"NCP" },
	{ 0x0452, NULL,				"SAP" },
	{ 0x0453, dissect_ipxrip, 	"RIP" },
	{ 0x0455, NULL,				"NetBIOS" },
	{ 0x0456, NULL,				"Diagnostic" },
	{ 0x0457, NULL,				"Serialization" },
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
	return dissect_data;
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
		return "NetBIOS";
	}
	else if (val >= 16 && val <= 31) {
		return "Experimental Protocol";
	}
	else {
		return "Unknown";
	}
}

gchar*
network_to_string(const guint8 *ad)
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

	/* Calculate here for use in win_info[] and in tree */
	dnet = network_to_string((guint8*)&pd[offset+6]);
	snet = network_to_string((guint8*)&pd[offset+18]);
	dsocket = pntohs(&pd[offset+16]);

	if (fd->win_info[0]) {
		strcpy(fd->win_info[3], "IPX");
		sprintf(fd->win_info[4], "%s (0x%04X)", port_text(dsocket), dsocket);
	}

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
		ssocket = pntohs(&pd[offset+28]);
		add_item_to_tree(ipx_tree, offset+28,   2,
			"Source Socket: %s (0x%04X)", port_text(ssocket), ssocket);
	}
	offset += 30;

	switch (ipx_type) {
		case 0: /* IPX */
			dissect_data(pd, offset, fd, tree);
			break;

		case 5: /* SPX */
			dissect_spx(pd, offset, fd, tree);
			break;

		case 17: /* NCP */
			dissect_ncp(pd, offset, fd, tree);
			break;

		case 20: /* NetBIOS */
			dissect_data(pd, offset, fd, tree);
			break;

		default:
			dissect = port_func(dsocket);
			if (dissect) {
				dissect(pd, offset, fd, tree);
			}
			else {
				dissect_data(pd, offset, fd, tree);
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

	if (fd->win_info[0]) {
		strcpy(fd->win_info[3], "SPX");
		strcpy(fd->win_info[4], "SPX");
	}

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

	if (fd->win_info[0]) {
		strcpy(fd->win_info[3], "IPX RIP");
		if (operation < 2) {
			sprintf(fd->win_info[4], "RIP %s", rip_type[operation]);
		}
		else {
			strcpy(fd->win_info[4], "IPX RIP");
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

			add_item_to_tree(rip_tree, cursor,      8,
				"Route Vector: %s, %d hop%s, %d tick%s",
				network_to_string((guint8*)&route.network),
				route.hops,  route.hops  == 1 ? "" : "s",
				route.ticks, route.ticks == 1 ? "" : "s");
		}
	}
}
