/* packet-ipx.c
 * Routines for NetWare's IPX
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
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

/* The information in this module (IPX, SPX, NCP) comes from:
	NetWare LAN Analysis, Second Edition
	Laura A. Chappell and Dan E. Hakes
	(c) 1994 Novell, Inc.
	Novell Press, San Jose.
	ISBN: 0-7821-1362-1
*/

static void
dissect_spx(const u_char *pd, int offset, frame_data *fd, GtkTree *tree);
static void
dissect_ncp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree);


struct port_info {
	u_short	port;
	char	*text;
};

struct conn_info {
	u_char	ctrl;
	char	*text;
};

struct req_info {
	u_short	req;
	char	*text;
};

/* ================================================================= */
/* IPX                                                               */
/* ================================================================= */
static char*
port_text(u_short port) {
	int i=0;

	static struct port_info	ports[] = {
		{ 0x0451, "NCP" },
		{ 0x0452, "SAP" },
		{ 0x0453, "RIP" },
		{ 0x0455, "NetBIOS" },
		{ 0x0456, "Diagnostic" },
		{ 0x0457, "Serialization" },
		{ 0x0000, NULL }
	};

	while (ports[i].text != NULL) {
		if (ports[i].port == port) {
			return ports[i].text;
		}
		i++;
	}
	return "Unknown";
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

	/* Calculate here for use in win_info[] and in tree */
	dnet = network_to_string((guint8*)&pd[offset+6]);
	snet = network_to_string((guint8*)&pd[offset+18]);
	dsocket = pntohs(&pd[offset+16]);

	if (fd->win_info[0]) {
		strcpy(fd->win_info[3], "IPX");
		/*sprintf(fd->win_info[4], "Network %s --> %s", snet, dnet);*/
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
			dissect_data(pd, offset, fd, tree); /* the IPX payload */
			break;
		case 5: /* SPX */
			dissect_spx(pd, offset, fd, tree);
			break;
		case 17: /* NCP */
			dissect_ncp(pd, offset, fd, tree);
			break;
		case 20: /* NetBIOS */
			dissect_data(pd, offset, fd, tree); /* until implemented */
			break;
		default:
			dissect_data(pd, offset, fd, tree);
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
/* NCP                                                               */
/* ================================================================= */
static char*
req_text(u_short req) {
	int i=0;

	static struct req_info	reqs[] = {
		{ 0x1111,	"Create a service connection" },
		{ 0x2222, "Service request" },
		{ 0x3333, "Service reply" },
		{ 0x5555, "Destroy service connection" },
		{ 0x7777, "Burst mode transfer" },
		{ 0x9999, "Request being processed" },
		{ 0x0000, NULL }
	};

	while (reqs[i].text != NULL) {
		if (reqs[i].req == req) {
			return reqs[i].text;
		}
		i++;
	}
	return "Unknown";
}

static char*
ncp2222_func(u_short func) {
	int i=0;

	static struct req_info	ncp[] = {
		{ 17,	"Print and Queue Services" },
		{ 21,	"Message Services" },
		{ 22,	"File and Directory Services" },
		{ 23,	"Binding and Rights Services" },
		{ 34,	"Transaction Tacking Services" },
		{ 35,	"Apple File Services" },
		{ 86,	"Extended Attributes Services" },
		{ 87,	"File and Directory Services" },
		{ 88,	"Auditing Services" },
		{ 104,	"Netware Directory Services" },
		{ 123,	"Netware 4.x Statistical Information Services" },
		{ 0,	NULL }
	};

	while (ncp[i].text != NULL) {
		if (ncp[i].req == func) {
			return ncp[i].text;
		}
		i++;
	}
	return "Unknown";
}

static char*
ncp2222_subfunc(u_short func, u_short subfunc) {
	int i=0;
	struct req_info	*info_ptr = NULL;

	/* Accounting Services */
	static struct req_info	ncp_23[] = {
		{ 150,	"Get Current Account Status" },
		{ 151,	"Submit Account Charge" },
		{ 152,	"Submit Account Hold" },
		{ 153,	"Submit Account Note" },
		{ 0,	NULL }
	};

	/* Apple File Services */
	static struct req_info	ncp_35[] = {
		{ 1,	"AFP Create Directory" },
		{ 2,	"AFP Create File" },
		{ 3,	"AFP Delete" },
		{ 4,	"AFP Get Entry ID from Name" },
		{ 5,	"AFP Get File Information" },
		{ 6,	"AFP Get Entry ID From NetWare Handle" },
		{ 7,	"AFP Rename" },
		{ 8,	"AFP Open File Fork" },
		{ 9,	"AFP Set File Information" },
		{ 10,	"AFP Scan File Information" },
		{ 11,	"AFP 2.0 Alloc Temporary Directory Handle" },
		{ 12,	"AFP Get Entry ID from Name Path" },
		{ 13,	"AFP 2.0 Create Directory" },
		{ 14,	"AFP 2.0 Create File" },
/* ???	{ 15,	"AFP 2.0 Delete File" }, just guessing */
		{ 16,	"AFP 2.0 Set File Information" },
		{ 17,	"AFP 2.0 Scan File Information" },
		{ 18,	"AFP Get DOS Name from Entry ID" },
		{ 19,	"AFP Get Macintosh Info on Deleted File" },
		{ 0,	NULL }
	};

	/* Auditing Services */
	static struct req_info	ncp_88[] = {
		{ 1,	"Query Volume Audit Status" },
		{ 2,	"Add Audit Property" },
		{ 3,	"Add Auditor Access" },

		{ 0,	NULL }
	};

	switch (func) {
		case 23:
			info_ptr = ncp_23;
			break;
		case 35:
			info_ptr = ncp_35;
			break;
		case 88:
			info_ptr = ncp_88;
			break;
		default:
			return "Unkown function";
	}


	while (info_ptr[i].text != NULL) {
		if (info_ptr[i].req == subfunc) {
			printf("subfunc=%s\n", info_ptr[i].text);
			return info_ptr[i].text;
		}
		i++;
	}
	return "Unknown";
}


static void
dissect_ncp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {

	GtkWidget	*ncp_tree, *ti;
	guint16		ncp_type;
	int			ncp_hdr;

	if (fd->win_info[0]) {
		strcpy(fd->win_info[3], "NCP");
		strcpy(fd->win_info[4], "NCP");
	}

	ncp_type = pntohs(&pd[offset]);

	if (ncp_type == 0x1111 || ncp_type == 0x2222 || ncp_type == 0x5555 ||
		ncp_type == 0x7777) {
		ncp_hdr = 6;
	}
	else if (ncp_type == 0x3333 || ncp_type == 0x9999) {
		ncp_hdr = 8;
	}
	else {
		ncp_hdr = 1; /* ? */
	}

	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), offset, ncp_hdr,
			"NetWare Core Protocol");
		ncp_tree = gtk_tree_new();
		add_subtree(ti, ncp_tree, ETT_NCP);

		add_item_to_tree(ncp_tree, offset,      2,
			"Type: %s", req_text( pntohs( &pd[offset] ) ) );

		add_item_to_tree(ncp_tree, offset+2,    1,
			"Sequence Number: %d", pd[offset+2]);

		add_item_to_tree(ncp_tree, offset+3,    1,
			"Connection Number Low: %d", pd[offset+3]);

		add_item_to_tree(ncp_tree, offset+4,    1,
			"Task Number: %d", pd[offset+4]);

		add_item_to_tree(ncp_tree, offset+5,    1,
			"Connection Number High: %d", pd[offset+5]);

		if (ncp_hdr == 8) {
			add_item_to_tree(ncp_tree, offset+6,    1,
				"Completion Code: %d", pd[offset+6]);

			add_item_to_tree(ncp_tree, offset+7,    1,
				"Connection Status: %d", pd[offset+7]);
		}

		offset += ncp_hdr;

		if (ncp_type == 0x2222) {
			/* my offset is different now */
			add_item_to_tree(ncp_tree, offset,		1,
				"Function Code: %s (%d)",
				ncp2222_func(pd[offset]), pd[offset]);

			add_item_to_tree(ncp_tree, offset+2,	1,
				"Subfunction Code: %s (%d)",
				ncp2222_subfunc(pd[offset], pd[offset+2]), pd[offset+2]);

			offset += 3;
		}

		dissect_data(pd, offset, fd, tree);
	}
}
