/* packet-ncp.c
 * Routines for NetWare Core Protocol
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-ncp.c,v 1.1 1998/09/23 05:25:11 gram Exp $
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

/* The information in this module comes from:
	NetWare LAN Analysis, Second Edition
	Laura A. Chappell and Dan E. Hakes
	(c) 1994 Novell, Inc.
	Novell Press, San Jose.
	ISBN: 0-7821-1362-1

  And from the ncpfs source code by Volker Lendecke
*/


struct req_info {
	u_short	req;
	char	*text;
};


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


void
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
