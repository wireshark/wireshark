/* packet-ncp.c
 * Routines for NetWare Core Protocol
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-ncp.c,v 1.6 1998/11/12 00:06:34 gram Exp $
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

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "packet-ipx.h"
#include "packet-ncp.h"

/* The information in this module comes from:
	NetWare LAN Analysis, Second Edition
	Laura A. Chappell and Dan E. Hakes
	(c) 1994 Novell, Inc.
	Novell Press, San Jose.
	ISBN: 0-7821-1362-1

  And from the ncpfs source code by Volker Lendecke
*/



static value_string request_reply_values[] = {
	{ 0x1111,	"Create a service connection" },
	{ 0x2222, "Service request" },
	{ 0x3333, "Service reply" },
	{ 0x5555, "Destroy service connection" },
	{ 0x7777, "Burst mode transfer" },
	{ 0x9999, "Request being processed" },
	{ 0x0000, NULL }
};


static value_string ncp2222_func[] = {
	{ 17,	"Print and Queue Services" },
	{ 21,	"Message Services" },
	{ 22,	"File and Directory Services" },
	{ 23,	"Binding and Rights Services" },
	{ 34,	"Transaction Tacking Services" },
	{ 35,	"Apple File Services" },
	{ 72,	"File Services" }, /* guess */
	{ 86,	"Extended Attributes Services" },
	{ 87,	"File and Directory Services" },
	{ 88,	"Auditing Services" },
	{ 104,	"Netware Directory Services" },
	{ 123,	"Netware 4.x Statistical Information Services" },
	{ 0,	NULL }
};

static char*
ncp2222_subfunc(u_short func, u_short subfunc) {
	value_string	*info_ptr = NULL;

	/* Accounting Services */
	static value_string	ncp_23[] = {
		{ 150,	"Get Current Account Status" },
		{ 151,	"Submit Account Charge" },
		{ 152,	"Submit Account Hold" },
		{ 153,	"Submit Account Note" },
		{ 0,	NULL }
	};

	/* Apple File Services */
	static value_string	ncp_35[] = {
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

	/* File services */ /* guess */
	static value_string ncp_72[] = {
		{ 0xbb,	"Read" },
		{ 0,	NULL }
	};

	/* Auditing Services */
	static value_string	ncp_88[] = {
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
		case 72:
			info_ptr = ncp_72;
			break;
		case 88:
			info_ptr = ncp_88;
			break;
		default:
			return "Unknown function";
	}

	return val_to_str(subfunc, info_ptr, "Unknown");
}


void
ncp_read(GtkWidget *tree, const u_char *pd, int offset)
{
	struct ncp_read_header header;

	memcpy(header.handle, &pd[offset], 6);
	header.offset = pntohl(&pd[offset+6]);
	header.bytes = pntohs(&pd[offset+10]);

	add_item_to_tree(tree, offset,    6,
			"File Handle: 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X ",
			header.handle[0], header.handle[1], header.handle[2],
			header.handle[3], header.handle[4], header.handle[5]);
	
	add_item_to_tree(tree, offset+6,    4,
			"Starting Offset: %d", header.offset);

	add_item_to_tree(tree, offset+10,    2,
			"Bytes to Read: %d", header.bytes);

}

void
dissect_ncp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {

	GtkWidget	*ncp_tree, *ti;
	guint16		ncp_type;
	int			ncp_hdr;
	struct ncp_common_header	header;
	struct ncp_request_header	request;
	struct ncp_reply_header		reply;
	char						*ncp_type_text[] = { "Unknown",
		"Request", "Reply" };

	ncp_type = pntohs(&pd[offset]);
	header.type = ncp_type;
	header.sequence = pd[offset+2];
	header.conn_low = pd[offset+3];
	header.task = pd[offset+4];
	header.conn_high = pd[offset+5];

	if (ncp_type == 0x1111 || ncp_type == 0x2222 || ncp_type == 0x5555 ||
		ncp_type == 0x7777) {
		ncp_hdr = 7;
		request.function = pd[offset+6];
	}
	else if (ncp_type == 0x3333 || ncp_type == 0x9999) {
		ncp_hdr = 8;
		reply.completion_code = pd[offset+6];
		reply.connection_state = pd[offset+7];
	}
	else {
		ncp_hdr = 6; /* in order to get ncp_type_text[0] */
	}

	if (fd->win_info[COL_NUM]) {
		strcpy(fd->win_info[COL_PROTOCOL], "NCP");
		/* I take advantage of the ncp_hdr length to use as an index into
		 * ncp_type_text[]. Ugly hack, but quick.  */
		sprintf(fd->win_info[COL_INFO], "%s", ncp_type_text[ncp_hdr - 6]);
	}


	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), offset, END_OF_FRAME,
			"NetWare Core Protocol");
		ncp_tree = gtk_tree_new();
		add_subtree(ti, ncp_tree, ETT_NCP);

		add_item_to_tree(ncp_tree, offset,      2,
			"Type: %s", val_to_str( header.type, request_reply_values,
					"Unknown (%04X)"));

		add_item_to_tree(ncp_tree, offset+2,    1,
			"Sequence Number: %d", header.sequence);

		add_item_to_tree(ncp_tree, offset+3,    1,
			"Connection Number Low: %d", header.conn_low);

		add_item_to_tree(ncp_tree, offset+4,    1,
			"Task Number: %d", header.task);

		add_item_to_tree(ncp_tree, offset+5,    1,
			"Connection Number High: %d", header.conn_high);

		if (ncp_hdr == 8) {
			add_item_to_tree(ncp_tree, offset+6,    1,
				"Completion Code: %d", reply.completion_code);

			add_item_to_tree(ncp_tree, offset+7,    1,
				"Connection Status: %d", reply.connection_state);
		}
		else {
			add_item_to_tree(ncp_tree, offset+6,		1,
				"Function Code: %s (%d)",
				match_strval(request.function, ncp2222_func),
				request.function);
		}

		offset += ncp_hdr;

		if (ncp_type == 0x2222) {
			/* my offset is different now */
			add_item_to_tree(ncp_tree, offset,	1,
				"Subfunction Code: %s (%d)",
				ncp2222_subfunc(pd[offset-1], pd[offset]), pd[offset]);

			if (request.function == 0x48) {
				ncp_read(ncp_tree, pd, offset+1);
			}
			else {
				dissect_data(pd, offset, fd, tree);
			}
		}
		else {
			dissect_data(pd, offset, fd, tree);
		}
	}
}
