/* packet-nbns.c
 * Routines for NetBIOS Name Service packet disassembly
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-nbns.c,v 1.1 1998/10/14 04:09:11 gram Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>
#include <pcap.h>

#include <stdio.h>
#include <memory.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"

/* Packet structure taken from RFC 1002. See also RFC 1001.
 * The Samba source code, specifically nmblib.c, also helps a lot. */

struct nbns_header {

	guint16		name_tran_id;
	guint8		r;
	guint8		opcode;
	struct {
		guint8	bcast;
		guint8	recursion_available;
		guint8	recursion_desired;
		guint8	trunc;
		guint8	authoritative;
	} nm_flags;
	guint8		rcode;
	guint16		qdcount;
	guint16		ancount;
	guint16		nscount;
	guint16		arcount;
};

void
dissect_nbns(const u_char *pd, int offset, frame_data *fd, GtkTree *tree)
{
	GtkWidget			*nbns_tree, *ti;
	struct nbns_header	header;
	int					nm_flags;

	char *opcode[] = {
		"Query",
		"Unknown",
		"Unknown",
		"Unknown",
		"Unknown",
		"Registration",
		"Release",
		"Wait and Acknowledge",
		"Refresh"
		"Refresh(altcode)"
		"Unknown",
		"Unknown",
		"Unknown",
		"Unknown",
		"Unknown",
		"Multi-Homed Registration",
	};

	if (fd->win_info[COL_NUM]) {
			/*strcpy(fd->win_info[COL_PROTOCOL], "NBNS (UDP)");*/
			strcpy(fd->win_info[COL_PROTOCOL], "NBNS");
			strcpy(fd->win_info[COL_INFO], "NetBIOS Name Service");
	}

	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), offset, END_OF_FRAME,
				"NetBIOS Name Service");
		nbns_tree = gtk_tree_new();
		add_subtree(ti, nbns_tree, ETT_NBNS);

		/* This is taken from samba/source/nmlib.c, parse_nmb() */
		header.name_tran_id = pntohs(&pd[offset]);
		header.opcode = (pd[offset+2] >> 3) & 0xf;
		header.r = (pd[offset+2] >> 7) & 1;

		nm_flags = ((pd[offset+2] & 0x7) << 4) + (pd[offset+3] >> 4);
		header.nm_flags.bcast = (nm_flags & 1) ? 1 : 0;
		header.nm_flags.recursion_available = (nm_flags & 8) ? 1 : 0;
		header.nm_flags.recursion_desired = (nm_flags & 0x10) ? 1 : 0;
		header.nm_flags.trunc = (nm_flags & 0x20) ? 1 : 0;
		header.nm_flags.authoritative = (nm_flags & 0x40) ? 1 : 0;

		header.rcode = pd[offset+3] & 0xf;
		header.qdcount = pletohs(&pd[offset+4]);
		header.ancount = pletohs(&pd[offset+6]);
		header.nscount = pletohs(&pd[offset+8]);
		header.arcount = pletohs(&pd[offset+10]);

		add_item_to_tree(nbns_tree, offset,		2, "Transaction ID: 0x%04X",
				header.name_tran_id);
		add_item_to_tree(nbns_tree, offset + 2,	1,	"Type: %s",
				header.r == 0 ? "Request" : "Response" );
		
		if (header.opcode <= 15) {
			add_item_to_tree(nbns_tree, offset + 2, 1, "Operation: %s (%d)",
					opcode[header.opcode], header.opcode);
		}
		else {
			add_item_to_tree(nbns_tree, offset + 2, 1, "Operation: Unknown (%d)",
					header.opcode);
		}

/*		add_item_to_tree(nbns_tree, offset+2,	2, */
	}
}















