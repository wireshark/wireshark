/* packet-nbipx.c
 * Routines for NetBIOS over IPX packet disassembly
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-nbipx.c,v 1.2 1998/10/14 04:28:49 gram Exp $
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
#include "packet-ipx.h" /* for ipxnet_to_string() */

/* There is no RFC or public specification of Netware or Microsoft
 * NetBIOS over IPX packets. I have had to decode the protocol myself,
 * so there are holes and perhaps errors in this code. (gram)
 */

struct nbipx_header {
	guint32		router[8];
	guint8		name_type;
	guint8		packet_type;
	char		name[17];
};



void
dissect_nbipx_ns(const u_char *pd, int offset, frame_data *fd, GtkTree *tree)
{
	GtkWidget			*nbipx_tree, *ti;
	struct nbipx_header	header;
	int					i, rtr_offset;

	char				*packet_type[] = {
		"",
		"Name Query"
	};

	header.name_type = pd[offset+32];
	header.packet_type = pd[offset+33];
	memcpy(header.name, &pd[offset+34], 16);
	header.name[16] = 0; /* null-terminate the string */

	if (fd->win_info[COL_NUM]) {
			strcpy(fd->win_info[COL_PROTOCOL], "NetBIOS");

			switch (header.packet_type) {
				case 1:
					sprintf(fd->win_info[COL_INFO], "Name Query for %s",
							header.name);
					break;

				default:
					strcpy(fd->win_info[COL_INFO], "NetBIOS over IPX");
			}
	}

	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), offset, END_OF_FRAME,
				"NetBIOS over IPX");
		nbipx_tree = gtk_tree_new();
		add_subtree(ti, nbipx_tree, ETT_NBIPX);

		if (header.packet_type <= 1) {
			add_item_to_tree(nbipx_tree, offset+33, 1,
					"Packet Type: %s (%02X)", packet_type[header.packet_type],
					header.packet_type);
		}
		else {
			add_item_to_tree(nbipx_tree, offset+33, 1,
					"Packet Type: Unknown (%02X)", header.packet_type);
		}

		/* Eight routers are listed */
		for (i = 0; i < 8; i++) {
			rtr_offset = offset + (i << 2);
			memcpy(&header.router[i], &pd[rtr_offset], 4);
			if (header.router[i] != 0) {
				add_item_to_tree(nbipx_tree, rtr_offset, 4, "IPX Network: %s",
						ipxnet_to_string((guint8*)&header.router[i]));
			}
		}

		add_item_to_tree(nbipx_tree, offset+32, 1, "Name Type: %02X",
				header.name_type);
		add_item_to_tree(nbipx_tree, offset+34, 16, "Name String: %s",
				header.name);
	}
}















