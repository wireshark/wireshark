/* packet-nbipx.c
 * Routines for NetBIOS over IPX packet disassembly
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-nbipx.c,v 1.8 1999/07/07 22:51:47 gram Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

/*#include <memory.h>*/
#include <glib.h>
#include "packet.h"
#include "packet-ipx.h" /* for ipxnet_to_string() */

enum nbipx_protocol {
	NETBIOS_NETWARE,
	NETBIOS_NWLINK
};

static void
nbipx_ns(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
		enum nbipx_protocol nbipx, int max_data);

/* There is no RFC or public specification of Netware or Microsoft
 * NetBIOS over IPX packets. I have had to decode the protocol myself,
 * so there are holes and perhaps errors in this code. (gram)
 */
static char
*packet_type[] = {
		"",
		"Name Query"
};

struct nbipx_header {
	/* Netware & NT NetBIOS over IPX */
	guint32		router[8];
	guint8		name_type;
	guint8		packet_type;

	char		name[17];

	/* NT NetBIOS over IPX */
	guint16		junk;
	char		node_name[17];
	
};


/* NetWare */
void
dissect_nbipx_ns(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
		int max_data)
{
	nbipx_ns(pd, offset, fd, tree, NETBIOS_NETWARE, max_data);
}

void
dissect_nwlink_dg(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
		int max_data)
{
	nbipx_ns(pd, offset, fd, tree, NETBIOS_NWLINK, max_data);
}


static void
nbipx_ns(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
		enum nbipx_protocol nbipx, int max_data)
{
	proto_tree			*nbipx_tree;
	proto_item			*ti;
	struct nbipx_header	header;
	int					i, rtr_offset;
	int					name_offset;

	if (nbipx == NETBIOS_NETWARE) {
		name_offset = 34;
	}
	else {
		name_offset = 36;
	}


	header.name_type = pd[offset+32];
	header.packet_type = pd[offset+33];
	memcpy(header.name, &pd[offset+name_offset], 16);
	header.name[16] = 0; /* null-terminate the string */

	if (nbipx == NETBIOS_NWLINK) {
		memcpy(header.node_name, &pd[offset+52], 16);
		header.node_name[17] = 0; /* null-terminate the string */
	}

	if (check_col(fd, COL_PROTOCOL)) {
		if (nbipx == NETBIOS_NETWARE) {
			col_add_str(fd, COL_PROTOCOL, "NetBIOS");
		}
		else {
			col_add_str(fd, COL_PROTOCOL, "NWLink");
		}
	}

	if (check_col(fd, COL_INFO)) {
			switch (header.packet_type) {
				case 1:
					col_add_fstr(fd, COL_INFO, "Name Query for %s", header.name);
					break;

				case 2:
					col_add_fstr(fd, COL_INFO, "SMB over NBIPX");
					break;
				

				default:
					col_add_str(fd, COL_INFO, "NetBIOS over IPX");
			}
	}

	if (tree) {
		ti = proto_tree_add_text(tree, offset, 68,
				"NetBIOS over IPX");
		nbipx_tree = proto_item_add_subtree(ti, ETT_NBIPX);

		if (header.packet_type <= 1) {
			proto_tree_add_text(nbipx_tree, offset+33, 1,
					"Packet Type: %s (%02X)", packet_type[header.packet_type],
					header.packet_type);
		}
		else {
			proto_tree_add_text(nbipx_tree, offset+33, 1,
					"Packet Type: Unknown (%02X)", header.packet_type);
		}

		/* Eight routers are listed */
		for (i = 0; i < 8; i++) {
			rtr_offset = offset + (i << 2);
			memcpy(&header.router[i], &pd[rtr_offset], 4);
			if (header.router[i] != 0) {
				proto_tree_add_text(nbipx_tree, rtr_offset, 4, "IPX Network: %s",
						ipxnet_to_string((guint8*)&header.router[i]));
			}
		}

		proto_tree_add_text(nbipx_tree, offset+32, 1, "Name Type: %02X",
				header.name_type);

		if (nbipx == NETBIOS_NETWARE) {
			proto_tree_add_text(nbipx_tree, offset+name_offset, 16,
					"Name String: %s", header.name);
		}
		else {
			proto_tree_add_text(nbipx_tree, offset+name_offset, 16,
					"Group Name String: %s", header.name);
			proto_tree_add_text(nbipx_tree, offset+52, 16,
					"Node Name String: %s", header.node_name);

		}
	}

	if (nbipx == NETBIOS_NWLINK) {
		switch (header.packet_type) {
			case 2:
				dissect_smb(pd, offset + 68, fd, tree, max_data - 68);
				break;
				
			default:
				dissect_data(pd, offset + 68, fd, tree);
				break;
		}
	}
}




