/* packet-nbipx.c
 * Routines for NetBIOS over IPX packet disassembly
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-nbipx.c,v 1.11 1999/09/02 23:17:56 guy Exp $
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

#include <glib.h>
#include "packet.h"
#include "packet-ipx.h" /* for ipxnet_to_string() */
#include "packet-netbios.h"

static int proto_nbipx = -1;

enum nbipx_protocol {
	NETBIOS_NETWARE,
	NETBIOS_NWLINK
};

static void
nbipx_ns(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
		enum nbipx_protocol nbipx, int max_data);
static void
dissect_nbipx_dg(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
		int max_data);

/* There is no RFC or public specification of Netware or Microsoft
 * NetBIOS over IPX packets. I have had to decode the protocol myself,
 * so there are holes and perhaps errors in this code. (gram)
 *
 * A list of "NovelNetBIOS" packet types can be found at
 *
 *	http://www.protocols.com/pbook/novel.htm#NetBIOS
 *
 * and at least some of those packet types appear to match what's in
 * some NBIPX packets.
 *
 * Note, however, that the offset of the packet type in an NBIPX packet
 * *DEPENDS ON THE PACKET TYPE*; "Find name" and "Name recognized" have
 * it at one offset, "Directed datagram" has it at another.  Does the
 * NBIPX code base it on the length, or what?  Non-broadcast directed
 * datagram packets have an IPX type of "IPX", just as "Find name" and
 * "Name recognized" do....  For now, we base it on the length.
 */
#define NBIPX_FIND_NAME		1
#define NBIPX_NAME_RECOGNIZED	2
#define NBIPX_CHECK_NAME	3
#define NBIPX_NAME_IN_USE	4
#define NBIPX_DEREGISTER_NAME	5
#define NBIPX_SESSION_DATA	6
#define NBIPX_SESSION_END	7
#define NBIPX_SESSION_END_ACK	8
#define NBIPX_STATUS_QUERY	9
#define NBIPX_STATUS_RESPONSE	10
#define NBIPX_DIRECTED_DATAGRAM	11

static const value_string nbipx_data_stream_type_vals[] = {
	{NBIPX_FIND_NAME,		"Find name"},
	{NBIPX_NAME_RECOGNIZED,		"Name recognized"},
	{NBIPX_CHECK_NAME,		"Check name"},
	{NBIPX_NAME_IN_USE,		"Name in use"},
	{NBIPX_DEREGISTER_NAME,		"Deregister name"},
	{NBIPX_SESSION_DATA,		"Session data"},
	{NBIPX_SESSION_END,		"Session end"},
	{NBIPX_SESSION_END_ACK,		"Session end ACK"},
	{NBIPX_STATUS_QUERY,		"Status query"},
	{NBIPX_STATUS_RESPONSE,		"Status response"},
	{NBIPX_DIRECTED_DATAGRAM,	"Directed datagram"},
	{0,				NULL}
};

#define NWLINK_NAME_QUERY	1
#define	NWLINK_SMB		2
#define	NWLINK_NETBIOS_DATAGRAM	3

static const value_string nwlink_data_stream_type_vals[] = {
	{NWLINK_NAME_QUERY,		"Name query"},
	{NWLINK_SMB,			"SMB"},
	{NWLINK_NETBIOS_DATAGRAM,	"NetBIOS datagram"},
	{0,				NULL}
};

struct nbipx_ns_header {
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
dissect_nbipx(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	int	max_data = pi.captured_len - offset;

	/*
	 * As said above, we look at the length of the packet to decide
	 * whether to treat it as a name-service packet or a datagram
	 * (the packet type would tell us, but it's at a *DIFFERENT
	 * LOCATION* in different types of packet...).
	 */
	if (END_OF_FRAME == 50)
		nbipx_ns(pd, offset, fd, tree, NETBIOS_NETWARE, max_data);
	else
		dissect_nbipx_dg(pd, offset, fd, tree, max_data);
}

void
dissect_nwlink_dg(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	int	max_data = pi.captured_len - offset;

	nbipx_ns(pd, offset, fd, tree, NETBIOS_NWLINK, max_data);
}


static void
nbipx_ns(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
		enum nbipx_protocol nbipx, int max_data)
{
	proto_tree			*nbipx_tree;
	proto_item			*ti;
	struct nbipx_ns_header	header;
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
			col_add_str(fd, COL_PROTOCOL, "NBIPX");
		}
		else {
			col_add_str(fd, COL_PROTOCOL, "NWLink");
		}
	}

	if (check_col(fd, COL_INFO)) {
		if (nbipx == NETBIOS_NETWARE) {
			switch (header.packet_type) {
			case NBIPX_FIND_NAME:
			case NBIPX_NAME_RECOGNIZED:
			case NBIPX_CHECK_NAME:
			case NBIPX_NAME_IN_USE:
			case NBIPX_DEREGISTER_NAME:
				col_add_fstr(fd, COL_INFO, "%s %s",
					val_to_str(header.packet_type, nbipx_data_stream_type_vals, "Unknown"),
					header.name);
				break;

			default:
				col_add_fstr(fd, COL_INFO, "%s",
					val_to_str(header.packet_type, nbipx_data_stream_type_vals, "Unknown"));
				break;
			}
		}
		else {
			switch (header.packet_type) {
			case NWLINK_NAME_QUERY:
				col_add_fstr(fd, COL_INFO, "Name Query for %s", header.name);
				break;

			case NWLINK_SMB:
				/* Session? */
				col_add_fstr(fd, COL_INFO, "SMB over NBIPX");
				break;

			case NWLINK_NETBIOS_DATAGRAM:
				/* Datagram? (Where did we see this?) */
				col_add_fstr(fd, COL_INFO, "NetBIOS datagram over NBIPX");
				break;
				
			default:
				col_add_str(fd, COL_INFO, "NetBIOS over IPX (NWLink)");
				break;
			}
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_nbipx, offset, 68, NULL);
		nbipx_tree = proto_item_add_subtree(ti, ETT_NBIPX);

		if (nbipx == NETBIOS_NETWARE) {
			proto_tree_add_text(nbipx_tree, offset+33, 1,
				"Packet Type: %s (%02X)",
				val_to_str(header.packet_type, nbipx_data_stream_type_vals, "Unknown"),
				header.packet_type);
		} else {
			proto_tree_add_text(nbipx_tree, offset+33, 1,
				"Packet Type: %s (%02X)",
				val_to_str(header.packet_type, nwlink_data_stream_type_vals, "Unknown"),
				header.packet_type);
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
			netbios_add_name("Name", &pd[offset], offset,
					name_offset, nbipx_tree);
		}
		else {
			netbios_add_name("Group name", &pd[offset], offset,
					name_offset, nbipx_tree);
			netbios_add_name("Node name", &pd[offset], offset,
					52, nbipx_tree);
		}
	}

	if (nbipx == NETBIOS_NWLINK) {
		switch (header.packet_type) {
			case NWLINK_SMB:
			case NWLINK_NETBIOS_DATAGRAM:
				dissect_smb(pd, offset + 68, fd, tree, max_data - 68);
				break;
				
			default:
				dissect_data(pd, offset + 68, fd, tree);
				break;
		}
	}
}

static void
dissect_nbipx_dg(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
		int max_data)
{
	proto_tree			*nbipx_tree;
	proto_item			*ti;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "NetBIOS");

	if (check_col(fd, COL_INFO))
		col_add_fstr(fd, COL_INFO, "NetBIOS datagram over NBIPX");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_nbipx, offset, 68, NULL);
		nbipx_tree = proto_item_add_subtree(ti, ETT_NBIPX);

		proto_tree_add_text(nbipx_tree, offset+1, 1,
				"Packet Type: %s (%02X)",
				val_to_str(pd[offset+1], nbipx_data_stream_type_vals, "Unknown"),
				pd[offset+1]);
		proto_tree_add_text(nbipx_tree, offset, 1,
		    "Connection control: 0x%02x", pd[offset]);
		netbios_add_name("Receiver's Name", &pd[offset],
		    offset, 2, nbipx_tree);
		netbios_add_name("Sender's Name", &pd[offset],
		    offset, 2+16, nbipx_tree);

		dissect_smb(pd, offset+2+16+16, fd, tree, max_data - 2+16+16);
	}
}

void
proto_register_nbipx(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "nbipx.abbreviation", TYPE, VALS_POINTER }},
        };*/

        proto_nbipx = proto_register_protocol("NetBIOS over IPX", "nbipx");
 /*       proto_register_field_array(proto_nbipx, hf, array_length(hf));*/
}
