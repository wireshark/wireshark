/* packet-nbipx.c
 * Routines for NetBIOS over IPX packet disassembly
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-nbipx.c,v 1.33 2001/01/03 06:55:30 guy Exp $
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

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-ipx.h"
#include "packet-netbios.h"
#include "packet-smb.h"

static int proto_nbipx = -1;

static gint ett_nbipx = -1;
static gint ett_nbipx_conn_ctrl = -1;
static gint ett_nbipx_name_type_flags = -1;

enum nbipx_protocol {
	NETBIOS_NETWARE,
	NETBIOS_NWLINK
};

static void
dissect_nbipx_ns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_nbipx_dg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

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

/* NetWare */
static void
dissect_nbipx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	CHECK_DISPLAY_AS_DATA(proto_nbipx, tvb, pinfo, tree);

	pinfo->current_proto = "NBIPX";

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "NBIPX");
	if (check_col(pinfo->fd, COL_INFO))
		col_clear(pinfo->fd, COL_INFO);

	/*
	 * As said above, we look at the length of the packet to decide
	 * whether to treat it as a name-service packet or a datagram
	 * (the packet type would tell us, but it's at a *DIFFERENT
	 * LOCATION* in different types of packet...).
	 */
	if (tvb_reported_length(tvb) == 50)
		dissect_nbipx_ns(tvb, pinfo, tree);
	else
		dissect_nbipx_dg(tvb, pinfo, tree);
}

static void
add_routers(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	int		i;
	int		rtr_offset;
	guint32		router;

	/* Eight routers are listed */
	for (i = 0; i < 8; i++) {
		rtr_offset = offset + (i << 2);
		tvb_memcpy(tvb, (guint8 *)&router, rtr_offset, 4);
		if (router != 0) {
			proto_tree_add_text(tree, tvb, rtr_offset, 4,
			    "IPX Network: %s",
			    ipxnet_to_string((guint8*)&router));
		}
	}
}

static void
dissect_nbipx_ns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree		*nbipx_tree;
	proto_item		*ti;
	int			offset = 0;
	guint8			packet_type;
	guint8			name_type_flag;
	proto_tree		*name_type_flag_tree;
	proto_item		*tf;
	char			name[(NETBIOS_NAME_LEN - 1)*4 + 1];
	int			name_type;

	name_type_flag = tvb_get_guint8(tvb, offset+32);
	packet_type = tvb_get_guint8(tvb, offset+33);
	name_type = get_netbios_name(tvb, offset+34, name);

	if (check_col(pinfo->fd, COL_INFO)) {
		switch (packet_type) {
		case NBIPX_FIND_NAME:
		case NBIPX_NAME_RECOGNIZED:
		case NBIPX_CHECK_NAME:
		case NBIPX_NAME_IN_USE:
		case NBIPX_DEREGISTER_NAME:
			col_add_fstr(pinfo->fd, COL_INFO, "%s %s<%02x>",
				val_to_str(packet_type, nbipx_data_stream_type_vals, "Unknown"),
				name, name_type);
			break;

		default:
			col_add_fstr(pinfo->fd, COL_INFO, "%s",
				val_to_str(packet_type, nbipx_data_stream_type_vals, "Unknown"));
			break;
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_nbipx, tvb, offset, 50,
		    FALSE);
		nbipx_tree = proto_item_add_subtree(ti, ett_nbipx);

		add_routers(nbipx_tree, tvb, offset);

		tf = proto_tree_add_text(nbipx_tree, tvb, offset+32, 1,
			"Name type flag: 0x%02x", name_type_flag);
		name_type_flag_tree = proto_item_add_subtree(tf,
				ett_nbipx_name_type_flags);
		proto_tree_add_text(name_type_flag_tree, tvb, offset+32,
		    1, "%s",
		    decode_boolean_bitfield(name_type_flag, 0x80, 8,
		      "Group name", "Unique name"));
		proto_tree_add_text(name_type_flag_tree, tvb, offset+32,
		    1, "%s",
		    decode_boolean_bitfield(name_type_flag, 0x40, 8,
		      "Name in use", "Name not used"));
		proto_tree_add_text(name_type_flag_tree, tvb, offset+32,
		    1, "%s",
		    decode_boolean_bitfield(name_type_flag, 0x04, 8,
		      "Name registered", "Name not registered"));
		proto_tree_add_text(name_type_flag_tree, tvb, offset+32,
		    1, "%s",
		    decode_boolean_bitfield(name_type_flag, 0x02, 8,
		      "Name duplicated", "Name not duplicated"));
		proto_tree_add_text(name_type_flag_tree, tvb, offset+32,
		    1, "%s",
		    decode_boolean_bitfield(name_type_flag, 0x01, 8,
		      "Name deregistered", "Name not deregistered"));

		proto_tree_add_text(nbipx_tree, tvb, offset+33, 1,
			"Packet Type: %s (%02X)",
			val_to_str(packet_type, nbipx_data_stream_type_vals, "Unknown"),
			packet_type);

		netbios_add_name("Name", tvb, offset + 34, nbipx_tree);
	}
}

static void
dissect_nbipx_dg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree			*nbipx_tree;
	proto_item			*ti;
	int				offset = 0;
	guint8				conn_control;
	proto_tree			*cc_tree;
	guint8				packet_type;
	tvbuff_t			*next_tvb;
	const guint8			*next_pd;
	int				next_offset;

	if (check_col(pinfo->fd, COL_INFO))
		col_add_fstr(pinfo->fd, COL_INFO, "NetBIOS datagram over NBIPX");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_nbipx, tvb, offset,
		    2+NETBIOS_NAME_LEN+NETBIOS_NAME_LEN, FALSE);
		nbipx_tree = proto_item_add_subtree(ti, ett_nbipx);

		conn_control = tvb_get_guint8(tvb, offset);
		ti = proto_tree_add_text(nbipx_tree, tvb, offset, 1,
		    "Connection control: 0x%02x", conn_control);
		cc_tree = proto_item_add_subtree(ti, ett_nbipx_conn_ctrl);
		proto_tree_add_text(cc_tree, tvb, offset, 1, "%s",
		      decode_boolean_bitfield(conn_control, 0x80, 8,
			      "System packet", "Non-system packet"));
		proto_tree_add_text(cc_tree, tvb, offset, 1, "%s",
		      decode_boolean_bitfield(conn_control, 0x40, 8,
			      "Send acknowledge", "No send acknowledge"));
		proto_tree_add_text(cc_tree, tvb, offset, 1, "%s",
		      decode_boolean_bitfield(conn_control, 0x20, 8,
			      "Attention", "No attention"));
		proto_tree_add_text(cc_tree, tvb, offset, 1, "%s",
		      decode_boolean_bitfield(conn_control, 0x10, 8,
			      "End of message", "No end of message"));
		proto_tree_add_text(cc_tree, tvb, offset, 1, "%s",
		      decode_boolean_bitfield(conn_control, 0x08, 8,
			      "Resend", "No resend"));
		offset += 1;

		packet_type = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(nbipx_tree, tvb, offset, 1,
				"Packet Type: %s (%02X)",
				val_to_str(packet_type, nbipx_data_stream_type_vals, "Unknown"),
				packet_type);
		offset += 1;

		if (!netbios_add_name("Receiver's Name", tvb, offset,
		    nbipx_tree))
			return;
		offset += NETBIOS_NAME_LEN;

		if (!netbios_add_name("Sender's Name", tvb, offset,
		    nbipx_tree))
			return;
		offset += NETBIOS_NAME_LEN;

		if (tvb_offset_exists(tvb, offset)) {
			next_tvb = tvb_new_subset(tvb, offset, -1, -1);
			tvb_compat(next_tvb, &next_pd, &next_offset);
			dissect_smb(next_pd, next_offset, pinfo->fd, tree,
			    tvb_length(next_tvb));
		}
	}
}

static void
dissect_nwlink_dg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*nbipx_tree;
	proto_item	*ti;
	int		offset = 0;
	guint8		packet_type;
	guint8		name_type_flag;
	proto_tree	*name_type_flag_tree;
	proto_item	*tf;
	char		name[(NETBIOS_NAME_LEN - 1)*4 + 1];
	int		name_type;
	char		node_name[(NETBIOS_NAME_LEN - 1)*4 + 1];
	int		node_name_type = 0;
	tvbuff_t	*next_tvb;
	const guint8	*next_pd;
	int		next_offset;

	name_type_flag = tvb_get_guint8(tvb, offset+32);
	packet_type = tvb_get_guint8(tvb, offset+33);
	name_type = get_netbios_name(tvb, offset+36, name);
	node_name_type = get_netbios_name(tvb, offset+52, node_name);

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "NWLink");

	if (check_col(pinfo->fd, COL_INFO)) {
		/*
		 * XXX - Microsoft Network Monitor thinks that the octet
		 * at 32 is a packet type, e.g. "mailslot write" for
		 * browser announcements, and that the octet at 33 is a
		 * name type, in the sense of the 16th byte of a
		 * NetBIOS name.
		 *
		 * A name type of 2 shows up in a "host announcement",
		 * and a name type of 3 shows up in a "local master
		 * annoumcement", so maybe that field really *is* a
		 * name type - the fact that it's not associated with
		 * any of the NetBIOS names in the packet nonwithstanding.
		 *
		 * I haven't seen any packets with the name type octet
		 * being anything other than 2 or 3, so I don't know
		 * whether those are name service operations; however,
		 * given that NWLink, unlike socket-0x0455 NBIPX,
		 * has separate sockets for name queries and datagrams,
		 * it may be that this really is a name type, and that
		 * these are all datagrams, not name queries.
		 */
		switch (packet_type) {
		case NWLINK_NAME_QUERY:
			col_add_fstr(pinfo->fd, COL_INFO, "Name Query for %s<%02x>",
					name, name_type);
			break;

		case NWLINK_SMB:
			/* Session? */
			col_add_fstr(pinfo->fd, COL_INFO, "SMB over NBIPX");
			break;

		case NWLINK_NETBIOS_DATAGRAM:
			/* Datagram? (Where did we see this?) */
			col_add_fstr(pinfo->fd, COL_INFO, "NetBIOS datagram over NBIPX");
			break;
				
		default:
			col_set_str(pinfo->fd, COL_INFO, "NetBIOS over IPX (NWLink)");
			break;
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_nbipx, tvb, offset, 68, FALSE);
		nbipx_tree = proto_item_add_subtree(ti, ett_nbipx);

		add_routers(nbipx_tree, tvb, offset);

		/*
		 * XXX - is "packet_type" really a packet type?  See
		 * above.
		 */
		if (packet_type != NWLINK_SMB &&
		      packet_type != NWLINK_NETBIOS_DATAGRAM) {
			tf = proto_tree_add_text(nbipx_tree, tvb, offset+32, 1,
				"Name type flag: 0x%02x",
				name_type_flag);
			name_type_flag_tree = proto_item_add_subtree(tf,
					ett_nbipx_name_type_flags);
			proto_tree_add_text(name_type_flag_tree, tvb, offset+32,
			    1, "%s",
			    decode_boolean_bitfield(name_type_flag, 0x80, 8,
			      "Group name", "Unique name"));
			proto_tree_add_text(name_type_flag_tree, tvb, offset+32,
			    1, "%s",
			    decode_boolean_bitfield(name_type_flag, 0x40, 8,
			      "Name in use", "Name not used"));
			proto_tree_add_text(name_type_flag_tree, tvb, offset+32,
			    1, "%s",
			    decode_boolean_bitfield(name_type_flag, 0x04, 8,
			      "Name registered", "Name not registered"));
			proto_tree_add_text(name_type_flag_tree, tvb, offset+32,
			    1, "%s",
			    decode_boolean_bitfield(name_type_flag, 0x02, 8,
			      "Name duplicated", "Name not duplicated"));
			proto_tree_add_text(name_type_flag_tree, tvb, offset+32,
			    1, "%s",
			    decode_boolean_bitfield(name_type_flag, 0x01, 8,
			      "Name deregistered", "Name not deregistered"));

			if (!netbios_add_name("Group name", tvb, offset+36,
			    nbipx_tree))
				return;
			if (!netbios_add_name("Node name", tvb, offset+52,
			    nbipx_tree))
				return;
			proto_tree_add_text(nbipx_tree, tvb, offset+33, 1,
			    "Packet Type: %s (%02X)",
			    val_to_str(packet_type, nwlink_data_stream_type_vals, "Unknown"),
			    packet_type);
		} else {
			proto_tree_add_text(nbipx_tree, tvb, offset+32, 1,
			    "Packet type: 0x%02x", name_type_flag);
			proto_tree_add_text(nbipx_tree, tvb, offset+33, 1,
			    "Name Type: %s (0x%02x)",
			    netbios_name_type_descr(packet_type),
			    packet_type);
			proto_tree_add_text(nbipx_tree, tvb, offset+34, 2,
			    "Message ID: 0x%04x",
			    tvb_get_letohs(tvb, offset+34));
			if (!netbios_add_name("Requested name", tvb, offset+36,
			    nbipx_tree))
				return;
			if (!netbios_add_name("Source name", tvb, offset+52,
			    nbipx_tree))
				return;
		}
	}

	offset += 68;

	if (tvb_offset_exists(tvb, offset)) {
		next_tvb = tvb_new_subset(tvb, offset, -1, -1);

		switch (packet_type) {
		case NWLINK_SMB:
		case NWLINK_NETBIOS_DATAGRAM:
			tvb_compat(next_tvb, &next_pd, &next_offset);
			dissect_smb(next_pd, next_offset, pinfo->fd, tree,
			    tvb_length(next_tvb));
			break;
				
		default:
			dissect_data(next_tvb, 0, pinfo, tree);
			break;
		}
	}
}

void
proto_register_nbipx(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "nbipx.abbreviation", TYPE, VALS_POINTER }},
        };*/
	static gint *ett[] = {
		&ett_nbipx,
		&ett_nbipx_conn_ctrl,
		&ett_nbipx_name_type_flags,
	};

        proto_nbipx = proto_register_protocol("NetBIOS over IPX",
	    "NBIPX", "nbipx");
 /*       proto_register_field_array(proto_nbipx, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("nbipx", dissect_nbipx);
}

void
proto_reg_handoff_nbipx(void)
{
	dissector_add("ipx.socket", IPX_SOCKET_NWLINK_SMB_DGRAM, dissect_nwlink_dg);
}
