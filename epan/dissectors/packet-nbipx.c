/* packet-nbipx.c
 * Routines for NetBIOS over IPX packet disassembly
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include <glib.h>
#include <epan/packet.h>
#include "packet-ipx.h"
#include "packet-netbios.h"

static int proto_nbipx = -1;

static gint ett_nbipx = -1;
static gint ett_nbipx_conn_ctrl = -1;
static gint ett_nbipx_name_type_flags = -1;

static void dissect_conn_control(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_packet_type(tvbuff_t *tvb, int offset, guint8 packet_type,
    proto_tree *tree);

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
 * Note, however, that it appears that sometimes NBIPX packets have
 * 8 IPX addresses at the beginning, and sometimes they don't.
 *
 * In the section on "NetBIOS Broadcasts", the document at
 *
 *	http://www.microsoft.com/technet/network/ipxrout.asp
 *
 * says that "the NetBIOS over IPX Broadcast header" contains 8 IPX
 * network numbers in the "IPX WAN broadcast header", and that it's
 * followed by a "Name Type Flags" byte (giving information about the
 * name being registered, deregistered, or checked), a "Data Stream
 * Type 2" byte giving the type of operation (NBIPX_FIND_NAME,
 * NBIPX_NAME_RECOGNIZED, or NBIPX_CHECK_NAME - the latter is called
 * "Add Name"), and a 16-byte NetBIOS name.
 *
 * It also says that "NetBIOS over IPX Broadcast packets" have a
 * packet type of 0x14 (20, or IPX_PACKET_TYPE_WANBCAST) and a
 * socket number of 0x455 (IPX_SOCKET_NETBIOS).
 *
 * However, there are also non-broadcast packets that *also* contain
 * the 8 IPX network numbers; they appear to be replies to broadcast
 * packets, and have a packet type of 0x4 (IPX_PACKET_TYPE_PEP).
 *
 * Other IPX_PACKET_TYPE_PEP packets to and from the IPX_SOCKET_NETBIOS
 * socket, however, *don't* have the 8 IPX network numbers; there does
 * not seem to be any obvious algorithm to determine whether the packet
 * has the addresses or not.  Microsoft Knowledge Base article Q128335
 * appears to show some code from the NBIPX implementation in NT that
 * tries to determine the packet type - and it appears to use heuristics
 * based on the packet length and on looking at what might be the NBIPX
 * "Data Stream Type" byte depending on whether the packet has the 8
 * IPX network numbers or not.
 *
 * So, for now, we treat *all* NBIPX packets as having a "Data Stream
 * Type" byte, preceded by another byte of NBIPX information and
 * followed by more NBIPX stuff, and assume that it's preceded by
 * 8 IPX network numbers iff:
 *
 *	the packet is a WAN Broadcast packet
 *
 * or
 *
 *	the packet is the right size for one of those PEP name replies
 *	(50 bytes) *and* has a name packet type as the Data Stream
 *	Type byte at the offset where that byte would be if the packet
 *	does have the 8 IPX network numbers at the beginning.
 *
 * The page at
 *
 *	http://ourworld.compuserve.com/homepages/TimothyDEvans/encap.htm
 *
 * indicates, under "NBIPX session packets", that "NBIPX session packets"
 * have
 *
 *	1 byte of NBIPX connection control flag
 *	1 byte of data stream type
 *	2 bytes of source connection ID
 *	2 bytes of destination connection ID
 *	2 bytes of send sequence number
 *	2 bytes of total data length
 *	2 bytes of offset
 *	2 bytes of data length
 *	2 bytes of receive sequence number
 *	2 bytes of "bytes received"
 *
 * followed by data.
 *
 * Packets with a data stream type of NBIPX_DIRECTED_DATAGRAM appear to
 * have, following the data stream type, two NetBIOS names, the first
 * of which is the receiver's NetBIOS name and the second of which is
 * the sender's NetBIOS name.  The page at
 *
 *	http://support.microsoft.com/support/kb/articles/q203/0/51.asp
 *
 * speaks of type 4 (PEP) packets as being used for "SAP, NetBIOS sessions
 * and directed datagrams" and type 20 (WAN Broadcast) as being used for
 * "NetBIOS name resolution broadcasts" (but nothing about the non-broadcast
 * type 4 name resolution stuff).
 *
 * We assume that this means that, once you get past the 8 IPX network
 * numbers if present:
 *
 *	the first byte is a name type byte for the name packets
 *	and a connection control flag for the other packets;
 *
 *	the second byte is a data stream type;
 *
 *	the rest of the bytes are:
 *
 *		the NetBIOS name being registered/deregistered/etc.,
 *		for name packets;
 *
 *		the two NetBIOS names, followed by the NetBIOS
 *		datagram, for NBIPX_DIRECTED_DATAGRAM packets;
 *
 *		the session packet header, possibly followed by
 *		session data, for session packets.
 *
 * We don't know yet how to interpret NBIPX_STATUS_QUERY or
 * NBIPX_STATUS_RESPONSE.
 *
 * For now, we treat the datagrams and session data as SMB stuff.
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
dissect_nbipx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gboolean	has_routes;
	proto_tree	*nbipx_tree = NULL;
	proto_item	*ti = NULL;
	int		offset = 0;
	guint8		packet_type;
	guint8		name_type_flag;
	proto_tree	*name_type_flag_tree;
	proto_item	*tf;
	char		name[(NETBIOS_NAME_LEN - 1)*4 + 1];
	int		name_type;
	gboolean	has_payload;
	tvbuff_t	*next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBIPX");
	col_clear(pinfo->cinfo, COL_INFO);

	if (pinfo->ipxptype == IPX_PACKET_TYPE_WANBCAST) {
		/*
		 * This is a WAN Broadcast packet; we assume it will have
		 * 8 IPX addresses at the beginning.
		 */
		has_routes = TRUE;
	} else {
		/*
		 * This isn't a WAN Broadcast packet, but it still might
		 * have the 8 addresses.
		 *
		 * If it's the right length for a name operation,
		 * and, if we assume it has routes, the packet type
		 * is a name operation, assume it has routes.
		 *
		 * NOTE: this will throw an exception if the byte that
		 * would be the packet type byte if this has the 8
		 * addresses isn't present; if that's the case, we don't
		 * know how to interpret this packet, so we can't dissect
		 * it anyway.
		 */
		has_routes = FALSE;	/* start out assuming it doesn't */
		if (tvb_reported_length(tvb) == 50) {
			packet_type = tvb_get_guint8(tvb, offset + 32 + 1);
			switch (packet_type) {

			case NBIPX_FIND_NAME:
			case NBIPX_NAME_RECOGNIZED:
			case NBIPX_CHECK_NAME:
			case NBIPX_NAME_IN_USE:
			case NBIPX_DEREGISTER_NAME:
				has_routes = TRUE;
				break;
			}
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_nbipx, tvb, 0,
		    -1, ENC_NA);
		nbipx_tree = proto_item_add_subtree(ti, ett_nbipx);
	}

	if (has_routes) {
		if (tree)
			add_routers(nbipx_tree, tvb, 0);
		offset += 32;
	}

	packet_type = tvb_get_guint8(tvb, offset + 1);

	switch (packet_type) {

	case NBIPX_FIND_NAME:
	case NBIPX_NAME_RECOGNIZED:
	case NBIPX_CHECK_NAME:
	case NBIPX_NAME_IN_USE:
	case NBIPX_DEREGISTER_NAME:
		name_type_flag = tvb_get_guint8(tvb, offset);
		name_type = get_netbios_name(tvb, offset+2, name, (NETBIOS_NAME_LEN - 1)*4 + 1);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s<%02x>",
				val_to_str(packet_type, nbipx_data_stream_type_vals, "Unknown"),
				name, name_type);
		}
		if (nbipx_tree) {
			tf = proto_tree_add_text(nbipx_tree, tvb, offset, 1,
				"Name type flag: 0x%02x", name_type_flag);
			name_type_flag_tree = proto_item_add_subtree(tf,
					ett_nbipx_name_type_flags);
			proto_tree_add_text(name_type_flag_tree, tvb, offset,
			    1, "%s",
			    decode_boolean_bitfield(name_type_flag, 0x80, 8,
			      "Group name", "Unique name"));
			proto_tree_add_text(name_type_flag_tree, tvb, offset,
			    1, "%s",
			    decode_boolean_bitfield(name_type_flag, 0x40, 8,
			      "Name in use", "Name not used"));
			proto_tree_add_text(name_type_flag_tree, tvb, offset,
			    1, "%s",
			    decode_boolean_bitfield(name_type_flag, 0x04, 8,
			      "Name registered", "Name not registered"));
			proto_tree_add_text(name_type_flag_tree, tvb, offset,
			    1, "%s",
			    decode_boolean_bitfield(name_type_flag, 0x02, 8,
			      "Name duplicated", "Name not duplicated"));
			proto_tree_add_text(name_type_flag_tree, tvb, offset,
			    1, "%s",
			    decode_boolean_bitfield(name_type_flag, 0x01, 8,
			      "Name deregistered", "Name not deregistered"));
		}
		offset += 1;

		dissect_packet_type(tvb, offset, packet_type, nbipx_tree);
		offset += 1;

		if (nbipx_tree)
			netbios_add_name("Name", tvb, offset, nbipx_tree);
		offset += NETBIOS_NAME_LEN;

		/*
		 * No payload to be interpreted by another protocol.
		 */
		has_payload = FALSE;
		break;

	case NBIPX_SESSION_DATA:
	case NBIPX_SESSION_END:
	case NBIPX_SESSION_END_ACK:
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_str(pinfo->cinfo, COL_INFO,
				val_to_str(packet_type, nbipx_data_stream_type_vals, "Unknown"));
		}
		dissect_conn_control(tvb, offset, nbipx_tree);
		offset += 1;

		dissect_packet_type(tvb, offset, packet_type, nbipx_tree);
		offset += 1;

		if (nbipx_tree) {
			proto_tree_add_text(nbipx_tree, tvb, offset, 2,
			    "Source connection ID: 0x%04X",
			    tvb_get_letohs(tvb, offset));
		}
		offset += 2;

		if (nbipx_tree) {
			proto_tree_add_text(nbipx_tree, tvb, offset, 2,
			    "Destination connection ID: 0x%04X",
			    tvb_get_letohs(tvb, offset));
		}
		offset += 2;

		if (nbipx_tree) {
			proto_tree_add_text(nbipx_tree, tvb, offset, 2,
			    "Send sequence number: %u",
			    tvb_get_letohs(tvb, offset));
		}
		offset += 2;

		if (nbipx_tree) {
			proto_tree_add_text(nbipx_tree, tvb, offset, 2,
			    "Total data length: %u",
			    tvb_get_letohs(tvb, offset));
		}
		offset += 2;

		if (nbipx_tree) {
			proto_tree_add_text(nbipx_tree, tvb, offset, 2,
			    "Offset: %u",
			    tvb_get_letohs(tvb, offset));
		}
		offset += 2;

		if (nbipx_tree) {
			proto_tree_add_text(nbipx_tree, tvb, offset, 2,
			    "Data length: %u",
			    tvb_get_letohs(tvb, offset));
		}
		offset += 2;

		if (nbipx_tree) {
			proto_tree_add_text(nbipx_tree, tvb, offset, 2,
			    "Receive sequence number: %u",
			    tvb_get_letohs(tvb, offset));
		}
		offset += 2;

		if (nbipx_tree) {
			proto_tree_add_text(nbipx_tree, tvb, offset, 2,
			    "Bytes received: %u",
			    tvb_get_letohs(tvb, offset));
		}
		offset += 2;

		/*
		 * We may have payload to dissect.
		 */
		has_payload = TRUE;
		break;

	case NBIPX_DIRECTED_DATAGRAM:
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_str(pinfo->cinfo, COL_INFO,
				val_to_str(packet_type, nbipx_data_stream_type_vals, "Unknown"));
		}
		dissect_conn_control(tvb, offset, nbipx_tree);
		offset += 1;

		dissect_packet_type(tvb, offset, packet_type, nbipx_tree);
		offset += 1;

		if (nbipx_tree)
			netbios_add_name("Receiver's Name", tvb, offset,
			    nbipx_tree);
		offset += NETBIOS_NAME_LEN;

		if (nbipx_tree)
			netbios_add_name("Sender's Name", tvb, offset,
			    nbipx_tree);
		offset += NETBIOS_NAME_LEN;

		/*
		 * We may have payload to dissect.
		 */
		has_payload = TRUE;
		break;

	default:
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_str(pinfo->cinfo, COL_INFO,
				val_to_str(packet_type, nbipx_data_stream_type_vals, "Unknown"));
		}

		/*
		 * We don't know what the first byte is.
		 */
		offset += 1;

		/*
		 * The second byte is a data stream type byte.
		 */
		dissect_packet_type(tvb, offset, packet_type, nbipx_tree);
		offset += 1;

		/*
		 * We don't know what the rest of the packet is.
		 */
		has_payload = FALSE;
	}

	/*
	 * Set the length of the NBIPX tree item.
	 */
	if (ti != NULL)
		proto_item_set_len(ti, offset);

	if (has_payload && tvb_offset_exists(tvb, offset)) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		dissect_netbios_payload(next_tvb, pinfo, tree);
	}
}

static void
dissect_conn_control(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint8		conn_control;
	proto_item	*ti;
	proto_tree	*cc_tree;

	if (tree) {
		conn_control = tvb_get_guint8(tvb, offset);
		ti = proto_tree_add_text(tree, tvb, offset, 1,
		    "Connection control: 0x%02x", conn_control);
		cc_tree = proto_item_add_subtree(ti, ett_nbipx_conn_ctrl);
		proto_tree_add_text(cc_tree, tvb, offset, 1, "%s",
		      decode_boolean_bitfield(conn_control, 0x80, 8,
			      "System packet", "Non-system packet"));
		proto_tree_add_text(cc_tree, tvb, offset, 1, "%s",
		      decode_boolean_bitfield(conn_control, 0x40, 8,
			      "Acknowledgement required",
			      "Acknowledgement not required"));
		proto_tree_add_text(cc_tree, tvb, offset, 1, "%s",
		      decode_boolean_bitfield(conn_control, 0x20, 8,
			      "Attention", "No attention"));
		proto_tree_add_text(cc_tree, tvb, offset, 1, "%s",
		      decode_boolean_bitfield(conn_control, 0x10, 8,
			      "End of message", "No end of message"));
		proto_tree_add_text(cc_tree, tvb, offset, 1, "%s",
		      decode_boolean_bitfield(conn_control, 0x08, 8,
			      "Resend", "No resend"));
	}
}

static void
dissect_packet_type(tvbuff_t *tvb, int offset, guint8 packet_type,
    proto_tree *tree)
{
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 1,
				"Packet Type: %s (%02X)",
				val_to_str(packet_type, nbipx_data_stream_type_vals, "Unknown"),
				packet_type);
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
}

void
proto_reg_handoff_nbipx(void)
{
	dissector_handle_t nbipx_handle;

	nbipx_handle = create_dissector_handle(dissect_nbipx, proto_nbipx);
	dissector_add_uint("ipx.socket", IPX_SOCKET_NETBIOS, nbipx_handle);
}

/*
 * Microsoft appear to have something they call "direct hosting", where
 * SMB - and, I infer, related stuff, such as name resolution - runs
 * directly over IPX.  (In Windows 2000, they also run SMB directly over
 * TCP, on port 445, and that also appears to be called "direct hosting".
 * Wireshark handles SMB-over-TCP.)
 *
 * The document at
 *
 *	http://support.microsoft.com/support/kb/articles/q203/0/51.asp
 *
 * speaks of NMPI - the "Name Management Protocol on IPX" - as being
 * "Microsoft's protocol for name management support when you use IPX
 * without the NetBIOS interface," and says that "This process of routing
 * the SMB protocol directly through IPX is known as Direct Hosting."
 *
 * It speaks of IPX socket 0x551 as being for NMPI; we define it as
 * IPX_SOCKET_NWLINK_SMB_NAMEQUERY.
 *
 * We also define IPX_SOCKET_NWLINK_SMB_DGRAM as 0x0553 and define
 * IPX_SOCKET_NWLINK_SMB_BROWSE as 0x0555 (with a "? not sure on this"
 * comment after the latter one).
 *
 * We have seen at least some browser announcements on IPX socket 0x553;
 * those are WAN broadcast packets, complete with 8 IPX network
 * numbers, and with the header containing the usual two NetBIOS names
 * that show up in NetBIOS datagrams.
 *
 * Network Monitor calls those packets NMPI packets, even though they're
 * on socket 0x553, not socket 0x551, and contain SMB datagrams, not name
 * resolution packets.
 *
 * At least some of this is discussed in the "SMBPUB.DOC" Word document
 * stored in
 *
 *	ftp://ftp.microsoft.com/developr/drg/CIFS/smbpub.zip
 *
 * which can also be found in text form at
 *
 *	http://www.samba.org/samba/ftp/specs/smbpub.txt
 *
 * which says that for "connectionless IPX transport" the sockets that
 * are used are:
 *
 *	SMB_SERVER_SOCKET (0x550) - SMB requests from clients
 *	SMB_NAME_SOCKET (0x551) - name claims and name query messages
 *	REDIR_SOCKET (0x552) - used by the redirector (client) for
 *		sending SMB requests and receiving SMB replies
 *	MAILSLOT_SOCKET (0x553) - used by the redirector and browser
 * 		for mailslot datagrams
 *	MESSENGER_SOCKET (0x554) - used by the redirector to send
 *		messages from client to client
 *
 * Name claim/query packets, and mailslot datagrams, are:
 *
 *	8 IPX network addresses
 *	1 byte of opcode
 *	1 byte of name type
 * 	2 bytes of message ID
 *	16 bytes of name being sought or claimed
 *	16 bytes of requesting machine
 *
 * The opcode is one of:
 *
 *	INAME_CLAIM (0xf1) - server name claim message
 *	INAME_DELETE (0xf2) - relinquish server name
 *	INAME_QUERY (0xf3) - locate server name
 *	INAME_FOUND (0xf4) - response to INAME_QUERY
 *	IMSG_HANGUP (0xf5) - messenger hangup
 *	IMSLOT_SEND (0xfc) - mailslot write
 *	IMSLOT_FIND (0xfd) - find name for mailslot write
 *	IMSLOT_NAME (0xfe) - response to IMSLOT_FIND
 *
 * The name type is one of:
 *
 *	INTYPE_MACHINE	1
 *	INTYPE_WKGROUP	2
 *	INTYPE_BROWSER	3
 */
static int proto_nmpi = -1;

static gint ett_nmpi = -1;
static gint ett_nmpi_name_type_flags = -1;

/*
 * Opcodes.
 */
#define	INAME_CLAIM	0xf1
#define INAME_DELETE	0xf2
#define INAME_QUERY	0xf3
#define INAME_FOUND	0xf4
#define IMSG_HANGUP	0xf5
#define	IMSLOT_SEND	0xfc
#define IMSLOT_FIND	0xfd
#define IMSLOT_NAME	0xfe

static const value_string nmpi_opcode_vals[] = {
	{INAME_CLAIM,	"Claim name"},
	{INAME_DELETE,	"Delete name"},
	{INAME_QUERY,	"Query name"},
	{INAME_FOUND,	"Name found"},
	{IMSG_HANGUP,	"Messenger hangup"},
	{IMSLOT_SEND,	"Mailslot write"},
	{IMSLOT_FIND,	"Find mailslot name"},
	{IMSLOT_NAME,	"Mailslot name found"},
	{0,		NULL}
};

/*
 * Name types.
 */
#define INTYPE_MACHINE		1
#define INTYPE_WORKGROUP	2
#define INTYPE_BROWSER		3

static const value_string nmpi_name_type_vals[] = {
	{INTYPE_MACHINE,	"Machine"},
	{INTYPE_WORKGROUP,	"Workgroup"},
	{INTYPE_BROWSER,	"Browser"},
	{0,			NULL}
};

static void
dissect_nmpi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*nmpi_tree = NULL;
	proto_item	*ti;
	int		offset = 0;
	guint8		opcode;
	guint8		nmpi_name_type;
	char		name[(NETBIOS_NAME_LEN - 1)*4 + 1];
	int		name_type;
	char		node_name[(NETBIOS_NAME_LEN - 1)*4 + 1];
	/*int		node_name_type = 0;*/
	tvbuff_t	*next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NMPI");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_nmpi, tvb, offset, 68,
		    ENC_NA);
		nmpi_tree = proto_item_add_subtree(ti, ett_nmpi);

		add_routers(nmpi_tree, tvb, offset);
	}
	offset += 32;

	/*
	 * XXX - we don't use "node_name" or "node_name_type".
	 */
	opcode = tvb_get_guint8(tvb, offset);
	nmpi_name_type = tvb_get_guint8(tvb, offset+1);
	name_type = get_netbios_name(tvb, offset+4, name, (NETBIOS_NAME_LEN - 1)*4 + 1);
	/*node_name_type = */get_netbios_name(tvb, offset+20, node_name, (NETBIOS_NAME_LEN - 1)*4 + 1);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		switch (opcode) {

		case INAME_CLAIM:
			col_add_fstr(pinfo->cinfo, COL_INFO, "Claim name %s<%02x>",
					name, name_type);
			break;

		case INAME_DELETE:
			col_add_fstr(pinfo->cinfo, COL_INFO, "Delete name %s<%02x>",
					name, name_type);
			break;

		case INAME_QUERY:
			col_add_fstr(pinfo->cinfo, COL_INFO, "Query name %s<%02x>",
					name, name_type);
			break;

		case INAME_FOUND:
			col_add_fstr(pinfo->cinfo, COL_INFO, "Name %s<%02x> found",
					name, name_type);
			break;

		case IMSG_HANGUP:
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "Messenger hangup on %s<%02x>", name, name_type);
			break;

		case IMSLOT_SEND:
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "Mailslot write to %s<%02x>", name, name_type);
			break;

		case IMSLOT_FIND:
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "Find mailslot name %s<%02x>", name, name_type);
			break;

		case IMSLOT_NAME:
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "Mailslot name %s<%02x> found", name, name_type);
			break;

		default:
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "Unknown NMPI op 0x%02x: name %s<%02x>",
			    opcode, name, name_type);
			break;
		}
	}

	if (tree) {
		proto_tree_add_text(nmpi_tree, tvb, offset, 1,
		    "Opcode: %s (0x%02x)",
		    val_to_str(opcode, nmpi_opcode_vals, "Unknown"),
		    opcode);
		proto_tree_add_text(nmpi_tree, tvb, offset+1, 1,
		    "Name Type: %s (0x%02x)",
		    val_to_str(nmpi_name_type, nmpi_name_type_vals, "Unknown"),
		    nmpi_name_type);
		proto_tree_add_text(nmpi_tree, tvb, offset+2, 2,
		    "Message ID: 0x%04x",
		    tvb_get_letohs(tvb, offset+2));
		netbios_add_name("Requested name", tvb, offset+4, nmpi_tree);
		netbios_add_name("Source name", tvb, offset+20, nmpi_tree);
	}

	offset += 1 + 1 + 2 + NETBIOS_NAME_LEN + NETBIOS_NAME_LEN;

	if (opcode == IMSLOT_SEND && tvb_offset_exists(tvb, offset)) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		dissect_netbios_payload(next_tvb, pinfo, tree);
	}
}

void
proto_register_nmpi(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "nmpi.abbreviation", TYPE, VALS_POINTER }},
        };*/
	static gint *ett[] = {
		&ett_nmpi,
		&ett_nmpi_name_type_flags,
	};

        proto_nmpi = proto_register_protocol("Name Management Protocol over IPX",
	    "NMPI", "nmpi");
 /*       proto_register_field_array(proto_nmpi, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nmpi(void)
{
	dissector_handle_t nmpi_handle;

	nmpi_handle = create_dissector_handle(dissect_nmpi, proto_nmpi);
	dissector_add_uint("ipx.socket", IPX_SOCKET_NWLINK_SMB_NAMEQUERY,
	    nmpi_handle);
	dissector_add_uint("ipx.socket", IPX_SOCKET_NWLINK_SMB_MAILSLOT,
	    nmpi_handle);
}
