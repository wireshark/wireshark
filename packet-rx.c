/* packet-rx.c
 * Routines for RX packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 * Based on routines from tcpdump patches by
 *   Ken Hornstein <kenh@cmf.nrl.navy.mil>
 *
 * $Id: packet-rx.c,v 1.12 2000/05/31 05:07:38 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-rx.h"
#include "packet-afs.h"
#include "resolv.h"

#define UDP_PORT_RX_LOW		7000
#define UDP_PORT_RX_HIGH	7009
#define UDP_PORT_RX_AFS_BACKUPS	7021

static const value_string rx_types[] = {
	{ RX_PACKET_TYPE_DATA,		"data" },
	{ RX_PACKET_TYPE_ACK,		"ack" },
	{ RX_PACKET_TYPE_BUSY,		"busy" },
	{ RX_PACKET_TYPE_ABORT,		"abort" },
	{ RX_PACKET_TYPE_ACKALL,	"ackall" },
	{ RX_PACKET_TYPE_CHALLENGE,	"challenge" },
	{ RX_PACKET_TYPE_RESPONSE,	"response" },
	{ RX_PACKET_TYPE_DEBUG,		"debug" },
	{ RX_PACKET_TYPE_PARAMS,	"params" },
	{ RX_PACKET_TYPE_VERSION,	"version" },
	{ 0,				NULL },
};

static const value_string rx_flags[] = {
	{ RX_CLIENT_INITIATED,	"client-init" },
	{ RX_REQUEST_ACK,	"req-ack" },
	{ RX_LAST_PACKET,	"last-pckt" },
	{ RX_MORE_PACKETS,	"more-pckts" },
	{ RX_FREE_PACKET,	"free-pckt" }
};

static int proto_rx = -1;

static int hf_rx_epoch = -1;
static int hf_rx_cid = -1;
static int hf_rx_seq = -1;
static int hf_rx_serial = -1;
static int hf_rx_callnumber = -1;
static int hf_rx_type = -1;
static int hf_rx_flags = -1;
static int hf_rx_flags_clientinit = -1;
static int hf_rx_flags_request_ack = -1;
static int hf_rx_flags_last_packet = -1;
static int hf_rx_flags_more_packets = -1;
static int hf_rx_flags_free_packet = -1;
static int hf_rx_userstatus = -1;
static int hf_rx_securityindex = -1;
static int hf_rx_spare = -1;
static int hf_rx_serviceid = -1;

static gint ett_rx = -1;
static gint ett_rx_flags = -1;

static void
dissect_rx(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree      *rx_tree, *rx_tree_flags, *rx_flags, *ti;
	struct rx_header *rxh;
	int reply;

	rxh = (struct rx_header *) &pd[offset];

	/* get at least a full packet structure */
	if ( !BYTES_ARE_IN_FRAME(offset, sizeof(struct rx_header)) )
		return;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "RX");


	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_rx, NullTVB, offset,
			sizeof(struct rx_header), "RX Protocol (%s)", 
			val_to_str(rxh->type,rx_types,"unknown (%d)"));
		rx_tree = proto_item_add_subtree(ti, ett_rx);

		proto_tree_add_uint(rx_tree, hf_rx_epoch, NullTVB,
			offset, 4, pntohl(&rxh->epoch));
		proto_tree_add_uint(rx_tree, hf_rx_cid, NullTVB,
			offset+4, 4, pntohl(&rxh->cid));
		proto_tree_add_uint(rx_tree, hf_rx_callnumber, NullTVB,
			offset+8, 4, pntohl(&rxh->callNumber));
		proto_tree_add_uint(rx_tree, hf_rx_seq, NullTVB,
			offset+12, 4, pntohl(&rxh->seq));
		proto_tree_add_uint(rx_tree, hf_rx_serial, NullTVB,
			offset+16, 4, pntohl(&rxh->serial));

		proto_tree_add_uint(rx_tree, hf_rx_type, NullTVB,
			offset+20, 1, rxh->type);

		rx_flags = proto_tree_add_uint(rx_tree, hf_rx_flags, NullTVB,
			offset+21, 1, rxh->flags);
		rx_tree_flags = proto_item_add_subtree(rx_flags, ett_rx_flags);
		proto_tree_add_uint(rx_tree_flags, hf_rx_flags_free_packet, NullTVB,
			offset+21, 1, rxh->flags);
		proto_tree_add_uint(rx_tree_flags, hf_rx_flags_more_packets, NullTVB,
			offset+21, 1, rxh->flags);
		proto_tree_add_uint(rx_tree_flags, hf_rx_flags_last_packet, NullTVB,
			offset+21, 1, rxh->flags);
		proto_tree_add_uint(rx_tree_flags, hf_rx_flags_request_ack, NullTVB,
			offset+21, 1, rxh->flags);
		proto_tree_add_uint(rx_tree_flags, hf_rx_flags_clientinit, NullTVB,
			offset+21, 1, rxh->flags);

		proto_tree_add_uint(rx_tree, hf_rx_userstatus, NullTVB,
			offset+22, 1, rxh->userStatus);
		proto_tree_add_uint(rx_tree, hf_rx_securityindex, NullTVB,
			offset+23, 1, rxh->securityIndex);
		proto_tree_add_uint(rx_tree, hf_rx_spare, NullTVB,
			offset+24, 2, pntohs(&rxh->spare));
		proto_tree_add_uint(rx_tree, hf_rx_serviceid, NullTVB,
			offset+26, 2, pntohs(&rxh->serviceId));
	}

	if (check_col(fd, COL_INFO))
		col_add_fstr(fd, COL_INFO,
			"Type: %s  "
			"Seq: %lu  "
			"Call: %lu  "
			"Source Port: %s  "
			"Destination Port: %s  ",
			val_to_str(rxh->type, rx_types, "%d"),
			(unsigned long)pntohl(&rxh->seq),
			(unsigned long)pntohl(&rxh->callNumber),
			get_udp_port(pi.srcport),
			get_udp_port(pi.destport)
		);

	reply = (rxh->flags & RX_CLIENT_INITIATED) == 0;
	if ( (rxh->type == RX_PACKET_TYPE_ABORT && reply) ||
		rxh->type == RX_PACKET_TYPE_DATA )
	{
		dissect_afs(pd,offset,fd,tree);
	}
}

void
proto_register_rx(void)
{
	static hf_register_info hf[] = {
		{ &hf_rx_epoch, {
			"Epoch", "rx.epoch", FT_UINT32, BASE_DEC,
			NULL, 0, "Epoch" }},
		{ &hf_rx_cid, {
			"CID", "rx.cid", FT_UINT32, BASE_DEC,
			NULL, 0, "CID" }},
		{ &hf_rx_callnumber, {
			"Call Number", "rx.callnumber", FT_UINT32, BASE_DEC,
			NULL, 0, "Call Number" }},
		{ &hf_rx_seq, {
			"Sequence Number", "rx.seq", FT_UINT32, BASE_DEC,
			NULL, 0, "Sequence Number" }},
		{ &hf_rx_serial, {
			"Serial", "rx.serial", FT_UINT32, BASE_DEC,
			NULL, 0, "Serial" }},
		{ &hf_rx_type, {
			"Type", "rx.type", FT_UINT8, BASE_DEC,
			VALS(rx_types), 0, "Type" }},
		{ &hf_rx_flags, {
			"Flags", "rx.flags", FT_UINT8, BASE_HEX,
			NULL, 0, "Flags" }},
		{ &hf_rx_flags_clientinit, {
			"Client Initiated", "rx.flags.client_init", FT_UINT8, BASE_BIN,
			NULL, RX_CLIENT_INITIATED, "Client Initiated" }},
		{ &hf_rx_flags_request_ack, {
			"Request Ack", "rx.flags.request_ack", FT_UINT8, BASE_BIN,
			NULL, RX_REQUEST_ACK, "Request Ack" }},
		{ &hf_rx_flags_last_packet, {
			"Last Packet", "rx.flags.last_packet", FT_UINT8, BASE_BIN,
			NULL, RX_LAST_PACKET, "Last Packet" }},
		{ &hf_rx_flags_more_packets, {
			"More Packets", "rx.flags.more_packets", FT_UINT8, BASE_BIN,
			NULL, RX_MORE_PACKETS, "More Packets" }},
		{ &hf_rx_flags_free_packet, {
			"Free Packet", "rx.flags.free_packet", FT_UINT8, BASE_BIN,
			NULL, RX_FREE_PACKET, "Free Packet" }},
		{ &hf_rx_userstatus, {
			"User Status", "rx.userstatus", FT_UINT32, BASE_DEC,
			NULL, 0, "User Status" }},
		{ &hf_rx_securityindex, {
			"Security Index", "rx.securityindex", FT_UINT32, BASE_DEC,
			NULL, 0, "Security Index" }},
		{ &hf_rx_spare, {
			"Spare/Checksum", "rx.spare", FT_UINT16, BASE_DEC,
			NULL, 0, "Spare/Checksum" }},
		{ &hf_rx_serviceid, {
			"Service ID", "rx.serviceid", FT_UINT16, BASE_DEC,
			NULL, 0, "Service ID" }},
	};
	static gint *ett[] = {
		&ett_rx,
		&ett_rx_flags,
	};

	proto_rx = proto_register_protocol("RX Protocol", "rx");
	proto_register_field_array(proto_rx, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rx(void)
{
	int port;

	/* Ports in the range UDP_PORT_RX_LOW to UDP_PORT_RX_HIGH
	   are all used for various AFS services. */
	for (port = UDP_PORT_RX_LOW; port <= UDP_PORT_RX_HIGH; port++)
		dissector_add("udp.port", port, dissect_rx);
	dissector_add("udp.port", UDP_PORT_RX_AFS_BACKUPS, dissect_rx);
}
