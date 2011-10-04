/* packet-rx.c
 * Routines for RX packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 * Based on routines from tcpdump patches by
 *   Ken Hornstein <kenh@cmf.nrl.navy.mil>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#include <glib.h>
#include <epan/packet.h>
#include "packet-rx.h"
#include <epan/addr_resolv.h>

/*
 * See
 *
 *	http://web.mit.edu/kolya/afs/rx/rx-spec
 *
 * XXX - is the "Epoch" really a UN*X time?  The high-order bit, according
 * to that spec, is a flag bit.
 */

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

static const value_string rx_reason[] = {
	{ RX_ACK_REQUESTED,		"Ack Requested"		},
	{ RX_ACK_DUPLICATE,		"Duplicate Packet"	},
	{ RX_ACK_OUT_OF_SEQUENCE,	"Out Of Sequence"	},
	{ RX_ACK_EXEEDS_WINDOW,		"Exceeds Window" 	},
	{ RX_ACK_NOSPACE,		"No Space"		},
	{ RX_ACK_PING,			"Ping"			},
	{ RX_ACK_PING_RESPONSE,		"Ping Response"		},
	{ RX_ACK_DELAY,			"Delay"			},
	{ RX_ACK_IDLE,			"Idle"			},
	{ 0,				NULL			}
};

static const value_string rx_ack_type[] = {
	{ RX_ACK_TYPE_NACK,	"NACK"	},
	{ RX_ACK_TYPE_ACK,	"ACK"	},
	{ 0,			NULL	}
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
static int hf_rx_bufferspace = -1;
static int hf_rx_maxskew = -1;
static int hf_rx_first_packet = -1;
static int hf_rx_prev_packet = -1;
static int hf_rx_reason = -1;
static int hf_rx_numacks = -1;
static int hf_rx_ack_type = -1;
static int hf_rx_ack = -1;
static int hf_rx_challenge = -1;
static int hf_rx_version = -1;
static int hf_rx_nonce = -1;
static int hf_rx_inc_nonce = -1;
static int hf_rx_min_level = -1;
static int hf_rx_level = -1;
static int hf_rx_response = -1;
static int hf_rx_encrypted = -1;
static int hf_rx_kvno = -1;
static int hf_rx_ticket_len = -1;
static int hf_rx_ticket = -1;
static int hf_rx_ifmtu = -1;
static int hf_rx_maxmtu = -1;
static int hf_rx_rwind = -1;
static int hf_rx_maxpackets = -1;
static int hf_rx_abort = -1;
static int hf_rx_abortcode = -1;

static gint ett_rx = -1;
static gint ett_rx_flags = -1;
static gint ett_rx_ack = -1;
static gint ett_rx_challenge = -1;
static gint ett_rx_response = -1;
static gint ett_rx_encrypted = -1;
static gint ett_rx_abort = -1;

static dissector_handle_t afs_handle;

static int
dissect_rx_response_encrypted(tvbuff_t *tvb, proto_tree *parent_tree, int offset)
{
	proto_tree *tree;
	proto_item *item;
	int old_offset=offset;
	int i;
	guint32 callnumber;

	item = proto_tree_add_item(parent_tree, hf_rx_encrypted, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rx_encrypted);

	/* epoch : 4 bytes */
	{
		nstime_t ts;
		ts.secs = tvb_get_ntohl(tvb, offset);
		ts.nsecs = 0;

		proto_tree_add_time(tree, hf_rx_epoch, tvb,
			offset, 4, &ts);
		offset += 4;
	}

	/* cid : 4 bytes */
	proto_tree_add_item(tree, hf_rx_cid, tvb, offset, 4, FALSE);
	offset += 4;

	/*FIXME dont know how to handle this checksum, skipping it */
	offset += 4;

	/* sequrityindex : 1 byte */
	proto_tree_add_item(tree, hf_rx_securityindex, tvb, offset, 1, FALSE);
	offset += 4;

	for (i=0; i<RX_MAXCALLS; i++) {
		/* callnumber : 4 bytes */
		callnumber = tvb_get_ntohl(tvb, offset);
		proto_tree_add_uint(tree, hf_rx_callnumber, tvb,
			offset, 4, callnumber);
		offset += 4;
	}

	/* inc nonce : 4 bytes */
	proto_tree_add_item(tree, hf_rx_inc_nonce, tvb, offset, 4, FALSE);
	offset += 4;

	/* level : 4 bytes */
	proto_tree_add_item(tree, hf_rx_level, tvb, offset, 4, FALSE);
	offset += 4;

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
dissect_rx_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, guint32 seq, guint32 callnumber)
{
	proto_tree *tree;
	proto_item *item;
	guint32 version, tl;
	int old_offset=offset;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO,
			"RESPONSE  "
			"Seq: %lu  "
			"Call: %lu  "
			"Source Port: %s  "
			"Destination Port: %s  ",
			(unsigned long)seq,
			(unsigned long)callnumber,
			get_udp_port(pinfo->srcport),
			get_udp_port(pinfo->destport)
		);
	}

	item = proto_tree_add_item(parent_tree, hf_rx_response, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rx_response);

	version = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_rx_version, tvb,
		offset, 4, version);
	offset += 4;

	if (version==2) {
		/* skip unused */
		offset += 4;

		/* encrypted : struct */
		offset = dissect_rx_response_encrypted(tvb, tree, offset);

		/* kvno */
		proto_tree_add_item(tree, hf_rx_kvno, tvb, offset, 4, FALSE);
		offset += 4;

		/* ticket_len */
		tl = tvb_get_ntohl(tvb, offset);
		proto_tree_add_uint(tree, hf_rx_ticket_len, tvb,
			offset, 4, tl);
		offset += 4;

		tvb_ensure_bytes_exist(tvb, offset, tl);
		proto_tree_add_item(tree, hf_rx_ticket, tvb, offset, tl, ENC_NA);
		offset += tl;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
dissect_rx_abort(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, guint32 seq, guint32 callnumber)
{
	proto_tree *tree;
	proto_item *item;
	int old_offset=offset;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO,
			"ABORT  "
			"Seq: %lu  "
			"Call: %lu  "
			"Source Port: %s  "
			"Destination Port: %s  ",
			(unsigned long)seq,
			(unsigned long)callnumber,
			get_udp_port(pinfo->srcport),
			get_udp_port(pinfo->destport)
		);
	}

	item = proto_tree_add_item(parent_tree, hf_rx_abort, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rx_abort);

	/* kvno */
	proto_tree_add_item(tree, hf_rx_abortcode, tvb, offset, 4, FALSE);
	offset += 4;

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
dissect_rx_challenge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, guint32 seq, guint32 callnumber)
{
	proto_tree *tree;
	proto_item *item;
	guint32 version;
	int old_offset=offset;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO,
			"CHALLENGE  "
			"Seq: %lu  "
			"Call: %lu  "
			"Source Port: %s  "
			"Destination Port: %s  ",
			(unsigned long)seq,
			(unsigned long)callnumber,
			get_udp_port(pinfo->srcport),
			get_udp_port(pinfo->destport)
		);
	}

	item = proto_tree_add_item(parent_tree, hf_rx_challenge, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rx_challenge);

	version = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_rx_version, tvb,
		offset, 4, version);
	offset += 4;

	if (version==2) {
		proto_tree_add_item(tree, hf_rx_nonce, tvb, offset, 4, FALSE);
		offset += 4;

		proto_tree_add_item(tree, hf_rx_min_level, tvb, offset, 4, FALSE);
		offset += 4;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
dissect_rx_acks(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, guint32 seq, guint32 callnumber)
{
	proto_tree *tree;
	proto_item *item;
	guint8 num;
	int old_offset = offset;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO,
			"ACK  "
			"Seq: %lu  "
			"Call: %lu  "
			"Source Port: %s  "
			"Destination Port: %s  ",
			(unsigned long)seq,
			(unsigned long)callnumber,
			get_udp_port(pinfo->srcport),
			get_udp_port(pinfo->destport)
		);
	}

	item = proto_tree_add_item(parent_tree, hf_rx_ack, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rx_ack);


	/* bufferspace: 2 bytes*/
	proto_tree_add_item(tree, hf_rx_bufferspace, tvb, offset, 2, FALSE);
	offset += 2;

	/* maxskew: 2 bytes*/
	proto_tree_add_item(tree, hf_rx_maxskew, tvb, offset, 2, FALSE);
	offset += 2;

	/* first packet: 4 bytes*/
	proto_tree_add_item(tree, hf_rx_first_packet, tvb, offset, 4, FALSE);
	offset += 4;

	/* prev packet: 4 bytes*/
	proto_tree_add_item(tree, hf_rx_prev_packet, tvb, offset, 4, FALSE);
	offset += 4;

	/* serial : 4 bytes */
	proto_tree_add_item(tree, hf_rx_serial, tvb, offset, 4, FALSE);
	offset += 4;

	/* reason : 1 byte */
	proto_tree_add_item(tree, hf_rx_reason, tvb, offset, 1, FALSE);
	offset += 1;

	/* nACKs */
	num = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_rx_numacks, tvb, offset, 1, num);
	offset += 1;

	while(num--){
		proto_tree_add_item(tree, hf_rx_ack_type, tvb, offset, 1,
			FALSE);
		offset += 1;
	}

	/* Some implementations adds some extra fields.
	 * As far as I can see, these first add 3 padding bytes and then
         * up to 4 32-bit values. (0,3,4 have been witnessed)
	 *
	 * RX as a protocol seems to be completely nondefined and seems to lack
	 * any sort of documentation other than "read the source of any of the
	 * (compatible?) implementations.
         */
	if (tvb_length_remaining(tvb, offset)>3) {
		offset += 3;	/* guess. some implementations adds 3 bytes */

		if (tvb_reported_length_remaining(tvb, offset) >= 4){
			proto_tree_add_item(tree, hf_rx_ifmtu, tvb, offset, 4,
				FALSE);
			offset += 4;
		}
		if (tvb_reported_length_remaining(tvb, offset) >= 4){
			proto_tree_add_item(tree, hf_rx_maxmtu, tvb, offset, 4,
				FALSE);
			offset += 4;
		}
		if (tvb_reported_length_remaining(tvb, offset) >= 4){
			proto_tree_add_item(tree, hf_rx_rwind, tvb, offset, 4,
				FALSE);
			offset += 4;
		}
		if (tvb_reported_length_remaining(tvb, offset) >= 4){
			proto_tree_add_item(tree, hf_rx_maxpackets, tvb, offset, 4,
				FALSE);
			offset += 4;
		}
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
dissect_rx_flags(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *parent_tree, int offset)
{
	proto_tree *tree;
	proto_item *item;
	guint8 flags;

	flags = tvb_get_guint8(tvb, offset);
	rxinfo->flags = flags;

	item = proto_tree_add_uint(parent_tree, hf_rx_flags, tvb,
		offset, 1, flags);
	tree = proto_item_add_subtree(item, ett_rx_flags);

	proto_tree_add_boolean(tree, hf_rx_flags_free_packet, tvb,
		offset, 1, flags);
	proto_tree_add_boolean(tree, hf_rx_flags_more_packets, tvb,
		offset, 1, flags);
	proto_tree_add_boolean(tree, hf_rx_flags_last_packet, tvb,
		offset, 1, flags);
	proto_tree_add_boolean(tree, hf_rx_flags_request_ack, tvb,
		offset, 1, flags);
	proto_tree_add_boolean(tree, hf_rx_flags_clientinit, tvb,
		offset, 1, flags);

	offset += 1;
	return offset;
}

static int
dissect_rx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_tree *tree;
	proto_item *item;
	int offset = 0;
	struct rxinfo rxinfo;
	guint8 type;
	nstime_t ts;
	guint32 seq, callnumber;
	guint16 serviceid;

	/* Ensure we have enough data */
	if (tvb_length(tvb) < 28)
		return 0;

	/* Make sure it's a known type */
	type = tvb_get_guint8(tvb, 20);
	if (type == 0 || type == 10 || type == 11 || type == 12 || type > 13)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RX");
	col_clear(pinfo->cinfo, COL_INFO);

	item = proto_tree_add_protocol_format(parent_tree, proto_rx, tvb,
		offset,	28, "RX Protocol");
	tree = proto_item_add_subtree(item, ett_rx);

	/* epoch : 4 bytes */
	rxinfo.epoch = tvb_get_ntohl(tvb, offset);
	ts.secs = rxinfo.epoch;
	ts.nsecs = 0;
	proto_tree_add_time(tree, hf_rx_epoch, tvb, offset, 4, &ts);
	offset += 4;

	/* cid : 4 bytes */
	rxinfo.cid = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_rx_cid, tvb, offset, 4, FALSE);
	offset += 4;

	/* callnumber : 4 bytes */
	callnumber = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_rx_callnumber, tvb,
		offset, 4, callnumber);
	offset += 4;
	rxinfo.callnumber = callnumber;

	/* seq : 4 bytes */
	seq = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_rx_seq, tvb,
		offset, 4, seq);
	offset += 4;
	rxinfo.seq = seq;

	/* serial : 4 bytes */
	proto_tree_add_item(tree, hf_rx_serial, tvb, offset, 4, FALSE);
	offset += 4;

	/* type : 1 byte */
	type = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_rx_type, tvb,
		offset, 1, type);
	offset += 1;
	rxinfo.type = type;

	/* flags : 1 byte */
	offset = dissect_rx_flags(tvb, &rxinfo, tree, offset);

	/* userstatus : 1 byte */
	proto_tree_add_item(tree, hf_rx_userstatus, tvb, offset, 1, FALSE);
	offset += 1;

	/* sequrityindex : 1 byte */
	proto_tree_add_item(tree, hf_rx_securityindex, tvb, offset, 1, FALSE);
	offset += 1;

	/*
	 * How clever: even though the AFS header files indicate that the
	 * serviceId is first, it's really encoded _after_ the spare field.
	 * I wasted a day figuring that out!
	 */

	/* spare */
	proto_tree_add_item(tree, hf_rx_spare, tvb, offset, 2, FALSE);
	offset += 2;

	/* service id : 2 bytes */
	serviceid = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(tree, hf_rx_serviceid, tvb,
		offset, 2, serviceid);
	offset += 2;
	rxinfo.serviceid = serviceid;

	switch (type) {
	case RX_PACKET_TYPE_ACK:
		/*dissect_rx_acks(tvb, pinfo, parent_tree, offset,
			cant create it in a parallell tree, then ett seasrch
			wont work */
		dissect_rx_acks(tvb, pinfo, tree, offset,
			seq, callnumber);
		break;
	case RX_PACKET_TYPE_ACKALL:
		/* does not contain any payload */
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
				"ACKALL  "
				"Seq: %lu  "
				"Call: %lu  "
				"Source Port: %s  "
				"Destination Port: %s  ",
				(unsigned long)seq,
				(unsigned long)callnumber,
				get_udp_port(pinfo->srcport),
				get_udp_port(pinfo->destport)
			);
		}
		break;
	case RX_PACKET_TYPE_CHALLENGE:
		dissect_rx_challenge(tvb, pinfo, tree, offset, seq, callnumber);
		break;
	case RX_PACKET_TYPE_RESPONSE:
		dissect_rx_response(tvb, pinfo, tree, offset, seq, callnumber);
		break;
	case RX_PACKET_TYPE_DATA: {
		tvbuff_t *next_tvb;
		void* pd_save;
		pd_save = pinfo->private_data;
		pinfo->private_data = &rxinfo;
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		call_dissector(afs_handle, next_tvb, pinfo, parent_tree);
		pinfo->private_data = pd_save;
		};
		break;
	case RX_PACKET_TYPE_ABORT:
		dissect_rx_abort(tvb, pinfo, tree, offset, seq, callnumber);
		break;
	}

	return(tvb_length(tvb));
}

void
proto_register_rx(void)
{
	static hf_register_info hf[] = {
		{ &hf_rx_epoch, {
			"Epoch", "rx.epoch", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_cid, {
			"CID", "rx.cid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_callnumber, {
			"Call Number", "rx.callnumber", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_seq, {
			"Sequence Number", "rx.seq", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_serial, {
			"Serial", "rx.serial", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_type, {
			"Type", "rx.type", FT_UINT8, BASE_DEC,
			VALS(rx_types), 0, NULL, HFILL }},

		{ &hf_rx_flags, {
			"Flags", "rx.flags", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_flags_clientinit, {
			"Client Initiated", "rx.flags.client_init", FT_BOOLEAN, 8,
			NULL, RX_CLIENT_INITIATED, NULL, HFILL }},

		{ &hf_rx_flags_request_ack, {
			"Request Ack", "rx.flags.request_ack", FT_BOOLEAN, 8,
			NULL, RX_REQUEST_ACK, NULL, HFILL }},

		{ &hf_rx_flags_last_packet, {
			"Last Packet", "rx.flags.last_packet", FT_BOOLEAN, 8,
			NULL, RX_LAST_PACKET, NULL, HFILL }},

		{ &hf_rx_flags_more_packets, {
			"More Packets", "rx.flags.more_packets", FT_BOOLEAN, 8,
			NULL, RX_MORE_PACKETS, NULL, HFILL }},

		{ &hf_rx_flags_free_packet, {
			"Free Packet", "rx.flags.free_packet", FT_BOOLEAN, 8,
			NULL, RX_FREE_PACKET, NULL, HFILL }},

		/* XXX - what about RX_SLOW_START_OR_JUMBO? */

		{ &hf_rx_userstatus, {
			"User Status", "rx.userstatus", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_securityindex, {
			"Security Index", "rx.securityindex", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_spare, {
			"Spare/Checksum", "rx.spare", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_serviceid, {
			"Service ID", "rx.serviceid", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_bufferspace, {
			"Bufferspace", "rx.bufferspace", FT_UINT16, BASE_DEC,
			NULL, 0, "Number Of Packets Available", HFILL }},

		{ &hf_rx_maxskew, {
			"Max Skew", "rx.maxskew", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_first_packet, {
			"First Packet", "rx.first", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_prev_packet, {
			"Prev Packet", "rx.prev", FT_UINT32, BASE_DEC,
			NULL, 0, "Previous Packet", HFILL }},

		{ &hf_rx_reason, {
			"Reason", "rx.reason", FT_UINT8, BASE_DEC,
			VALS(rx_reason), 0, "Reason For This ACK", HFILL }},

		{ &hf_rx_numacks, {
			"Num ACKs", "rx.num_acks", FT_UINT8, BASE_DEC,
			NULL, 0, "Number Of ACKs", HFILL }},

		{ &hf_rx_ack_type, {
			"ACK Type", "rx.ack_type", FT_UINT8, BASE_DEC,
			VALS(rx_ack_type), 0, "Type Of ACKs", HFILL }},

		{ &hf_rx_ack, {
			"ACK Packet", "rx.ack", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_challenge, {
			"CHALLENGE Packet", "rx.challenge", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_version, {
			"Version", "rx.version", FT_UINT32, BASE_DEC,
			NULL, 0, "Version Of Challenge/Response", HFILL }},

		{ &hf_rx_nonce, {
			"Nonce", "rx.nonce", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_inc_nonce, {
			"Inc Nonce", "rx.inc_nonce", FT_UINT32, BASE_HEX,
			NULL, 0, "Incremented Nonce", HFILL }},

		{ &hf_rx_min_level, {
			"Min Level", "rx.min_level", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_level, {
			"Level", "rx.level", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_response, {
			"RESPONSE Packet", "rx.response", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_abort, {
			"ABORT Packet", "rx.abort", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_encrypted, {
			"Encrypted", "rx.encrypted", FT_NONE, BASE_NONE,
			NULL, 0, "Encrypted part of response packet", HFILL }},

		{ &hf_rx_kvno, {
			"kvno", "rx.kvno", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_ticket_len, {
			"Ticket len", "rx.ticket_len", FT_UINT32, BASE_DEC,
			NULL, 0, "Ticket Length", HFILL }},

		{ &hf_rx_ticket, {
			"ticket", "rx.ticket", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_ifmtu, {
			"Interface MTU", "rx.if_mtu", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_maxmtu, {
			"Max MTU", "rx.max_mtu", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_rwind, {
			"rwind", "rx.rwind", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_maxpackets, {
			"Max Packets", "rx.max_packets", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rx_abortcode, {
			"Abort Code", "rx.abort_code", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

	};
	static gint *ett[] = {
		&ett_rx,
		&ett_rx_flags,
		&ett_rx_ack,
		&ett_rx_challenge,
		&ett_rx_response,
		&ett_rx_encrypted,
		&ett_rx_abort
	};

	proto_rx = proto_register_protocol("RX Protocol", "RX", "rx");
	proto_register_field_array(proto_rx, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rx(void)
{
	dissector_handle_t rx_handle;

	int port;

	/*
	 * Get handle for the AFS dissector.
	 */
	afs_handle = find_dissector("afs");

	/* Ports in the range UDP_PORT_RX_LOW to UDP_PORT_RX_HIGH
	   are all used for various AFS services. */
	rx_handle = new_create_dissector_handle(dissect_rx, proto_rx);
	for (port = UDP_PORT_RX_LOW; port <= UDP_PORT_RX_HIGH; port++)
		dissector_add_uint("udp.port", port, rx_handle);
	dissector_add_uint("udp.port", UDP_PORT_RX_AFS_BACKUPS, rx_handle);
}
