/* packet-eigrp.c
 * Routines for EIGRP Stub Routing, Authentication and IPv6 TLV dissection
 *
 * Copyright 2009, Jochen Bartl <jochen.bartl@gmail.com>
 *
 * Routines for EIGRP dissection
 * Copyright 2000, Paul Ionescu <paul@acorp.ro>
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
#include <epan/addr_resolv.h>

#include <epan/atalk-utils.h>
#include <epan/addr_and_mask.h>
#include <epan/ipproto.h>
#include "packet-ipx.h"
#include <epan/expert.h>

/*
 * See
 *
 *	http://www.rhyshaden.com/eigrp.htm
 */

#define EIGRP_UPDATE    0x01
#define EIGRP_REQUEST   0x02
#define EIGRP_QUERY     0x03
#define EIGRP_REPLY     0x04
#define EIGRP_HELLO     0x05
#define EIGRP_SAP	0x06
#define EIGRP_SIA_QUERY	0x0a
#define EIGRP_SIA_REPLY 0x0b
#define EIGRP_HI	0x20  /* This value is for my own need to make a difference between Hello and Ack */
#define EIGRP_ACK	0x40  /* This value is for my own need to make a difference between Hello and Ack */

#define TLV_PAR		0x0001
#define TLV_AUTH	0x0002
#define TLV_SEQ		0x0003
#define TLV_SV		0x0004
#define TLV_NMS		0x0005
#define TLV_STUB	0x0006
#define TLV_IP_INT	0x0102
#define TLV_IP_EXT	0x0103
#define TLV_AT_INT	0x0202
#define TLV_AT_EXT	0x0203
#define TLV_AT_CBL	0x0204
#define TLV_IPX_INT	0x0302
#define TLV_IPX_EXT	0x0303
#define TLV_IP6_INT 	0x0402
#define TLV_IP6_EXT 	0x0403

#define EIGRP_FLAGS_INIT 	0x00000001
#define EIGRP_FLAGS_CONDRECV 	0x00000002
#define EIGRP_FLAGS_RESTART	0x00000004
#define EIGRP_FLAGS_ENDOFTABLE	0x00000008

#define EIGRP_STUB_FLAGS_CONNECTED 	0x0001
#define EIGRP_STUB_FLAGS_STATIC 	0x0002
#define EIGRP_STUB_FLAGS_SUMMARY 	0x0004
#define EIGRP_STUB_FLAGS_RECVONLY 	0x0008
#define EIGRP_STUB_FLAGS_REDIST 	0x0010
#define EIGRP_STUB_FLAGS_LEAKMAP 	0x0020

#define EIGRP_IP_EXT_FLAGS_EXT 		0x01
#define EIGRP_IP_EXT_FLAGS_DEFAULT	0x02

#define EIGRP_HEADER_LENGTH 		20

static gint proto_eigrp = -1;

static gint hf_eigrp_version = -1;
static gint hf_eigrp_opcode = -1;
static gint hf_eigrp_checksum = -1;

static gint hf_eigrp_flags = -1; /* Flags Tree */
static gint hf_eigrp_flags_init = -1;
static gint hf_eigrp_flags_condrecv = -1;
static gint hf_eigrp_flags_restart = -1;
static gint hf_eigrp_flags_eot = -1;

static gint hf_eigrp_sequence = -1;
static gint hf_eigrp_acknowledge = -1;
static gint hf_eigrp_as = -1;
static gint hf_eigrp_tlv = -1;
static gint hf_eigrp_tlv_size = -1;

/* EIGRP Parameters TLV */
static gint hf_eigrp_par_k1 = -1;
static gint hf_eigrp_par_k2 = -1;
static gint hf_eigrp_par_k3 = -1;
static gint hf_eigrp_par_k4 = -1;
static gint hf_eigrp_par_k5 = -1;
static gint hf_eigrp_par_reserved = -1;
static gint hf_eigrp_par_holdtime = -1;

/* Authentication TLV */
static gint hf_eigrp_auth_type = -1;
static gint hf_eigrp_auth_keysize = -1;
static gint hf_eigrp_auth_keyid = -1;
static gint hf_eigrp_auth_nullpad = -1;
static gint hf_eigrp_auth_data = -1;

/* Sequence TLV */
static gint hf_eigrp_seq_addrlen = -1;
static gint hf_eigrp_seq_ipaddr = -1;
static gint hf_eigrp_seq_ip6addr = -1;

/* Software Version TLV */
static gint hf_eigrp_sv_ios = -1;
static gint hf_eigrp_sv_eigrp = -1;

/* Next multicast sequence TLV */
static gint hf_eigrp_nms = -1;

/* Stub routing TLV */
static gint hf_eigrp_stub_flags = -1; /* Stub Flags Tree */
static gint hf_eigrp_stub_flags_connected = -1;
static gint hf_eigrp_stub_flags_static = -1;
static gint hf_eigrp_stub_flags_summary = -1;
static gint hf_eigrp_stub_flags_recvonly = -1;
static gint hf_eigrp_stub_flags_redist = -1;
static gint hf_eigrp_stub_flags_leakmap = -1;

/* IP internal route TLV */
static gint hf_eigrp_ip_int_nexthop = -1;
static gint hf_eigrp_ip_int_delay = -1;
static gint hf_eigrp_ip_int_bandwidth = -1;
static gint hf_eigrp_ip_int_mtu = -1;
static gint hf_eigrp_ip_int_hopcount = -1;
static gint hf_eigrp_ip_int_reliability = -1;
static gint hf_eigrp_ip_int_load = -1;
static gint hf_eigrp_ip_int_reserved = -1;
static gint hf_eigrp_ip_int_prefixlen = -1;
static gint hf_eigrp_ip_int_dst = -1;

/* IP external route TLV */
static gint hf_eigrp_ip_ext_nexthop = -1;
static gint hf_eigrp_ip_ext_origrouter = -1;
static gint hf_eigrp_ip_ext_as = -1;
static gint hf_eigrp_ip_ext_tag = -1;
static gint hf_eigrp_ip_ext_metric = -1;
static gint hf_eigrp_ip_ext_reserved = -1;
static gint hf_eigrp_ip_ext_proto = -1;

static gint hf_eigrp_ip_ext_flags = -1; /* IP external route Flags Tree */
static gint hf_eigrp_ip_ext_flags_ext = -1;
static gint hf_eigrp_ip_ext_flags_default = -1;

static gint hf_eigrp_ip_ext_delay = -1;
static gint hf_eigrp_ip_ext_bandwidth = -1;
static gint hf_eigrp_ip_ext_mtu = -1;
static gint hf_eigrp_ip_ext_hopcount = -1;
static gint hf_eigrp_ip_ext_reliability = -1;
static gint hf_eigrp_ip_ext_load = -1;
static gint hf_eigrp_ip_ext_reserved2 = -1;
static gint hf_eigrp_ip_ext_prefixlen = -1;

/* IPX internal route TLV */
static gint hf_eigrp_ipx_int_nexthop_addr = -1;
static gint hf_eigrp_ipx_int_nexthop_id = -1;
static gint hf_eigrp_ipx_int_delay = -1;
static gint hf_eigrp_ipx_int_bandwidth = -1;
static gint hf_eigrp_ipx_int_mtu = -1;
static gint hf_eigrp_ipx_int_hopcount = -1;
static gint hf_eigrp_ipx_int_reliability = -1;
static gint hf_eigrp_ipx_int_load = -1;
static gint hf_eigrp_ipx_int_reserved = -1;
static gint hf_eigrp_ipx_int_dst = -1;

/* IPX external route TLV */
static gint hf_eigrp_ipx_ext_nexthop_addr = -1;
static gint hf_eigrp_ipx_ext_nexthop_id = -1;
static gint hf_eigrp_ipx_ext_origrouter = -1;
static gint hf_eigrp_ipx_ext_as = -1;
static gint hf_eigrp_ipx_ext_tag = -1;
static gint hf_eigrp_ipx_ext_proto = -1;
static gint hf_eigrp_ipx_ext_reserved = -1;
static gint hf_eigrp_ipx_ext_metric = -1;
static gint hf_eigrp_ipx_ext_extdelay = -1;
static gint hf_eigrp_ipx_ext_delay = -1;
static gint hf_eigrp_ipx_ext_bandwidth = -1;
static gint hf_eigrp_ipx_ext_mtu = -1;
static gint hf_eigrp_ipx_ext_hopcount = -1;
static gint hf_eigrp_ipx_ext_reliability = -1;
static gint hf_eigrp_ipx_ext_load = -1;
static gint hf_eigrp_ipx_ext_reserved2 = -1;
static gint hf_eigrp_ipx_ext_dst = -1;

/* AppleTalk cable configuration TLV */
static gint hf_eigrp_at_cbl_routerid = -1;

/* AppleTalk internal route TLV */
static gint hf_eigrp_at_int_delay = -1;
static gint hf_eigrp_at_int_bandwidth = -1;
static gint hf_eigrp_at_int_mtu = -1;
static gint hf_eigrp_at_int_hopcount = -1;
static gint hf_eigrp_at_int_reliability = -1;
static gint hf_eigrp_at_int_load = -1;
static gint hf_eigrp_at_int_reserved = -1;

/* AppleTalk external route TLV */
static gint hf_eigrp_at_ext_origrouter = -1;
static gint hf_eigrp_at_ext_as = -1;
static gint hf_eigrp_at_ext_tag = -1;
static gint hf_eigrp_at_ext_proto = -1;

static gint hf_eigrp_at_ext_flags = -1; /* AppleTalk external route Flags Tree */
static gint hf_eigrp_at_ext_flags_ext = -1;
static gint hf_eigrp_at_ext_flags_default = -1;

static gint hf_eigrp_at_ext_metric = -1;

static gint hf_eigrp_at_ext_delay = -1;
static gint hf_eigrp_at_ext_bandwidth = -1;
static gint hf_eigrp_at_ext_mtu = -1;
static gint hf_eigrp_at_ext_hopcount = -1;
static gint hf_eigrp_at_ext_reliability = -1;
static gint hf_eigrp_at_ext_load = -1;
static gint hf_eigrp_at_ext_reserved = -1;

/* IPv6 internal route TLV */
static gint hf_eigrp_ip6_int_nexthop = -1;
static gint hf_eigrp_ip6_int_delay = -1;
static gint hf_eigrp_ip6_int_bandwidth = -1;
static gint hf_eigrp_ip6_int_mtu = -1;
static gint hf_eigrp_ip6_int_hopcount = -1;
static gint hf_eigrp_ip6_int_reliability = -1;
static gint hf_eigrp_ip6_int_load = -1;
static gint hf_eigrp_ip6_int_reserved = -1;
static gint hf_eigrp_ip6_int_prefixlen = -1;

/* IPv6 external route TLV */
static gint hf_eigrp_ip6_ext_nexthop = -1;
static gint hf_eigrp_ip6_ext_origrouter = -1;
static gint hf_eigrp_ip6_ext_as = -1;
static gint hf_eigrp_ip6_ext_tag = -1;
static gint hf_eigrp_ip6_ext_metric = -1;
static gint hf_eigrp_ip6_ext_reserved = -1;
static gint hf_eigrp_ip6_ext_proto = -1;

static gint hf_eigrp_ip6_ext_flags = -1; /* IPv6 external route Flags Tree */
static gint hf_eigrp_ip6_ext_flags_ext = -1;
static gint hf_eigrp_ip6_ext_flags_default = -1;

static gint hf_eigrp_ip6_ext_delay = -1;
static gint hf_eigrp_ip6_ext_bandwidth = -1;
static gint hf_eigrp_ip6_ext_mtu = -1;
static gint hf_eigrp_ip6_ext_hopcount = -1;
static gint hf_eigrp_ip6_ext_reliability = -1;
static gint hf_eigrp_ip6_ext_load = -1;
static gint hf_eigrp_ip6_ext_reserved2 = -1;
static gint hf_eigrp_ip6_ext_prefixlen = -1;

static gint ett_eigrp = -1;
static gint ett_eigrp_flags = -1;
static gint ett_tlv = -1;
static gint ett_eigrp_stub_flags = -1;
static gint ett_eigrp_ip_ext_flags = -1;
static gint ett_eigrp_ip6_ext_flags = -1;
static gint ett_eigrp_at_ext_flags = -1;

static dissector_handle_t ipxsap_handle;


static const value_string eigrp_opcode_vals[] = {
	{ EIGRP_HELLO,		"Hello/Ack" },
	{ EIGRP_UPDATE,		"Update" },
	{ EIGRP_REPLY, 		"Reply" },
	{ EIGRP_QUERY, 		"Query" },
	{ EIGRP_REQUEST,	"Request" },
	{ EIGRP_SAP,		"IPX/SAP Update" },
	{ EIGRP_SIA_QUERY, 	"SIA-Query" },
	{ EIGRP_SIA_REPLY, 	"SIA-Reply" },
	{ EIGRP_HI,		"Hello" },
	{ EIGRP_ACK,		"Acknowledge" },
	{ 0,				NULL }
};

static const value_string eigrp_tlv_vals[] = {
	{ TLV_PAR,     "EIGRP Parameters"},
	{ TLV_AUTH,    "Authentication data"},
	{ TLV_SEQ ,    "Sequence"},
	{ TLV_SV,      "Software Version"},
	{ TLV_NMS   ,  "Next multicast sequence"},
	{ TLV_STUB  ,  "Stub routing"},
	{ TLV_IP_INT,  "IP internal route"},
	{ TLV_IP_EXT,  "IP external route"},
	{ TLV_AT_INT,  "AppleTalk internal route"},
	{ TLV_AT_EXT,  "AppleTalk external route"},
	{ TLV_AT_CBL,  "AppleTalk cable configuration"},
	{ TLV_IPX_INT, "IPX internal route"},
	{ TLV_IPX_EXT, "IPX external route"},
	{ TLV_IP6_INT,  "IPv6 internal route"},
	{ TLV_IP6_EXT,  "IPv6 external route"},
	{ 0,		NULL}
};

static const value_string eigrp_pid_vals[] = {
	{ 1,	"IGRP"},
	{ 2,	"EIGRP"},
	{ 3,	"Static Route"},
	{ 4,	"RIP"},
	{ 5,	"Hello"},
	{ 6,	"OSPF"},
	{ 7,	"IS-IS"},
	{ 8,	"EGP"},
	{ 9,	"BGP"},
	{ 10,	"IDRP"},
	{ 11,	"Connected link"},
	{ 0,	NULL}
};

static const value_string eigrp_auth_type_vals[] = {
	{ 2,	"MD5"},
	{ 0,	NULL}
};

static void dissect_eigrp_par(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti);
static void dissect_eigrp_auth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_eigrp_seq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_eigrp_sv(tvbuff_t *tvb, proto_tree *tree, proto_item *ti);
static void dissect_eigrp_nms(tvbuff_t *tvb, proto_tree *tree, proto_item *ti);
static void dissect_eigrp_stub(tvbuff_t *tvb, proto_tree *tree);

static void dissect_eigrp_ip_int(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti);
static void dissect_eigrp_ip_ext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti);

static void dissect_eigrp_ipx_int(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti);
static void dissect_eigrp_ipx_ext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti);

static void dissect_eigrp_at_cbl(tvbuff_t *tvb, proto_tree *tree, proto_item *ti);
static void dissect_eigrp_at_int(tvbuff_t *tvb, proto_tree *tree, proto_item *ti);
static void dissect_eigrp_at_ext(tvbuff_t *tvb, proto_tree *tree, proto_item *ti);

static void dissect_eigrp_ip6_int(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti);
static void dissect_eigrp_ip6_ext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti);


static void dissect_eigrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

	proto_tree *eigrp_tree = NULL, *tlv_tree, *eigrp_flags_tree;
	proto_item *ti;

	guint opcode, opcode_tmp;
	guint16 tlv;
	guint32 ack, size, offset = EIGRP_HEADER_LENGTH;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EIGRP");
	col_clear(pinfo->cinfo, COL_INFO);

	opcode_tmp = opcode = tvb_get_guint8(tvb, 1);
	ack = tvb_get_ntohl(tvb, 12);
	if (opcode == EIGRP_HELLO) { if (ack == 0) opcode_tmp = EIGRP_HI; else opcode_tmp = EIGRP_ACK; }

	col_add_str(pinfo->cinfo, COL_INFO,
			val_to_str(opcode_tmp, eigrp_opcode_vals, "Unknown (0x%04x)"));

	if (tree) {

		ti = proto_tree_add_protocol_format(tree, proto_eigrp, tvb, 0, -1, "Cisco EIGRP");

		eigrp_tree = proto_item_add_subtree(ti, ett_eigrp);

		proto_tree_add_item(eigrp_tree, hf_eigrp_version, tvb, 0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(eigrp_tree, hf_eigrp_opcode, tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(eigrp_tree, hf_eigrp_checksum, tvb, 2, 2, ENC_BIG_ENDIAN);
/* Decode the EIGRP Flags Field */

		ti = proto_tree_add_item(eigrp_tree, hf_eigrp_flags, tvb, 4, 4, ENC_BIG_ENDIAN);
		eigrp_flags_tree = proto_item_add_subtree(ti, ett_eigrp_flags);

		proto_tree_add_item(eigrp_flags_tree, hf_eigrp_flags_init, tvb, 4, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(eigrp_flags_tree, hf_eigrp_flags_condrecv, tvb, 4, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(eigrp_flags_tree, hf_eigrp_flags_restart, tvb, 4, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(eigrp_flags_tree, hf_eigrp_flags_eot, tvb, 4, 4, ENC_BIG_ENDIAN);

/* End Decode the EIGRP Flags Field */

		proto_tree_add_item(eigrp_tree, hf_eigrp_sequence, tvb, 8, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(eigrp_tree, hf_eigrp_acknowledge, tvb, 12, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(eigrp_tree, hf_eigrp_as, tvb, 16, 4, ENC_BIG_ENDIAN);
	}

	if (opcode == EIGRP_SAP) {
		call_dissector(ipxsap_handle, tvb_new_subset(tvb, EIGRP_HEADER_LENGTH, -1, -1), pinfo, eigrp_tree);
		return;
	}

	if (tree) {
		while (tvb_reported_length_remaining(tvb, offset) > 0) {

			tlv = tvb_get_ntohs(tvb, offset);
			size =  tvb_get_ntohs(tvb, offset + 2);

			if (size == 0) {
				ti = proto_tree_add_text(eigrp_tree, tvb, offset, -1, "Unknown data (maybe authentication)");
				expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "Unknown data (maybe authentication)");
				return;
			}

			ti = proto_tree_add_text(eigrp_tree, tvb, offset,size,
				"%s", val_to_str(tlv, eigrp_tlv_vals, "Unknown (0x%04x)"));

			tlv_tree = proto_item_add_subtree(ti, ett_tlv);
			proto_tree_add_item(tlv_tree, hf_eigrp_tlv, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_eigrp_tlv_size, tvb, offset + 2, 2, ENC_BIG_ENDIAN);


			switch (tlv) {
				case TLV_PAR:
					dissect_eigrp_par(tvb_new_subset(tvb, offset + 4, size - 4, -1), pinfo, tlv_tree, ti);
					break;
				case TLV_AUTH:
					dissect_eigrp_auth(tvb_new_subset(tvb, offset + 4, size - 4, -1), pinfo, tlv_tree);
					break;
				case TLV_SEQ:
					dissect_eigrp_seq(tvb_new_subset(tvb, offset + 4, size - 4, -1), pinfo, tlv_tree);
					break;
				case TLV_SV:
					dissect_eigrp_sv(tvb_new_subset(tvb, offset + 4, size - 4, -1), tlv_tree, ti);
					break;
				case TLV_NMS:
					dissect_eigrp_nms(tvb_new_subset(tvb, offset + 4, size - 4, -1), tlv_tree, ti);
					break;
				case TLV_STUB:
					dissect_eigrp_stub(tvb_new_subset(tvb, offset + 4, size - 4, -1), tlv_tree);
					break;

				case TLV_IP_INT:
					dissect_eigrp_ip_int(tvb_new_subset(tvb, offset + 4, size - 4, -1), pinfo, tlv_tree, ti);
					break;
				case TLV_IP_EXT:
					dissect_eigrp_ip_ext(tvb_new_subset(tvb, offset + 4, size - 4, -1), pinfo, tlv_tree, ti);
					break;

				case TLV_IPX_INT:
					dissect_eigrp_ipx_int(tvb_new_subset(tvb, offset + 4, size - 4, -1), pinfo, tlv_tree, ti);
					break;
				case TLV_IPX_EXT:
					dissect_eigrp_ipx_ext(tvb_new_subset(tvb, offset + 4, size - 4, -1), pinfo, tlv_tree, ti);
					break;

				case TLV_AT_CBL:
					dissect_eigrp_at_cbl(tvb_new_subset(tvb, offset + 4, size - 4, -1), tlv_tree, ti);
					break;
				case TLV_AT_INT:
					dissect_eigrp_at_int(tvb_new_subset(tvb, offset + 4, size - 4, -1), tlv_tree, ti);
					break;
				case TLV_AT_EXT:
					dissect_eigrp_at_ext(tvb_new_subset(tvb, offset + 4, size - 4, -1), tlv_tree, ti);
					break;

				case TLV_IP6_INT:
					dissect_eigrp_ip6_int(tvb_new_subset(tvb, offset + 4, size - 4, -1), pinfo, tlv_tree, ti);
					break;
				case TLV_IP6_EXT:
					dissect_eigrp_ip6_ext(tvb_new_subset(tvb, offset + 4, size - 4, -1), pinfo, tlv_tree, ti);
					break;
				default:
					expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Unknown TLV (0x%04x)", tlv);
			}

			offset += size;
		}
	}
}



static void dissect_eigrp_par(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti) {

	int offset = 0;
	guint8 k1, k2, k3, k4, k5;

	k1 = tvb_get_guint8(tvb, 1);
	proto_tree_add_item(tree, hf_eigrp_par_k1, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	k2 = tvb_get_guint8(tvb, 1);
	proto_tree_add_item(tree, hf_eigrp_par_k2, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	k3 = tvb_get_guint8(tvb, 1);
	proto_tree_add_item(tree, hf_eigrp_par_k3, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	k4 = tvb_get_guint8(tvb, 1);
	proto_tree_add_item(tree, hf_eigrp_par_k4, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	k5 = tvb_get_guint8(tvb, 1);
	proto_tree_add_item(tree, hf_eigrp_par_k5, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_par_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_par_holdtime, tvb, offset, 2, ENC_BIG_ENDIAN);

	if (k1 == 255 && k2 == 255 && k3 == 255 && k4 == 255 && k5 == 255) {
		proto_item_append_text(ti, ": Goodbye Message");
		expert_add_info_format(pinfo, ti, PI_RESPONSE_CODE, PI_NOTE, "Goodbye Message (Graceful Shutdown)");
	}
}

static void dissect_eigrp_auth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

	proto_item *ti_keysize;
	int offset = 0;
	guint16 keysize;

	keysize = tvb_get_ntohs(tvb, 2);

	proto_tree_add_item(tree, hf_eigrp_auth_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	ti_keysize = proto_tree_add_item(tree, hf_eigrp_auth_keysize, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_eigrp_auth_keyid, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_auth_nullpad, tvb, offset, 12, FALSE);
	offset += 12;

	switch (keysize) {
		/* MD5 */
		case 16:
			proto_tree_add_item(tree, hf_eigrp_auth_data, tvb, offset, keysize, FALSE);
			break;
		default:
			expert_add_info_format(pinfo, ti_keysize, PI_UNDECODED, PI_WARN,
					"Invalid key size %u: Only a value of 16 for MD5 is supported", keysize);
	}
}

static void dissect_eigrp_seq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

	proto_item *ti_addrlen;
	int offset = 0;
	guint8 addr_len;

	addr_len = tvb_get_guint8(tvb, 0);

	ti_addrlen = proto_tree_add_item(tree, hf_eigrp_seq_addrlen, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	switch (addr_len) {
		/* IPv4 */
		case 4:
			proto_tree_add_item(tree, hf_eigrp_seq_ipaddr, tvb, offset, addr_len, ENC_BIG_ENDIAN);
			break;
		/* IPX */
		case 10:
			proto_tree_add_text(tree, tvb, offset, addr_len, "IPX Address = %08x.%04x.%04x.%04x",
					tvb_get_ntohl(tvb, 1), tvb_get_ntohs(tvb, 5),
					tvb_get_ntohs(tvb, 7), tvb_get_ntohs(tvb, 9));
			break;
		/* IPv6 */
		case 16:
			proto_tree_add_item(tree, hf_eigrp_seq_ip6addr, tvb, offset, addr_len, ENC_NA);
			break;
		default:
			expert_add_info_format(pinfo, ti_addrlen, PI_MALFORMED, PI_ERROR, "Invalid address length");
	}
}

static void dissect_eigrp_sv(tvbuff_t *tvb, proto_tree *tree, proto_item *ti) {

	int offset = 0;
	guint8 ios_rel_major, ios_rel_minor;
	guint8 eigrp_rel_major, eigrp_rel_minor;

	ios_rel_major = tvb_get_guint8(tvb, 0);
	ios_rel_minor = tvb_get_guint8(tvb, 1);
	proto_tree_add_text(tree, tvb, offset, 2, "IOS release version: %u.%u",
			    ios_rel_major, ios_rel_minor);
	offset += 2;
	proto_item_append_text(ti, ": IOS=%u.%u", ios_rel_major, ios_rel_minor);

	eigrp_rel_major = tvb_get_guint8(tvb, 2);
	eigrp_rel_minor = tvb_get_guint8(tvb, 3);
	proto_tree_add_text(tree,tvb,offset, 2, "EIGRP release version: %u.%u",
			    eigrp_rel_major, eigrp_rel_minor);
	proto_item_append_text(ti, ", EIGRP=%u.%u",
			       eigrp_rel_major, eigrp_rel_minor);
}

static void dissect_eigrp_nms(tvbuff_t *tvb, proto_tree *tree, proto_item *ti) {

	proto_tree_add_item(tree, hf_eigrp_nms, tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_item_append_text(ti, ": %u", tvb_get_ntohl(tvb, 0));
}

static void dissect_eigrp_stub(tvbuff_t *tvb, proto_tree *tree) {

	proto_tree *eigrp_stub_flags_tree;
	proto_item *ti;

	ti = proto_tree_add_item(tree, hf_eigrp_stub_flags, tvb, 0, 2, ENC_BIG_ENDIAN);
	eigrp_stub_flags_tree = proto_item_add_subtree(ti, ett_eigrp_stub_flags);

	proto_tree_add_item(eigrp_stub_flags_tree, hf_eigrp_stub_flags_connected, tvb, 0, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(eigrp_stub_flags_tree, hf_eigrp_stub_flags_static, tvb, 0, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(eigrp_stub_flags_tree, hf_eigrp_stub_flags_summary, tvb, 0, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(eigrp_stub_flags_tree, hf_eigrp_stub_flags_recvonly, tvb, 0, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(eigrp_stub_flags_tree, hf_eigrp_stub_flags_redist, tvb, 0, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(eigrp_stub_flags_tree, hf_eigrp_stub_flags_leakmap, tvb, 0, 2, ENC_BIG_ENDIAN);
}

static void dissect_eigrp_ip_int(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti) {

	guint8 ip_addr[4], length;
	int addr_len, offset = 0;
	proto_item *ti_prefixlen, *ti_dst;

	tvb_memcpy(tvb, ip_addr, 0, 4);

	proto_tree_add_item(tree, hf_eigrp_ip_int_nexthop, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip_int_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip_int_bandwidth, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip_int_mtu, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(tree, hf_eigrp_ip_int_hopcount, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ip_int_reliability, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ip_int_load, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ip_int_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	for (offset = 20; tvb_length_remaining(tvb, offset) > 0; offset += (1 + addr_len)) {
		length = tvb_get_guint8(tvb, offset);
		addr_len = ipv4_addr_and_mask(tvb, offset + 1, ip_addr, length);

		if (addr_len < 0) {
			ti_prefixlen = proto_tree_add_item(tree, hf_eigrp_ip_int_prefixlen, tvb, offset, 1, ENC_BIG_ENDIAN);
			expert_add_info_format(pinfo, ti_prefixlen, PI_UNDECODED, PI_WARN,
					"Invalid prefix length %u, must be <= 32", length);
			addr_len = 4; /* assure we can exit the loop */
		} else {
			proto_tree_add_item(tree, hf_eigrp_ip_int_prefixlen, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			ti_dst = proto_tree_add_text(tree, tvb, offset, addr_len, "Destination: %s", ip_to_str(ip_addr));
			proto_item_append_text (ti,"  %c   %s/%u%s", offset == 21 ? '=':',',
				ip_to_str(ip_addr), length, ((tvb_get_ntohl(tvb, 4 )== 0xffffffff) ? " - Destination unreachable":""));
			if (tvb_get_ntohl(tvb, 4) == 0xffffffff) {
				expert_add_info_format(pinfo, ti_dst, PI_RESPONSE_CODE, PI_NOTE, "Destination unreachable");
			}
		}
	}
}

static void dissect_eigrp_ip_ext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti) {

	guint8 ip_addr[4], length;
	int addr_len, offset = 0;
	proto_tree *eigrp_ip_ext_flags_tree;
	proto_item *eigrp_ip_ext_ti, *ti_prefixlen, *ti_dst;

	eigrp_ip_ext_ti = ti;

	tvb_memcpy(tvb, ip_addr, 0, 4);
	proto_tree_add_item(tree, hf_eigrp_ip_ext_nexthop, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	tvb_memcpy(tvb,ip_addr, 4, 4);
	proto_tree_add_item(tree, hf_eigrp_ip_ext_origrouter, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip_ext_as, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip_ext_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip_ext_metric, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip_ext_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_eigrp_ip_ext_proto, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

/* Decode the IP external route Flags Field */
	ti = proto_tree_add_item(tree, hf_eigrp_ip_ext_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	eigrp_ip_ext_flags_tree = proto_item_add_subtree(ti, ett_eigrp_ip_ext_flags);

	proto_tree_add_item(eigrp_ip_ext_flags_tree, hf_eigrp_ip_ext_flags_ext, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(eigrp_ip_ext_flags_tree, hf_eigrp_ip_ext_flags_default, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
/* End Decode the IP external route Flags Field */

	proto_tree_add_item(tree, hf_eigrp_ip_ext_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip_ext_bandwidth, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip_ext_mtu, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(tree, hf_eigrp_ip_ext_hopcount, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ip_ext_reliability, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ip_ext_load, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ip_ext_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	for (offset = 40; tvb_length_remaining(tvb, offset) > 0; offset += (1 + addr_len)) {
		length = tvb_get_guint8(tvb, offset);
		addr_len = ipv4_addr_and_mask(tvb, offset + 1, ip_addr, length);

		if (addr_len < 0) {
			ti_prefixlen = proto_tree_add_item(tree, hf_eigrp_ip_ext_prefixlen, tvb, offset, 1, ENC_BIG_ENDIAN);
			expert_add_info_format(pinfo, ti_prefixlen, PI_UNDECODED, PI_WARN,
					"Invalid prefix length %u, must be <= 32", length);
			addr_len = 4; /* assure we can exit the loop */
		} else {
			proto_tree_add_item(tree, hf_eigrp_ip_ext_prefixlen, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			ti_dst = proto_tree_add_text(tree, tvb, offset, addr_len, "Destination = %s", ip_to_str(ip_addr));
			proto_item_append_text(eigrp_ip_ext_ti, "  %c   %s/%u%s", offset == 41 ? '=':',',
				ip_to_str(ip_addr), length, ((tvb_get_ntohl(tvb, 24) == 0xffffffff) ? " - Destination unreachable":""));
			if (tvb_get_ntohl(tvb, 24) == 0xffffffff) {
				expert_add_info_format(pinfo, ti_dst, PI_RESPONSE_CODE, PI_NOTE, "Destination unreachable");
			}
		}
	}
}



static void dissect_eigrp_ipx_int(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti) {

	int offset = 0;
	proto_item *ti_dst;

	proto_tree_add_item(tree, hf_eigrp_ipx_int_nexthop_addr, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ipx_int_nexthop_id, tvb, offset, 6, FALSE);
	offset += 6;
	proto_tree_add_item(tree, hf_eigrp_ipx_int_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ipx_int_bandwidth, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ipx_int_mtu, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(tree, hf_eigrp_ipx_int_hopcount, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ipx_int_reliability, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ipx_int_load, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ipx_int_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	ti_dst = proto_tree_add_item(tree, hf_eigrp_ipx_int_dst, tvb, offset, 4, ENC_NA);
	proto_item_append_text(ti, "  =   %08x%s", tvb_get_ntohl(tvb, 26), ((tvb_get_ntohl(tvb, 10) == 0xffffffff) ? " - Destination unreachable":""));
	if (tvb_get_ntohl(tvb, 10) == 0xffffffff) {
		expert_add_info_format(pinfo, ti_dst, PI_RESPONSE_CODE, PI_NOTE, "Destination unreachable");
	}
}

static void dissect_eigrp_ipx_ext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti) {

	int offset = 0;
	proto_item *ti_dst;

	proto_tree_add_item(tree, hf_eigrp_ipx_ext_nexthop_addr, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_nexthop_id, tvb, offset, 6, FALSE);
	offset += 6;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_origrouter, tvb, offset, 6, FALSE);
	offset += 6;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_as, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_proto, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_metric, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_extdelay, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_eigrp_ipx_ext_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_bandwidth, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_mtu, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_hopcount, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_reliability, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_load, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ipx_ext_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	ti_dst = proto_tree_add_item(tree, hf_eigrp_ipx_ext_dst, tvb, offset, 4, ENC_NA);
	proto_item_append_text(ti, "  =   %08x%s", tvb_get_ntohl(tvb, 46), ((tvb_get_ntohl(tvb, 30) == 0xffffffff) ? " - Destination unreachable":""));
	if (tvb_get_ntohl(tvb, 30) == 0xffffffff) {
		expert_add_info_format(pinfo, ti_dst, PI_RESPONSE_CODE, PI_NOTE, "Destination unreachable");
	}
}



static void dissect_eigrp_at_cbl(tvbuff_t *tvb, proto_tree *tree, proto_item *ti) {

	proto_tree_add_text(tree, tvb, 0, 4, "AppleTalk Cable Range = %u-%u", tvb_get_ntohs(tvb, 0), tvb_get_ntohs(tvb, 2));
	proto_tree_add_item(tree, hf_eigrp_at_cbl_routerid, tvb, 4, 4, ENC_BIG_ENDIAN);
	proto_item_append_text(ti, ": Cable range= %u-%u, Router ID= %u", tvb_get_ntohs(tvb, 0), tvb_get_ntohs(tvb, 2), tvb_get_ntohl(tvb, 4));

}

static void dissect_eigrp_at_int(tvbuff_t *tvb, proto_tree *tree, proto_item *ti) {

	int offset = 0;

	proto_tree_add_text(tree, tvb, offset, 4, "Next Hop Address = %u.%u", tvb_get_ntohs(tvb, 0), tvb_get_ntohs(tvb, 2));
	offset += 4;

	proto_tree_add_item(tree, hf_eigrp_at_int_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_at_int_bandwidth, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_at_int_mtu, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(tree, hf_eigrp_at_int_hopcount, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_at_int_reliability, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_at_int_load, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_at_int_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_text(tree,tvb,offset,4,"Cable range = %u-%u",tvb_get_ntohs(tvb,20),tvb_get_ntohs(tvb,22));

	proto_item_append_text(ti, ": %u-%u", tvb_get_ntohs(tvb, 20), tvb_get_ntohs(tvb, 22));
}

static void dissect_eigrp_at_ext(tvbuff_t *tvb, proto_tree *tree, proto_item *ti) {

	int offset = 0;
	proto_tree *eigrp_at_ext_flags_tree;

	proto_tree_add_text(tree, tvb, offset, 4, "Next Hop Address = %u.%u", tvb_get_ntohs(tvb, 0), tvb_get_ntohs(tvb, 2));
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_at_ext_origrouter, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_at_ext_as, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_at_ext_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_at_ext_proto, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

/* Decode the AppleTalk external route Flags Field */
	ti = proto_tree_add_item(tree, hf_eigrp_at_ext_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	eigrp_at_ext_flags_tree = proto_item_add_subtree(ti, ett_eigrp_at_ext_flags);

	proto_tree_add_item(eigrp_at_ext_flags_tree, hf_eigrp_at_ext_flags_ext, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(eigrp_at_ext_flags_tree, hf_eigrp_at_ext_flags_default, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
/* End Decode the AppleTalk external route Flags Field */

	proto_tree_add_item(tree, hf_eigrp_at_ext_metric, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_eigrp_at_ext_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_at_ext_bandwidth, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_at_ext_mtu, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(tree, hf_eigrp_at_ext_hopcount, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_at_ext_reliability, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_at_ext_load, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_at_ext_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_text(tree, tvb, offset, 4, "Cable range = %u-%u", tvb_get_ntohs(tvb, 36), tvb_get_ntohs(tvb, 38));

	proto_item_append_text(ti, ": %u-%u", tvb_get_ntohs(tvb, 36), tvb_get_ntohs(tvb, 38));
}

static void dissect_eigrp_ip6_int(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti) {

	guint8 length;
	int addr_len, offset = 0;
	struct e_in6_addr addr;
	proto_item *ti_prefixlen, *ti_dst;

	proto_tree_add_item(tree, hf_eigrp_ip6_int_nexthop, tvb, offset, 16, ENC_NA);
	offset += 16;
	proto_tree_add_item(tree, hf_eigrp_ip6_int_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip6_int_bandwidth, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip6_int_mtu, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(tree, hf_eigrp_ip6_int_hopcount, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ip6_int_reliability, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ip6_int_load, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ip6_int_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	for (offset = 32; tvb_length_remaining(tvb, offset) > 0; offset += (1 + addr_len)) {
		length = tvb_get_guint8(tvb, offset);
		addr_len = ipv6_addr_and_mask(tvb, offset + 1, &addr, length);

		if (addr_len < 0) {
			ti_prefixlen = proto_tree_add_item(tree, hf_eigrp_ip6_int_prefixlen, tvb, offset, 1, ENC_BIG_ENDIAN);
			expert_add_info_format(pinfo, ti_prefixlen, PI_UNDECODED, PI_WARN,
					"Invalid prefix length %u, must be <= 128", length);
			addr_len = 16; /* assure we can exit the loop */
		} else {
			proto_tree_add_item(tree, hf_eigrp_ip6_int_prefixlen, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			if ((length < 128) && (length % 8 == 0)) {
				addr_len++;
			}

			ti_dst = proto_tree_add_text(tree, tvb, offset, addr_len, "Destination: %s", ip6_to_str(&addr));
			proto_item_append_text(ti, "  %c   %s/%u%s", offset == 33 ? '=':',',
				ip6_to_str(&addr), length, ((tvb_get_ntohl(tvb, 16) == 0xffffffff) ? " - Destination unreachable":""));
			if (tvb_get_ntohl(tvb, 16) == 0xffffffff) {
				expert_add_info_format(pinfo, ti_dst, PI_RESPONSE_CODE, PI_NOTE, "Destination unreachable");
			}
		}
	}
}

static void dissect_eigrp_ip6_ext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti) {

	guint8 length;
	int addr_len, offset = 0;
	struct e_in6_addr addr;
	proto_tree *eigrp_ip6_ext_flags_tree;
	proto_item *eigrp_ip6_ext_ti, *ti_prefixlen, *ti_dst;

	eigrp_ip6_ext_ti = ti;

	proto_tree_add_item(tree, hf_eigrp_ip6_ext_nexthop, tvb, offset, 16, ENC_NA);
	offset += 16;
	proto_tree_add_item(tree, hf_eigrp_ip6_ext_origrouter, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip6_ext_as, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip6_ext_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip6_ext_metric, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip6_ext_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_eigrp_ip6_ext_proto, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

/* Decode the IPv6 external route Flags Field */
	ti = proto_tree_add_item(tree, hf_eigrp_ip6_ext_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	eigrp_ip6_ext_flags_tree = proto_item_add_subtree(ti, ett_eigrp_ip6_ext_flags);

	proto_tree_add_item(eigrp_ip6_ext_flags_tree, hf_eigrp_ip6_ext_flags_ext, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(eigrp_ip6_ext_flags_tree, hf_eigrp_ip6_ext_flags_default, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
/* End Decode the IPv6 external route Flags Field */

	proto_tree_add_item(tree, hf_eigrp_ip6_ext_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip6_ext_bandwidth, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ip6_ext_mtu, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(tree, hf_eigrp_ip6_ext_hopcount, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ip6_ext_reliability, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ip6_ext_load, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_eigrp_ip6_ext_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	for (offset = 52; tvb_length_remaining(tvb, offset) > 0; offset += (1 + addr_len))
	{
		length = tvb_get_guint8(tvb, offset);
		addr_len = ipv6_addr_and_mask(tvb, offset + 1, &addr, length);

		if (addr_len < 0) {
			ti_prefixlen = proto_tree_add_item(tree, hf_eigrp_ip6_ext_prefixlen, tvb, offset, 1, ENC_BIG_ENDIAN);
			expert_add_info_format(pinfo, ti_prefixlen, PI_UNDECODED, PI_WARN,
					"Invalid prefix length %u, must be <= 128", length);
			addr_len = 16; /* assure we can exit the loop */
		} else {
			proto_tree_add_item(tree, hf_eigrp_ip6_ext_prefixlen, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			if ((length < 128) && (length % 8 == 0)) {
				addr_len++;
			}

			ti_dst = proto_tree_add_text(tree, tvb, offset, addr_len, "Destination: %s", ip6_to_str(&addr));
			proto_item_append_text(eigrp_ip6_ext_ti, "  %c   %s/%u%s", offset == 53 ? '=':',',
				ip6_to_str(&addr), length, ((tvb_get_ntohl(tvb, 36) == 0xffffffff) ? " - Destination unreachable":""));
			if (tvb_get_ntohl(tvb, 36) == 0xffffffff) {
				expert_add_info_format(pinfo, ti_dst, PI_RESPONSE_CODE, PI_NOTE, "Destination unreachable");
			}
		}
	}
}


void proto_register_eigrp(void) {

	static hf_register_info hf[] = {
		{ &hf_eigrp_version,
		  { "Version", "eigrp.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_opcode,
		  { "Opcode", "eigrp.opcode",
		    FT_UINT8, BASE_DEC, VALS(eigrp_opcode_vals), 0x0,
		    "Opcode number", HFILL }
		},
		{ &hf_eigrp_checksum,
		  { "Checksum", "eigrp.checksum",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_flags,
		  { "Flags", "eigrp.flags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_flags_init,
		  { "Init", "eigrp.flags.init",
		    FT_BOOLEAN, 32, NULL, EIGRP_FLAGS_INIT,
		    NULL, HFILL }
		},
		{ &hf_eigrp_flags_condrecv,
		  { "Conditional Receive", "eigrp.flags.condrecv",
		    FT_BOOLEAN, 32, NULL, EIGRP_FLAGS_CONDRECV,
		    NULL, HFILL }
		},
		{ &hf_eigrp_flags_restart,
		  { "Restart", "eigrp.flags.restart",
		    FT_BOOLEAN, 32, NULL, EIGRP_FLAGS_RESTART,
		    NULL, HFILL },
		},
		{ &hf_eigrp_flags_eot,
		  { "End Of Table", "eigrp.flags.eot",
		    FT_BOOLEAN, 32, NULL, EIGRP_FLAGS_ENDOFTABLE,
		    NULL, HFILL }
		},
		{ &hf_eigrp_sequence,
		  { "Sequence", "eigrp.seq",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_acknowledge,
		  { "Acknowledge", "eigrp.ack",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_as,
		  { "Autonomous System", "eigrp.as",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Autonomous System number", HFILL }
		},
		{ &hf_eigrp_tlv,
		  { "Type",           "eigrp.tlv",
		    FT_UINT16, BASE_DEC, VALS(eigrp_tlv_vals), 0x0,
		    "Type/Length/Value", HFILL }
		},
		{ &hf_eigrp_tlv_size,
		  { "Size", "eigrp.tlv.size",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "TLV size", HFILL }
		},
/* EIGRP Parameters TLV */
		{ &hf_eigrp_par_k1,
		  { "K1", "eigrp.par.k1",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_par_k2,
		  { "K2", "eigrp.par.k2",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_par_k3,
		  { "K3", "eigrp.par.k3",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_par_k4,
		  { "K4", "eigrp.par.k4",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_par_k5,
		  { "K5", "eigrp.par.k5",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_par_reserved,
		  { "Reserved", "eigrp.par.reserved",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_par_holdtime,
		  { "Hold Time", "eigrp.par.holdtime",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
/* Authentication TLV */
		{ &hf_eigrp_auth_type,
		  { "Authentication Type", "eigrp.auth.type",
		    FT_UINT16, BASE_DEC, VALS(eigrp_auth_type_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_auth_keysize,
		  { "Key size", "eigrp.auth.keysize",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_auth_keyid,
		  { "Key ID", "eigrp.auth.keyid",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_auth_nullpad,
		  { "Nullpad", "eigrp.auth.nullapd",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_auth_data,
		  { "Data", "eigrp.auth.data",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
/* Sequence TLV */
		{ &hf_eigrp_seq_addrlen,
		  { "Address length", "eigrp.seq.addrlen",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_seq_ipaddr,
		  { "IP Address", "eigrp.seq.ipaddr",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_seq_ip6addr,
		  { "IPv6 Address", "eigrp.seq.ip6addr",
		    FT_IPv6, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
/* Software Version TLV */
		{ &hf_eigrp_sv_ios,
		  { "IOS release version", "eigrp.sv.ios",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_sv_eigrp,
		  { "EIGRP release version", "eigrp.sv.eigrp",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
/* Next multicast sequence TLV */
		{ &hf_eigrp_nms,
		  { "Next Multicast Sequence", "eigrp.nms",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
/* Stub routing TLV */
		{ &hf_eigrp_stub_flags,
		  { "Stub Flags", "eigrp.stub_flags",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_stub_flags_connected,
		  { "Connected", "eigrp.stub_flags.connected",
		    FT_BOOLEAN, 16, NULL, EIGRP_STUB_FLAGS_CONNECTED,
		    NULL, HFILL }
		},
		{ &hf_eigrp_stub_flags_static,
		  { "Static", "eigrp.stub_flags.static",
		    FT_BOOLEAN, 16, NULL, EIGRP_STUB_FLAGS_STATIC,
		    NULL, HFILL }
		},
		{ &hf_eigrp_stub_flags_summary,
		  { "Summary", "eigrp.stub_flags.summary",
		    FT_BOOLEAN, 16, NULL, EIGRP_STUB_FLAGS_SUMMARY,
		    NULL, HFILL }
		},
		{ &hf_eigrp_stub_flags_recvonly,
		  { "Receive-Only", "eigrp.stub_flags.recvonly",
		    FT_BOOLEAN, 16, NULL, EIGRP_STUB_FLAGS_RECVONLY,
		    NULL, HFILL }
		},
		{ &hf_eigrp_stub_flags_redist,
		  { "Redistributed", "eigrp.stub_flags.redist",
		    FT_BOOLEAN, 16, NULL, EIGRP_STUB_FLAGS_REDIST,
		    NULL, HFILL }
		},
		{ &hf_eigrp_stub_flags_leakmap,
		  { "Leak-Map", "eigrp.stub_flags.leakmap",
		    FT_BOOLEAN, 16, NULL, EIGRP_STUB_FLAGS_LEAKMAP,
		    NULL, HFILL }
		},
/* IP internal route TLV */
		{ &hf_eigrp_ip_int_nexthop,
		  { "Next Hop", "eigrp.ip_int.nexthop",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_int_delay,
		  { "Delay", "eigrp.ip_int.delay",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_int_bandwidth,
		  { "Bandwidth", "eigrp.ip_int.bandwidth",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_int_mtu,
		  { "MTU", "eigrp.ip_int.mtu",
		    FT_UINT24, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_int_hopcount,
		  { "Hop Count", "eigrp.ip_int.hopcount",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_int_reliability,
		  { "Reliability", "eigrp.ip_int.reliability",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_int_load,
		  { "Load", "eigrp.ip_int.load",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_int_reserved,
		  { "Reserved", "eigrp.ip_int.reserved",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_int_prefixlen,
		  { "Prefix Length", "eigrp.ip_int.prefixlen",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_int_dst,
		  { "Destination", "eigrp.ip_int.dst",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
/* IP external route TLV */
		{ &hf_eigrp_ip_ext_nexthop,
		  { "Next Hop", "eigrp.ip_ext.nexthop",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_origrouter,
		  { "Originating router", "eigrp.ip_ext.origrouter",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_as,
		  { "Originating A.S.", "eigrp.ip_ext.as",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_tag,
		  { "Arbitrary tag", "eigrp.ip_ext.tag",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_metric,
		  { "External protocol metric", "eigrp.ip_ext.metric",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_reserved,
		  { "Reserved", "eigrp.ip_ext.reserved",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_proto,
		  { "External protocol ID", "eigrp.ip_ext.proto",
		    FT_UINT8, BASE_DEC, VALS(eigrp_pid_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_flags,
		  { "Flags", "eigrp.ip_ext.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_flags_ext,
		  { "External Route", "eigrp.ip_ext.flags.ext",
		    FT_BOOLEAN, 8, NULL, EIGRP_IP_EXT_FLAGS_EXT,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_flags_default,
		  { "Candidate Default Route", "eigrp.ip_ext.flags.default",
		    FT_BOOLEAN, 8, NULL, EIGRP_IP_EXT_FLAGS_DEFAULT,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_delay,
		  { "Delay", "eigrp.ip_ext.delay",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_bandwidth,
		  { "Bandwidth", "eigrp.ip_ext.bandwidth",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_mtu,
		  { "MTU", "eigrp.ip_ext.mtu",
		    FT_UINT24, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_hopcount,
		  { "Hop Count", "eigrp.ip_ext.hopcount",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_reliability,
		  { "Reliability", "eigrp.ip_ext.reliability",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_load,
		  { "Load", "eigrp.ip_ext.load",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_reserved2,
		  { "Reserved", "eigrp.ip_ext.reserved2",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip_ext_prefixlen,
		  { "Prefix Length", "eigrp.ip_ext.prefixlen",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
/* IPX internal route TLV */
		{ &hf_eigrp_ipx_int_nexthop_addr,
		  { "Next Hop Address", "eigrp.ipx_int.nexthop_addr",
		    FT_IPXNET, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_int_nexthop_id,
		  { "Next Hop ID", "eigrp.ipx_int.nexthop_id",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_int_delay,
		  { "Delay", "eigrp.ipx_int.delay",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_int_bandwidth,
		  { "Bandwidth", "eigrp.ipx_int.bandwidth",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_int_mtu,
		  { "MTU", "eigrp.ipx_int.mtu",
		    FT_UINT24, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_int_hopcount,
		  { "Hop Count", "eigrp.ipx_int.hopcount",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_int_reliability,
		  { "Reliability", "eigrp.ipx_int.reliability",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_int_load,
		  { "Load", "eigrp.ipx_int.load",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_int_reserved,
		  { "Reserved", "eigrp.ipx_int.reserved",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_int_dst,
		  { "Destination", "eigrp.ipx_int.dst",
		    FT_IPXNET, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
/* IPX external route TLV */
		{ &hf_eigrp_ipx_ext_nexthop_addr,
		  { "Next Hop Address", "eigrp.ipx_ext.nexthop_addr",
		    FT_IPXNET, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_nexthop_id,
		  { "Next Hop ID", "eigrp.ipx_ext.nexthop_id",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_origrouter,
		  { "Originating router", "eigrp.ipx_ext.origrouter",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_as,
		  { "Originating A.S.", "eigrp.ipx_ext.as",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_tag,
		  { "Arbitrary tag", "eigrp.ipx_ext.tag",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_proto,
		  { "External protocol ID", "eigrp.ipx_ext.proto",
		    FT_UINT8, BASE_DEC, VALS(eigrp_pid_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_reserved,
		  { "Reserved", "eigrp.ipx_ext.reserved",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_metric,
		  { "External protocol metric", "eigrp.ipx_ext.metric",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_extdelay,
		  { "External protocol delay", "eigrp.ipx_ext.extdelay",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_delay,
		  { "Delay", "eigrp.ipx_ext.delay",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_bandwidth,
		  { "Bandwidth", "eigrp.ipx_ext.bandwidth",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_mtu,
		  { "MTU", "eigrp.ipx_ext.mtu",
		    FT_UINT24, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_hopcount,
		  { "Hop Count", "eigrp.ipx_ext.hopcount",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_reliability,
		  { "Reliability", "eigrp.ipx_ext.reliability",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_load,
		  { "Load", "eigrp.ipx_ext.load",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_reserved2,
		  { "Reserved", "eigrp.ipx_ext.reserved2",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ipx_ext_dst,
		  { "Destination", "eigrp.ipx_ext.dst",
		    FT_IPXNET, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
/* AppleTalk cable configuration TLV */
		{ &hf_eigrp_at_cbl_routerid,
		  { "AppleTalk Router ID", "eigrp.at_cbl.routerid",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
/* AppleTalk internal route TLV */
		{ &hf_eigrp_at_int_delay,
		  { "Delay", "eigrp.at_int.delay",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_int_bandwidth,
		  { "Bandwidth", "eigrp.at_int.bandwidth",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_int_mtu,
		  { "MTU", "eigrp.at_int.mtu",
		    FT_UINT24, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_int_hopcount,
		  { "Hop Count", "eigrp.at_int.hopcount",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_int_reliability,
		  { "Reliability", "eigrp.at_int.reliability",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_int_load,
		  { "Load", "eigrp.at_int.load",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_int_reserved,
		  { "Reserved", "eigrp.at_int.reserved",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
/* AppleTalk external route TLV */
		{ &hf_eigrp_at_ext_origrouter,
		  { "Originating router", "eigrp.at_ext.origrouter",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_as,
		  { "Originating A.S.", "eigrp.at_ext.as",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_tag,
		  { "Arbitrary tag", "eigrp.at_ext.tag",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_proto,
		  { "External protocol ID", "eigrp.at_ext.proto",
		    FT_UINT8, BASE_DEC, VALS(eigrp_pid_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_flags,
		  { "Flags", "eigrp.at_ext.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_flags_ext,
		  { "External Route", "eigrp.at_ext.flags.ext",
		    FT_BOOLEAN, 8, NULL, EIGRP_IP_EXT_FLAGS_EXT,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_flags_default,
		  { "Candidate Default Route", "eigrp.at_ext.flags.default",
		    FT_BOOLEAN, 8, NULL, EIGRP_IP_EXT_FLAGS_DEFAULT,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_metric,
		  { "External protocol metric", "eigrp.at_ext.metric",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_delay,
		  { "Delay", "eigrp.at_ext.delay",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_bandwidth,
		  { "Bandwidth", "eigrp.at_ext.bandwidth",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_mtu,
		  { "MTU", "eigrp.at_ext.mtu",
		    FT_UINT24, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_hopcount,
		  { "Hop Count", "eigrp.at_ext.hopcount",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_reliability,
		  { "Reliability", "eigrp.at_ext.reliability",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_load,
		  { "Load", "eigrp.at_ext.load",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_at_ext_reserved,
		  { "Reserved", "eigrp.at_ext.reserved",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
/* IPv6 internal route TLV */
		{ &hf_eigrp_ip6_int_nexthop,
		  { "Next Hop", "eigrp.ip6_int.nexthop",
		    FT_IPv6, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_int_delay,
		  { "Delay", "eigrp.ip6_int.delay",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_int_bandwidth,
		  { "Bandwidth", "eigrp.ip6_int.bandwidth",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_int_mtu,
		  { "MTU", "eigrp.ip6_int.mtu",
		    FT_UINT24, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_int_hopcount,
		  { "Hop Count", "eigrp.ip6_int.hopcount",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_int_reliability,
		  { "Reliability", "eigrp.ip6_int.reliability",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_int_load,
		  { "Load", "eigrp.ip6_int.load",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_int_reserved,
		  { "Reserved", "eigrp.ip6_int.reserved",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_int_prefixlen,
		  { "Prefix Length", "eigrp.ip6_int.prefixlen",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
/* IPv6 external route TLV */
		{ &hf_eigrp_ip6_ext_nexthop,
		  { "Next Hop", "eigrp.ip6_ext.nexthop",
		    FT_IPv6, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_origrouter,
		  { "Originating router", "eigrp.ip6_ext.origrouter",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_as,
		  { "Originating A.S.", "eigrp.ip6_ext.as",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_tag,
		  { "Arbitrary tag", "eigrp.ip6_ext.tag",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_metric,
		  { "External protocol metric", "eigrp.ip6_ext.metric",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_reserved,
		  { "Reserved", "eigrp.ip6_ext.reserved",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_proto,
		  { "External protocol ID", "eigrp.ip6_ext.proto",
		    FT_UINT8, BASE_DEC, VALS(eigrp_pid_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_flags,
		  { "Flags", "eigrp.ip6_ext.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_flags_ext,
		  { "External Route", "eigrp.ip6_ext.flags.ext",
		    FT_BOOLEAN, 8, NULL, EIGRP_IP_EXT_FLAGS_EXT,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_flags_default,
		  { "Candidate Default Route", "eigrp.ip6_ext.flags.default",
		    FT_BOOLEAN, 8, NULL, EIGRP_IP_EXT_FLAGS_DEFAULT,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_delay,
		  { "Delay", "eigrp.ip6_ext.delay",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_bandwidth,
		  { "Bandwidth", "eigrp.ip6_ext.bandwidth",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_mtu,
		  { "MTU", "eigrp.ip6_ext.mtu",
		    FT_UINT24, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_hopcount,
		  { "Hop Count", "eigrp.ip6_ext.hopcount",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_reliability,
		  { "Reliability", "eigrp.ip6_ext.reliability",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_load,
		  { "Load", "eigrp.ip6_ext.load",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_reserved2,
		  { "Reserved", "eigrp.ip6_ext.reserved2",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_eigrp_ip6_ext_prefixlen,
		  { "Prefix Length", "eigrp.ip6_ext.prefixlen",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_eigrp,
		&ett_eigrp_flags,
		&ett_tlv,
		&ett_eigrp_stub_flags,
		&ett_eigrp_ip_ext_flags,
		&ett_eigrp_ip6_ext_flags,
		&ett_eigrp_at_ext_flags
	};

	proto_eigrp = proto_register_protocol("Enhanced Interior Gateway Routing Protocol", "EIGRP", "eigrp");
	proto_register_field_array(proto_eigrp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_eigrp(void) {

	dissector_handle_t eigrp_handle;

	ipxsap_handle = find_dissector("ipxsap");
	eigrp_handle = create_dissector_handle(dissect_eigrp, proto_eigrp);
	dissector_add_uint("ip.proto", IP_PROTO_EIGRP, eigrp_handle);
	dissector_add_uint("ddp.type", DDP_EIGRP, eigrp_handle);
	dissector_add_uint("ipx.socket", IPX_SOCKET_EIGRP, eigrp_handle);
}
