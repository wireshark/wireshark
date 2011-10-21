/* packet-batadv.c
 * Routines for B.A.T.M.A.N. Advanced dissection
 * Copyright 2008-2010  Sven Eckelmann <sven@narfation.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/addr_resolv.h>
#include <epan/reassemble.h>

/* Start content from packet-batadv.h */
#define ETH_P_BATMAN  0x4305

#define BATADV_PACKET_V5        0x01
#define BATADV_ICMP_V5          0x02
#define BATADV_UNICAST_V5       0x03
#define BATADV_BCAST_V5         0x04
#define BATADV_VIS_V5           0x05
#define BATADV_UNICAST_FRAG_V12 0x06
#define BATADV_TT_QUERY_V14     0x07
#define BATADV_ROAM_ADV_V14     0x08

#define ECHO_REPLY 0
#define DESTINATION_UNREACHABLE 3
#define ECHO_REQUEST 8
#define TTL_EXCEEDED 11

#define TT_TYPE_MASK    0x3
#define TT_REQUEST      0
#define TT_RESPONSE     1

#define TT_FULL_TABLE   0x04

#define TT_CHANGE_DEL   0x01
#define TT_CLIENT_ROAM  0x02

#define BAT_RR_LEN 16

struct batman_packet_v5 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
	guint8  ttl;
	guint8  gwflags;  /* flags related to gateway functions: gateway class */
	guint8  tq;
	guint16 seqno;
	address orig;
	address prev_sender;
	guint8  num_tt;
	guint8  pad;
};
#define BATMAN_PACKET_V5_SIZE 22

struct batman_packet_v7 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
	guint8  tq;
	guint16 seqno;
	address orig;
	address prev_sender;
	guint8  ttl;
	guint8  num_tt;
};
#define BATMAN_PACKET_V7_SIZE 20

struct batman_packet_v9 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
	guint8  tq;
	guint16 seqno;
	address orig;
	address prev_sender;
	guint8  ttl;
	guint8  num_tt;
	guint8  gwflags;
	guint8  pad;
};
#define BATMAN_PACKET_V9_SIZE 22

struct batman_packet_v10 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
	guint8  tq;
	guint32 seqno;
	address orig;
	address prev_sender;
	guint8  ttl;
	guint8  num_tt;
	guint8  gwflags;
	guint8  pad;
};
#define BATMAN_PACKET_V10_SIZE 24

struct batman_packet_v11 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
	guint8  tq;
	guint32 seqno;
	address orig;
	address prev_sender;
	guint8  ttl;
	guint8  num_tt;
};
#define BATMAN_PACKET_V11_SIZE 22

struct batman_packet_v14 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  ttl;
	guint8  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
	guint32 seqno;
	address orig;
	address prev_sender;
	guint8  gw_flags;  /* flags related to gateway class */
	guint8  tq;
	guint8  tt_num_changes;
	guint8  ttvn; /* translation table version number */
	guint16 tt_crc;
};
#define BATMAN_PACKET_V14_SIZE 26

struct icmp_packet_v6 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  msg_type;   /* 0 = ECHO REPLY, 3 = DESTINATION_UNREACHABLE, 8 = ECHO_REQUEST, 11 = TTL exceeded */
	address dst;
	address orig;
	guint8  ttl;
	guint8  uid;
	guint16 seqno;
};
#define ICMP_PACKET_V6_SIZE 19

struct icmp_packet_v7 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  msg_type;   /* 0 = ECHO REPLY, 3 = DESTINATION_UNREACHABLE, 8 = ECHO_REQUEST, 11 = TTL exceeded */
	guint8  ttl;
	address dst;
	address orig;
	guint16 seqno;
	guint8  uid;
};
#define ICMP_PACKET_V7_SIZE 19

struct icmp_packet_v14 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  ttl;
	guint8  msg_type; /* see ICMP message types above */
	address dst;
	address orig;
	guint16 seqno;
	guint8  uid;
	guint8  reserved;
};
#define ICMP_PACKET_V14_SIZE 20

struct unicast_packet_v6 {
	guint8  packet_type;
	guint8  version;
	address dest;
	guint8  ttl;
};
#define UNICAST_PACKET_V6_SIZE 9

struct unicast_packet_v14 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  ttl;
	guint8  ttvn; /* destination translation table version number */
	address dest;
};
#define UNICAST_PACKET_V14_SIZE 12

struct unicast_frag_packet_v12 {
	guint8   packet_type;
	guint8   version;
	address  dest;
	guint8   ttl;
	guint8   flags;
	address  orig;
	guint16  seqno;
};
#define UNICAST_FRAG_PACKET_V12_SIZE 18

struct unicast_frag_packet_v14 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  ttl;
	guint8  ttvn; /* destination translation table version number */
	address dest;
	guint8  flags;
	guint8  align;
	address orig;
	guint16 seqno;
};
#define UNICAST_FRAG_PACKET_V14_SIZE 20

struct bcast_packet_v6 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	address orig;
	guint16 seqno;
};
#define BCAST_PACKET_V6_SIZE 10

struct bcast_packet_v10 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	address orig;
	guint8  ttl;
	guint32 seqno;
};
#define BCAST_PACKET_V10_SIZE 13

struct bcast_packet_v14 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  ttl;
	guint8  reserved;
	guint32 seqno;
	address orig;
};
#define BCAST_PACKET_V14_SIZE 14

struct vis_packet_v6 {
	guint8  packet_type;
	guint8  version;      /* batman version field */
	guint8  vis_type;     /* which type of vis-participant sent this? */
	guint8  seqno;        /* sequence number */
	guint8  entries;      /* number of entries behind this struct */
	guint8  ttl;          /* TTL */
	address vis_orig;     /* originator that informs about its neighbours */
	address target_orig;  /* who should receive this packet */
	address sender_orig;  /* who sent or rebroadcasted this packet */
};
#define VIS_PACKET_V6_SIZE 24

struct vis_packet_v10 {
	guint8  packet_type;
	guint8  version;      /* batman version field */
	guint8  vis_type;     /* which type of vis-participant sent this? */
	guint8  entries;      /* number of entries behind this struct */
	guint32 seqno;        /* sequence number */
	guint8  ttl;          /* TTL */
	address vis_orig;     /* originator that informs about its neighbours */
	address target_orig;  /* who should receive this packet */
	address sender_orig;  /* who sent or rebroadcasted this packet */
};
#define VIS_PACKET_V10_SIZE 27

struct vis_packet_v14 {
	guint8  packet_type;
	guint8  version;        /* batman version field */
	guint8  ttl;		 /* TTL */
	guint8  vis_type;	 /* which type of vis-participant sent this? */
	guint32 seqno;		 /* sequence number */
	guint8  entries;	 /* number of entries behind this struct */
	guint8  reserved;
	address vis_orig;	 /* originator that announces its neighbors */
	address target_orig; /* who should receive this packet */
	address sender_orig; /* who sent or rebroadcasted this packet */
};
#define VIS_PACKET_V14_SIZE 28

#define VIS_ENTRY_V6_SIZE 7
#define VIS_ENTRY_V8_SIZE 13

#define VIS_TYPE_SERVER_SYNC  0
#define VIS_TYPE_CLIENT_UPDATE  1

struct tt_query_packet_v14 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  ttl;
	guint8  flags;
	address dst;
	address src;
	guint8  ttvn;
	guint16 tt_data;
};
#define TT_QUERY_PACKET_V14_SIZE 19

#define TT_ENTRY_V14_SIZE 7

struct roam_adv_packet_v14 {
	guint8  packet_type;
	guint8  version;
	guint8  ttl;
	guint8  reserved;
	address dst;
	address src;
	address client;
};
#define ROAM_ADV_PACKET_V14_SIZE 22
/* End content from packet-batadv.h */

/* trees */
static gint ett_batadv_batman = -1;
static gint ett_batadv_batman_flags = -1;
static gint ett_batadv_batman_gwflags = -1;
static gint ett_batadv_batman_tt = -1;
static gint ett_batadv_bcast = -1;
static gint ett_batadv_icmp = -1;
static gint ett_batadv_icmp_rr = -1;
static gint ett_batadv_unicast = -1;
static gint ett_batadv_unicast_frag = -1;
static gint ett_batadv_vis = -1;
static gint ett_batadv_vis_entry = -1;
static gint ett_batadv_tt_query = -1;
static gint ett_batadv_tt_query_flags = -1;
static gint ett_batadv_tt_entry = -1;
static gint ett_batadv_tt_entry_flags = -1;
static gint ett_batadv_roam_adv = -1;
static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

/* hfs */
static int hf_batadv_packet_type = -1;

static int hf_batadv_batman_version = -1;
static int hf_batadv_batman_flags = -1;
static int hf_batadv_batman_ttl = -1;
static int hf_batadv_batman_gwflags = -1;
static int hf_batadv_batman_tq = -1;
static int hf_batadv_batman_seqno = -1;
static int hf_batadv_batman_seqno32 = -1;
static int hf_batadv_batman_orig = -1;
static int hf_batadv_batman_prev_sender = -1;
static int hf_batadv_batman_num_tt = -1;
static int hf_batadv_batman_tt_num_changes = -1;
static int hf_batadv_batman_ttvn = -1;
static int hf_batadv_batman_tt_crc = -1;
static int hf_batadv_batman_tt = -1;

static int hf_batadv_bcast_version = -1;
static int hf_batadv_bcast_orig = -1;
static int hf_batadv_bcast_seqno = -1;
static int hf_batadv_bcast_seqno32 = -1;
static int hf_batadv_bcast_ttl = -1;

static int hf_batadv_icmp_version = -1;
static int hf_batadv_icmp_msg_type = -1;
static int hf_batadv_icmp_dst = -1;
static int hf_batadv_icmp_orig = -1;
static int hf_batadv_icmp_ttl = -1;
static int hf_batadv_icmp_uid = -1;
static int hf_batadv_icmp_seqno = -1;

static int hf_batadv_unicast_version = -1;
static int hf_batadv_unicast_dst = -1;
static int hf_batadv_unicast_ttl = -1;
static int hf_batadv_unicast_ttvn = -1;

static int hf_batadv_unicast_frag_version = -1;
static int hf_batadv_unicast_frag_dst = -1;
static int hf_batadv_unicast_frag_ttl = -1;
static int hf_batadv_unicast_frag_ttvn = -1;
static int hf_batadv_unicast_frag_flags = -1;
static int hf_batadv_unicast_frag_orig = -1;
static int hf_batadv_unicast_frag_seqno = -1;

static int hf_batadv_vis_version = -1;
static int hf_batadv_vis_type = -1;
static int hf_batadv_vis_seqno = -1;
static int hf_batadv_vis_seqno32 = -1;
static int hf_batadv_vis_entries = -1;
static int hf_batadv_vis_ttl = -1;
static int hf_batadv_vis_vis_orig = -1;
static int hf_batadv_vis_target_orig = -1;
static int hf_batadv_vis_sender_orig = -1;
static int hf_batadv_vis_entry_src = -1;
static int hf_batadv_vis_entry_dst = -1;
static int hf_batadv_vis_entry_quality = -1;

static int hf_batadv_tt_query_version = -1;
static int hf_batadv_tt_query_ttl = -1;
static int hf_batadv_tt_query_flags = -1;
static int hf_batadv_tt_query_flags_type = -1;
static int hf_batadv_tt_query_flags_full_table = -1;
static int hf_batadv_tt_query_dst = -1;
static int hf_batadv_tt_query_src = -1;
static int hf_batadv_tt_query_ttvn = -1;
static int hf_batadv_tt_query_tt_crc = -1;
static int hf_batadv_tt_query_entries = -1;
static int hf_batadv_tt_entry = -1;
static int hf_batadv_tt_entry_flags = -1;
static int hf_batadv_tt_entry_flags_change_del = -1;
static int hf_batadv_tt_entry_flags_client_roam = -1;

static int hf_batadv_roam_adv_version = -1;
static int hf_batadv_roam_adv_ttl = -1;
static int hf_batadv_roam_adv_dst = -1;
static int hf_batadv_roam_adv_src = -1;
static int hf_batadv_roam_adv_client = -1;

static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;

/* flags */
static int hf_batadv_batman_flags_directlink = -1;
static int hf_batadv_batman_flags_vis_server = -1;
static int hf_batadv_batman_flags_primaries_first_hop = -1;
static int hf_batadv_unicast_frag_flags_head = -1;
static int hf_batadv_unicast_frag_flags_largetail = -1;

static const value_string icmp_packettypenames[] = {
	{ ECHO_REPLY, "ECHO_REPLY" },
	{ DESTINATION_UNREACHABLE, "DESTINATION UNREACHABLE" },
	{ ECHO_REQUEST, "ECHO_REQUEST" },
	{ TTL_EXCEEDED, "TTL exceeded" },
	{ 0, NULL }
};

static const value_string vis_packettypenames[] = {
	{ VIS_TYPE_SERVER_SYNC, "SERVER_SYNC" },
	{ VIS_TYPE_CLIENT_UPDATE, "CLIENT_UPDATE" },
	{ 0, NULL }
};

static const value_string tt_query_type_v14[] = {
	{TT_REQUEST, "Request"},
	{TT_RESPONSE, "Response"},
	{0, NULL}
};

static const fragment_items msg_frag_items = {
	/* Fragment subtrees */
	&ett_msg_fragment,
	&ett_msg_fragments,
	/* Fragment fields */
	&hf_msg_fragments,
	&hf_msg_fragment,
	&hf_msg_fragment_overlap,
	&hf_msg_fragment_overlap_conflicts,
	&hf_msg_fragment_multiple_tails,
	&hf_msg_fragment_too_long_fragment,
	&hf_msg_fragment_error,
	&hf_msg_fragment_count,
	/* Reassembled in field */
	&hf_msg_reassembled_in,
	&hf_msg_reassembled_length,
	/* Tag */
	"Message fragments"
};


/* forward declaration */
void proto_reg_handoff_batadv(void);

static dissector_handle_t batman_handle;

/* supported packet dissectors */
static void dissect_batadv_batman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v7(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v9(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v10(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v11(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v14(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_bcast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_bcast_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_bcast_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_bcast_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_icmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_icmp_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_icmp_v7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_icmp_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_unicast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_unicast_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_unicast_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_unicast_frag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_unicast_frag_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_unicast_frag_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_vis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_vis_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_vis_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_vis_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_tt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_vis_entry_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_vis_entry_v8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_tt_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_tt_query_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_tt_entry_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_roam_adv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_roam_adv_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* other dissectors */
static dissector_handle_t data_handle;
static dissector_handle_t eth_handle;

static int proto_batadv_plugin = -1;

/* tap */
static int batadv_tap = -1;
static int batadv_follow_tap = -1;

/* segmented messages */
static GHashTable *msg_fragment_table = NULL;
static GHashTable *msg_reassembled_table = NULL;

static unsigned int batadv_ethertype = ETH_P_BATMAN;

static void dissect_batman_plugin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 type;

	col_clear(pinfo->cinfo, COL_INFO);

	type = tvb_get_guint8(tvb, 0);

	switch (type) {
	case BATADV_PACKET_V5:
		dissect_batadv_batman(tvb, pinfo, tree);
		break;
	case BATADV_ICMP_V5:
		dissect_batadv_icmp(tvb, pinfo, tree);
		break;
	case BATADV_UNICAST_V5:
		dissect_batadv_unicast(tvb, pinfo, tree);
		break;
	case BATADV_UNICAST_FRAG_V12:
		dissect_batadv_unicast_frag(tvb, pinfo, tree);
		break;
	case BATADV_BCAST_V5:
		dissect_batadv_bcast(tvb, pinfo, tree);
		break;
	case BATADV_VIS_V5:
		dissect_batadv_vis(tvb, pinfo, tree);
		break;
	case BATADV_TT_QUERY_V14:
		dissect_batadv_tt_query(tvb, pinfo, tree);
		break;
	case BATADV_ROAM_ADV_V14:
		dissect_batadv_roam_adv(tvb, pinfo, tree);
		break;
	default:
		/* dunno */
	{
		tvbuff_t *next_tvb;
		guint length_remaining;

		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_???");

		length_remaining = tvb_length_remaining(tvb, 1);
		next_tvb = tvb_new_subset(tvb, 0, length_remaining, -1);
		call_dissector(data_handle, next_tvb, pinfo, tree);
		break;
	}
	}
}

static void dissect_batadv_batman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;
	int offset = 0;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_BATMAN");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 5:
	case 6:
		while (offset != -1 && tvb_length_remaining(tvb, offset) >= BATMAN_PACKET_V5_SIZE) {
			offset = dissect_batadv_batman_v5(tvb, offset, pinfo, tree);
		}
		break;
	case 7:
	case 8:
		while (offset != -1 && tvb_length_remaining(tvb, offset) >= BATMAN_PACKET_V7_SIZE) {
			offset = dissect_batadv_batman_v7(tvb, offset, pinfo, tree);
		}
		break;
	case 9:
		while (offset != -1 && tvb_length_remaining(tvb, offset) >= BATMAN_PACKET_V9_SIZE) {
			offset = dissect_batadv_batman_v9(tvb, offset, pinfo, tree);
		}
		break;
	case 11:
	case 13:
		while (offset != -1 && tvb_length_remaining(tvb, offset) >= BATMAN_PACKET_V11_SIZE) {
			offset = dissect_batadv_batman_v11(tvb, offset, pinfo, tree);
		}
		break;
	case 10:
	case 12:
		while (offset != -1 && tvb_length_remaining(tvb, offset) >= BATMAN_PACKET_V10_SIZE) {
			offset = dissect_batadv_batman_v10(tvb, offset, pinfo, tree);
		}
		break;
	case 14:
		while (offset != -1 && tvb_length_remaining(tvb, offset) >= BATMAN_PACKET_V14_SIZE) {
			offset = dissect_batadv_batman_v14(tvb, offset, pinfo, tree);
		}
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_gwflags(tvbuff_t *tvb, guint8 gwflags, int offset, proto_item *tgw)
{
	proto_tree *gwflags_tree;
	guint8 s = (gwflags & 0x80) >> 7;
	guint8 downbits = (gwflags & 0x78) >> 3;
	guint8 upbits = (gwflags & 0x07);
	guint down, up;

	if (gwflags == 0) {
		down = 0;
		up = 0;
	} else {
		down = 32 * (s + 2) * (1 << downbits);
		up = ((upbits + 1) * down) / 8;
	}

	gwflags_tree =  proto_item_add_subtree(tgw, ett_batadv_batman_gwflags);
	proto_tree_add_text(gwflags_tree, tvb, offset, 1, "Download Speed: %dkbit", down);
	proto_tree_add_text(gwflags_tree, tvb, offset, 1, "Upload Speed: %dkbit", up);

}

static int dissect_batadv_batman_v5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf, *tgw;
	proto_tree *batadv_batman_tree = NULL, *flag_tree;
	guint8 type;
	struct batman_packet_v5 *batman_packeth;
	const guint8  *prev_sender_addr, *orig_addr;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = ep_alloc(sizeof(struct batman_packet_v5));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET_V5) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+3);
	batman_packeth->gwflags = tvb_get_guint8(tvb, offset+4);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+5);
	batman_packeth->seqno = tvb_get_ntohs(tvb, offset+6);
	orig_addr = tvb_get_ptr(tvb, offset+8, 6);
	SET_ADDRESS(&batman_packeth->orig, AT_ETHER, 6, orig_addr);
	prev_sender_addr = tvb_get_ptr(tvb, offset+14, 6);
	SET_ADDRESS(&batman_packeth->prev_sender, AT_ETHER, 6, prev_sender_addr);
	batman_packeth->num_tt = tvb_get_guint8(tvb, offset+20);
	batman_packeth->pad = tvb_get_guint8(tvb, offset+21);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V5_SIZE,
			                                    "B.A.T.M.A.N., Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V5_SIZE, ENC_NA);
		}
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET_V5,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET_V5);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tf = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_directlink, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_vis_server, tvb, offset, 1, batman_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tgw = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_gwflags, tvb, offset, 1, ENC_BIG_ENDIAN);
	dissect_batadv_gwflags(tvb, batman_packeth->gwflags, offset, tgw);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, prev_sender_addr);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_num_tt, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_tt; i++) {
		next_tvb = tvb_new_subset(tvb, offset, 6, 6);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_batadv_tt(next_tvb, pinfo, batadv_batman_tree);
		offset += 6;
	}

	return offset;
}

static int dissect_batadv_batman_v7(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf;
	proto_tree *batadv_batman_tree = NULL, *flag_tree;
	guint8 type;
	struct batman_packet_v7 *batman_packeth;
	const guint8  *prev_sender_addr, *orig_addr;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = ep_alloc(sizeof(struct batman_packet_v7));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET_V5) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohs(tvb, offset+4);
	orig_addr = tvb_get_ptr(tvb, offset+6, 6);
	SET_ADDRESS(&batman_packeth->orig, AT_ETHER, 6, orig_addr);
	prev_sender_addr = tvb_get_ptr(tvb, offset+12, 6);
	SET_ADDRESS(&batman_packeth->prev_sender, AT_ETHER, 6, prev_sender_addr);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+18);
	batman_packeth->num_tt = tvb_get_guint8(tvb, offset+19);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V7_SIZE,
			                                    "B.A.T.M.A.N., Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V7_SIZE, ENC_NA);
		}
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET_V5,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET_V5);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tf = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_directlink, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_vis_server, tvb, offset, 1, batman_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, prev_sender_addr);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_num_tt, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_tt; i++) {
		next_tvb = tvb_new_subset(tvb, offset, 6, 6);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_batadv_tt(next_tvb, pinfo, batadv_batman_tree);
		offset += 6;
	}

	return offset;
}

static int dissect_batadv_batman_v9(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf, *tgw;
	proto_tree *batadv_batman_tree = NULL, *flag_tree;
	guint8 type;
	struct batman_packet_v9 *batman_packeth;
	const guint8  *prev_sender_addr, *orig_addr;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = ep_alloc(sizeof(struct batman_packet_v9));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET_V5) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohs(tvb, offset+4);
	orig_addr = tvb_get_ptr(tvb, offset+6, 6);
	SET_ADDRESS(&batman_packeth->orig, AT_ETHER, 6, orig_addr);
	prev_sender_addr = tvb_get_ptr(tvb, offset+12, 6);
	SET_ADDRESS(&batman_packeth->prev_sender, AT_ETHER, 6, prev_sender_addr);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+18);
	batman_packeth->num_tt = tvb_get_guint8(tvb, offset+19);
	batman_packeth->gwflags = tvb_get_guint8(tvb, offset+20);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V9_SIZE,
			                                    "B.A.T.M.A.N., Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V9_SIZE, ENC_NA);
		}
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET_V5,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET_V5);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tf = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_directlink, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_vis_server, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_primaries_first_hop, tvb, offset, 1, batman_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, prev_sender_addr);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_num_tt, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tgw = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_gwflags, tvb, offset, 1, ENC_BIG_ENDIAN);
	dissect_batadv_gwflags(tvb, batman_packeth->gwflags, offset, tgw);
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_tt; i++) {
		next_tvb = tvb_new_subset(tvb, offset, 6, 6);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_batadv_tt(next_tvb, pinfo, batadv_batman_tree);
		offset += 6;
	}

	return offset;
}

static int dissect_batadv_batman_v10(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf, *tgw;
	proto_tree *batadv_batman_tree = NULL, *flag_tree;
	guint8 type;
	struct batman_packet_v10 *batman_packeth;
	const guint8  *prev_sender_addr, *orig_addr;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = ep_alloc(sizeof(struct batman_packet_v10));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET_V5) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohl(tvb, offset+4);
	orig_addr = tvb_get_ptr(tvb, offset+8, 6);
	SET_ADDRESS(&batman_packeth->orig, AT_ETHER, 6, orig_addr);
	prev_sender_addr = tvb_get_ptr(tvb, offset+14, 6);
	SET_ADDRESS(&batman_packeth->prev_sender, AT_ETHER, 6, prev_sender_addr);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+20);
	batman_packeth->num_tt = tvb_get_guint8(tvb, offset+21);
	batman_packeth->gwflags = tvb_get_guint8(tvb, offset+22);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V10_SIZE,
			                                    "B.A.T.M.A.N., Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V10_SIZE, ENC_NA);
		}
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET_V5,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET_V5);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tf = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_directlink, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_vis_server, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_primaries_first_hop, tvb, offset, 1, batman_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, prev_sender_addr);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_num_tt, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tgw = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_gwflags, tvb, offset, 1, ENC_BIG_ENDIAN);
	dissect_batadv_gwflags(tvb, batman_packeth->gwflags, offset, tgw);
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_tt; i++) {
		next_tvb = tvb_new_subset(tvb, offset, 6, 6);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_batadv_tt(next_tvb, pinfo, batadv_batman_tree);
		offset += 6;
	}

	return offset;
}

static int dissect_batadv_batman_v11(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf;
	proto_tree *batadv_batman_tree = NULL, *flag_tree;
	guint8 type;
	struct batman_packet_v11 *batman_packeth;
	const guint8  *prev_sender_addr, *orig_addr;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = ep_alloc(sizeof(struct batman_packet_v11));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET_V5) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohl(tvb, offset+4);
	orig_addr = tvb_get_ptr(tvb, offset+8, 6);
	SET_ADDRESS(&batman_packeth->orig, AT_ETHER, 6, orig_addr);
	prev_sender_addr = tvb_get_ptr(tvb, offset+14, 6);
	SET_ADDRESS(&batman_packeth->prev_sender, AT_ETHER, 6, prev_sender_addr);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+20);
	batman_packeth->num_tt = tvb_get_guint8(tvb, offset+21);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V11_SIZE,
			                                    "B.A.T.M.A.N., Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V11_SIZE, ENC_NA);
		}
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET_V5,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET_V5);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tf = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_directlink, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_vis_server, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_primaries_first_hop, tvb, offset, 1, batman_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, prev_sender_addr);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_num_tt, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_tt; i++) {
		next_tvb = tvb_new_subset(tvb, offset, 6, 6);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_batadv_tt(next_tvb, pinfo, batadv_batman_tree);
		offset += 6;
	}

	return offset;
}

static int dissect_batadv_batman_v14(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf, *tgw;
	proto_tree *batadv_batman_tree = NULL, *flag_tree;
	guint8 type;
	struct batman_packet_v14 *batman_packeth;
	const guint8  *prev_sender_addr, *orig_addr;
	gint i;

	tvbuff_t *next_tvb;
	guint length_remaining;

	batman_packeth = ep_alloc(sizeof(struct batman_packet_v14));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET_V5) {
		return -1;
	}

	batman_packeth->ttl = tvb_get_guint8(tvb, offset+2);
	batman_packeth->flags = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohl(tvb, offset+4);
	orig_addr = tvb_get_ptr(tvb, offset+8, 6);
	SET_ADDRESS(&batman_packeth->orig, AT_ETHER, 6, orig_addr);
	prev_sender_addr = tvb_get_ptr(tvb, offset+14, 6);
	SET_ADDRESS(&batman_packeth->prev_sender, AT_ETHER, 6, prev_sender_addr);
	batman_packeth->gw_flags = tvb_get_guint8(tvb, offset+20);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+21);
	batman_packeth->tt_num_changes = tvb_get_guint8(tvb, offset+22);
	batman_packeth->ttvn = tvb_get_guint8(tvb, offset+23);
	batman_packeth->tt_crc = tvb_get_ntohs(tvb, offset+24);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V14_SIZE,
			                                    "B.A.T.M.A.N., Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V14_SIZE, ENC_NA);
		}
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET_V5,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET_V5);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tf = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_directlink, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_vis_server, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_batman_flags_primaries_first_hop, tvb, offset, 1, batman_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, prev_sender_addr);
	offset += 6;

	tgw = proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_gwflags, tvb, offset, 1, ENC_BIG_ENDIAN);
	dissect_batadv_gwflags(tvb, batman_packeth->gw_flags, offset, tgw);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tt_num_changes, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttvn, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tt_crc, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->tt_num_changes; i++) {
		next_tvb = tvb_new_subset(tvb, offset, TT_ENTRY_V14_SIZE, TT_ENTRY_V14_SIZE);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_tt_entry_v14(next_tvb, pinfo, batadv_batman_tree);
		offset += TT_ENTRY_V14_SIZE;
	}

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}

	return offset;
}

static void dissect_batadv_tt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	const guint8  *tt;
	proto_tree *batadv_batman_tt_tree = NULL;

	tt = tvb_get_ptr(tvb, 0, 6);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, 6,
			                                    "B.A.T.M.A.N. TT: %s (%s)",
			                                    get_ether_name(tt), ether_to_str(tt));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, 6, ENC_NA);
		}
		batadv_batman_tt_tree = proto_item_add_subtree(ti, ett_batadv_batman_tt);
	}

	proto_tree_add_ether(batadv_batman_tt_tree, hf_batadv_batman_tt, tvb, 0, 6, tt);
}

static void dissect_batadv_bcast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_BCAST");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 6:
	case 7:
	case 8:
	case 9:
		dissect_batadv_bcast_v6(tvb, pinfo, tree);
		break;
	case 10:
	case 11:
	case 12:
	case 13:
		dissect_batadv_bcast_v10(tvb, pinfo, tree);
		break;
	case 14:
		dissect_batadv_bcast_v14(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_bcast_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct bcast_packet_v6 *bcast_packeth;
	const guint8  *orig_addr;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;
	proto_tree *batadv_bcast_tree = NULL;

	bcast_packeth = ep_alloc(sizeof(struct bcast_packet_v6));

	bcast_packeth->version = tvb_get_guint8(tvb, 1);
	orig_addr = tvb_get_ptr(tvb, 2, 6);
	SET_ADDRESS(&bcast_packeth->orig, AT_ETHER, 6, orig_addr);
	bcast_packeth->seqno = tvb_get_ntohs(tvb, 8);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", bcast_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, BCAST_PACKET_V6_SIZE,
			                                    "B.A.T.M.A.N. Bcast, Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, BCAST_PACKET_V6_SIZE, ENC_NA);
		}
		batadv_bcast_tree = proto_item_add_subtree(ti, ett_batadv_bcast);
	}

	/* items */
	proto_tree_add_uint_format(batadv_bcast_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_BCAST_V5,
					"Packet Type: %s (%u)", "BATADV_BCAST", BATADV_BCAST_V5);
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_ether(batadv_bcast_tree, hf_batadv_bcast_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, bcast_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(eth_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_bcast_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct bcast_packet_v10 *bcast_packeth;
	const guint8  *orig_addr;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;
	proto_tree *batadv_bcast_tree = NULL;

	bcast_packeth = ep_alloc(sizeof(struct bcast_packet_v10));

	bcast_packeth->version = tvb_get_guint8(tvb, 1);
	orig_addr = tvb_get_ptr(tvb, 2, 6);
	SET_ADDRESS(&bcast_packeth->orig, AT_ETHER, 6, orig_addr);
	bcast_packeth->ttl = tvb_get_guint8(tvb, 8);
	bcast_packeth->seqno = tvb_get_ntohl(tvb, 9);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", bcast_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, BCAST_PACKET_V10_SIZE,
			                                    "B.A.T.M.A.N. Bcast, Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, BCAST_PACKET_V10_SIZE, ENC_NA);
		}
		batadv_bcast_tree = proto_item_add_subtree(ti, ett_batadv_bcast);
	}

	/* items */
	proto_tree_add_uint_format(batadv_bcast_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_BCAST_V5,
					"Packet Type: %s (%u)", "BATADV_BCAST", BATADV_BCAST_V5);
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_ether(batadv_bcast_tree, hf_batadv_bcast_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_seqno32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, bcast_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(eth_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_bcast_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct bcast_packet_v14 *bcast_packeth;
	const guint8  *orig_addr;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;
	proto_tree *batadv_bcast_tree = NULL;

	bcast_packeth = ep_alloc(sizeof(struct bcast_packet_v14));

	bcast_packeth->version = tvb_get_guint8(tvb, 1);
	bcast_packeth->ttl = tvb_get_guint8(tvb, 2);
	bcast_packeth->reserved = tvb_get_guint8(tvb, 3);
	bcast_packeth->seqno = tvb_get_ntohl(tvb, 4);
	orig_addr = tvb_get_ptr(tvb, 8, 6);
	SET_ADDRESS(&bcast_packeth->orig, AT_ETHER, 6, orig_addr);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", bcast_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, BCAST_PACKET_V14_SIZE,
			                                    "B.A.T.M.A.N. Bcast, Orig: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, BCAST_PACKET_V14_SIZE, ENC_NA);
		}
		batadv_bcast_tree = proto_item_add_subtree(ti, ett_batadv_bcast);
	}

	/* items */
	proto_tree_add_uint_format(batadv_bcast_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_BCAST_V5,
					"Packet Type: %s (%u)", "BATADV_BCAST", BATADV_BCAST_V5);
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_seqno32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_ether(batadv_bcast_tree, hf_batadv_bcast_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, bcast_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(eth_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_icmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_ICMP");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 6:
		dissect_batadv_icmp_v6(tvb, pinfo, tree);
		break;
	case 7:
	case 8:
	case 9:
	case 10:
	case 11:
	case 12:
	case 13:
		dissect_batadv_icmp_v7(tvb, pinfo, tree);
		break;
	case 14:
		dissect_batadv_icmp_v14(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_icmp_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct icmp_packet_v6 *icmp_packeth;
	const guint8  *dst_addr, *orig_addr;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;
	proto_tree *batadv_icmp_tree = NULL;

	icmp_packeth = ep_alloc(sizeof(struct icmp_packet_v6));

	icmp_packeth->version = tvb_get_guint8(tvb, 1);
	icmp_packeth->msg_type = tvb_get_guint8(tvb, 2);
	dst_addr = tvb_get_ptr(tvb, 3, 6);
	SET_ADDRESS(&icmp_packeth->dst, AT_ETHER, 6, dst_addr);
	orig_addr = tvb_get_ptr(tvb, 9, 6);
	SET_ADDRESS(&icmp_packeth->orig, AT_ETHER, 6, orig_addr);
	icmp_packeth->ttl = tvb_get_guint8(tvb, 15);
	icmp_packeth->uid = tvb_get_guint8(tvb, 16);
	icmp_packeth->seqno = tvb_get_ntohs(tvb, 17);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
		     val_to_str(icmp_packeth->msg_type, icmp_packettypenames, "Unknown (0x%02x)"),
		     icmp_packeth->seqno);
	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, ICMP_PACKET_V6_SIZE,
			                                    "B.A.T.M.A.N. ICMP, Orig: %s (%s), Dst: %s (%s)",
			                                    get_ether_name(orig_addr), ether_to_str(orig_addr), get_ether_name(dst_addr), ether_to_str(dst_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, ICMP_PACKET_V6_SIZE, ENC_NA);
		}
		batadv_icmp_tree = proto_item_add_subtree(ti, ett_batadv_icmp);
	}

	/* items */
	proto_tree_add_uint_format(batadv_icmp_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_ICMP_V5,
					"Packet Type: %s (%u)", "BATADV_ICMP", BATADV_ICMP_V5);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_ether(batadv_icmp_tree, hf_batadv_icmp_dst, tvb, offset, 6, dst_addr);
	offset += 6;

	proto_tree_add_ether(batadv_icmp_tree, hf_batadv_icmp_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_uid, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, icmp_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void
dissect_batadv_icmp_rr(proto_tree *batadv_icmp_tree, tvbuff_t *tvb, int offset)
{
	proto_tree *field_tree = NULL;
	proto_item *tf;
	int ptr, i;

	ptr = tvb_get_guint8(tvb, offset);
	if (ptr < 1 || ptr > BAT_RR_LEN)
		return;

	tf = proto_tree_add_text(batadv_icmp_tree, tvb, offset, 1+ 6 * BAT_RR_LEN, "ICMP RR");
	field_tree = proto_item_add_subtree(tf, ett_batadv_icmp_rr);
	proto_tree_add_text(field_tree, tvb, offset, 1, "Pointer: %d", ptr);

	ptr--;
	offset++;
	for (i = 0; i < BAT_RR_LEN; i++) {
		proto_tree_add_text(field_tree, tvb, offset, 6, "%s%s",
				    (i > ptr) ? "-" : tvb_ether_to_str(tvb, offset),
				    (i == ptr) ? " <- (current)" : "");

		offset += 6;
	}
}

static void dissect_batadv_icmp_v7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct icmp_packet_v7 *icmp_packeth;
	const guint8  *dst_addr, *orig_addr;
	proto_item *ti;
	proto_tree *batadv_icmp_tree = NULL;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;

	icmp_packeth = ep_alloc(sizeof(struct icmp_packet_v7));

	icmp_packeth->version = tvb_get_guint8(tvb, 1);
	icmp_packeth->msg_type = tvb_get_guint8(tvb, 2);
	icmp_packeth->ttl = tvb_get_guint8(tvb, 3);
	dst_addr = tvb_get_ptr(tvb, 4, 6);
	SET_ADDRESS(&icmp_packeth->dst, AT_ETHER, 6, dst_addr);
	orig_addr = tvb_get_ptr(tvb, 10, 6);
	SET_ADDRESS(&icmp_packeth->orig, AT_ETHER, 6, orig_addr);
	icmp_packeth->seqno = tvb_get_ntohs(tvb, 16);
	icmp_packeth->uid = tvb_get_guint8(tvb, 17);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
		     val_to_str(icmp_packeth->msg_type, icmp_packettypenames, "Unknown (0x%02x)"),
		     icmp_packeth->seqno);

	/* Set tree info */
	if (tree) {
		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, ICMP_PACKET_V7_SIZE,
								"B.A.T.M.A.N. ICMP, Orig: %s (%s), Dst: %s (%s)",
								get_ether_name(orig_addr), ether_to_str(orig_addr), get_ether_name(dst_addr), ether_to_str(dst_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, ICMP_PACKET_V7_SIZE, ENC_NA);
		}
		batadv_icmp_tree = proto_item_add_subtree(ti, ett_batadv_icmp);
	}

	/* items */
	proto_tree_add_uint_format(batadv_icmp_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_ICMP_V5,
					"Packet Type: %s (%u)", "BATADV_ICMP", BATADV_ICMP_V5);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_ether(batadv_icmp_tree, hf_batadv_icmp_dst, tvb, offset, 6, dst_addr);
	offset += 6;

	proto_tree_add_ether(batadv_icmp_tree, hf_batadv_icmp_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_uid, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* rr data available? */
	length_remaining = tvb_length_remaining(tvb, offset);
	if (length_remaining >= 1 + BAT_RR_LEN * 6) {
		dissect_batadv_icmp_rr(batadv_icmp_tree, tvb, offset);
		offset += 1 + BAT_RR_LEN * 6;
	}

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, icmp_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_icmp_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct icmp_packet_v14 *icmp_packeth;
	const guint8  *dst_addr, *orig_addr;
	proto_item *ti;
	proto_tree *batadv_icmp_tree = NULL;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;

	icmp_packeth = ep_alloc(sizeof(struct icmp_packet_v14));

	icmp_packeth->version = tvb_get_guint8(tvb, 1);
	icmp_packeth->ttl = tvb_get_guint8(tvb, 2);
	icmp_packeth->msg_type = tvb_get_guint8(tvb, 3);
	dst_addr = tvb_get_ptr(tvb, 4, 6);
	SET_ADDRESS(&icmp_packeth->dst, AT_ETHER, 6, dst_addr);
	orig_addr = tvb_get_ptr(tvb, 10, 6);
	SET_ADDRESS(&icmp_packeth->orig, AT_ETHER, 6, orig_addr);
	icmp_packeth->seqno = tvb_get_ntohs(tvb, 16);
	icmp_packeth->uid = tvb_get_guint8(tvb, 17);
	icmp_packeth->reserved = tvb_get_guint8(tvb, 18);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
		     val_to_str(icmp_packeth->msg_type, icmp_packettypenames, "Unknown (0x%02x)"),
		     icmp_packeth->seqno);

	/* Set tree info */
	if (tree) {
		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, ICMP_PACKET_V14_SIZE,
								"B.A.T.M.A.N. ICMP, Orig: %s (%s), Dst: %s (%s)",
								get_ether_name(orig_addr), ether_to_str(orig_addr), get_ether_name(dst_addr), ether_to_str(dst_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, ICMP_PACKET_V14_SIZE, ENC_NA);
		}
		batadv_icmp_tree = proto_item_add_subtree(ti, ett_batadv_icmp);
	}

	/* items */
	proto_tree_add_uint_format(batadv_icmp_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_ICMP_V5,
					"Packet Type: %s (%u)", "BATADV_ICMP", BATADV_ICMP_V5);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_ether(batadv_icmp_tree, hf_batadv_icmp_dst, tvb, offset, 6, dst_addr);
	offset += 6;

	proto_tree_add_ether(batadv_icmp_tree, hf_batadv_icmp_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_uid, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	/* rr data available? */
	length_remaining = tvb_length_remaining(tvb, offset);
	if (length_remaining >= 1 + BAT_RR_LEN * 6) {
		dissect_batadv_icmp_rr(batadv_icmp_tree, tvb, offset);
		offset += 1 + BAT_RR_LEN * 6;
	}

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, orig_addr);

	tap_queue_packet(batadv_tap, pinfo, icmp_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_unicast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_UNICAST");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 6:
	case 7:
	case 8:
	case 9:
	case 10:
	case 11:
	case 12:
	case 13:
		dissect_batadv_unicast_v6(tvb, pinfo, tree);
		break;
	case 14:
		dissect_batadv_unicast_v14(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_unicast_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct unicast_packet_v6 *unicast_packeth;
	const guint8  *dest_addr;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;
	proto_tree *batadv_unicast_tree = NULL;

	unicast_packeth = ep_alloc(sizeof(struct unicast_packet_v6));

	unicast_packeth->version = tvb_get_guint8(tvb, 1);
	dest_addr = tvb_get_ptr(tvb, 2, 6);
	SET_ADDRESS(&unicast_packeth->dest, AT_ETHER, 6, dest_addr);
	unicast_packeth->ttl = tvb_get_guint8(tvb, 8);

	/* Set info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, UNICAST_PACKET_V6_SIZE,
			                                    "B.A.T.M.A.N. Unicast, Dst: %s (%s)",
			                                    get_ether_name(dest_addr), ether_to_str(dest_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, UNICAST_PACKET_V6_SIZE, ENC_NA);
		}
		batadv_unicast_tree = proto_item_add_subtree(ti, ett_batadv_unicast);
	}

	/* items */
	proto_tree_add_uint_format(batadv_unicast_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_UNICAST_V5,
					"Packet Type: %s (%u)", "BATADV_UNICAST", BATADV_UNICAST_V5);
	offset += 1;

	proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_ether(batadv_unicast_tree, hf_batadv_unicast_dst, tvb, offset, 6, dest_addr);
	offset += 6;

	proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dest_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dest_addr);

	tap_queue_packet(batadv_tap, pinfo, unicast_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(eth_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_unicast_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct unicast_packet_v14 *unicast_packeth;
	const guint8  *dest_addr;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;
	proto_tree *batadv_unicast_tree = NULL;

	unicast_packeth = ep_alloc(sizeof(struct unicast_packet_v14));

	unicast_packeth->version = tvb_get_guint8(tvb, 1);
	unicast_packeth->ttl = tvb_get_guint8(tvb, 2);
	unicast_packeth->ttvn = tvb_get_guint8(tvb, 3);
	dest_addr = tvb_get_ptr(tvb, 4, 6);
	SET_ADDRESS(&unicast_packeth->dest, AT_ETHER, 6, dest_addr);

	/* Set info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, UNICAST_PACKET_V14_SIZE,
			                                    "B.A.T.M.A.N. Unicast, Dst: %s (%s)",
			                                    get_ether_name(dest_addr), ether_to_str(dest_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, UNICAST_PACKET_V14_SIZE, ENC_NA);
		}
		batadv_unicast_tree = proto_item_add_subtree(ti, ett_batadv_unicast);
	}

	/* items */
	proto_tree_add_uint_format(batadv_unicast_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_UNICAST_V5,
					"Packet Type: %s (%u)", "BATADV_UNICAST", BATADV_UNICAST_V5);
	offset += 1;

	proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_ttvn, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_ether(batadv_unicast_tree, hf_batadv_unicast_dst, tvb, offset, 6, dest_addr);
	offset += 6;

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dest_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dest_addr);

	tap_queue_packet(batadv_tap, pinfo, unicast_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);

	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(eth_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_unicast_frag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_UNICAST_FRAG");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 12:
	case 13:
		dissect_batadv_unicast_frag_v12(tvb, pinfo, tree);
		break;
	case 14:
		dissect_batadv_unicast_frag_v14(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_unicast_frag_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf;
	struct unicast_frag_packet_v12 *unicast_frag_packeth;
	const guint8  *dest_addr, *orig_addr;
	gboolean save_fragmented = FALSE;
	fragment_data *frag_msg = NULL;
	proto_tree *batadv_unicast_frag_tree = NULL, *flag_tree;

	tvbuff_t *new_tvb;
	int offset = 0;
	int head = 0;

	unicast_frag_packeth = ep_alloc(sizeof(struct unicast_frag_packet_v12));

	unicast_frag_packeth->version = tvb_get_guint8(tvb, 1);
	dest_addr = tvb_get_ptr(tvb, 2, 6);
	SET_ADDRESS(&unicast_frag_packeth->dest, AT_ETHER, 6, dest_addr);
	unicast_frag_packeth->ttl = tvb_get_guint8(tvb, 8);
	unicast_frag_packeth->flags = tvb_get_guint8(tvb, 9);
	orig_addr = tvb_get_ptr(tvb, 10, 6);
	SET_ADDRESS(&unicast_frag_packeth->orig, AT_ETHER, 6, orig_addr);
	unicast_frag_packeth->seqno = tvb_get_ntohs(tvb, 16);

	save_fragmented = pinfo->fragmented;
	pinfo->fragmented = TRUE;

	/* Set info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, UNICAST_FRAG_PACKET_V12_SIZE,
			                                    "B.A.T.M.A.N. Unicast Fragment, Dst: %s (%s)",
			                                    get_ether_name(dest_addr), ether_to_str(dest_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, UNICAST_FRAG_PACKET_V12_SIZE, ENC_NA);
		}
		batadv_unicast_frag_tree = proto_item_add_subtree(ti, ett_batadv_unicast_frag);
	}

	/* items */
	proto_tree_add_uint_format(batadv_unicast_frag_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_UNICAST_FRAG_V12,
					"Packet Type: %s (%u)", "BATADV_UNICAST_FRAG", BATADV_UNICAST_FRAG_V12);
	offset += 1;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_ether(batadv_unicast_frag_tree, hf_batadv_unicast_frag_dst, tvb, offset, 6, dest_addr);
	offset += 6;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tf = proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_unicast_frag_flags_head, tvb, offset, 1, unicast_frag_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_unicast_frag_flags_largetail, tvb, offset, 1, unicast_frag_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_ether(batadv_unicast_frag_tree, hf_batadv_unicast_frag_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dest_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dest_addr);

	tap_queue_packet(batadv_tap, pinfo, unicast_frag_packeth);

	head = (unicast_frag_packeth->flags & 0x1);
	frag_msg = fragment_add_seq_check(tvb, offset, pinfo,
		unicast_frag_packeth->seqno + head,
		msg_fragment_table,
		msg_reassembled_table,
		1 - head,
		tvb_length_remaining(tvb, offset),
		head);

	new_tvb = process_reassembled_data(tvb, offset, pinfo,
		"Reassembled Message", frag_msg, &msg_frag_items,
		NULL, batadv_unicast_frag_tree);
	if (new_tvb) {
		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, new_tvb);
		}

		call_dissector(eth_handle, new_tvb, pinfo, tree);
	}

	pinfo->fragmented = save_fragmented;
}

static void dissect_batadv_unicast_frag_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf;
	struct unicast_frag_packet_v14 *unicast_frag_packeth;
	const guint8  *dest_addr, *orig_addr;
	gboolean save_fragmented = FALSE;
	fragment_data *frag_msg = NULL;
	proto_tree *batadv_unicast_frag_tree = NULL, *flag_tree;

	tvbuff_t *new_tvb;
	int offset = 0;
	int head = 0;

	unicast_frag_packeth = ep_alloc(sizeof(struct unicast_frag_packet_v14));

	unicast_frag_packeth->version = tvb_get_guint8(tvb, 1);
	unicast_frag_packeth->ttl = tvb_get_guint8(tvb, 2);
	unicast_frag_packeth->ttvn = tvb_get_guint8(tvb, 3);
	dest_addr = tvb_get_ptr(tvb, 4, 6);
	SET_ADDRESS(&unicast_frag_packeth->dest, AT_ETHER, 6, dest_addr);
	unicast_frag_packeth->flags = tvb_get_guint8(tvb, 10);
	unicast_frag_packeth->align = tvb_get_guint8(tvb, 11);
	orig_addr = tvb_get_ptr(tvb, 12, 6);
	SET_ADDRESS(&unicast_frag_packeth->orig, AT_ETHER, 6, orig_addr);
	unicast_frag_packeth->seqno = tvb_get_ntohs(tvb, 18);

	save_fragmented = pinfo->fragmented;
	pinfo->fragmented = TRUE;

	/* Set info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, UNICAST_FRAG_PACKET_V14_SIZE,
			                                    "B.A.T.M.A.N. Unicast Fragment, Dst: %s (%s)",
			                                    get_ether_name(dest_addr), ether_to_str(dest_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, UNICAST_FRAG_PACKET_V14_SIZE, ENC_NA);
		}
		batadv_unicast_frag_tree = proto_item_add_subtree(ti, ett_batadv_unicast_frag);
	}

	/* items */
	proto_tree_add_uint_format(batadv_unicast_frag_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_UNICAST_FRAG_V12,
					"Packet Type: %s (%u)", "BATADV_UNICAST", BATADV_UNICAST_FRAG_V12);
	offset += 1;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_ttvn, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_ether(batadv_unicast_frag_tree, hf_batadv_unicast_frag_dst, tvb, offset, 6, dest_addr);
	offset += 6;

	tf = proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_unicast_frag_flags_head, tvb, offset, 1, unicast_frag_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_unicast_frag_flags_largetail, tvb, offset, 1, unicast_frag_packeth->flags);
	/* </flags> */
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	proto_tree_add_ether(batadv_unicast_frag_tree, hf_batadv_unicast_frag_orig, tvb, offset, 6, orig_addr);
	offset += 6;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, orig_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dest_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dest_addr);

	tap_queue_packet(batadv_tap, pinfo, unicast_frag_packeth);

	head = (unicast_frag_packeth->flags & 0x1);
	frag_msg = fragment_add_seq_check(tvb, offset, pinfo,
		unicast_frag_packeth->seqno + head,
		msg_fragment_table,
		msg_reassembled_table,
		1 - head,
		tvb_length_remaining(tvb, offset),
		head);

	new_tvb = process_reassembled_data(tvb, offset, pinfo,
		"Reassembled Message", frag_msg, &msg_frag_items,
		NULL, batadv_unicast_frag_tree);
	if (new_tvb) {
		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, new_tvb);
		}

		call_dissector(eth_handle, new_tvb, pinfo, tree);
	}

	pinfo->fragmented = save_fragmented;
}

static void dissect_batadv_vis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_VIS");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 6:
	case 7:
	case 8:
	case 9:
		dissect_batadv_vis_v6(tvb, pinfo, tree);
		break;
	case 10:
	case 11:
	case 12:
	case 13:
		dissect_batadv_vis_v10(tvb, pinfo, tree);
		break;
	case 14:
		dissect_batadv_vis_v14(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_vis_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct vis_packet_v6 *vis_packeth;
	const guint8  *vis_orig_addr, *target_orig_addr, *sender_orig_addr;
	proto_tree *batadv_vis_tree = NULL;

	tvbuff_t *next_tvb;
	guint length_remaining, entry_size;
	int offset = 0, i;

	vis_packeth = ep_alloc(sizeof(struct vis_packet_v6));

	vis_packeth->version = tvb_get_guint8(tvb, 1);
	vis_packeth->vis_type = tvb_get_guint8(tvb, 2);
	vis_packeth->seqno = tvb_get_guint8(tvb, 3);
	vis_packeth->entries = tvb_get_guint8(tvb, 4);
	vis_packeth->ttl = tvb_get_guint8(tvb, 5);

	vis_orig_addr = tvb_get_ptr(tvb, 6, 6);
	SET_ADDRESS(&vis_packeth->vis_orig, AT_ETHER, 6, vis_orig_addr);
	target_orig_addr = tvb_get_ptr(tvb, 12, 6);
	SET_ADDRESS(&vis_packeth->target_orig, AT_ETHER, 6, target_orig_addr);
	sender_orig_addr = tvb_get_ptr(tvb, 18, 6);
	SET_ADDRESS(&vis_packeth->sender_orig, AT_ETHER, 6, sender_orig_addr);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
		     val_to_str(vis_packeth->vis_type, vis_packettypenames, "Unknown (0x%02x)"),
		     vis_packeth->seqno);
	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_PACKET_V6_SIZE,
			                                    "B.A.T.M.A.N. Vis, Orig: %s (%s)",
			                                    get_ether_name(vis_orig_addr), ether_to_str(vis_orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, VIS_PACKET_V6_SIZE, ENC_NA);
		}
		batadv_vis_tree = proto_item_add_subtree(ti, ett_batadv_vis);
	}

	/* items */
	proto_tree_add_uint_format(batadv_vis_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_VIS_V5,
					"Packet Type: %s (%u)", "BATADV_VIS", BATADV_VIS_V5);
	offset += 1;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_seqno, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_entries, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_vis_orig, tvb, offset, 6, vis_orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_target_orig, tvb, offset, 6, target_orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_sender_orig, tvb, offset, 6, sender_orig_addr);
	offset += 6;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, sender_orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, vis_orig_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, target_orig_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, target_orig_addr);

	tap_queue_packet(batadv_tap, pinfo, vis_packeth);

	switch (vis_packeth->version) {
	case 6:
	case 7:
		entry_size = VIS_ENTRY_V6_SIZE;
		break;
	default:
	case 8:
	case 9:
		entry_size = VIS_ENTRY_V8_SIZE;
		break;
	}

	for (i = 0; i < vis_packeth->entries; i++) {
		next_tvb = tvb_new_subset(tvb, offset, entry_size, entry_size);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		if (batadv_vis_tree != NULL) {
			switch (vis_packeth->version) {
			case 6:
			case 7:
				dissect_vis_entry_v6(next_tvb, pinfo, batadv_vis_tree);
				break;
			default:
			case 8:
			case 9:
				dissect_vis_entry_v8(next_tvb, pinfo, batadv_vis_tree);
				break;
			}
		}

		offset += entry_size;
	}

	length_remaining = tvb_length_remaining(tvb, offset);
	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_vis_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct vis_packet_v10 *vis_packeth;
	const guint8  *vis_orig_addr, *target_orig_addr, *sender_orig_addr;
	proto_tree *batadv_vis_tree = NULL;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0, i;

	vis_packeth = ep_alloc(sizeof(struct vis_packet_v10));

	vis_packeth->version = tvb_get_guint8(tvb, 1);
	vis_packeth->vis_type = tvb_get_guint8(tvb, 2);
	vis_packeth->entries = tvb_get_guint8(tvb, 3);
	vis_packeth->seqno = tvb_get_ntohl(tvb, 4);
	vis_packeth->ttl = tvb_get_guint8(tvb, 8);

	vis_orig_addr = tvb_get_ptr(tvb, 9, 6);
	SET_ADDRESS(&vis_packeth->vis_orig, AT_ETHER, 6, vis_orig_addr);
	target_orig_addr = tvb_get_ptr(tvb, 15, 6);
	SET_ADDRESS(&vis_packeth->target_orig, AT_ETHER, 6, target_orig_addr);
	sender_orig_addr = tvb_get_ptr(tvb, 21, 6);
	SET_ADDRESS(&vis_packeth->sender_orig, AT_ETHER, 6, sender_orig_addr);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
		     val_to_str(vis_packeth->vis_type, vis_packettypenames, "Unknown (0x%02x)"),
		     vis_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_PACKET_V10_SIZE,
			                                    "B.A.T.M.A.N. Vis, Orig: %s (%s)",
			                                    get_ether_name(vis_orig_addr), ether_to_str(vis_orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, VIS_PACKET_V10_SIZE, ENC_NA);
		}
		batadv_vis_tree = proto_item_add_subtree(ti, ett_batadv_vis);
	}

	/* items */
	proto_tree_add_uint_format(batadv_vis_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_VIS_V5,
					"Packet Type: %s (%u)", "BATADV_VIS", BATADV_VIS_V5);
	offset += 1;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_entries, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_seqno32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_vis_orig, tvb, offset, 6, vis_orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_target_orig, tvb, offset, 6, target_orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_sender_orig, tvb, offset, 6, sender_orig_addr);
	offset += 6;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, sender_orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, vis_orig_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, target_orig_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, target_orig_addr);

	tap_queue_packet(batadv_tap, pinfo, vis_packeth);

	for (i = 0; i < vis_packeth->entries; i++) {
		next_tvb = tvb_new_subset(tvb, offset, VIS_ENTRY_V8_SIZE, VIS_ENTRY_V8_SIZE);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_vis_entry_v8(next_tvb, pinfo, batadv_vis_tree);
		offset += VIS_ENTRY_V8_SIZE;
	}

	length_remaining = tvb_length_remaining(tvb, offset);
	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_vis_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct vis_packet_v14 *vis_packeth;
	const guint8  *vis_orig_addr, *target_orig_addr, *sender_orig_addr;
	proto_tree *batadv_vis_tree = NULL;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0, i;

	vis_packeth = ep_alloc(sizeof(struct vis_packet_v14));

	vis_packeth->version = tvb_get_guint8(tvb, 1);
	vis_packeth->ttl = tvb_get_guint8(tvb, 2);
	vis_packeth->vis_type = tvb_get_guint8(tvb, 3);
	vis_packeth->seqno = tvb_get_ntohl(tvb, 4);
	vis_packeth->entries = tvb_get_guint8(tvb, 8);
	vis_packeth->reserved = tvb_get_guint8(tvb, 9);

	vis_orig_addr = tvb_get_ptr(tvb, 10, 6);
	SET_ADDRESS(&vis_packeth->vis_orig, AT_ETHER, 6, vis_orig_addr);
	target_orig_addr = tvb_get_ptr(tvb, 16, 6);
	SET_ADDRESS(&vis_packeth->target_orig, AT_ETHER, 6, target_orig_addr);
	sender_orig_addr = tvb_get_ptr(tvb, 22, 6);
	SET_ADDRESS(&vis_packeth->sender_orig, AT_ETHER, 6, sender_orig_addr);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
		     val_to_str(vis_packeth->vis_type, vis_packettypenames, "Unknown (0x%02x)"),
		     vis_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_PACKET_V14_SIZE,
			                                    "B.A.T.M.A.N. Vis, Orig: %s (%s)",
			                                    get_ether_name(vis_orig_addr), ether_to_str(vis_orig_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, VIS_PACKET_V14_SIZE, ENC_NA);
		}
		batadv_vis_tree = proto_item_add_subtree(ti, ett_batadv_vis);
	}

	/* items */
	proto_tree_add_uint_format(batadv_vis_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_VIS_V5,
					"Packet Type: %s (%u)", "BATADV_VIS", BATADV_VIS_V5);
	offset += 1;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_seqno32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_entries, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_vis_orig, tvb, offset, 6, vis_orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_target_orig, tvb, offset, 6, target_orig_addr);
	offset += 6;

	proto_tree_add_ether(batadv_vis_tree, hf_batadv_vis_sender_orig, tvb, offset, 6, sender_orig_addr);
	offset += 6;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, sender_orig_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, vis_orig_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, target_orig_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, target_orig_addr);

	tap_queue_packet(batadv_tap, pinfo, vis_packeth);

	for (i = 0; i < vis_packeth->entries; i++) {
		next_tvb = tvb_new_subset(tvb, offset, VIS_ENTRY_V8_SIZE, VIS_ENTRY_V8_SIZE);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_vis_entry_v8(next_tvb, pinfo, batadv_vis_tree);
		offset += VIS_ENTRY_V8_SIZE;
	}

	length_remaining = tvb_length_remaining(tvb, offset);
	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_vis_entry_v6(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	const guint8  *dst;
	proto_tree    *batadv_vis_entry_tree = NULL;

	dst = tvb_get_ptr(tvb, 0, 6);

	if (tree) {
		proto_item    *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_ENTRY_V6_SIZE,
			                                    "VIS Entry: %s (%s)",
			                                    get_ether_name(dst), ether_to_str(dst));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, VIS_ENTRY_V6_SIZE, ENC_NA);
		}
		batadv_vis_entry_tree = proto_item_add_subtree(ti, ett_batadv_vis_entry);
	}

	proto_tree_add_ether(batadv_vis_entry_tree, hf_batadv_vis_entry_dst, tvb, 0, 6, dst);
	proto_tree_add_item(batadv_vis_entry_tree, hf_batadv_vis_entry_quality, tvb, 6, 1, ENC_BIG_ENDIAN);
}

static void dissect_vis_entry_v8(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	const guint8  *dst, *src;
	proto_tree *batadv_vis_entry_tree = NULL;

	src = tvb_get_ptr(tvb, 0, 6);
	dst = tvb_get_ptr(tvb, 6, 6);

	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_ENTRY_V8_SIZE,
			                                    "VIS Entry: %s (%s)",
			                                    get_ether_name(dst), ether_to_str(dst));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, VIS_ENTRY_V8_SIZE, ENC_NA);
		}
		batadv_vis_entry_tree = proto_item_add_subtree(ti, ett_batadv_vis_entry);
	}

	proto_tree_add_ether(batadv_vis_entry_tree, hf_batadv_vis_entry_src, tvb, 0, 6, src);
	proto_tree_add_ether(batadv_vis_entry_tree, hf_batadv_vis_entry_dst, tvb, 6, 6, dst);
	proto_tree_add_item(batadv_vis_entry_tree, hf_batadv_vis_entry_quality, tvb, 12, 1, ENC_BIG_ENDIAN);
}

static void dissect_batadv_tt_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_TT_QUERY");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 14:
		dissect_batadv_tt_query_v14(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_tt_query_v14(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	struct tt_query_packet_v14 *tt_query_packeth;
	const guint8  *dst_addr, *src_addr;
	proto_item *tf;
	proto_tree *batadv_tt_query_tree = NULL, *flag_tree;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0, i;
	int tt_type;

	tt_query_packeth = ep_alloc(sizeof(struct tt_query_packet_v14));

	tt_query_packeth->version = tvb_get_guint8(tvb, 1);
	tt_query_packeth->ttl = tvb_get_guint8(tvb, 2);
	tt_query_packeth->flags = tvb_get_guint8(tvb, 3);

	dst_addr = tvb_get_ptr(tvb, 4, 6);
	SET_ADDRESS(&tt_query_packeth->dst, AT_ETHER, 6, dst_addr);
	src_addr = tvb_get_ptr(tvb, 10, 6);
	SET_ADDRESS(&tt_query_packeth->src, AT_ETHER, 6, src_addr);
	tt_query_packeth->ttvn = tvb_get_guint8(tvb, 16);
	tt_query_packeth->tt_data = tvb_get_ntohs(tvb, 17);

	tt_type = TT_TYPE_MASK & tt_query_packeth->flags;

	/* Set info column */
	switch (tt_type) {
	case TT_REQUEST:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Request=%u", tt_query_packeth->ttvn);
		break;
	case TT_RESPONSE:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Response=%u", tt_query_packeth->ttvn);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Type %u", tt_type);
		break;
	}

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, TT_QUERY_PACKET_V14_SIZE,
			                                    "B.A.T.M.A.N. TT Query, Dst: %s (%s)",
			                                    get_ether_name(dst_addr), ether_to_str(dst_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, TT_QUERY_PACKET_V14_SIZE, ENC_NA);
		}
		batadv_tt_query_tree = proto_item_add_subtree(ti, ett_batadv_tt_query);
	}

	/* items */
	proto_tree_add_uint_format(batadv_tt_query_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_TT_QUERY_V14,
					"Packet Type: %s (%u)", "BATADV_TT_QUERY", BATADV_TT_QUERY_V14);
	offset += 1;

	proto_tree_add_item(batadv_tt_query_tree, hf_batadv_tt_query_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_tt_query_tree, hf_batadv_tt_query_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tf = proto_tree_add_item(batadv_tt_query_tree, hf_batadv_tt_query_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_tt_query_flags);
	proto_tree_add_uint(flag_tree, hf_batadv_tt_query_flags_type, tvb, offset, 1, tt_type);
	proto_tree_add_boolean(flag_tree, hf_batadv_tt_query_flags_full_table, tvb, offset, 1, tt_query_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_ether(batadv_tt_query_tree, hf_batadv_tt_query_dst, tvb, offset, 6, dst_addr);
	offset += 6;

	proto_tree_add_ether(batadv_tt_query_tree, hf_batadv_tt_query_src, tvb, offset, 6, src_addr);
	offset += 6;

	proto_tree_add_item(batadv_tt_query_tree, hf_batadv_tt_query_ttvn, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	switch (tt_type) {
	case TT_REQUEST:
		proto_tree_add_item(batadv_tt_query_tree, hf_batadv_tt_query_tt_crc, tvb, offset, 2, ENC_BIG_ENDIAN);
		break;
	case TT_RESPONSE:
		proto_tree_add_item(batadv_tt_query_tree, hf_batadv_tt_query_entries, tvb, offset, 2, ENC_BIG_ENDIAN);
		break;
	default:
		break;
	}
	offset += 2;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, src_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, src_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dst_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dst_addr);

	tap_queue_packet(batadv_tap, pinfo, tt_query_packeth);

	if (tt_type == TT_RESPONSE) {
		for (i = 0; i < tt_query_packeth->tt_data; i++) {
			next_tvb = tvb_new_subset(tvb, offset, TT_ENTRY_V14_SIZE, TT_ENTRY_V14_SIZE);

			if (have_tap_listener(batadv_follow_tap)) {
				tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
			}

			dissect_tt_entry_v14(next_tvb, pinfo, batadv_tt_query_tree);
			offset += TT_ENTRY_V14_SIZE;
		}
	}

	length_remaining = tvb_length_remaining(tvb, offset);
	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_tt_entry_v14(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	const guint8  *entry;
	guint8  flags;
	proto_item *tf;
	proto_tree *batadv_tt_entry_tree = NULL, *flag_tree;

	flags = tvb_get_guint8(tvb, 0);
	entry = tvb_get_ptr(tvb, 1, 6);

	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, TT_ENTRY_V14_SIZE,
			                                    "TT Entry: %s (%s)",
			                                    get_ether_name(entry), ether_to_str(entry));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, TT_ENTRY_V14_SIZE, ENC_NA);
		}
		batadv_tt_entry_tree = proto_item_add_subtree(ti, ett_batadv_tt_entry);
	}

	tf = proto_tree_add_item(batadv_tt_entry_tree, hf_batadv_tt_entry_flags, tvb, 0, 1, ENC_BIG_ENDIAN);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_batadv_tt_entry_flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_tt_entry_flags_change_del, tvb, 0, 1, flags);
	proto_tree_add_boolean(flag_tree, hf_batadv_tt_entry_flags_client_roam, tvb, 0, 1, flags);
	/* </flags> */
	proto_tree_add_ether(batadv_tt_entry_tree, hf_batadv_tt_entry, tvb, 1, 6, entry);
}

static void dissect_batadv_roam_adv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_ROAM_ADV");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 14:
		dissect_batadv_roam_adv_v14(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_roam_adv_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct roam_adv_packet_v14 *roam_adv_packeth;
	const guint8  *dst_addr, *src_addr, *client_addr;
	proto_tree *batadv_roam_adv_tree = NULL;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;

	roam_adv_packeth = ep_alloc(sizeof(struct roam_adv_packet_v14));

	roam_adv_packeth->version = tvb_get_guint8(tvb, 1);
	roam_adv_packeth->ttl = tvb_get_guint8(tvb, 2);
	dst_addr = tvb_get_ptr(tvb, 4, 6);
	SET_ADDRESS(&roam_adv_packeth->dst, AT_ETHER, 6, dst_addr);
	src_addr = tvb_get_ptr(tvb, 10, 6);
	SET_ADDRESS(&roam_adv_packeth->src, AT_ETHER, 6, src_addr);
	client_addr = tvb_get_ptr(tvb, 16, 6);
	SET_ADDRESS(&roam_adv_packeth->client, AT_ETHER, 6, client_addr);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Client %s (%s)", get_ether_name(client_addr), ether_to_str(client_addr));

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, ROAM_ADV_PACKET_V14_SIZE,
			                                    "B.A.T.M.A.N. Roam: %s (%s)",
			                                    get_ether_name(client_addr), ether_to_str(client_addr));
		} else {
			ti = proto_tree_add_item(tree, proto_batadv_plugin, tvb, 0, ROAM_ADV_PACKET_V14_SIZE, ENC_NA);
		}
		batadv_roam_adv_tree = proto_item_add_subtree(ti, ett_batadv_roam_adv);
	}

	/* items */
	proto_tree_add_uint_format(batadv_roam_adv_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_ROAM_ADV_V14,
					"Packet Type: %s (%u)", "BATADV_ROAM_ADV", BATADV_ROAM_ADV_V14);
	offset += 1;

	proto_tree_add_item(batadv_roam_adv_tree, hf_batadv_roam_adv_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_roam_adv_tree, hf_batadv_roam_adv_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	proto_tree_add_ether(batadv_roam_adv_tree, hf_batadv_roam_adv_dst, tvb, offset, 6, dst_addr);
	offset += 6;

	proto_tree_add_ether(batadv_roam_adv_tree, hf_batadv_roam_adv_src, tvb, offset, 6, src_addr);
	offset += 6;

	proto_tree_add_ether(batadv_roam_adv_tree, hf_batadv_roam_adv_client, tvb, offset, 6, client_addr);
	offset += 6;

	SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, src_addr);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, src_addr);

	SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dst_addr);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dst_addr);

	tap_queue_packet(batadv_tap, pinfo, roam_adv_packeth);

	length_remaining = tvb_length_remaining(tvb, offset);
	if (length_remaining != 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void batadv_init_routine(void)
{
        fragment_table_init(&msg_fragment_table);
        reassembled_table_init(&msg_reassembled_table);
}

void proto_register_batadv(void)
{
	module_t *batadv_module;

	static hf_register_info hf[] = {
		{ &hf_batadv_packet_type,
		  { "Packet Type", "batadv.batman.packet_type",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_version,
		  { "Version", "batadv.batman.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_flags,
		  { "Flags", "batadv.batman.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_ttl,
		  { "Time to Live", "batadv.batman.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_gwflags,
		  { "Gateway Flags", "batadv.batman.gwflags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_tq,
		  { "Transmission Quality", "batadv.batman.tq",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_seqno,
		  { "Sequence number", "batadv.batman.seq",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_seqno32,
		  { "Sequence number", "batadv.batman.seq",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_orig,
		  { "Originator", "batadv.batman.orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_prev_sender,
		  { "Received from", "batadv.batman.prev_sender",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_num_tt,
		  { "Number of TTs", "batadv.batman.num_tt",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_tt_num_changes,
		  { "Number of TT Changes", "batadv.batman.tt_num_changes",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_ttvn,
		  { "TT Version", "batadv.batman.ttvn",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_tt_crc,
		  { "CRC of TT", "batadv.batman.tt_crc",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_flags_directlink,
		  { "DirectLink", "batadv.batman.flags.directlink",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_flags_vis_server,
		  { "VIS_SERVER", "batadv.batman.flags.vis_server",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_flags_primaries_first_hop,
		  { "PRIMARIES_FIRST_HOP", "batadv.batman.flags.primaries_first_hop",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_tt,
		  { "Translation Table", "batadv.batman.tt",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_bcast_version,
		  { "Version", "batadv.bcast.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_bcast_orig,
		  { "Originator", "batadv.bcast.orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_bcast_seqno,
		  { "Sequence number", "batadv.bcast.seq",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_bcast_seqno32,
		  { "Sequence number", "batadv.bcast.seq",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_bcast_ttl,
		  { "Time to Live", "batadv.bcast.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_icmp_version,
		  { "Version", "batadv.icmp.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_icmp_msg_type,
		  { "Message Type", "batadv.icmp.msg_type",
		    FT_UINT8, BASE_DEC, VALS(icmp_packettypenames), 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_icmp_dst,
		  { "Destination", "batadv.icmp.dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_icmp_orig,
		  { "Originator", "batadv.icmp.orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_icmp_ttl,
		  { "Time to Live", "batadv.icmp.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_icmp_uid,
		  { "UID", "batadv.icmp.uid",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_icmp_seqno,
		  { "Sequence number", "batadv.icmp.seq",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_unicast_version,
		  { "Version", "batadv.unicast.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_dst,
		  { "Destination", "batadv.unicast.dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_ttl,
		  { "Time to Live", "batadv.unicast.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_ttvn,
		  { "TT Version", "batadv.unicast.ttvn",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_frag_version,
		  { "Version", "batadv.unicast_frag.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_frag_dst,
		  { "Destination", "batadv.unicast_frag.dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_frag_ttl,
		  { "Time to Live", "batadv.unicast_frag.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_frag_ttvn,
		  { "TT Version", "batadv.unicast_frag.ttvn",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_frag_flags,
		  { "Flags", "batadv.unicast_frag.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_frag_flags_head,
		  { "Head", "batadv.unicast_frag.flags.head",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_frag_flags_largetail,
		  { "Largetail", "batadv.unicast_frag.flags.largetail",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_frag_orig,
		  { "Originator", "batadv.unicast_frag.orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_frag_seqno,
		  { "Sequence number", "batadv.unicast_frag.seq",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_version,
		  { "Version", "batadv.vis.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_type,
		  { "Type", "batadv.vis.type",
		    FT_UINT8, BASE_DEC, VALS(vis_packettypenames), 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_seqno,
		  { "Sequence number", "batadv.vis.seq",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_vis_seqno32,
		  { "Sequence number", "batadv.vis.seq",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_vis_entries,
		  { "Entries", "batadv.vis.entries",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of entries", HFILL}
		},
		{ &hf_batadv_vis_ttl,
		  { "Time to Live", "batadv.vis.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_vis_vis_orig,
		  { "Originator", "batadv.vis.vis_orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_target_orig,
		  { "Target Originator", "batadv.vis.target_orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_sender_orig,
		  { "Forwarding Originator", "batadv.vis.sender_orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_entry_src,
		  { "Source", "batadv.vis.src",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_entry_dst,
		  { "Destination", "batadv.vis.dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_vis_entry_quality,
		  { "Quality", "batadv.vis.quality",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tt_query_version,
		  { "Version", "batadv.tt_query.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tt_query_ttl,
		  { "Time to Live", "batadv.tt_query.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_tt_query_flags,
		  { "Flags", "batadv.tt_query.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tt_query_flags_type,
		  { "Query Type", "batadv.tt_query.flags.type",
		    FT_UINT8, BASE_HEX, VALS (&tt_query_type_v14), TT_TYPE_MASK,
		    NULL, HFILL }
		},
		{ &hf_batadv_tt_query_flags_full_table,
		  { "Full Table", "batadv.tt_query.flags.full_table",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), TT_FULL_TABLE,
		    NULL, HFILL }
		},
		{ &hf_batadv_tt_query_dst,
		  { "Destination", "batadv.tt_query.dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tt_query_src,
		  { "Source", "batadv.tt_query.src",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tt_query_ttvn,
		  { "TT Version", "batadv.tt_query.ttvn",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tt_query_tt_crc,
		  { "CRC of TT", "batadv.tt_query.tt_crc",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tt_query_entries,
		  { "Entries", "batadv.tt_query.entries",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Number of entries", HFILL }
		},
		{ &hf_batadv_roam_adv_version,
		  { "Version", "batadv.roam_adv.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_roam_adv_ttl,
		  { "Time to Live", "batadv.roam_adv.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_roam_adv_src,
		  { "Source", "batadv.roam_adv.src",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_roam_adv_dst,
		  { "Destination", "batadv.roam_adv.dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_roam_adv_client,
		  { "Client", "batadv.roam_adv.client",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_msg_fragments,
		  {"Message fragments", "batadv.unicast_frag.fragments",
		    FT_NONE, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_batadv_tt_entry,
		  { "Entry", "batadv.tt_entry.entry",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tt_entry_flags,
		  { "Flags", "batadv.tt_entry.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tt_entry_flags_change_del,
		  { "Delete", "batadv.tt_entry.flags.change_del",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), TT_CHANGE_DEL,
		    NULL, HFILL }
		},
		{ &hf_batadv_tt_entry_flags_client_roam,
		  { "Client Roam", "batadv.tt_entry.flags.client_roam",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), TT_CLIENT_ROAM,
		    NULL, HFILL }
		},
		{ &hf_msg_fragment,
		  {"Message fragment", "batadv.unicast_frag.fragment",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_msg_fragment_overlap,
		  {"Message fragment overlap", "batadv.unicast_frag.fragment.overlap",
		    FT_BOOLEAN, 0, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_msg_fragment_overlap_conflicts,
		   {"Message fragment overlapping with conflicting data",
		    "batadv.unicast_frag.fragment.overlap.conflicts",
		    FT_BOOLEAN, 0, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_msg_fragment_multiple_tails,
		  {"Message has multiple tail fragments",
		    "batadv.unicast_frag.fragment.multiple_tails",
		    FT_BOOLEAN, 0, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_msg_fragment_too_long_fragment,
		  {"Message fragment too long", "batadv.unicast_frag.fragment.too_long_fragment",
		    FT_BOOLEAN, 0, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_msg_fragment_error,
		  {"Message defragmentation error", "batadv.unicast_frag.fragment.error",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_msg_fragment_count,
		  {"Message fragment count", "batadv.unicast_frag.fragment.count",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_msg_reassembled_in,
		  {"Reassembled in", "batadv.msg.reassembled.in",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_msg_reassembled_length,
		  {"Reassembled length", "batadv.msg.reassembled.length",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_batadv_batman,
		&ett_batadv_batman_flags,
		&ett_batadv_batman_tt,
		&ett_batadv_batman_gwflags,
		&ett_batadv_bcast,
		&ett_batadv_icmp,
		&ett_batadv_icmp_rr,
		&ett_batadv_unicast,
		&ett_batadv_unicast_frag,
		&ett_batadv_vis,
		&ett_batadv_vis_entry,
		&ett_batadv_tt_query,
		&ett_batadv_tt_query_flags,
		&ett_batadv_tt_entry,
		&ett_batadv_tt_entry_flags,
		&ett_batadv_roam_adv,
		&ett_msg_fragment,
		&ett_msg_fragments
	};

	proto_batadv_plugin = proto_register_protocol(
	                              "B.A.T.M.A.N. Advanced Protocol",
	                              "BATADV",          /* short name */
	                              "batadv"           /* abbrev */
	                      );

	batadv_module = prefs_register_protocol(proto_batadv_plugin,
						proto_reg_handoff_batadv);

	prefs_register_uint_preference(batadv_module, "batmanadv.ethertype",
	                               "Ethertype",
	                               "Ethertype used to indicate B.A.T.M.A.N. packet.",
	                               16, &batadv_ethertype);

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_batadv_plugin, hf, array_length(hf));

	register_init_routine(&batadv_init_routine);
}

void proto_reg_handoff_batadv(void)
{
	static gboolean inited = FALSE;
	static unsigned int old_batadv_ethertype;

	if (!inited) {
		batman_handle = create_dissector_handle(dissect_batman_plugin, proto_batadv_plugin);

		data_handle = find_dissector("data");
		eth_handle = find_dissector("eth");

		batadv_tap = register_tap("batman");
		batadv_follow_tap = register_tap("batman_follow");

		inited = TRUE;
	} else {
		dissector_delete_uint("ethertype", old_batadv_ethertype, batman_handle);
	}

	old_batadv_ethertype = batadv_ethertype;
	dissector_add_uint("ethertype", batadv_ethertype, batman_handle);
}
