/* packet-batadv.c
 * Routines for B.A.T.M.A.N. Advanced dissection
 * Copyright 2008-2010  Sven Eckelmann <sven@narfation.org>
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

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/addr_resolv.h>
#include <epan/reassemble.h>
#include <epan/expert.h>

/* Start content from packet-batadv.h */
#define ETH_P_BATMAN  0x4305

#define BATADV_PACKET_V5         0x01
#define BATADV_ICMP_V5           0x02
#define BATADV_UNICAST_V5        0x03
#define BATADV_BCAST_V5          0x04
#define BATADV_VIS_V5            0x05
#define BATADV_UNICAST_FRAG_V12  0x06
#define BATADV_TT_QUERY_V14      0x07
#define BATADV_ROAM_ADV_V14      0x08
#define BATADV_ROAM_ADV_V14      0x08
#define BATADV_UNICAST_4ADDR_V14 0x09

#define BATADV_IV_OGM_V15        0x00
#define BATADV_BCAST_V15         0x01
#define BATADV_CODED_V15         0x02
#define BATADV_UNICAST_V15       0x40
#define BATADV_UNICAST_FRAG_V15  0x41
#define BATADV_UNICAST_4ADDR_V15 0x42
#define BATADV_ICMP_V15          0x43
#define BATADV_UNICAST_TVLV_V15  0x44

#define BATADV_TVLV_V15_GW       0x01
#define BATADV_TVLV_V15_DAT      0x02
#define BATADV_TVLV_V15_NC       0x03
#define BATADV_TVLV_V15_TT       0x04
#define BATADV_TVLV_V15_ROAM     0x05
#define BATADV_TVLV_V15_MCAST    0x06

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

#define UNICAST_4ADDR_DATA            0x01
#define UNICAST_4ADDR_DAT_DHT_GET     0x02
#define UNICAST_4ADDR_DAT_DHT_PUT     0x03
#define UNICAST_4ADDR_DAT_CACHE_REPLY 0x04

#define BATADV_TVLVL_TT_TYPE_MASK      0x0F
#define BATADV_TVLVL_TT_OGM_DIFF       0x01
#define BATADV_TVLVL_TT_REQUEST        0x02
#define BATADV_TVLVL_TT_RESPONSE       0x04
#define BATADV_TVLVL_TT_FULL_TABLE     0x10

#define BATADV_TVLVL_TT_CHANGE_DEL     0x01
#define BATADV_TVLVL_TT_CHANGE_ROAM    0x02
#define BATADV_TVLVL_TT_CHANGE_WIFI    0x10
#define BATADV_TVLVL_TT_CHANGE_ISOLATE 0x20

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

struct iv_ogm_packet_v15 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  ttl;
	guint8  flags;
	guint32 seqno;
	address orig;
	address prev_sender;
	guint8  reserved;
	guint8  tq;
	guint16 tvlv_len;
};
#define IV_OGM_PACKET_V15_SIZE 24

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

struct icmp_packet_v15 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  ttl;
	guint8  msg_type; /* see ICMP message types above */
	address dst;
	address orig;
	guint8  uid;
	guint8  rr_ptr;
	guint16 seqno;
};
#define ICMP_PACKET_V15_SIZE 20

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
#define UNICAST_PACKET_V14_SIZE 10

struct unicast_4addr_packet_v14 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  ttl;
	guint8  ttvn; /* destination translation table version number */
	address dest;
	address src;
	guint8  subtype;
	guint8  reserved;
};
#define UNICAST_4ADDR_PACKET_V14_SIZE 18

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

struct unicast_frag_packet_v15 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  ttl;
	guint8  no; /* only upper 4 bit are used */
	address dest;
	address orig;
	guint16 seqno;
	guint16 total_size;
};
#define UNICAST_FRAG_PACKET_V15_SIZE 20

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

struct coded_packet_v15 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  ttl;
	guint8  first_ttvn;
	address first_source;
	address first_orig_dest;
	guint32 first_crc;
	guint8  second_ttl;
	guint8  second_ttvn;
	address second_dest;
	address second_source;
	address second_orig_dest;
	guint32 second_crc;
	guint16 coded_len;
};
#define CODED_PACKET_V15_SIZE 46

struct unicast_tvlv_packet_v15 {
	guint8  packet_type;
	guint8  version;  /* batman version field */
	guint8  ttl;
	guint8  reserved;
	address dest;
	address src;
	guint16 tvlv_len;
	guint16 align;
};
#define UNICAST_TVLV_PACKET_V15_SIZE 20
/* End content from packet-batadv.h */

/* trees */
static gint ett_batadv_batman = -1;
static gint ett_batadv_batman_flags = -1;
static gint ett_batadv_batman_gwflags = -1;
static gint ett_batadv_batman_tt = -1;
static gint ett_batadv_iv_ogm = -1;
static gint ett_batadv_iv_ogm_flags = -1;
static gint ett_batadv_bcast = -1;
static gint ett_batadv_icmp = -1;
static gint ett_batadv_icmp_rr = -1;
static gint ett_batadv_unicast = -1;
static gint ett_batadv_unicast_4addr = -1;
static gint ett_batadv_unicast_frag = -1;
static gint ett_batadv_unicast_tvlv = -1;
static gint ett_batadv_vis = -1;
static gint ett_batadv_vis_entry = -1;
static gint ett_batadv_tt_query = -1;
static gint ett_batadv_tt_query_flags = -1;
static gint ett_batadv_tt_entry = -1;
static gint ett_batadv_tt_entry_flags = -1;
static gint ett_batadv_roam_adv = -1;
static gint ett_batadv_coded = -1;
static gint ett_batadv_tvlv = -1;
static gint ett_batadv_tvlv_mcast_flags = -1;
static gint ett_batadv_tvlv_vid = -1;
static gint ett_batadv_tvlv_tt_flags = -1;
static gint ett_batadv_tvlv_tt_vlan = -1;
static gint ett_batadv_tvlv_tt_change = -1;
static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static expert_field ei_batadv_tvlv_unknown_version = EI_INIT;

/* hfs */
static int hf_batadv_packet_type = -1;

static int hf_batadv_batman_version = -1;
static int hf_batadv_batman_flags = -1;
static int hf_batadv_batman_ttl = -1;
static int hf_batadv_batman_gwflags = -1;
static int hf_batadv_batman_gwflags_dl_speed = -1;
static int hf_batadv_batman_gwflags_ul_speed = -1;
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

static int hf_batadv_iv_ogm_version = -1;
static int hf_batadv_iv_ogm_ttl = -1;
static int hf_batadv_iv_ogm_flags = -1;
static int hf_batadv_iv_ogm_seqno = -1;
static int hf_batadv_iv_ogm_orig = -1;
static int hf_batadv_iv_ogm_prev_sender = -1;
static int hf_batadv_iv_ogm_tq = -1;
static int hf_batadv_iv_ogm_tvlv_len = -1;

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

static int hf_batadv_icmp_rr_pointer = -1;
static int hf_batadv_icmp_rr_ether = -1;

static int hf_batadv_unicast_version = -1;
static int hf_batadv_unicast_dst = -1;
static int hf_batadv_unicast_ttl = -1;
static int hf_batadv_unicast_ttvn = -1;

static int hf_batadv_unicast_4addr_version = -1;
static int hf_batadv_unicast_4addr_dst = -1;
static int hf_batadv_unicast_4addr_ttl = -1;
static int hf_batadv_unicast_4addr_ttvn = -1;
static int hf_batadv_unicast_4addr_src = -1;
static int hf_batadv_unicast_4addr_subtype = -1;

static int hf_batadv_unicast_frag_version = -1;
static int hf_batadv_unicast_frag_dst = -1;
static int hf_batadv_unicast_frag_ttl = -1;
static int hf_batadv_unicast_frag_ttvn = -1;
static int hf_batadv_unicast_frag_flags = -1;
static int hf_batadv_unicast_frag_orig = -1;
static int hf_batadv_unicast_frag_seqno = -1;
static int hf_batadv_unicast_frag_no = -1;
static int hf_batadv_unicast_frag_total_size = -1;

static int hf_batadv_unicast_tvlv_version = -1;
static int hf_batadv_unicast_tvlv_ttl = -1;
static int hf_batadv_unicast_tvlv_dst = -1;
static int hf_batadv_unicast_tvlv_src = -1;
static int hf_batadv_unicast_tvlv_len = -1;

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

static int hf_batadv_coded_version = -1;
static int hf_batadv_coded_ttl = -1;
static int hf_batadv_coded_first_ttvn = -1;
static int hf_batadv_coded_first_source = -1;
static int hf_batadv_coded_first_orig_dest = -1;
static int hf_batadv_coded_first_crc = -1;
static int hf_batadv_coded_second_ttl = -1;
static int hf_batadv_coded_second_ttvn = -1;
static int hf_batadv_coded_second_dest = -1;
static int hf_batadv_coded_second_source = -1;
static int hf_batadv_coded_second_orig_dest = -1;
static int hf_batadv_coded_second_crc = -1;
static int hf_batadv_coded_coded_len = -1;

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

static int hf_batadv_tvlv_type = -1;
static int hf_batadv_tvlv_version = -1;
static int hf_batadv_tvlv_len = -1;

static int hf_batadv_tvlv_gw_download = -1;
static int hf_batadv_tvlv_gw_upload = -1;

static int hf_batadv_tvlv_roam_addr = -1;
static int hf_batadv_tvlv_roam_vid = -1;
static int hf_batadv_tvlv_vid_vlan = -1;
static int hf_batadv_tvlv_vid_tagged = -1;

static int hf_batadv_tvlv_tt_flags = -1;
static int hf_batadv_tvlv_tt_flags_type = -1;
static int hf_batadv_tvlv_tt_flags_full_table = -1;
static int hf_batadv_tvlv_tt_ttvn = -1;
static int hf_batadv_tvlv_tt_num_vlan = -1;
static int hf_batadv_tvlv_tt_vlan_crc = -1;
static int hf_batadv_tvlv_tt_vlan_vid = -1;
static int hf_batadv_tvlv_tt_change_flags = -1;
static int hf_batadv_tvlv_tt_change_vid = -1;
static int hf_batadv_tvlv_tt_change_addr = -1;

/* flags */
static int hf_batadv_batman_flags_directlink = -1;
static int hf_batadv_batman_flags_vis_server = -1;
static int hf_batadv_batman_flags_not_best_next_hop = -1;
static int hf_batadv_batman_flags_primaries_first_hop = -1;
static int hf_batadv_unicast_frag_flags_head = -1;
static int hf_batadv_unicast_frag_flags_largetail = -1;
static int hf_batadv_iv_ogm_flags_not_best_next_hop = -1;
static int hf_batadv_iv_ogm_flags_primaries_first_hop = -1;
static int hf_batadv_iv_ogm_flags_directlink = -1;
static int hf_batadv_tvlv_mcast_flags_unsnoopables = -1;
static int hf_batadv_tvlv_mcast_flags_ipv4 = -1;
static int hf_batadv_tvlv_mcast_flags_ipv6 = -1;
static int hf_batadv_tvlv_tt_change_flags_del = -1;
static int hf_batadv_tvlv_tt_change_flags_roam = -1;
static int hf_batadv_tvlv_tt_change_flags_wifi = -1;
static int hf_batadv_tvlv_tt_change_flags_isolate = -1;

static const value_string unicast_4addr_typenames[] = {
	{ UNICAST_4ADDR_DATA, "Data" },
	{ UNICAST_4ADDR_DAT_DHT_GET, "DHT Get" },
	{ UNICAST_4ADDR_DAT_DHT_PUT, "DHT Put" },
	{ UNICAST_4ADDR_DAT_CACHE_REPLY, "DHT Cache Reply" },
	{ 0, NULL }
};

static const value_string tvlv_v15_typenames[] = {
	{ BATADV_TVLV_V15_GW, "Gateway information" },
	{ BATADV_TVLV_V15_DAT, "Distributed ARP Table" },
	{ BATADV_TVLV_V15_NC, "Network Coding" },
	{ BATADV_TVLV_V15_TT, "Translation Table" },
	{ BATADV_TVLV_V15_ROAM, "Roaming" },
	{ BATADV_TVLV_V15_MCAST, "Multicast" },
	{ 0, NULL }
};

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

static const value_string tvlv_tt_typenames[] = {
	{BATADV_TVLVL_TT_OGM_DIFF, "OGM Diff"},
	{BATADV_TVLVL_TT_REQUEST, "Request"},
	{BATADV_TVLVL_TT_RESPONSE, "Response"},
	{0, NULL}
};

static const int * batman_v5_flags[] = {
	&hf_batadv_batman_flags_directlink,
	&hf_batadv_batman_flags_vis_server,
	NULL
};

static const int * batman_v9_flags[] = {
	&hf_batadv_batman_flags_directlink,
	&hf_batadv_batman_flags_vis_server,
	&hf_batadv_batman_flags_primaries_first_hop,
	NULL
};

static const int * batman_v14_flags[] = {
	&hf_batadv_batman_flags_directlink,
	&hf_batadv_batman_flags_vis_server,
	&hf_batadv_batman_flags_primaries_first_hop,
	&hf_batadv_batman_flags_not_best_next_hop,
	NULL
};

static const int * unicast_frag_flags[] = {
	&hf_batadv_unicast_frag_flags_head,
	&hf_batadv_unicast_frag_flags_largetail,
	NULL
};

static const int * tt_query_flags[] = {
	&hf_batadv_tt_query_flags_type,
	&hf_batadv_tt_query_flags_full_table,
	NULL
};

static const int * tt_entry_flags[] = {
	&hf_batadv_tt_entry_flags_change_del,
	&hf_batadv_tt_entry_flags_client_roam,
	NULL
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
	/* Reassembled data field */
	NULL,
	/* Tag */
	"Message fragments"
};


/* forward declaration */
void proto_register_batadv(void);
void proto_reg_handoff_batadv(void);

static dissector_handle_t batman_handle;

/* supported packet dissectors */
static void dissect_batadv_v5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_batman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v7(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v9(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v10(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v11(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_batman_v14(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_iv_ogm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_batadv_iv_ogm_v15(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_bcast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_bcast_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_bcast_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_bcast_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_icmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_icmp_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_icmp_v7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_icmp_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_icmp_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_unicast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_unicast_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_unicast_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_unicast_4addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_unicast_4addr_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_unicast_frag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_unicast_frag_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_unicast_frag_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_unicast_frag_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

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

static void dissect_batadv_coded(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_coded_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_unicast_tvlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_unicast_tvlv_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_batadv_tvlv_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_batadv_tvlv_v15_header(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint8 type);
static void dissect_batadv_tvlv_v15_dat(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint8 version);
static void dissect_batadv_tvlv_v15_nc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint8 version);
static void dissect_batadv_tvlv_v15_mcast(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint8 version);
static void dissect_batadv_tvlv_v15_gw(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint8 version);
static void dissect_batadv_tvlv_v15_roam(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint8 version);
static void dissect_batadv_tvlv_v15_tt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint8 version);
static int dissect_batadv_tvlv_v15_tt_vlan(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset);
static int dissect_batadv_tvlv_v15_tt_change(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset);


/* other dissectors */
static dissector_handle_t eth_handle;

static int proto_batadv_plugin = -1;

/* tap */
static int batadv_tap = -1;
static int batadv_follow_tap = -1;

/* segmented messages */
static reassembly_table msg_reassembly_table;

static unsigned int batadv_ethertype = ETH_P_BATMAN;

static int dissect_batadv_plugin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint8 version;

	col_clear(pinfo->cinfo, COL_INFO);

	version = tvb_get_guint8(tvb, 1);
	if (version < 15)
		dissect_batadv_v5(tvb, pinfo, tree);
	else
		dissect_batadv_v15(tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

static void dissect_batadv_v5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 type;

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
	case BATADV_UNICAST_4ADDR_V14:
		dissect_batadv_unicast_4addr(tvb, pinfo, tree);
		break;
	default:
		/* dunno */
	{
		tvbuff_t *next_tvb;
		gint length_remaining;

		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_???");

		length_remaining = tvb_reported_length_remaining(tvb, 0);
		if (length_remaining > 0) {
			next_tvb = tvb_new_subset_remaining(tvb, 0);
			call_data_dissector(next_tvb, pinfo, tree);
		}
		break;
	}
	}
}

static void dissect_batadv_v15(tvbuff_t *tvb, packet_info *pinfo,
			       proto_tree *tree)
{
	guint8 type;

	type = tvb_get_guint8(tvb, 0);

	switch (type) {
	case BATADV_IV_OGM_V15:
		dissect_batadv_iv_ogm(tvb, pinfo, tree);
		break;
	case BATADV_BCAST_V15:
		dissect_batadv_bcast(tvb, pinfo, tree);
		break;
	case BATADV_CODED_V15:
		dissect_batadv_coded(tvb, pinfo, tree);
		break;
	case BATADV_UNICAST_V15:
		dissect_batadv_unicast(tvb, pinfo, tree);
		break;
	case BATADV_UNICAST_FRAG_V15:
		dissect_batadv_unicast_frag(tvb, pinfo, tree);
		break;
	case BATADV_UNICAST_4ADDR_V15:
		dissect_batadv_unicast_4addr(tvb, pinfo, tree);
		break;
	case BATADV_ICMP_V15:
		dissect_batadv_icmp(tvb, pinfo, tree);
		break;
	case BATADV_UNICAST_TVLV_V15:
		dissect_batadv_unicast_tvlv(tvb, pinfo, tree);
		break;
	default:
		/* dunno */
	{
		tvbuff_t *next_tvb;
		gint length_remaining;

		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_???");

		length_remaining = tvb_captured_length_remaining(tvb, 0);
		if (length_remaining > 0) {
			next_tvb = tvb_new_subset_remaining(tvb, 0);
			call_data_dissector(next_tvb, pinfo, tree);
		}
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
		while (offset != -1 && tvb_reported_length_remaining(tvb, offset) >= BATMAN_PACKET_V5_SIZE) {
			offset = dissect_batadv_batman_v5(tvb, offset, pinfo, tree);
		}
		break;
	case 7:
	case 8:
		while (offset != -1 && tvb_reported_length_remaining(tvb, offset) >= BATMAN_PACKET_V7_SIZE) {
			offset = dissect_batadv_batman_v7(tvb, offset, pinfo, tree);
		}
		break;
	case 9:
		while (offset != -1 && tvb_reported_length_remaining(tvb, offset) >= BATMAN_PACKET_V9_SIZE) {
			offset = dissect_batadv_batman_v9(tvb, offset, pinfo, tree);
		}
		break;
	case 11:
	case 13:
		while (offset != -1 && tvb_reported_length_remaining(tvb, offset) >= BATMAN_PACKET_V11_SIZE) {
			offset = dissect_batadv_batman_v11(tvb, offset, pinfo, tree);
		}
		break;
	case 10:
	case 12:
		while (offset != -1 && tvb_reported_length_remaining(tvb, offset) >= BATMAN_PACKET_V10_SIZE) {
			offset = dissect_batadv_batman_v10(tvb, offset, pinfo, tree);
		}
		break;
	case 14:
		while (offset != -1 && tvb_reported_length_remaining(tvb, offset) >= BATMAN_PACKET_V14_SIZE) {
			offset = dissect_batadv_batman_v14(tvb, offset, pinfo, tree);
		}
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_data_dissector(tvb, pinfo, tree);
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
	proto_tree_add_uint_format_value(gwflags_tree, hf_batadv_batman_gwflags_dl_speed, tvb, offset, 1, down, "%dkbit", down);
	proto_tree_add_uint_format_value(gwflags_tree, hf_batadv_batman_gwflags_ul_speed, tvb, offset, 1, up, "%dkbit", up);
}

static int dissect_batadv_batman_v5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tgw;
	proto_tree *batadv_batman_tree = NULL;
	guint8 type;
	struct batman_packet_v5 *batman_packeth;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = (struct batman_packet_v5 *)wmem_alloc(wmem_packet_scope(), sizeof(struct batman_packet_v5));

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
	set_address_tvb(&batman_packeth->orig, AT_ETHER, 6, tvb, offset+8);
	copy_address_shallow(&pinfo->dl_src, &batman_packeth->orig);
	copy_address_shallow(&pinfo->src, &batman_packeth->orig);
	set_address_tvb(&batman_packeth->prev_sender, AT_ETHER, 6, tvb, offset+14);

	batman_packeth->num_tt = tvb_get_guint8(tvb, offset+20);
	batman_packeth->pad = tvb_get_guint8(tvb, offset+21);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V5_SIZE,
							    "B.A.T.M.A.N., Orig: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &batman_packeth->orig));
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET_V5,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET_V5);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(batadv_batman_tree, tvb, offset, hf_batadv_batman_flags,
					ett_batadv_batman_flags, batman_v5_flags, ENC_BIG_ENDIAN);
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

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_num_tt, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_tt; i++) {
		next_tvb = tvb_new_subset_length(tvb, offset, 6);

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
	proto_tree *batadv_batman_tree = NULL;
	guint8 type;
	struct batman_packet_v7 *batman_packeth;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = (struct batman_packet_v7 *)wmem_alloc(wmem_packet_scope(), sizeof(struct batman_packet_v7));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET_V5) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohs(tvb, offset+4);
	set_address_tvb(&batman_packeth->orig, AT_ETHER, 6, tvb, offset+6);
	copy_address_shallow(&pinfo->dl_src, &batman_packeth->orig);
	copy_address_shallow(&pinfo->src, &batman_packeth->orig);
	set_address_tvb(&batman_packeth->prev_sender, AT_ETHER, 6, tvb, offset+12);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+18);
	batman_packeth->num_tt = tvb_get_guint8(tvb, offset+19);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V7_SIZE,
							    "B.A.T.M.A.N., Orig: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &batman_packeth->orig));
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET_V5,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET_V5);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(batadv_batman_tree, tvb, offset, hf_batadv_batman_flags,
					ett_batadv_batman_flags, batman_v5_flags, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_num_tt, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_tt; i++) {
		next_tvb = tvb_new_subset_length(tvb, offset, 6);

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
	proto_item *tgw;
	proto_tree *batadv_batman_tree = NULL;
	guint8 type;
	struct batman_packet_v9 *batman_packeth;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = (struct batman_packet_v9 *)wmem_alloc(wmem_packet_scope(), sizeof(struct batman_packet_v9));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET_V5) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohs(tvb, offset+4);
	set_address_tvb(&batman_packeth->orig, AT_ETHER, 6, tvb, offset+6);
	copy_address_shallow(&pinfo->dl_src, &batman_packeth->orig);
	copy_address_shallow(&pinfo->src, &batman_packeth->orig);
	set_address_tvb(&batman_packeth->prev_sender, AT_ETHER, 6, tvb, offset+12);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+18);
	batman_packeth->num_tt = tvb_get_guint8(tvb, offset+19);
	batman_packeth->gwflags = tvb_get_guint8(tvb, offset+20);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V9_SIZE,
							    "B.A.T.M.A.N., Orig: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &batman_packeth->orig));
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET_V5,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET_V5);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(batadv_batman_tree, tvb, offset, hf_batadv_batman_flags,
					ett_batadv_batman_flags, batman_v9_flags, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, ENC_NA);
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

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_tt; i++) {
		next_tvb = tvb_new_subset_length(tvb, offset, 6);

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
	proto_item *tgw;
	proto_tree *batadv_batman_tree = NULL;
	guint8 type;
	struct batman_packet_v10 *batman_packeth;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = (struct batman_packet_v10 *)wmem_alloc(wmem_packet_scope(), sizeof(struct batman_packet_v10));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET_V5) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohl(tvb, offset+4);
	set_address_tvb(&batman_packeth->orig, AT_ETHER, 6, tvb, offset+8);
	copy_address_shallow(&pinfo->dl_src, &batman_packeth->orig);
	copy_address_shallow(&pinfo->src, &batman_packeth->orig);
	set_address_tvb(&batman_packeth->prev_sender, AT_ETHER, 6, tvb, offset+14);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+20);
	batman_packeth->num_tt = tvb_get_guint8(tvb, offset+21);
	batman_packeth->gwflags = tvb_get_guint8(tvb, offset+22);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V10_SIZE,
							    "B.A.T.M.A.N., Orig: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &batman_packeth->orig));
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET_V5,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET_V5);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(batadv_batman_tree, tvb, offset, hf_batadv_batman_flags,
					ett_batadv_batman_flags, batman_v9_flags, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, ENC_NA);
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

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_tt; i++) {
		next_tvb = tvb_new_subset_length(tvb, offset, 6);

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
	proto_tree *batadv_batman_tree = NULL;
	guint8 type;
	struct batman_packet_v11 *batman_packeth;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = (struct batman_packet_v11 *)wmem_alloc(wmem_packet_scope(), sizeof(struct batman_packet_v11));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET_V5) {
		return -1;
	}

	batman_packeth->flags = tvb_get_guint8(tvb, offset+2);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohl(tvb, offset+4);
	set_address_tvb(&batman_packeth->orig, AT_ETHER, 6, tvb, offset+8);
	copy_address_shallow(&pinfo->dl_src, &batman_packeth->orig);
	copy_address_shallow(&pinfo->src, &batman_packeth->orig);
	set_address_tvb(&batman_packeth->prev_sender, AT_ETHER, 6, tvb, offset+14);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+20);
	batman_packeth->num_tt = tvb_get_guint8(tvb, offset+21);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V11_SIZE,
							    "B.A.T.M.A.N., Orig: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &batman_packeth->orig));
		batadv_batman_tree = proto_item_add_subtree(ti, ett_batadv_batman);
	}

	/* items */
	proto_tree_add_uint_format(batadv_batman_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_PACKET_V5,
					"Packet Type: %s (%u)", "BATADV_PACKET", BATADV_PACKET_V5);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(batadv_batman_tree, tvb, offset, hf_batadv_batman_flags,
					ett_batadv_batman_flags, batman_v9_flags, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_tq, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_num_tt, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->num_tt; i++) {
		next_tvb = tvb_new_subset_length(tvb, offset, 6);

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
	proto_item *tgw;
	proto_tree *batadv_batman_tree = NULL;
	guint8 type;
	struct batman_packet_v14 *batman_packeth;
	gint i;

	tvbuff_t *next_tvb;
	gint length_remaining;

	batman_packeth = (struct batman_packet_v14 *)wmem_alloc(wmem_packet_scope(), sizeof(struct batman_packet_v14));

	type = tvb_get_guint8(tvb, offset+0);
	batman_packeth->version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (batman_packeth->version == 0 || type != BATADV_PACKET_V5) {
		return -1;
	}

	batman_packeth->ttl = tvb_get_guint8(tvb, offset+2);
	batman_packeth->flags = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohl(tvb, offset+4);
	set_address_tvb(&batman_packeth->orig, AT_ETHER, 6, tvb, offset+8);
	copy_address_shallow(&pinfo->dl_src, &batman_packeth->orig);
	copy_address_shallow(&pinfo->src, &batman_packeth->orig);
	set_address_tvb(&batman_packeth->prev_sender, AT_ETHER, 6, tvb, offset+14);
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

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, offset, BATMAN_PACKET_V14_SIZE,
							    "B.A.T.M.A.N., Orig: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &batman_packeth->orig));
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

	proto_tree_add_bitmask(batadv_batman_tree, tvb, offset, hf_batadv_batman_flags,
					ett_batadv_batman_flags, batman_v14_flags, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_seqno32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_batman_tree, hf_batadv_batman_prev_sender, tvb, offset, 6, ENC_NA);
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

	tap_queue_packet(batadv_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->tt_num_changes; i++) {
		next_tvb = tvb_new_subset_length(tvb, offset, TT_ENTRY_V14_SIZE);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_tt_entry_v14(next_tvb, pinfo, batadv_batman_tree);
		offset += TT_ENTRY_V14_SIZE;
	}

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		call_data_dissector(next_tvb, pinfo, tree);
	}

	return offset;
}

static void dissect_batadv_iv_ogm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;
	int offset = 0;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_IV_OGM");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 15:
		while (offset != -1 &&
		       tvb_captured_length_remaining(tvb, offset) >= IV_OGM_PACKET_V15_SIZE) {
			offset = dissect_batadv_iv_ogm_v15(tvb, offset, pinfo, tree);
		}
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_data_dissector(tvb, pinfo, tree);
		break;
	}
}

static int dissect_batadv_iv_ogm_v15(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree)
{
	proto_tree *batadv_iv_ogm_tree = NULL;
	guint8 type, version;
	struct iv_ogm_packet_v15 *iv_ogm_packeth;
	tvbuff_t *next_tvb;
	static const int * flags[] = {
		&hf_batadv_iv_ogm_flags_directlink,
		&hf_batadv_iv_ogm_flags_primaries_first_hop,
		&hf_batadv_iv_ogm_flags_not_best_next_hop,
		NULL
	};

	type = tvb_get_guint8(tvb, offset+0);
	version = tvb_get_guint8(tvb, offset+1);

	/* don't interpret padding as B.A.T.M.A.N. advanced packet */
	if (version == 0 || type != BATADV_IV_OGM_V15)
		return -1;

	iv_ogm_packeth = (struct iv_ogm_packet_v15 *)wmem_alloc(wmem_packet_scope(),
								sizeof(struct iv_ogm_packet_v15));

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", iv_ogm_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin,
						    tvb, offset,
						    IV_OGM_PACKET_V15_SIZE + iv_ogm_packeth->tvlv_len,
						    "B.A.T.M.A.N. IV OGM, Orig: %s",
						    tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_ETHER, offset + 8));
		batadv_iv_ogm_tree = proto_item_add_subtree(ti, ett_batadv_iv_ogm);
	}

	/* items */
	iv_ogm_packeth->packet_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format_value(batadv_iv_ogm_tree,
					 hf_batadv_packet_type,
					 tvb, offset, 1, BATADV_IV_OGM_V15,
					 "%s (%u)", "BATADV_IV_OGM",
					 BATADV_IV_OGM_V15);
	offset += 1;

	iv_ogm_packeth->version = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_iv_ogm_tree, hf_batadv_iv_ogm_version, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	iv_ogm_packeth->ttl = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_iv_ogm_tree, hf_batadv_iv_ogm_ttl, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	iv_ogm_packeth->flags = tvb_get_guint8(tvb, offset);
	proto_tree_add_bitmask(batadv_iv_ogm_tree, tvb, offset,
			       hf_batadv_iv_ogm_flags, ett_batadv_iv_ogm_flags,
			       flags, ENC_NA);
	offset += 1;

	iv_ogm_packeth->seqno = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(batadv_iv_ogm_tree, hf_batadv_iv_ogm_seqno, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	set_address_tvb(&iv_ogm_packeth->orig, AT_ETHER, 6, tvb, offset);
	set_address_tvb(&pinfo->dl_src, AT_ETHER, 6, tvb, offset);
	set_address_tvb(&pinfo->src, AT_ETHER, 6, tvb, offset);
	proto_tree_add_item(batadv_iv_ogm_tree, hf_batadv_iv_ogm_orig, tvb,
			    offset, 6, ENC_NA);
	offset += 6;

	set_address_tvb(&iv_ogm_packeth->prev_sender, AT_ETHER, 6, tvb, offset);
	proto_tree_add_item(batadv_iv_ogm_tree, hf_batadv_iv_ogm_prev_sender, tvb,
			    offset, 6, ENC_NA);
	offset += 6;

	/* Skip 1 byte of padding. */
	iv_ogm_packeth->reserved = tvb_get_guint8(tvb, offset);
	offset += 1;

	iv_ogm_packeth->tq = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_iv_ogm_tree, hf_batadv_iv_ogm_tq, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	iv_ogm_packeth->tvlv_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(batadv_iv_ogm_tree, hf_batadv_iv_ogm_tvlv_len, tvb,
			    offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	tap_queue_packet(batadv_tap, pinfo, iv_ogm_packeth);

	if (iv_ogm_packeth->tvlv_len > 0) {
		next_tvb = tvb_new_subset_length(tvb, offset,
						 iv_ogm_packeth->tvlv_len);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_batadv_tvlv_v15(next_tvb, pinfo, batadv_iv_ogm_tree);
		offset += iv_ogm_packeth->tvlv_len;
	}

	return offset;
}

static void dissect_batadv_tt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree *batadv_batman_tt_tree;
	proto_item *ti;

	/* Set tree info */
	ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, 6,
							"B.A.T.M.A.N. TT: %s",
							tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_ETHER, 0));
	batadv_batman_tt_tree = proto_item_add_subtree(ti, ett_batadv_batman_tt);

	proto_tree_add_item(batadv_batman_tt_tree, hf_batadv_batman_tt, tvb, 0, 6, ENC_NA);
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
	case 15:
		dissect_batadv_bcast_v14(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_data_dissector(tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_bcast_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct bcast_packet_v6 *bcast_packeth;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0;
	proto_tree *batadv_bcast_tree = NULL;

	bcast_packeth = (struct bcast_packet_v6 *)wmem_alloc(wmem_packet_scope(), sizeof(struct bcast_packet_v6));

	bcast_packeth->version = tvb_get_guint8(tvb, 1);
	set_address_tvb(&bcast_packeth->orig, AT_ETHER, 6, tvb, 2);
	copy_address_shallow(&pinfo->dl_src, &bcast_packeth->orig);
	copy_address_shallow(&pinfo->src, &bcast_packeth->orig);
	bcast_packeth->seqno = tvb_get_ntohs(tvb, 8);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", bcast_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, BCAST_PACKET_V6_SIZE,
							    "B.A.T.M.A.N. Bcast, Orig: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &bcast_packeth->orig));
		batadv_bcast_tree = proto_item_add_subtree(ti, ett_batadv_bcast);
	}

	/* items */
	proto_tree_add_uint_format(batadv_bcast_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_BCAST_V5,
					"Packet Type: %s (%u)", "BATADV_BCAST", BATADV_BCAST_V5);
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	tap_queue_packet(batadv_tap, pinfo, bcast_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(eth_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_bcast_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct bcast_packet_v10 *bcast_packeth;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0;
	proto_tree *batadv_bcast_tree = NULL;

	bcast_packeth = (struct bcast_packet_v10 *)wmem_alloc(wmem_packet_scope(), sizeof(struct bcast_packet_v10));

	bcast_packeth->version = tvb_get_guint8(tvb, 1);
	set_address_tvb(&bcast_packeth->orig, AT_ETHER, 6, tvb, 2);
	copy_address_shallow(&pinfo->dl_src, &bcast_packeth->orig);
	copy_address_shallow(&pinfo->src, &bcast_packeth->orig);
	bcast_packeth->ttl = tvb_get_guint8(tvb, 8);
	bcast_packeth->seqno = tvb_get_ntohl(tvb, 9);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", bcast_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, BCAST_PACKET_V10_SIZE,
							    "B.A.T.M.A.N. Bcast, Orig: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &bcast_packeth->orig));
		batadv_bcast_tree = proto_item_add_subtree(ti, ett_batadv_bcast);
	}

	/* items */
	proto_tree_add_uint_format(batadv_bcast_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_BCAST_V5,
					"Packet Type: %s (%u)", "BATADV_BCAST", BATADV_BCAST_V5);
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_seqno32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	tap_queue_packet(batadv_tap, pinfo, bcast_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(eth_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_bcast_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct bcast_packet_v14 *bcast_packeth;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0;
	proto_tree *batadv_bcast_tree = NULL;

	bcast_packeth = (struct bcast_packet_v14 *)wmem_alloc(wmem_packet_scope(), sizeof(struct bcast_packet_v14));

	bcast_packeth->packet_type = tvb_get_guint8(tvb, 0);
	bcast_packeth->version = tvb_get_guint8(tvb, 1);
	bcast_packeth->ttl = tvb_get_guint8(tvb, 2);
	bcast_packeth->reserved = tvb_get_guint8(tvb, 3);
	bcast_packeth->seqno = tvb_get_ntohl(tvb, 4);
	set_address_tvb(&bcast_packeth->orig, AT_ETHER, 6, tvb, 8);
	copy_address_shallow(&pinfo->dl_src, &bcast_packeth->orig);
	copy_address_shallow(&pinfo->src, &bcast_packeth->orig);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", bcast_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, BCAST_PACKET_V14_SIZE,
							    "B.A.T.M.A.N. Bcast, Orig: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &bcast_packeth->orig));
		batadv_bcast_tree = proto_item_add_subtree(ti, ett_batadv_bcast);
	}

	/* items */
	proto_tree_add_uint_format_value(batadv_bcast_tree,
					 hf_batadv_packet_type, tvb, offset, 1,
					 bcast_packeth->packet_type,
					 "%s (%u)", "BATADV_BCAST",
					 bcast_packeth->packet_type);
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_seqno32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(batadv_bcast_tree, hf_batadv_bcast_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	tap_queue_packet(batadv_tap, pinfo, bcast_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

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
	case 15:
		dissect_batadv_icmp_v15(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_data_dissector(tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_icmp_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct icmp_packet_v6 *icmp_packeth;
	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0;
	proto_tree *batadv_icmp_tree = NULL;

	icmp_packeth = (struct icmp_packet_v6 *)wmem_alloc(wmem_packet_scope(), sizeof(struct icmp_packet_v6));

	icmp_packeth->version = tvb_get_guint8(tvb, 1);
	icmp_packeth->msg_type = tvb_get_guint8(tvb, 2);
	set_address_tvb(&icmp_packeth->dst, AT_ETHER, 6, tvb, 3);
	set_address_tvb(&icmp_packeth->orig, AT_ETHER, 6, tvb, 9);

	copy_address_shallow(&pinfo->dl_src, &icmp_packeth->orig);
	copy_address_shallow(&pinfo->src, &icmp_packeth->orig);
	copy_address_shallow(&pinfo->dl_dst, &icmp_packeth->dst);
	copy_address_shallow(&pinfo->dst, &icmp_packeth->dst);

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

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, ICMP_PACKET_V6_SIZE,
							    "B.A.T.M.A.N. ICMP, Orig: %s, Dst: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &icmp_packeth->orig),
							    address_with_resolution_to_str(wmem_packet_scope(), &icmp_packeth->dst));
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

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_dst, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_uid, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	tap_queue_packet(batadv_tap, pinfo, icmp_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		call_data_dissector(next_tvb, pinfo, tree);
	}
}

static void
dissect_batadv_icmp_rr(proto_tree *batadv_icmp_tree, tvbuff_t *tvb, int offset)
{
	proto_tree *field_tree;
	int ptr, i;

	ptr = tvb_get_guint8(tvb, offset);
	if (ptr < 1 || ptr > BAT_RR_LEN)
		return;

	field_tree = proto_tree_add_subtree(batadv_icmp_tree, tvb, offset, 1+ 6 * BAT_RR_LEN,
										ett_batadv_icmp_rr, NULL, "ICMP RR");
	proto_tree_add_item(field_tree, hf_batadv_icmp_rr_pointer, tvb, offset, 1, ENC_BIG_ENDIAN);

	ptr--;
	offset++;
	for (i = 0; i < BAT_RR_LEN; i++) {
		proto_tree_add_ether_format(field_tree, hf_batadv_icmp_rr_ether, tvb, offset, 6, tvb_get_ptr(tvb, offset, 6),
				    "%s%s", (i > ptr) ? "-" : tvb_ether_to_str(tvb, offset),
				    (i == ptr) ? " <- (current)" : "");

		offset += 6;
	}
}

static void
dissect_batadv_icmp_rr_v15(proto_tree *batadv_icmp_tree, tvbuff_t *tvb,
			   int offset, int ptr)
{
	proto_tree *field_tree;
	int i;

	field_tree = proto_tree_add_subtree(batadv_icmp_tree, tvb, offset,
					    6 * BAT_RR_LEN,
					    ett_batadv_icmp_rr, NULL,
					    "ICMP RR");
	ptr--;

	for (i = 0; i < BAT_RR_LEN; i++) {
		proto_tree_add_ether_format(field_tree, hf_batadv_icmp_rr_ether,
					    tvb, offset, 6,
					    tvb_get_ptr(tvb, offset, 6),
					    "%s%s",
					    (i > ptr) ? "-" : tvb_ether_to_str(tvb, offset),
					    (i == ptr) ? " <- (current)" : "");

		offset += 6;
	}
}

static void dissect_batadv_icmp_v7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct icmp_packet_v7 *icmp_packeth;
	proto_item *ti;
	proto_tree *batadv_icmp_tree = NULL;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0;

	icmp_packeth = (struct icmp_packet_v7 *)wmem_alloc(wmem_packet_scope(), sizeof(struct icmp_packet_v7));

	icmp_packeth->version = tvb_get_guint8(tvb, 1);
	icmp_packeth->msg_type = tvb_get_guint8(tvb, 2);
	icmp_packeth->ttl = tvb_get_guint8(tvb, 3);
	set_address_tvb(&icmp_packeth->dst, AT_ETHER, 6, tvb, 4);
	set_address_tvb(&icmp_packeth->orig, AT_ETHER, 6, tvb, 10);

	copy_address_shallow(&pinfo->dl_src, &icmp_packeth->orig);
	copy_address_shallow(&pinfo->src, &icmp_packeth->orig);
	copy_address_shallow(&pinfo->dl_dst, &icmp_packeth->dst);
	copy_address_shallow(&pinfo->dst, &icmp_packeth->dst);

	icmp_packeth->seqno = tvb_get_ntohs(tvb, 16);
	icmp_packeth->uid = tvb_get_guint8(tvb, 17);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
		     val_to_str(icmp_packeth->msg_type, icmp_packettypenames, "Unknown (0x%02x)"),
		     icmp_packeth->seqno);

	/* Set tree info */
	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, ICMP_PACKET_V7_SIZE,
								"B.A.T.M.A.N. ICMP, Orig: %s, Dst: %s",
								address_with_resolution_to_str(wmem_packet_scope(), &icmp_packeth->orig),
								address_with_resolution_to_str(wmem_packet_scope(), &icmp_packeth->dst));
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

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_dst, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_uid, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* rr data available? */
	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining >= 1 + BAT_RR_LEN * 6) {
		dissect_batadv_icmp_rr(batadv_icmp_tree, tvb, offset);
		offset += 1 + BAT_RR_LEN * 6;
	}

	tap_queue_packet(batadv_tap, pinfo, icmp_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		call_data_dissector(next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_icmp_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct icmp_packet_v14 *icmp_packeth;
	proto_item *ti;
	proto_tree *batadv_icmp_tree = NULL;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0;

	icmp_packeth = (struct icmp_packet_v14 *)wmem_alloc(wmem_packet_scope(), sizeof(struct icmp_packet_v14));

	icmp_packeth->version = tvb_get_guint8(tvb, 1);
	icmp_packeth->ttl = tvb_get_guint8(tvb, 2);
	icmp_packeth->msg_type = tvb_get_guint8(tvb, 3);
	set_address_tvb(&icmp_packeth->dst, AT_ETHER, 6, tvb, 4);
	set_address_tvb(&icmp_packeth->orig, AT_ETHER, 6, tvb, 10);

	copy_address_shallow(&pinfo->dl_src, &icmp_packeth->orig);
	copy_address_shallow(&pinfo->src, &icmp_packeth->orig);
	copy_address_shallow(&pinfo->dl_dst, &icmp_packeth->dst);
	copy_address_shallow(&pinfo->dst, &icmp_packeth->dst);

	icmp_packeth->seqno = tvb_get_ntohs(tvb, 16);
	icmp_packeth->uid = tvb_get_guint8(tvb, 17);
	icmp_packeth->reserved = tvb_get_guint8(tvb, 18);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
		     val_to_str(icmp_packeth->msg_type, icmp_packettypenames, "Unknown (0x%02x)"),
		     icmp_packeth->seqno);

	/* Set tree info */
	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, ICMP_PACKET_V14_SIZE,
								"B.A.T.M.A.N. ICMP, Orig: %s, Dst: %s",
								address_with_resolution_to_str(wmem_packet_scope(), &icmp_packeth->orig),
								address_with_resolution_to_str(wmem_packet_scope(), &icmp_packeth->dst));
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

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_dst, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_uid, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	/* rr data available? */
	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining >= 1 + BAT_RR_LEN * 6) {
		dissect_batadv_icmp_rr(batadv_icmp_tree, tvb, offset);
		offset += 1 + BAT_RR_LEN * 6;
	}

	tap_queue_packet(batadv_tap, pinfo, icmp_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);
		call_data_dissector(next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_icmp_v15(tvbuff_t *tvb, packet_info *pinfo,
				    proto_tree *tree)
{
	struct icmp_packet_v15 *icmp_packeth;
	proto_item *ti;
	proto_tree *batadv_icmp_tree = NULL;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0;

	icmp_packeth = (struct icmp_packet_v15 *)wmem_alloc(wmem_packet_scope(),
							    sizeof(struct icmp_packet_v15));

	icmp_packeth->msg_type = tvb_get_guint8(tvb, offset + 4);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
		     val_to_str(icmp_packeth->msg_type, icmp_packettypenames,
				"Unknown (0x%02x)"),
		     icmp_packeth->seqno);

	/* Set tree info */
	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin,
						    tvb, 0, ICMP_PACKET_V14_SIZE,
						    "B.A.T.M.A.N. ICMP, Orig: %s, Dst: %s",
						    tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_ETHER, 10),
						    tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_ETHER, 4));
		batadv_icmp_tree = proto_item_add_subtree(ti, ett_batadv_icmp);
	}

	/* items */
	icmp_packeth->packet_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format_value(batadv_icmp_tree,
					 hf_batadv_packet_type, tvb,
					 offset, 1, icmp_packeth->packet_type,
					 "%s (%u)", "BATADV_ICMP",
					 icmp_packeth->packet_type);
	offset += 1;

	icmp_packeth->version = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_version, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	icmp_packeth->ttl = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_ttl, tvb, offset,
			    1, ENC_BIG_ENDIAN);
	offset += 1;

	icmp_packeth->msg_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_msg_type, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	set_address_tvb(&icmp_packeth->dst, AT_ETHER, 6, tvb, offset);
	copy_address_shallow(&pinfo->dl_dst, &icmp_packeth->dst);
	copy_address_shallow(&pinfo->dst, &icmp_packeth->dst);

	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_dst, tvb, offset,
			    6, ENC_NA);
	offset += 6;

	set_address_tvb(&icmp_packeth->orig, AT_ETHER, 6, tvb, offset);
	copy_address_shallow(&pinfo->dl_src, &icmp_packeth->orig);
	copy_address_shallow(&pinfo->src, &icmp_packeth->orig);
	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_orig, tvb, offset,
			    6, ENC_NA);
	offset += 6;

	icmp_packeth->uid = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_uid, tvb, offset,
			    1, ENC_BIG_ENDIAN);
	offset += 1;

	icmp_packeth->rr_ptr = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_rr_pointer, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	icmp_packeth->seqno = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(batadv_icmp_tree, hf_batadv_icmp_seqno, tvb, offset,
			    2, ENC_BIG_ENDIAN);
	offset += 2;

	/* rr data available? */
	length_remaining = tvb_captured_length_remaining(tvb, offset);
	if (length_remaining >= BAT_RR_LEN * 6) {
		dissect_batadv_icmp_rr_v15(batadv_icmp_tree, tvb, offset,
					   icmp_packeth->rr_ptr);
		offset += BAT_RR_LEN * 6;
	}

	tap_queue_packet(batadv_tap, pinfo, icmp_packeth);

	length_remaining = tvb_captured_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset(tvb, offset, length_remaining, -1);
		call_data_dissector(next_tvb, pinfo, tree);
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
	case 15:
		dissect_batadv_unicast_v14(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_data_dissector(tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_unicast_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct unicast_packet_v6 *unicast_packeth;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0;
	proto_tree *batadv_unicast_tree = NULL;

	unicast_packeth = (struct unicast_packet_v6 *)wmem_alloc(wmem_packet_scope(), sizeof(struct unicast_packet_v6));

	unicast_packeth->version = tvb_get_guint8(tvb, 1);
	set_address_tvb(&unicast_packeth->dest, AT_ETHER, 6, tvb, 2);
	copy_address_shallow(&pinfo->dl_dst, &unicast_packeth->dest);
	copy_address_shallow(&pinfo->dst, &unicast_packeth->dest);

	unicast_packeth->ttl = tvb_get_guint8(tvb, 8);

	/* Set info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, UNICAST_PACKET_V6_SIZE,
							    "B.A.T.M.A.N. Unicast, Dst: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &unicast_packeth->dest));
		batadv_unicast_tree = proto_item_add_subtree(ti, ett_batadv_unicast);
	}

	/* items */
	proto_tree_add_uint_format(batadv_unicast_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_UNICAST_V5,
					"Packet Type: %s (%u)", "BATADV_UNICAST", BATADV_UNICAST_V5);
	offset += 1;

	proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_dst, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tap_queue_packet(batadv_tap, pinfo, unicast_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(eth_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_unicast_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct unicast_packet_v14 *unicast_packeth;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0;
	proto_tree *batadv_unicast_tree = NULL;

	unicast_packeth = (struct unicast_packet_v14 *)wmem_alloc(wmem_packet_scope(), sizeof(struct unicast_packet_v14));

	unicast_packeth->packet_type = tvb_get_guint8(tvb, 0);
	unicast_packeth->version = tvb_get_guint8(tvb, 1);
	unicast_packeth->ttl = tvb_get_guint8(tvb, 2);
	unicast_packeth->ttvn = tvb_get_guint8(tvb, 3);
	set_address_tvb(&unicast_packeth->dest, AT_ETHER, 6, tvb, 4);
	copy_address_shallow(&pinfo->dl_dst, &unicast_packeth->dest);
	copy_address_shallow(&pinfo->dst, &unicast_packeth->dest);

	/* Set info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, UNICAST_PACKET_V14_SIZE,
							    "B.A.T.M.A.N. Unicast, Dst: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &unicast_packeth->dest));
		batadv_unicast_tree = proto_item_add_subtree(ti, ett_batadv_unicast);
	}

	/* items */
	proto_tree_add_uint_format_value(batadv_unicast_tree,
					 hf_batadv_packet_type, tvb, offset, 1,
					 unicast_packeth->packet_type,
					 "%s (%u)",
					 "BATADV_UNICAST",
					 unicast_packeth->packet_type);
	offset += 1;

	proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_ttvn, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_unicast_tree, hf_batadv_unicast_dst, tvb, offset, 6, ENC_NA);
	offset += 6;

	tap_queue_packet(batadv_tap, pinfo, unicast_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_dissector(eth_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_unicast_4addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_UNICAST_4ADDR");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 14:
	case 15:
		dissect_batadv_unicast_4addr_v14(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_data_dissector(tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_unicast_4addr_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct unicast_4addr_packet_v14 *unicast_4addr_packeth;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0;
	proto_tree *batadv_unicast_4addr_tree = NULL;

	unicast_4addr_packeth = (struct unicast_4addr_packet_v14 *)wmem_alloc(wmem_packet_scope(), sizeof(struct unicast_4addr_packet_v14));

	unicast_4addr_packeth->packet_type = tvb_get_guint8(tvb, 0);
	unicast_4addr_packeth->version = tvb_get_guint8(tvb, 1);
	unicast_4addr_packeth->ttl = tvb_get_guint8(tvb, 2);
	unicast_4addr_packeth->ttvn = tvb_get_guint8(tvb, 3);
	set_address_tvb(&unicast_4addr_packeth->dest, AT_ETHER, 6, tvb, 4);
	copy_address_shallow(&pinfo->dl_dst, &unicast_4addr_packeth->dest);
	copy_address_shallow(&pinfo->dst, &unicast_4addr_packeth->dest);

	set_address_tvb(&unicast_4addr_packeth->src, AT_ETHER, 6, tvb, 10);
	copy_address_shallow(&pinfo->dl_src, &unicast_4addr_packeth->src);
	copy_address_shallow(&pinfo->src, &unicast_4addr_packeth->src);
	unicast_4addr_packeth->subtype = tvb_get_guint8(tvb, 16);
	unicast_4addr_packeth->reserved = tvb_get_guint8(tvb, 17);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
		     val_to_str(unicast_4addr_packeth->subtype, unicast_4addr_typenames, "Unknown (0x%02x)"));

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, UNICAST_4ADDR_PACKET_V14_SIZE,
							    "B.A.T.M.A.N. Unicast 4Addr, Dst: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &unicast_4addr_packeth->dest));
		batadv_unicast_4addr_tree = proto_item_add_subtree(ti, ett_batadv_unicast_4addr);
	}

	/* items */
	proto_tree_add_uint_format_value(batadv_unicast_4addr_tree,
					 hf_batadv_packet_type, tvb, offset, 1,
					 unicast_4addr_packeth->packet_type,
					"%s (%u)", "BATADV_UNICAST_4ADDR",
					 unicast_4addr_packeth->packet_type);
	offset += 1;

	proto_tree_add_item(batadv_unicast_4addr_tree, hf_batadv_unicast_4addr_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_unicast_4addr_tree, hf_batadv_unicast_4addr_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_unicast_4addr_tree, hf_batadv_unicast_4addr_ttvn, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_unicast_4addr_tree, hf_batadv_unicast_4addr_dst, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_unicast_4addr_tree, hf_batadv_unicast_4addr_src, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_unicast_4addr_tree, hf_batadv_unicast_4addr_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	tap_queue_packet(batadv_tap, pinfo, unicast_4addr_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

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
	case 15:
		dissect_batadv_unicast_frag_v15(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_data_dissector(tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_unicast_frag_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct unicast_frag_packet_v12 *unicast_frag_packeth;
	gboolean save_fragmented;
	fragment_head *frag_msg = NULL;
	proto_tree *batadv_unicast_frag_tree = NULL;

	tvbuff_t *new_tvb;
	int offset = 0;
	int head = 0;
	gint length_remaining;

	unicast_frag_packeth = (struct unicast_frag_packet_v12 *)wmem_alloc(wmem_packet_scope(), sizeof(struct unicast_frag_packet_v12));

	unicast_frag_packeth->version = tvb_get_guint8(tvb, 1);
	set_address_tvb(&unicast_frag_packeth->dest, AT_ETHER, 6, tvb, 2);
	copy_address_shallow(&pinfo->dl_dst, &unicast_frag_packeth->dest);
	copy_address_shallow(&pinfo->dst, &unicast_frag_packeth->dest);
	unicast_frag_packeth->ttl = tvb_get_guint8(tvb, 8);
	unicast_frag_packeth->flags = tvb_get_guint8(tvb, 9);
	set_address_tvb(&unicast_frag_packeth->orig, AT_ETHER, 6, tvb, 10);
	copy_address_shallow(&pinfo->dl_src, &unicast_frag_packeth->orig);
	copy_address_shallow(&pinfo->src, &unicast_frag_packeth->orig);
	unicast_frag_packeth->seqno = tvb_get_ntohs(tvb, 16);

	save_fragmented = pinfo->fragmented;
	pinfo->fragmented = TRUE;

	/* Set info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, UNICAST_FRAG_PACKET_V12_SIZE,
							    "B.A.T.M.A.N. Unicast Fragment, Dst: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &unicast_frag_packeth->dest));
		batadv_unicast_frag_tree = proto_item_add_subtree(ti, ett_batadv_unicast_frag);
	}

	/* items */
	proto_tree_add_uint_format(batadv_unicast_frag_tree, hf_batadv_packet_type, tvb, offset, 1, BATADV_UNICAST_FRAG_V12,
					"Packet Type: %s (%u)", "BATADV_UNICAST_FRAG", BATADV_UNICAST_FRAG_V12);
	offset += 1;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_dst, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(batadv_unicast_frag_tree, tvb, offset, hf_batadv_unicast_frag_flags,
					ett_batadv_batman_flags, unicast_frag_flags, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	tap_queue_packet(batadv_tap, pinfo, unicast_frag_packeth);

	head = (unicast_frag_packeth->flags & 0x1);
	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining < 0)
		length_remaining = 0;
	frag_msg = fragment_add_seq_check(&msg_reassembly_table,
		tvb, offset,
		pinfo, unicast_frag_packeth->seqno + head, NULL,
		1 - head,
		length_remaining,
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
	struct unicast_frag_packet_v14 *unicast_frag_packeth;
	gboolean save_fragmented;
	fragment_head *frag_msg = NULL;
	proto_tree *batadv_unicast_frag_tree = NULL;

	tvbuff_t *new_tvb;
	int offset = 0;
	int head = 0;
	gint length_remaining;

	unicast_frag_packeth = (struct unicast_frag_packet_v14 *)wmem_alloc(wmem_packet_scope(), sizeof(struct unicast_frag_packet_v14));

	unicast_frag_packeth->version = tvb_get_guint8(tvb, 1);
	unicast_frag_packeth->ttl = tvb_get_guint8(tvb, 2);
	unicast_frag_packeth->ttvn = tvb_get_guint8(tvb, 3);
	set_address_tvb(&unicast_frag_packeth->dest, AT_ETHER, 6, tvb, 4);
	copy_address_shallow(&pinfo->dl_dst, &unicast_frag_packeth->dest);
	copy_address_shallow(&pinfo->dst, &unicast_frag_packeth->dest);
	unicast_frag_packeth->flags = tvb_get_guint8(tvb, 10);
	unicast_frag_packeth->align = tvb_get_guint8(tvb, 11);
	set_address_tvb(&unicast_frag_packeth->orig, AT_ETHER, 6, tvb, 12);
	copy_address_shallow(&pinfo->dl_src, &unicast_frag_packeth->orig);
	copy_address_shallow(&pinfo->src, &unicast_frag_packeth->orig);
	unicast_frag_packeth->seqno = tvb_get_ntohs(tvb, 18);

	save_fragmented = pinfo->fragmented;
	pinfo->fragmented = TRUE;

	/* Set info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, UNICAST_FRAG_PACKET_V14_SIZE,
							    "B.A.T.M.A.N. Unicast Fragment, Dst: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &unicast_frag_packeth->dest));
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

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_dst, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_bitmask(batadv_unicast_frag_tree, tvb, offset, hf_batadv_unicast_frag_flags,
					ett_batadv_batman_flags, unicast_frag_flags, ENC_BIG_ENDIAN);
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	tap_queue_packet(batadv_tap, pinfo, unicast_frag_packeth);

	head = (unicast_frag_packeth->flags & 0x1);
	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining < 0)
		length_remaining = 0;
	frag_msg = fragment_add_seq_check(&msg_reassembly_table,
		tvb, offset,
		pinfo, unicast_frag_packeth->seqno + head, NULL,
		1 - head,
		length_remaining,
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

static void dissect_batadv_unicast_frag_v15(tvbuff_t *tvb, packet_info *pinfo,
					    proto_tree *tree)
{
	struct unicast_frag_packet_v15 *unicast_frag_packeth;
	gboolean save_fragmented;
	fragment_head *frag_msg = NULL;
	proto_tree *batadv_unicast_frag_tree = NULL;

	tvbuff_t *new_tvb;
	int offset = 0;
	int frag_no = 0;
	gint length_remaining;

	unicast_frag_packeth = (struct unicast_frag_packet_v15 *)wmem_alloc(wmem_packet_scope(),
									    sizeof(struct unicast_frag_packet_v15));

	save_fragmented = pinfo->fragmented;
	pinfo->fragmented = TRUE;

	/* Set info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin,
						    tvb, 0,
						    UNICAST_FRAG_PACKET_V15_SIZE,
						    "B.A.T.M.A.N. Unicast Fragment, Dst: %s",
						    tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_ETHER, 4));
		batadv_unicast_frag_tree = proto_item_add_subtree(ti,
								  ett_batadv_unicast_frag);
	}

	/* items */
	unicast_frag_packeth->packet_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format_value(batadv_unicast_frag_tree,
					 hf_batadv_packet_type, tvb, offset, 1,
					 unicast_frag_packeth->packet_type,
					 "%s (%u)", "BATADV_UNICAST",
					 unicast_frag_packeth->packet_type);
	offset += 1;

	unicast_frag_packeth->version = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_unicast_frag_tree,
			    hf_batadv_unicast_frag_version, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
	offset += 1;

	unicast_frag_packeth->ttl = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_unicast_frag_tree,
			    hf_batadv_unicast_frag_ttl, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
	offset += 1;

	unicast_frag_packeth->no = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_no,
			    tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	set_address_tvb(&unicast_frag_packeth->dest, AT_ETHER, 6, tvb, offset);
	copy_address_shallow(&pinfo->dl_dst, &unicast_frag_packeth->dest);
	copy_address_shallow(&pinfo->dst, &unicast_frag_packeth->dest);
	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_dst,
			    tvb, offset, 6, ENC_NA);
	offset += 6;

	set_address_tvb(&unicast_frag_packeth->orig, AT_ETHER, 6, tvb, offset);
	copy_address_shallow(&pinfo->dl_src, &unicast_frag_packeth->orig);
	copy_address_shallow(&pinfo->src, &unicast_frag_packeth->orig);
	proto_tree_add_item(batadv_unicast_frag_tree, hf_batadv_unicast_frag_orig,
			    tvb, offset, 6, ENC_NA);
	offset += 6;

	unicast_frag_packeth->seqno = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(batadv_unicast_frag_tree,
			    hf_batadv_unicast_frag_seqno, tvb, offset, 2,
			    ENC_BIG_ENDIAN);
	offset += 2;

	unicast_frag_packeth->total_size = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(batadv_unicast_frag_tree,
			    hf_batadv_unicast_frag_total_size, tvb, offset, 2,
			    ENC_BIG_ENDIAN);
	offset += 2;

	tap_queue_packet(batadv_tap, pinfo, unicast_frag_packeth);

	frag_no = unicast_frag_packeth->no >> 4;
	/* only support 2 fragments */
	if (frag_no > 1)
		return;

	length_remaining = tvb_captured_length_remaining(tvb, offset);
	if (length_remaining < 0)
		length_remaining = 0;
	frag_msg = fragment_add_seq_check(&msg_reassembly_table,
					  tvb, offset, pinfo,
					  unicast_frag_packeth->seqno, NULL,
					  1 - frag_no, length_remaining, TRUE);

	/* Assemble 2 fragments */
	fragment_set_tot_len(&msg_reassembly_table, pinfo,
			     unicast_frag_packeth->seqno, NULL, 1);

	new_tvb = process_reassembled_data(tvb, offset, pinfo,
		"Reassembled Message", frag_msg, &msg_frag_items,
		NULL, batadv_unicast_frag_tree);
	if (new_tvb) {
		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, new_tvb);
		}

		call_dissector(batman_handle, new_tvb, pinfo, tree);
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
		call_data_dissector(tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_vis_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct vis_packet_v6 *vis_packeth;
	proto_tree *batadv_vis_tree = NULL;

	tvbuff_t *next_tvb;
	guint entry_size;
	gint length_remaining;
	int offset = 0, i;

	vis_packeth = (struct vis_packet_v6 *)wmem_alloc(wmem_packet_scope(), sizeof(struct vis_packet_v6));

	vis_packeth->version = tvb_get_guint8(tvb, 1);
	vis_packeth->vis_type = tvb_get_guint8(tvb, 2);
	vis_packeth->seqno = tvb_get_guint8(tvb, 3);
	vis_packeth->entries = tvb_get_guint8(tvb, 4);
	vis_packeth->ttl = tvb_get_guint8(tvb, 5);

	set_address_tvb(&vis_packeth->vis_orig, AT_ETHER, 6, tvb, 6);
	copy_address_shallow(&pinfo->src, &vis_packeth->vis_orig);
	set_address_tvb(&vis_packeth->target_orig, AT_ETHER, 6, tvb, 12);
	copy_address_shallow(&pinfo->dl_dst, &vis_packeth->target_orig);
	copy_address_shallow(&pinfo->dst, &vis_packeth->target_orig);
	set_address_tvb(&vis_packeth->sender_orig, AT_ETHER, 6, tvb, 18);
	copy_address_shallow(&pinfo->dl_src, &vis_packeth->sender_orig);


	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
		     val_to_str(vis_packeth->vis_type, vis_packettypenames, "Unknown (0x%02x)"),
		     vis_packeth->seqno);
	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_PACKET_V6_SIZE,
							    "B.A.T.M.A.N. Vis, Orig: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &vis_packeth->vis_orig));
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

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_vis_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_target_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_sender_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

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
		next_tvb = tvb_new_subset_length(tvb, offset, entry_size);

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

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_data_dissector(next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_vis_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct vis_packet_v10 *vis_packeth;
	proto_tree *batadv_vis_tree = NULL;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0, i;

	vis_packeth = (struct vis_packet_v10 *)wmem_alloc(wmem_packet_scope(), sizeof(struct vis_packet_v10));

	vis_packeth->version = tvb_get_guint8(tvb, 1);
	vis_packeth->vis_type = tvb_get_guint8(tvb, 2);
	vis_packeth->entries = tvb_get_guint8(tvb, 3);
	vis_packeth->seqno = tvb_get_ntohl(tvb, 4);
	vis_packeth->ttl = tvb_get_guint8(tvb, 8);

	set_address_tvb(&vis_packeth->vis_orig, AT_ETHER, 6, tvb, 9);
	copy_address_shallow(&pinfo->src, &vis_packeth->vis_orig);
	set_address_tvb(&vis_packeth->target_orig, AT_ETHER, 6, tvb, 15);
	copy_address_shallow(&pinfo->dl_dst, &vis_packeth->target_orig);
	copy_address_shallow(&pinfo->dst, &vis_packeth->target_orig);
    set_address_tvb(&vis_packeth->sender_orig, AT_ETHER, 6, tvb, 21);
	copy_address_shallow(&pinfo->dl_src, &vis_packeth->sender_orig);


	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
		     val_to_str(vis_packeth->vis_type, vis_packettypenames, "Unknown (0x%02x)"),
		     vis_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_PACKET_V10_SIZE,
							    "B.A.T.M.A.N. Vis, Orig: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &vis_packeth->vis_orig));
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

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_vis_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_target_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_sender_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	tap_queue_packet(batadv_tap, pinfo, vis_packeth);

	for (i = 0; i < vis_packeth->entries; i++) {
		next_tvb = tvb_new_subset_length(tvb, offset, VIS_ENTRY_V8_SIZE);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_vis_entry_v8(next_tvb, pinfo, batadv_vis_tree);
		offset += VIS_ENTRY_V8_SIZE;
	}

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_data_dissector(next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_vis_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct vis_packet_v14 *vis_packeth;
	proto_tree *batadv_vis_tree = NULL;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0, i;

	vis_packeth = (struct vis_packet_v14 *)wmem_alloc(wmem_packet_scope(), sizeof(struct vis_packet_v14));

	vis_packeth->version = tvb_get_guint8(tvb, 1);
	vis_packeth->ttl = tvb_get_guint8(tvb, 2);
	vis_packeth->vis_type = tvb_get_guint8(tvb, 3);
	vis_packeth->seqno = tvb_get_ntohl(tvb, 4);
	vis_packeth->entries = tvb_get_guint8(tvb, 8);
	vis_packeth->reserved = tvb_get_guint8(tvb, 9);

	set_address_tvb(&vis_packeth->vis_orig, AT_ETHER, 6, tvb, 10);
	copy_address_shallow(&pinfo->src, &vis_packeth->vis_orig);
	set_address_tvb(&vis_packeth->target_orig, AT_ETHER, 6, tvb, 16);
	copy_address_shallow(&pinfo->dl_dst, &vis_packeth->target_orig);
	copy_address_shallow(&pinfo->dst, &vis_packeth->target_orig);
	set_address_tvb(&vis_packeth->sender_orig, AT_ETHER, 6, tvb, 22);
	copy_address_shallow(&pinfo->dl_src, &vis_packeth->sender_orig);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] Seq=%u",
		     val_to_str(vis_packeth->vis_type, vis_packettypenames, "Unknown (0x%02x)"),
		     vis_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_PACKET_V14_SIZE,
							    "B.A.T.M.A.N. Vis, Orig: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &vis_packeth->vis_orig));
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

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_vis_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_target_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_vis_tree, hf_batadv_vis_sender_orig, tvb, offset, 6, ENC_NA);
	offset += 6;

	tap_queue_packet(batadv_tap, pinfo, vis_packeth);

	for (i = 0; i < vis_packeth->entries; i++) {
		next_tvb = tvb_new_subset_length(tvb, offset, VIS_ENTRY_V8_SIZE);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_vis_entry_v8(next_tvb, pinfo, batadv_vis_tree);
		offset += VIS_ENTRY_V8_SIZE;
	}

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_data_dissector(next_tvb, pinfo, tree);
	}
}

static void dissect_vis_entry_v6(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree    *batadv_vis_entry_tree;
	proto_item    *ti;

	ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_ENTRY_V6_SIZE,
							    "VIS Entry: %s",
							    tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_ETHER, 0));
	batadv_vis_entry_tree = proto_item_add_subtree(ti, ett_batadv_vis_entry);

	proto_tree_add_item(batadv_vis_entry_tree, hf_batadv_vis_entry_dst, tvb, 0, 6, ENC_NA);
	proto_tree_add_item(batadv_vis_entry_tree, hf_batadv_vis_entry_quality, tvb, 6, 1, ENC_BIG_ENDIAN);
}

static void dissect_vis_entry_v8(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree *batadv_vis_entry_tree;
	proto_item *ti;

	ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, VIS_ENTRY_V8_SIZE,
							    "VIS Entry: %s",
							    tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_ETHER, 6));
	batadv_vis_entry_tree = proto_item_add_subtree(ti, ett_batadv_vis_entry);

	proto_tree_add_item(batadv_vis_entry_tree, hf_batadv_vis_entry_src, tvb, 0, 6, ENC_NA);
	proto_tree_add_item(batadv_vis_entry_tree, hf_batadv_vis_entry_dst, tvb, 6, 6, ENC_NA);
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
		call_data_dissector(tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_tt_query_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct tt_query_packet_v14 *tt_query_packeth;
	proto_tree *batadv_tt_query_tree = NULL;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0, i;
	int tt_type;

	tt_query_packeth = (struct tt_query_packet_v14 *)wmem_alloc(wmem_packet_scope(), sizeof(struct tt_query_packet_v14));

	tt_query_packeth->version = tvb_get_guint8(tvb, 1);
	tt_query_packeth->ttl = tvb_get_guint8(tvb, 2);
	tt_query_packeth->flags = tvb_get_guint8(tvb, 3);

	set_address_tvb(&tt_query_packeth->dst, AT_ETHER, 6, tvb, 4);
	copy_address_shallow(&pinfo->dl_dst, &tt_query_packeth->dst);
	copy_address_shallow(&pinfo->dst, &tt_query_packeth->dst);

	set_address_tvb(&tt_query_packeth->src, AT_ETHER, 6, tvb, 10);
	copy_address_shallow(&pinfo->dl_src, &tt_query_packeth->src);
	copy_address_shallow(&pinfo->src, &tt_query_packeth->src);

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

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, TT_QUERY_PACKET_V14_SIZE,
							    "B.A.T.M.A.N. TT Query, Dst: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &tt_query_packeth->dst));
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

	proto_tree_add_bitmask(batadv_tt_query_tree, tvb, offset, hf_batadv_tt_query_flags,
					ett_batadv_tt_query_flags, tt_query_flags, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(batadv_tt_query_tree, hf_batadv_tt_query_dst, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_tt_query_tree, hf_batadv_tt_query_src, tvb, offset, 6, ENC_NA);
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

	tap_queue_packet(batadv_tap, pinfo, tt_query_packeth);

	if (tt_type == TT_RESPONSE) {
		for (i = 0; i < tt_query_packeth->tt_data; i++) {
			next_tvb = tvb_new_subset_length(tvb, offset, TT_ENTRY_V14_SIZE);

			if (have_tap_listener(batadv_follow_tap)) {
				tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
			}

			dissect_tt_entry_v14(next_tvb, pinfo, batadv_tt_query_tree);
			offset += TT_ENTRY_V14_SIZE;
		}
	}

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_data_dissector(next_tvb, pinfo, tree);
	}
}

static void dissect_tt_entry_v14(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree *batadv_tt_entry_tree;
	proto_item *ti;

	ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, TT_ENTRY_V14_SIZE,
							    "TT Entry: %s",
							    tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_ETHER, 1));
	batadv_tt_entry_tree = proto_item_add_subtree(ti, ett_batadv_tt_entry);

	proto_tree_add_bitmask(batadv_tt_entry_tree, tvb, 0, hf_batadv_tt_entry_flags,
					ett_batadv_tt_entry_flags, tt_entry_flags, ENC_BIG_ENDIAN);
	proto_tree_add_item(batadv_tt_entry_tree, hf_batadv_tt_entry, tvb, 1, 6, ENC_NA);
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
		call_data_dissector(tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_roam_adv_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct roam_adv_packet_v14 *roam_adv_packeth;
	proto_tree *batadv_roam_adv_tree = NULL;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0;

	roam_adv_packeth = (struct roam_adv_packet_v14 *)wmem_alloc(wmem_packet_scope(), sizeof(struct roam_adv_packet_v14));

	roam_adv_packeth->version = tvb_get_guint8(tvb, 1);
	roam_adv_packeth->ttl = tvb_get_guint8(tvb, 2);
	set_address_tvb(&roam_adv_packeth->dst, AT_ETHER, 6, tvb, 4);
	copy_address_shallow(&pinfo->dl_dst, &roam_adv_packeth->dst);
	copy_address_shallow(&pinfo->dst, &roam_adv_packeth->dst);
	set_address_tvb(&roam_adv_packeth->src, AT_ETHER, 6, tvb, 10);
	copy_address_shallow(&pinfo->dl_src, &roam_adv_packeth->src);
	copy_address_shallow(&pinfo->src, &roam_adv_packeth->src);
	set_address_tvb(&roam_adv_packeth->client, AT_ETHER, 6, tvb, 16);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Client %s", address_with_resolution_to_str(wmem_packet_scope(), &roam_adv_packeth->client));

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin, tvb, 0, ROAM_ADV_PACKET_V14_SIZE,
							    "B.A.T.M.A.N. Roam: %s",
							    address_with_resolution_to_str(wmem_packet_scope(), &roam_adv_packeth->client));
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

	proto_tree_add_item(batadv_roam_adv_tree, hf_batadv_roam_adv_dst, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_roam_adv_tree, hf_batadv_roam_adv_src, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(batadv_roam_adv_tree, hf_batadv_roam_adv_client, tvb, offset, 6, ENC_NA);
	offset += 6;

	tap_queue_packet(batadv_tap, pinfo, roam_adv_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_data_dissector(next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_coded(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_CODED");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 15:
		dissect_batadv_coded_v15(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_data_dissector(tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_coded_v15(tvbuff_t *tvb, packet_info *pinfo,
				     proto_tree *tree)
{
	struct coded_packet_v15 *coded_packeth;
	proto_tree *batadv_coded_tree = NULL;

	tvbuff_t *next_tvb;
	gint length_remaining;
	int offset = 0;

	coded_packeth = (struct coded_packet_v15 *)wmem_alloc(wmem_packet_scope(),
							      sizeof(struct coded_packet_v15));

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin,
						    tvb, 0,
						    CODED_PACKET_V15_SIZE,
						    "B.A.T.M.A.N. Coded");
		batadv_coded_tree = proto_item_add_subtree(ti, ett_batadv_coded);
	}

	/* items */
	coded_packeth->packet_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format_value(batadv_coded_tree,
					 hf_batadv_packet_type,
					 tvb, offset, 1,
					 coded_packeth->packet_type,
					 "%s (%u)", "BATADV_CODED",
					 coded_packeth->packet_type);
	offset += 1;

	coded_packeth->version = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_coded_tree, hf_batadv_coded_version, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	coded_packeth->ttl = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_coded_tree, hf_batadv_coded_ttl, tvb, offset,
			    1, ENC_BIG_ENDIAN);
	offset += 1;

	coded_packeth->first_ttvn = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_coded_tree, hf_batadv_coded_first_ttvn, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	set_address_tvb(&coded_packeth->first_source, AT_ETHER, 6, tvb, offset);
	copy_address_shallow(&pinfo->dl_src, &coded_packeth->first_source);
	copy_address_shallow(&pinfo->src, &coded_packeth->first_source);
	proto_tree_add_item(batadv_coded_tree, hf_batadv_coded_first_source,
			    tvb, offset, 6, ENC_NA);
	offset += 6;

	set_address_tvb(&coded_packeth->first_orig_dest, AT_ETHER, 6, tvb, offset);
	copy_address_shallow(&pinfo->dl_dst, &coded_packeth->first_orig_dest);
	copy_address_shallow(&pinfo->dst, &coded_packeth->first_orig_dest);
	proto_tree_add_item(batadv_coded_tree, hf_batadv_coded_first_orig_dest,
			    tvb, offset, 6, ENC_NA);
	offset += 6;

	coded_packeth->first_crc = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(batadv_coded_tree, hf_batadv_coded_first_crc, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	coded_packeth->second_ttl = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_coded_tree, hf_batadv_coded_second_ttl, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	coded_packeth->second_ttvn = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_coded_tree, hf_batadv_coded_second_ttvn, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	set_address_tvb(&coded_packeth->second_dest, AT_ETHER, 6, tvb, offset);
	proto_tree_add_item(batadv_coded_tree, hf_batadv_coded_second_dest,
			    tvb, offset, 6, ENC_NA);
	offset += 6;

	set_address_tvb(&coded_packeth->second_source, AT_ETHER, 6, tvb, offset);
	proto_tree_add_item(batadv_coded_tree, hf_batadv_coded_second_source,
			    tvb, offset, 6, ENC_NA);
	offset += 6;

	set_address_tvb(&coded_packeth->second_orig_dest, AT_ETHER, 6, tvb, offset);
	proto_tree_add_item(batadv_coded_tree, hf_batadv_coded_second_orig_dest,
			    tvb, offset, 6, ENC_NA);
	offset += 6;

	coded_packeth->second_crc = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(batadv_coded_tree, hf_batadv_coded_second_crc, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	coded_packeth->coded_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(batadv_coded_tree, hf_batadv_coded_coded_len, tvb,
			    offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	tap_queue_packet(batadv_tap, pinfo, coded_packeth);

	length_remaining = tvb_captured_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		call_data_dissector(next_tvb, pinfo, tree);
	}
}

static void dissect_batadv_unicast_tvlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BATADV_UNICAST_TVLV");

	version = tvb_get_guint8(tvb, 1);
	switch (version) {
	case 15:
		dissect_batadv_unicast_tvlv_v15(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d",
			     version);
		call_data_dissector(tvb, pinfo, tree);
		break;
	}
}

static void dissect_batadv_unicast_tvlv_v15(tvbuff_t *tvb, packet_info *pinfo,
					    proto_tree *tree)
{
	struct unicast_tvlv_packet_v15 *unicast_tvlv_packeth;

	tvbuff_t *next_tvb;
	int offset = 0;
	proto_tree *batadv_unicast_tvlv_tree = NULL;

	unicast_tvlv_packeth = (struct unicast_tvlv_packet_v15 *)wmem_alloc(wmem_packet_scope(),
									    sizeof(struct unicast_tvlv_packet_v15));

	/* Set info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		unicast_tvlv_packeth->tvlv_len = tvb_get_ntohs(tvb, 16);
		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin,
						    tvb, 0,
						    UNICAST_TVLV_PACKET_V15_SIZE + unicast_tvlv_packeth->tvlv_len,
						    "B.A.T.M.A.N. Unicast TVLV, Src: %s Dst: %s",
						    tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_ETHER, 10),
						    tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_ETHER, 4));
		batadv_unicast_tvlv_tree = proto_item_add_subtree(ti, ett_batadv_unicast_tvlv);
	}

	/* items */
	unicast_tvlv_packeth->packet_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format_value(batadv_unicast_tvlv_tree,
					 hf_batadv_packet_type, tvb, offset, 1,
					 unicast_tvlv_packeth->packet_type,
					 "%s (%u)", "BATADV_UNICAST_TVLV",
					 unicast_tvlv_packeth->packet_type);
	offset += 1;

	unicast_tvlv_packeth->version = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_unicast_tvlv_tree,
			    hf_batadv_unicast_tvlv_version, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
	offset += 1;

	unicast_tvlv_packeth->ttl = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(batadv_unicast_tvlv_tree,
			    hf_batadv_unicast_tvlv_ttl, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
	offset += 1;

	/* Skip 1 byte of padding. */
	offset += 1;

	set_address_tvb(&unicast_tvlv_packeth->dest, AT_ETHER, 6, tvb, offset);
	copy_address_shallow(&pinfo->dl_dst, &unicast_tvlv_packeth->dest);
	copy_address_shallow(&pinfo->dst, &unicast_tvlv_packeth->dest);
	proto_tree_add_item(batadv_unicast_tvlv_tree, hf_batadv_unicast_tvlv_dst,
			    tvb, offset, 6, ENC_NA);
	offset += 6;

	set_address_tvb(&unicast_tvlv_packeth->src, AT_ETHER, 6, tvb, offset);
	copy_address_shallow(&pinfo->dl_src, &unicast_tvlv_packeth->src);
	copy_address_shallow(&pinfo->src, &unicast_tvlv_packeth->src);
	proto_tree_add_item(batadv_unicast_tvlv_tree, hf_batadv_unicast_tvlv_src,
			    tvb, offset, 6, ENC_NA);
	offset += 6;

	unicast_tvlv_packeth->tvlv_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(batadv_unicast_tvlv_tree,
			    hf_batadv_unicast_tvlv_len, tvb, offset, 2,
			    ENC_BIG_ENDIAN);
	offset += 2;

	/* Skip 2 byte of padding. */
	offset += 2;

	tap_queue_packet(batadv_tap, pinfo, unicast_tvlv_packeth);

	if (unicast_tvlv_packeth->tvlv_len > 0) {
		next_tvb = tvb_new_subset_length(tvb, offset,
						 unicast_tvlv_packeth->tvlv_len);

		if (have_tap_listener(batadv_follow_tap)) {
			tap_queue_packet(batadv_follow_tap, pinfo, next_tvb);
		}

		dissect_batadv_tvlv_v15(next_tvb, pinfo,
					batadv_unicast_tvlv_tree);
		/*offset += unicast_tvlv_packeth->tvlv_len;*/
	}
}

static void dissect_batadv_tvlv_v15(tvbuff_t *tvb, packet_info *pinfo,
				    proto_tree *tree)
{
	guint8 type, version;
	guint16 length;
	int offset = 0;
	tvbuff_t *next_tvb;
	proto_tree *batadv_tvlv_tree = NULL;

	while (offset != -1 && tvb_captured_length_remaining(tvb, offset) >= 4) {

		type = tvb_get_guint8(tvb, offset + 0);
		version = tvb_get_guint8(tvb, offset + 1);
		length = tvb_get_ntohs(tvb, offset + 2) + 4;
		next_tvb = tvb_new_subset_length(tvb, offset, length);

		/* Set tree info */
		if (tree) {
			proto_item *ti;

			ti = proto_tree_add_protocol_format(tree,
							    proto_batadv_plugin,
							    next_tvb, 0, length,
							    "TVLV, %s",
							    val_to_str(type,
								       tvlv_v15_typenames,
								       "Unknown (0x%02x)"));
			batadv_tvlv_tree = proto_item_add_subtree(ti, ett_batadv_tvlv);
		}

		dissect_batadv_tvlv_v15_header(next_tvb, pinfo,
					       batadv_tvlv_tree, type);

		switch (type) {
		case BATADV_TVLV_V15_GW:
			dissect_batadv_tvlv_v15_gw(next_tvb, pinfo,
						   batadv_tvlv_tree, 4,
						   version);
			break;
		case BATADV_TVLV_V15_DAT:
			dissect_batadv_tvlv_v15_dat(next_tvb, pinfo,
						    batadv_tvlv_tree, 4,
						    version);
			break;
		case BATADV_TVLV_V15_NC:
			dissect_batadv_tvlv_v15_nc(next_tvb, pinfo,
						   batadv_tvlv_tree, 4,
						   version);
			break;
		case BATADV_TVLV_V15_TT:
			dissect_batadv_tvlv_v15_tt(next_tvb, pinfo,
						   batadv_tvlv_tree, 4,
						   version);
			break;
		case BATADV_TVLV_V15_ROAM:
			dissect_batadv_tvlv_v15_roam(next_tvb, pinfo,
						     batadv_tvlv_tree, 4,
						     version);
			break;
		case BATADV_TVLV_V15_MCAST:
			dissect_batadv_tvlv_v15_mcast(next_tvb, pinfo,
						      batadv_tvlv_tree, 4,
						      version);
			break;
		default:
			call_data_dissector(next_tvb, pinfo,
				       batadv_tvlv_tree);
			break;
		}
		offset += length;
	}
}

static void dissect_batadv_tvlv_v15_header(tvbuff_t *tvb,
					   packet_info *pinfo _U_,
					   proto_tree *tree, guint8 type)
{
	int offset = 0;

	/* items */
	proto_tree_add_uint_format_value(tree, hf_batadv_tvlv_type, tvb, offset,
					 1, type, "%s",
					 val_to_str(type, tvlv_v15_typenames,
						    "Unknown (0x%02x)"));
	offset += 1;

	proto_tree_add_item(tree, hf_batadv_tvlv_version, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_batadv_tvlv_len, tvb, offset, 2,
			    ENC_BIG_ENDIAN);
}

static void dissect_batadv_tvlv_v15_dat(tvbuff_t *tvb, packet_info *pinfo,
					proto_tree *tree, int offset,
					guint8 version)
{
	if (version != 0x01) {
		proto_tree_add_expert_format(
			tree, pinfo, &ei_batadv_tvlv_unknown_version, tvb,
			offset, 0, "Unknown version (0x%02x)", version);
		return;
	}
}

static void dissect_batadv_tvlv_v15_nc(tvbuff_t *tvb, packet_info *pinfo,
				       proto_tree *tree, int offset,
				       guint8 version)
{
	if (version != 0x01) {
		proto_tree_add_expert_format(
			tree, pinfo, &ei_batadv_tvlv_unknown_version, tvb,
			offset, 0, "Unknown version (0x%02x)", version);
		return;
	}
}

static void dissect_batadv_tvlv_v15_mcast(tvbuff_t *tvb, packet_info *pinfo,
					  proto_tree *tree, int offset,
					  guint8 version)
{
	static const int * flags[] = {
		&hf_batadv_tvlv_mcast_flags_unsnoopables,
		&hf_batadv_tvlv_mcast_flags_ipv4,
		&hf_batadv_tvlv_mcast_flags_ipv6,
		NULL
	};

	if (version != 0x01) {
		proto_tree_add_expert_format(
			tree, pinfo, &ei_batadv_tvlv_unknown_version, tvb,
			offset, 0, "Unknown version (0x%02x)", version);
		return;
	}

	proto_tree_add_bitmask(tree, tvb, offset, hf_batadv_iv_ogm_flags,
			       ett_batadv_tvlv_mcast_flags, flags, ENC_NA);

	/* 3 byte of padding. */
}

static void dissect_batadv_tvlv_v15_gw(tvbuff_t *tvb, packet_info *pinfo,
				       proto_tree *tree, int offset,
				       guint8 version)
{
	guint32 down, up;

	if (version != 0x01) {
		proto_tree_add_expert_format(
			tree, pinfo, &ei_batadv_tvlv_unknown_version, tvb,
			offset, 0, "Unknown version (0x%02x)", version);
		return;
	}

	down = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format_value(tree, hf_batadv_tvlv_gw_download,
					 tvb, offset, 4, down, "%u.%uMbit",
					 down / 10, down % 10);
	offset += 4;

	up = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format_value(tree, hf_batadv_tvlv_gw_upload, tvb,
					 offset, 4, up, "%u.%uMbit",
					 up / 10, up % 10);
}

static void dissect_batadv_tvlv_v15_roam(tvbuff_t *tvb, packet_info *pinfo,
					 proto_tree *tree, int offset,
					 guint8 version)
{
	static const int * flags[] = {
		&hf_batadv_tvlv_vid_vlan,
		&hf_batadv_tvlv_vid_tagged,
		NULL
	};

	if (version != 0x01) {
		proto_tree_add_expert_format(
			tree, pinfo, &ei_batadv_tvlv_unknown_version, tvb,
			offset, 0, "Unknown version (0x%02x)", version);
		return;
	}

	proto_tree_add_item(tree, hf_batadv_tvlv_roam_addr, tvb, offset, 6,
			    ENC_NA);
	offset += 6;

	proto_tree_add_bitmask(tree, tvb, offset, hf_batadv_tvlv_roam_vid,
			       ett_batadv_tvlv_vid, flags, ENC_NA);
}

static void dissect_batadv_tvlv_v15_tt(tvbuff_t *tvb, packet_info *pinfo,
				       proto_tree *tree, int offset,
				       guint8 version)
{
	guint16 num_vlan;
	int i;
	gint length_remaining;
	static const int * flags[] = {
		&hf_batadv_tvlv_tt_flags_type,
		&hf_batadv_tvlv_tt_flags_full_table,
		NULL
	};

	if (version != 0x01) {
		proto_tree_add_expert_format(
			tree, pinfo, &ei_batadv_tvlv_unknown_version, tvb,
			offset, 0, "Unknown version (0x%02x)", version);
		return;
	}

	proto_tree_add_bitmask(tree, tvb, offset, hf_batadv_tvlv_tt_flags,
			       ett_batadv_tvlv_tt_flags, flags, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_batadv_tvlv_tt_ttvn, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
	offset += 1;

	num_vlan = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_batadv_tvlv_tt_num_vlan, tvb, offset, 2,
			    ENC_BIG_ENDIAN);
	offset += 2;

	for (i = 0; i < num_vlan; i++)
		offset = dissect_batadv_tvlv_v15_tt_vlan(tvb, pinfo, tree,
							 offset);

	length_remaining = tvb_captured_length_remaining(tvb, offset);
	while (length_remaining > 0) {
		offset = dissect_batadv_tvlv_v15_tt_change(tvb, pinfo, tree,
							   offset);
		length_remaining = tvb_captured_length_remaining(tvb, offset);
	}
}

static int dissect_batadv_tvlv_v15_tt_vlan(tvbuff_t *tvb,
					   packet_info *pinfo _U_,
					   proto_tree *tree, int offset)
{
	proto_tree *vlan_tree = NULL;
	guint16 vid;
	static const int * flags[] = {
		&hf_batadv_tvlv_vid_vlan,
		&hf_batadv_tvlv_vid_tagged,
		NULL
	};

	vid = tvb_get_ntohs(tvb, offset + 4);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin,
						    tvb, offset, 8,
						    "VLAN, %04x", vid);
		vlan_tree = proto_item_add_subtree(ti, ett_batadv_tvlv_tt_vlan);
	}

	proto_tree_add_item(vlan_tree, hf_batadv_tvlv_tt_vlan_crc, tvb, offset,
			    4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_bitmask(vlan_tree, tvb, offset,
			       hf_batadv_tvlv_tt_vlan_vid,
			       ett_batadv_tvlv_vid, flags, ENC_NA);
	offset += 2;

	/* Skip 2 byte of padding. */
	offset += 2;

	return offset;
}

static int dissect_batadv_tvlv_v15_tt_change(tvbuff_t *tvb,
					     packet_info *pinfo _U_,
					     proto_tree *tree, int offset)
{
	proto_tree *change_tree = NULL;
	static const int * flags[] = {
		&hf_batadv_tvlv_tt_change_flags_del,
		&hf_batadv_tvlv_tt_change_flags_roam,
		&hf_batadv_tvlv_tt_change_flags_wifi,
		&hf_batadv_tvlv_tt_change_flags_isolate,
		NULL
	};
	static const int * flags_vlan[] = {
		&hf_batadv_tvlv_vid_vlan,
		&hf_batadv_tvlv_vid_tagged,
		NULL
	};

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_batadv_plugin,
						    tvb, offset, 12,
						    "Entry, %s",
						    tvb_address_with_resolution_to_str(wmem_packet_scope(), tvb, AT_ETHER, offset + 4));
		change_tree = proto_item_add_subtree(ti, ett_batadv_tvlv_tt_change);
	}

	proto_tree_add_bitmask(change_tree, tvb, offset,
			       hf_batadv_tvlv_tt_change_flags,
			ett_batadv_batman_flags, flags, ENC_NA);
	offset += 1;

	/* Skip 3 byte of padding. */
	offset += 3;

	proto_tree_add_item(change_tree, hf_batadv_tvlv_tt_change_addr, tvb,
			    offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_bitmask(change_tree, tvb, offset,
			       hf_batadv_tvlv_tt_change_vid,
			       ett_batadv_tvlv_vid, flags_vlan, ENC_NA);
	offset += 2;

	return offset;
}

static void batadv_init_routine(void)
{
	reassembly_table_init(&msg_reassembly_table,
			      &addresses_reassembly_table_functions);
}

static void batadv_cleanup_routine(void)
{
	reassembly_table_destroy(&msg_reassembly_table);
}

void proto_register_batadv(void)
{
	module_t *batadv_module;
	expert_module_t* expert_batadv;

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
		{ &hf_batadv_batman_gwflags_dl_speed,
		  { "Download Speed", "batadv.batman.gwflags.dl_speed",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_batman_gwflags_ul_speed,
		  { "Upload Speed", "batadv.batman.gwflags.ul_speed",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
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
		{ &hf_batadv_batman_flags_not_best_next_hop,
		  { "NOT_BEST_NEXT_HOP", "batadv.batman.flags.not_best_next_hop",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x8,
		    NULL, HFILL }
		},
		{ &hf_batadv_iv_ogm_version,
		  { "Version", "batadv.iv_ogm.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_iv_ogm_ttl,
		  { "Time to Live", "batadv.iv_ogm.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_iv_ogm_flags,
		  { "Flags", "batadv.iv_ogm.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_iv_ogm_seqno,
		  { "Sequence number", "batadv.iv_ogm.seq",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_iv_ogm_orig,
		  { "Originator", "batadv.iv_ogm.orig",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_iv_ogm_prev_sender,
		  { "Received from", "batadv.iv_ogm.prev_sender",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_iv_ogm_tq,
		  { "Transmission Quality", "batadv.iv_ogm.tq",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_iv_ogm_tvlv_len,
		  { "Length of TVLV", "batadv.iv_ogm.tvlv_len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_iv_ogm_flags_not_best_next_hop,
		  { "NOT_BEST_NEXT_HOP", "batadv.iv_ogm.flags.not_best_next_hop",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x1,
		    NULL, HFILL }
		},
		{ &hf_batadv_iv_ogm_flags_primaries_first_hop,
		  { "PRIMARIES_FIRST_HOP", "batadv.iv_ogm.flags.primaries_first_hop",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x2,
		    NULL, HFILL }
		},
		{ &hf_batadv_iv_ogm_flags_directlink,
		  { "DirectLink", "batadv.iv_ogm.flags.directlink",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x4,
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
		{ &hf_batadv_icmp_rr_pointer,
		  { "Pointer", "batadv.icmp.rr_pointer",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_icmp_rr_ether,
		  { "RR MAC", "batadv.icmp.rr_ether",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
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
		{ &hf_batadv_unicast_4addr_version,
		  { "Version", "batadv.unicast_4addr.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_4addr_dst,
		  { "Destination", "batadv.unicast_4addr.dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_4addr_ttl,
		  { "Time to Live", "batadv.unicast_4addr.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_4addr_ttvn,
		  { "TT Version", "batadv.unicast_4addr.ttvn",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_4addr_src,
		  { "Source", "batadv.unicast_4addr.src",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_4addr_subtype,
		  { "Subtype", "batadv.unicast_4addr.subtype",
		    FT_UINT8, BASE_DEC, VALS (unicast_4addr_typenames), 0x0,
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
		{ &hf_batadv_unicast_frag_no,
		  { "Fragment number", "batadv.unicast_frag.no",
		    FT_UINT8, BASE_DEC, NULL, 0xF0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_frag_total_size,
		  { "Complete Size", "batadv.unicast_frag.total_size",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_tvlv_version,
		  { "Version", "batadv.unicast_tvlv.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_tvlv_ttl,
		  { "Time to Live", "batadv.unicast_tvlv.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_tvlv_dst,
		  { "Destination", "batadv.unicast_tvlv.dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_tvlv_src,
		  { "Destination", "batadv.unicast_tvlv.src",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_unicast_tvlv_len,
		  { "Length of TVLV", "batadv.unicast_tvlv.len",
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
		    FT_UINT8, BASE_HEX, VALS (tt_query_type_v14), TT_TYPE_MASK,
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
		{ &hf_batadv_coded_version,
		  { "Version", "batadv.coded.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_coded_ttl,
		  { "Time to Live", "batadv.coded.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_coded_first_ttvn,
		  { "TT Version (First)", "batadv.coded.first_ttvn",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_coded_first_source,
		  { "Source (First)", "batadv.coded.first_src",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_coded_first_orig_dest,
		  { "Original Destination (First)", "batadv.coded.first_orig_dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_coded_first_crc,
		  { "CRC (First)", "batadv.coded.first_crc",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_coded_second_ttl,
		  { "Time to Live (Second)", "batadv.coded.second_ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_coded_second_ttvn,
		  { "TT Version (Second)", "batadv.coded.second_ttvn",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_batadv_coded_second_dest,
		  { "Destination (Second)", "batadv.coded.second_dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_coded_second_source,
		  { "Source (Second)", "batadv.coded.second_src",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_coded_second_orig_dest,
		  { "Original Destination (Second)", "batadv.coded.second_orig_dst",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_coded_second_crc,
		  { "CRC (Second)", "batadv.coded.second_crc",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_coded_coded_len,
		  { "Length", "batadv.coded.length",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
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
		    FT_BOOLEAN, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_msg_fragment_overlap_conflicts,
		   {"Message fragment overlapping with conflicting data",
		    "batadv.unicast_frag.fragment.overlap.conflicts",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_msg_fragment_multiple_tails,
		  {"Message has multiple tail fragments",
		    "batadv.unicast_frag.fragment.multiple_tails",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_msg_fragment_too_long_fragment,
		  {"Message fragment too long", "batadv.unicast_frag.fragment.too_long_fragment",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x00,
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
		},
		{ &hf_batadv_tvlv_type,
		  { "Type", "batadv.tvlv.length",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_version,
		  { "Version", "batadv.tvlv.length",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_len,
		  { "Length", "batadv.tvlv.len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_mcast_flags_unsnoopables,
		  { "Unsnoopables", "batadv.tvlv.mcast.flags.unsnoopables",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x1,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_mcast_flags_ipv4,
		  { "IPv4", "batadv.tvlv.mcast.flags.ipv4",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x2,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_mcast_flags_ipv6,
		  { "IPv6", "batadv.tvlv.mcast.flags.ipv6",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x4,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_gw_download,
		  { "Download Speed", "batadv.tvlv.gw.dl_speed",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_gw_upload,
		  { "Upload Speed", "batadv.tvlv.gw.ul_speed",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_roam_addr,
		  { "Address", "batadv.batman.addr",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_roam_vid,
		  { "VID", "batadv.tvlv.roam.vid",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_vid_vlan,
		  { "VLAN ID", "batadv.tvlv.vid_vlan",
		    FT_UINT16, BASE_DEC, NULL, 0x7fff,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_vid_tagged,
		  { "VLAN Tagged", "batadv.tvlv.vid_tagged",
		    FT_UINT16, BASE_DEC, NULL, 0x8000,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_flags,
		  { "Flags", "batadv.tvlv.tt.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_flags_type,
		  { "Query Type", "batadv.tvlv.tt.flags.type",
		    FT_UINT8, BASE_HEX, VALS(tvlv_tt_typenames),
		    BATADV_TVLVL_TT_TYPE_MASK,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_flags_full_table,
		  { "Full Table", "batadv.tvlv.tt.flags.full_table",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset),
		    BATADV_TVLVL_TT_FULL_TABLE,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_ttvn,
		  { "TT Version", "batadv.tvlv.tt.ttvn",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_num_vlan,
		  { "VLAN Entries", "batadv.tvlv.tt.num_vlan",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_vlan_crc,
		  { "CRC", "batadv.tvlv.tt.vlan.crc",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_vlan_vid,
		  { "VID", "batadv.tvlv.tt.vlan.vid",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_change_flags,
		  { "Flags", "batadv.tvlv.tt.change.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_change_flags_del,
		  { "Delete", "batadv.tvlv.tt.change.flags.del",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset),
		    BATADV_TVLVL_TT_CHANGE_DEL,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_change_flags_roam,
		  { "Client Roam", "batadv.tvlv.tt.change.flags.roam",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset),
		    BATADV_TVLVL_TT_CHANGE_ROAM,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_change_flags_wifi,
		  { "Wifi Client", "batadv.tvlv.tt.change.flags.wifi",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset),
		    BATADV_TVLVL_TT_CHANGE_WIFI,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_change_flags_isolate,
		  { "Isolate", "batadv.tvlv.tt.change.flags.isolate",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset),
		    BATADV_TVLVL_TT_CHANGE_ISOLATE,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_change_addr,
		  { "Address", "batadv.tvlv.tt.change.addr",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_batadv_tvlv_tt_change_vid,
		  { "VID", "batadv.tvlv.tt.change.vid",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_batadv_batman,
		&ett_batadv_batman_flags,
		&ett_batadv_batman_tt,
		&ett_batadv_batman_gwflags,
		&ett_batadv_iv_ogm,
		&ett_batadv_iv_ogm_flags,
		&ett_batadv_bcast,
		&ett_batadv_icmp,
		&ett_batadv_icmp_rr,
		&ett_batadv_unicast,
		&ett_batadv_unicast_4addr,
		&ett_batadv_unicast_frag,
		&ett_batadv_unicast_tvlv,
		&ett_batadv_vis,
		&ett_batadv_vis_entry,
		&ett_batadv_tt_query,
		&ett_batadv_tt_query_flags,
		&ett_batadv_tt_entry,
		&ett_batadv_tt_entry_flags,
		&ett_batadv_roam_adv,
		&ett_batadv_coded,
		&ett_batadv_tvlv,
		&ett_batadv_tvlv_vid,
		&ett_batadv_tvlv_mcast_flags,
		&ett_batadv_tvlv_tt_flags,
		&ett_batadv_tvlv_tt_vlan,
		&ett_batadv_tvlv_tt_change,
		&ett_msg_fragment,
		&ett_msg_fragments
	};

	static ei_register_info ei[] = {
		{ &ei_batadv_tvlv_unknown_version, { "batadv.error.tvlv_version_unknown", PI_UNDECODED, PI_ERROR, "BATADV Error: unknown TVLV version", EXPFILL }},
	};

	proto_batadv_plugin = proto_register_protocol(
				      "B.A.T.M.A.N. Advanced Protocol",
				      "BATADV",          /* short name */
				      "batadv"           /* abbrev */
			      );

	register_dissector("batadv",dissect_batadv_plugin,proto_batadv_plugin);

	batadv_module = prefs_register_protocol(proto_batadv_plugin,
						proto_reg_handoff_batadv);

	prefs_register_uint_preference(batadv_module, "batmanadv.ethertype",
				       "Ethertype",
				       "Ethertype used to indicate B.A.T.M.A.N. packet.",
				       16, &batadv_ethertype);

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_batadv_plugin, hf, array_length(hf));

	expert_batadv = expert_register_protocol(proto_batadv_plugin);
	expert_register_field_array(expert_batadv, ei, array_length(ei));

	register_init_routine(&batadv_init_routine);
	register_cleanup_routine(&batadv_cleanup_routine);
}

void proto_reg_handoff_batadv(void)
{
	static gboolean inited = FALSE;
	static unsigned int old_batadv_ethertype;

	if (!inited) {
		batman_handle = create_dissector_handle(dissect_batadv_plugin, proto_batadv_plugin);

		eth_handle = find_dissector_add_dependency("eth_withoutfcs", proto_batadv_plugin);

		batadv_tap = register_tap("batman");
		batadv_follow_tap = register_tap("batman_follow");

		inited = TRUE;
	} else {
		dissector_delete_uint("ethertype", old_batadv_ethertype, batman_handle);
	}

	old_batadv_ethertype = batadv_ethertype;
	dissector_add_uint("ethertype", batadv_ethertype, batman_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
