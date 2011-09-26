/* packet-bat.c
 * Routines for B.A.T.M.A.N. Layer 3 dissection
 * Copyright 2008-2010 Sven Eckelmann <sven@narfation.org>
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

/* Start content from packet-bat.h */
#define BAT_BATMAN_PORT  4305
#define BAT_GW_PORT  4306
#define BAT_VIS_PORT  4307

#define UNIDIRECTIONAL 0x80
#define DIRECTLINK 0x40

struct batman_packet_v5 {
	guint8  version;  /* batman version field */
	guint8  flags;    /* 0x80: UNIDIRECTIONAL link, 0x40: DIRECTLINK flag, ... */
	guint8  ttl;
	guint8  gwflags;  /* flags related to gateway functions: gateway class */
	guint16 seqno;
	guint16 gwport;
	address orig;
	address old_orig;
	guint8  tq;
	guint8  hna_len;
};
#define BATMAN_PACKET_V5_SIZE 18

struct gw_packet {
	guint8  type;
};
#define GW_PACKET_SIZE 1

#define TUNNEL_DATA 0x01
#define TUNNEL_IP_REQUEST 0x02
#define TUNNEL_IP_INVALID 0x03
#define TUNNEL_KEEPALIVE_REQUEST 0x04
#define TUNNEL_KEEPALIVE_REPLY 0x05

#define DATA_TYPE_NEIGH 1
#define DATA_TYPE_SEC_IF 2
#define DATA_TYPE_HNA 3

struct vis_packet_v22 {
	address sender_ip;
	guint8  version;
	guint8  gw_class;
	guint16 tq_max;
};
#define VIS_PACKET_V22_SIZE 8

struct vis_data_v22 {
	guint8  type;
	guint16 data;
	address ip;
};
#define VIS_PACKET_V22_DATA_SIZE 7

struct vis_packet_v23 {
	address sender_ip;
	guint8  version;
	guint8  gw_class;
	guint8  tq_max;
};
#define VIS_PACKET_V23_SIZE 7

struct vis_data_v23 {
	guint8  type;
	guint8  data;
	address ip;
};
#define VIS_PACKET_V23_DATA_SIZE 6
/* End content from packet-bat.h */

/* trees */
static gint ett_bat_batman = -1;
static gint ett_bat_batman_flags = -1;
static gint ett_bat_batman_gwflags = -1;
static gint ett_bat_batman_hna = -1;
static gint ett_bat_gw = -1;
static gint ett_bat_vis = -1;
static gint ett_bat_vis_entry = -1;

/* hfs */
static int hf_bat_batman_version = -1;
static int hf_bat_batman_flags = -1;
static int hf_bat_batman_ttl = -1;
static int hf_bat_batman_gwflags = -1;
static int hf_bat_batman_seqno = -1;
static int hf_bat_batman_gwport = -1;
static int hf_bat_batman_orig = -1;
static int hf_bat_batman_old_orig = -1;
static int hf_bat_batman_tq = -1;
static int hf_bat_batman_hna_len = -1;
static int hf_bat_batman_hna_network = -1;
static int hf_bat_batman_hna_netmask = -1;

static int hf_bat_gw_type = -1;
static int hf_bat_gw_ip = -1;

static int hf_bat_vis_vis_orig = -1;
static int hf_bat_vis_version = -1;
static int hf_bat_vis_gwflags = -1;
static int hf_bat_max_tq_v22 = -1;
static int hf_bat_max_tq_v23 = -1;
static int hf_bat_vis_data_type = -1;
static int hf_bat_vis_netmask = -1;
static int hf_bat_vis_tq_v22 = -1;
static int hf_bat_vis_tq_v23 = -1;
static int hf_bat_vis_data_ip = -1;

/* flags */
static int hf_bat_batman_flags_unidirectional = -1;
static int hf_bat_batman_flags_directlink = -1;

static const value_string gw_packettypenames[] = {
	{ TUNNEL_DATA, "DATA" },
	{ TUNNEL_IP_REQUEST, "IP_REQUEST" },
	{ TUNNEL_IP_INVALID, "IP_INVALID" },
	{ TUNNEL_KEEPALIVE_REQUEST, "KEEPALIVE_REQUEST" },
	{ TUNNEL_KEEPALIVE_REPLY, "KEEPALIVE_REPLY" },
	{ 0, NULL }
};

static const value_string vis_packettypenames[] = {
	{ DATA_TYPE_NEIGH, "NEIGH" },
	{ DATA_TYPE_SEC_IF, "SEC_IF" },
	{ DATA_TYPE_HNA, "HNA" },
	{ 0, NULL }
};

/* forward declaration */
void proto_reg_handoff_bat(void);

/* supported packet dissectors */
static void dissect_bat_batman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_bat_batman_v5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static void dissect_bat_gw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_bat_vis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_bat_vis_v22(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_vis_entry_v22(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_bat_vis_v23(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_vis_entry_v23(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_bat_hna(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* other dissectors */
static dissector_handle_t ip_handle;
static dissector_handle_t data_handle;

static int proto_bat_plugin = -1;

/* tap */
static int bat_tap = -1;
static int bat_follow_tap = -1;

/* values changed by preferences */
static guint global_bat_batman_udp_port = BAT_BATMAN_PORT;
static guint global_bat_gw_udp_port = BAT_GW_PORT;
static guint global_bat_vis_udp_port = BAT_VIS_PORT;



static void dissect_bat_batman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;
	int offset = 0;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_BATMAN");
	col_clear(pinfo->cinfo, COL_INFO);

	version = tvb_get_guint8(tvb, 0);
	switch (version) {
	case 5:
		while (tvb_reported_length_remaining(tvb, offset)) {
			offset = dissect_bat_batman_v5(tvb, offset, pinfo, tree);
		}
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_bat_gwflags(tvbuff_t *tvb, guint8 gwflags, int offset, proto_item *tgw)
{
	proto_tree *gwflags_tree;
	guint8 s = (gwflags & 0x80) >> 7;
	guint8 downbits = (gwflags & 0x78) >> 3;
	guint8 upbits = (gwflags & 0x07);
	guint down, up;

	down = 32 * (s + 2) * (1 << downbits);
	up = ((upbits + 1) * down) / 8;

	gwflags_tree =  proto_item_add_subtree(tgw, ett_bat_batman_gwflags);
	proto_tree_add_text(gwflags_tree, tvb, offset, 1, "Download Speed: %dkbit", down);
	proto_tree_add_text(gwflags_tree, tvb, offset, 1, "Upload Speed: %dkbit", up);

}

static int dissect_bat_batman_v5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tf, *tgw;
	proto_tree *bat_batman_tree = NULL, *flag_tree;
	struct batman_packet_v5 *batman_packeth;
	const guint8  *old_orig_addr, *orig_addr;
	guint32 old_orig, orig;
	gint i;

	tvbuff_t *next_tvb;

	batman_packeth = ep_alloc(sizeof(struct batman_packet_v5));

	batman_packeth->version = tvb_get_guint8(tvb, offset+0);
	batman_packeth->flags = tvb_get_guint8(tvb, offset+1);
	batman_packeth->ttl = tvb_get_guint8(tvb, offset+2);
	batman_packeth->gwflags = tvb_get_guint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohs(tvb, offset+4);
	batman_packeth->gwport = tvb_get_ntohs(tvb, offset+6);
	orig_addr = tvb_get_ptr(tvb, offset+8, 4);
	orig = tvb_get_ipv4(tvb, offset+8);
	SET_ADDRESS(&batman_packeth->orig, AT_IPv4, 4, orig_addr);
	old_orig_addr = tvb_get_ptr(tvb, offset+12, 4);
	old_orig = tvb_get_ipv4(tvb, offset+12);
	SET_ADDRESS(&batman_packeth->old_orig, AT_IPv4, 4, old_orig_addr);
	batman_packeth->tq = tvb_get_guint8(tvb, offset+16);
	batman_packeth->hna_len = tvb_get_guint8(tvb, offset+17);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, offset, BATMAN_PACKET_V5_SIZE,
							    "B.A.T.M.A.N., Orig: %s (%s)",
							    get_hostname(orig), ip_to_str(batman_packeth->orig.data));
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, offset, BATMAN_PACKET_V5_SIZE, ENC_BIG_ENDIAN);
		}
		bat_batman_tree = proto_item_add_subtree(ti, ett_bat_batman);
	}

	/* items */
	proto_tree_add_item(bat_batman_tree, hf_bat_batman_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tf = proto_tree_add_item(bat_batman_tree, hf_bat_batman_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* <flags> */
	flag_tree =  proto_item_add_subtree(tf, ett_bat_batman_flags);
	proto_tree_add_boolean(flag_tree, hf_bat_batman_flags_unidirectional, tvb, offset, 1, batman_packeth->flags);
	proto_tree_add_boolean(flag_tree, hf_bat_batman_flags_directlink, tvb, offset, 1, batman_packeth->flags);
	/* </flags> */
	offset += 1;

	proto_tree_add_item(bat_batman_tree, hf_bat_batman_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tgw = proto_tree_add_item(bat_batman_tree, hf_bat_batman_gwflags, tvb, offset, 1, ENC_BIG_ENDIAN);
	dissect_bat_gwflags(tvb, batman_packeth->gwflags, offset, tgw);
	offset += 1;

	proto_tree_add_item(bat_batman_tree, hf_bat_batman_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(bat_batman_tree, hf_bat_batman_gwport, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_ipv4(bat_batman_tree, hf_bat_batman_orig, tvb, offset, 4, orig);
	offset += 4;

	proto_tree_add_ipv4(bat_batman_tree, hf_bat_batman_old_orig, tvb, offset, 4,  old_orig);
	offset += 4;

	proto_tree_add_item(bat_batman_tree, hf_bat_batman_tq, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(bat_batman_tree, hf_bat_batman_hna_len, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	tap_queue_packet(bat_tap, pinfo, batman_packeth);

	for (i = 0; i < batman_packeth->hna_len; i++) {
		next_tvb = tvb_new_subset(tvb, offset, 5, 5);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		dissect_bat_hna(next_tvb, pinfo, bat_batman_tree);
		offset += 5;
	}

	return offset;
}

static void dissect_bat_hna(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint32 hna;
	guint8 hna_netmask;

	hna = tvb_get_ipv4(tvb, 0);
	hna_netmask = tvb_get_guint8(tvb, 4);


	/* Set tree info */
	if (tree) {
		proto_item *ti;
		proto_tree *bat_batman_hna_tree;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, 5,
							    "B.A.T.M.A.N. HNA: %s/%d",
							    tvb_ip_to_str(tvb, 0), hna_netmask);
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, 5, ENC_BIG_ENDIAN);
		}
		bat_batman_hna_tree = proto_item_add_subtree(ti, ett_bat_batman_hna);

		proto_tree_add_ipv4(bat_batman_hna_tree, hf_bat_batman_hna_network, tvb, 0, 4, hna);
		proto_tree_add_item(bat_batman_hna_tree, hf_bat_batman_hna_netmask, tvb, 4, 1, ENC_BIG_ENDIAN);
	}
}


static void dissect_bat_gw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct gw_packet *gw_packeth;
	guint32 ip;
	int ip_pos;

	tvbuff_t *next_tvb;
	guint length_remaining;
	int offset = 0;

	gw_packeth = ep_alloc(sizeof(struct gw_packet));
	gw_packeth->type = tvb_get_guint8(tvb, 0);

	switch (gw_packeth->type) {
		case TUNNEL_IP_INVALID:
			ip_pos = 13;
			break;
		default:
			ip_pos = 1;
	}
	ip = tvb_get_ipv4(tvb, ip_pos);

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_GW");

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Type=%s",
		     val_to_str(gw_packeth->type, gw_packettypenames, "Unknown (0x%02x)"));
	if (ip != 0) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " IP: %s (%s)",
				get_hostname(ip), tvb_ip_to_str(tvb, ip_pos));
	}


	/* Set tree info */
	if (tree) {
		proto_item *ti;
		proto_tree *bat_gw_entry_tree;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, 1,
							    "B.A.T.M.A.N. GW [%s]",
							    val_to_str(gw_packeth->type, gw_packettypenames, "Unknown (0x%02x)"));
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, 1, ENC_BIG_ENDIAN);
		}
		bat_gw_entry_tree = proto_item_add_subtree(ti, ett_bat_gw);

		proto_tree_add_item(bat_gw_entry_tree, hf_bat_gw_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		if (gw_packeth->type != TUNNEL_DATA && ip != 0) {
			proto_tree_add_ipv4(bat_gw_entry_tree, hf_bat_gw_ip, tvb, ip_pos, 4, ip);
			offset = ip_pos + 4;
		}
	}

	/* Calculate offset even when we got no tree */
	offset = 1;
	if (gw_packeth->type != TUNNEL_DATA && ip != 0)
		offset = ip_pos + 4;

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining != 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		if (gw_packeth->type == TUNNEL_DATA) {
			call_dissector(ip_handle, next_tvb, pinfo, tree);
		} else {
			call_dissector(data_handle, next_tvb, pinfo, tree);
		}
	}
}

static void dissect_bat_vis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_VIS");

	version = tvb_get_guint8(tvb, 4);
	switch (version) {
	case 22:
		dissect_bat_vis_v22(tvb, pinfo, tree);
		break;
	case 23:
		dissect_bat_vis_v23(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_dissector(data_handle, tvb, pinfo, tree);
		break;
	}
}

static void dissect_bat_vis_v22(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct vis_packet_v22 *vis_packeth;
	const guint8  *sender_ip_addr;
	guint32 sender_ip;
	proto_tree *bat_vis_tree = NULL;

	tvbuff_t *next_tvb;
	guint length_remaining, i;
	int offset = 0;

	vis_packeth = ep_alloc(sizeof(struct vis_packet_v22));

	sender_ip_addr = tvb_get_ptr(tvb, 0, 4);
	sender_ip = tvb_get_ipv4(tvb, 0);
	SET_ADDRESS(&vis_packeth->sender_ip, AT_IPv4, 4, sender_ip_addr);
	vis_packeth->version = tvb_get_guint8(tvb, 4);
	vis_packeth->gw_class = tvb_get_guint8(tvb, 5);
	vis_packeth->tq_max = tvb_get_ntohs(tvb, 6);

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_VIS");

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Src: %s (%s)",
		     get_hostname(sender_ip), ip_to_str(vis_packeth->sender_ip.data));

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, VIS_PACKET_V22_SIZE,
							    "B.A.T.M.A.N. Vis, Src: %s (%s)",
							    get_hostname(sender_ip), ip_to_str(vis_packeth->sender_ip.data));
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, VIS_PACKET_V22_SIZE, ENC_BIG_ENDIAN);
		}
		bat_vis_tree = proto_item_add_subtree(ti, ett_bat_vis);

		/* items */
		proto_tree_add_ipv4(bat_vis_tree, hf_bat_vis_vis_orig, tvb, offset, 4, sender_ip);
		offset += 4;

		proto_tree_add_item(bat_vis_tree, hf_bat_vis_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(bat_vis_tree, hf_bat_vis_gwflags, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(bat_vis_tree, hf_bat_max_tq_v22, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	/* Calculate offset even when we got no tree */
	offset = VIS_PACKET_V22_SIZE;

	tap_queue_packet(bat_tap, pinfo, vis_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);

	for (i = 0; i < length_remaining; i += VIS_PACKET_V22_DATA_SIZE) {
		next_tvb = tvb_new_subset(tvb, offset, VIS_PACKET_V22_DATA_SIZE, VIS_PACKET_V22_DATA_SIZE);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		if (bat_vis_tree != NULL) {
			dissect_vis_entry_v22(next_tvb, pinfo, tree);
		}

		offset += VIS_PACKET_V22_DATA_SIZE;
	}

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining != 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_vis_entry_v22(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	struct vis_data_v22 *vis_datah;
	const guint8  *ip_addr;
	guint32 ip;

	vis_datah = ep_alloc(sizeof(struct vis_data_v22));
	vis_datah->type = tvb_get_guint8(tvb, 0);
	vis_datah->data = tvb_get_ntohs(tvb, 1);
	ip_addr = tvb_get_ptr(tvb, 3, 4);
	ip = tvb_get_ipv4(tvb, 3);
	SET_ADDRESS(&vis_datah->ip, AT_IPv4, 4, ip_addr);


	/* Set tree info */
	if (tree) {
		proto_item *ti;
		proto_tree *bat_vis_entry_tree;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, 7,
							    "VIS Entry: [%s] %s (%s)",
							    val_to_str(vis_datah->type, vis_packettypenames, "Unknown (0x%02x)"),
							    get_hostname(ip), ip_to_str(vis_datah->ip.data));
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, 7, ENC_BIG_ENDIAN);
		}
		bat_vis_entry_tree = proto_item_add_subtree(ti, ett_bat_vis_entry);

		proto_tree_add_item(bat_vis_entry_tree, hf_bat_vis_data_type, tvb, 0, 1, ENC_BIG_ENDIAN);

		switch (vis_datah->type) {
		case DATA_TYPE_NEIGH:
			proto_tree_add_item(bat_vis_entry_tree, hf_bat_vis_tq_v22, tvb, 1, 2, ENC_BIG_ENDIAN);
			break;
		case DATA_TYPE_HNA:
			proto_tree_add_item(bat_vis_entry_tree, hf_bat_vis_netmask, tvb, 1, 1, ENC_BIG_ENDIAN);
			break;
		case DATA_TYPE_SEC_IF:
		default:
			break;
		}
		proto_tree_add_ipv4(bat_vis_entry_tree, hf_bat_vis_data_ip, tvb, 3, 4,  ip);
	}
}

static void dissect_bat_vis_v23(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct vis_packet_v23 *vis_packeth;
	const guint8  *sender_ip_addr;
	guint32 sender_ip;
	proto_tree *bat_vis_tree = NULL;

	tvbuff_t *next_tvb;
	guint length_remaining, i;
	int offset = 0;

	vis_packeth = ep_alloc(sizeof(struct vis_packet_v23));

	sender_ip_addr = tvb_get_ptr(tvb, 0, 4);
	sender_ip = tvb_get_ipv4(tvb, 0);
	SET_ADDRESS(&vis_packeth->sender_ip, AT_IPv4, 4, sender_ip_addr);
	vis_packeth->version = tvb_get_guint8(tvb, 4);
	vis_packeth->gw_class = tvb_get_guint8(tvb, 5);
	vis_packeth->tq_max = tvb_get_guint8(tvb, 6);

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_VIS");

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Src: %s (%s)",
		     get_hostname(sender_ip), ip_to_str(vis_packeth->sender_ip.data));

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, VIS_PACKET_V23_SIZE,
							    "B.A.T.M.A.N. Vis, Src: %s (%s)",
							    get_hostname(sender_ip), ip_to_str(vis_packeth->sender_ip.data));
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, VIS_PACKET_V23_SIZE, ENC_BIG_ENDIAN);
		}
		bat_vis_tree = proto_item_add_subtree(ti, ett_bat_vis);

		/* items */
		proto_tree_add_ipv4(bat_vis_tree, hf_bat_vis_vis_orig, tvb, offset, 4, sender_ip);
		offset += 4;

		proto_tree_add_item(bat_vis_tree, hf_bat_vis_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(bat_vis_tree, hf_bat_vis_gwflags, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(bat_vis_tree, hf_bat_max_tq_v23, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}

	/* Calculate offset even when we got no tree */
	offset = VIS_PACKET_V23_SIZE;

	tap_queue_packet(bat_tap, pinfo, vis_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);

	for (i = 0; i < length_remaining; i += VIS_PACKET_V23_DATA_SIZE) {
		next_tvb = tvb_new_subset(tvb, offset, VIS_PACKET_V23_DATA_SIZE, VIS_PACKET_V23_DATA_SIZE);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		if (bat_vis_tree != NULL) {
			dissect_vis_entry_v23(next_tvb, pinfo, tree);
		}

		offset += VIS_PACKET_V23_DATA_SIZE;
	}

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining != 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

static void dissect_vis_entry_v23(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	struct vis_data_v23 *vis_datah;
	const guint8  *ip_addr;
	guint32 ip;

	vis_datah = ep_alloc(sizeof(struct vis_data_v23));
	vis_datah->type = tvb_get_guint8(tvb, 0);
	vis_datah->data = tvb_get_guint8(tvb, 1);
	ip_addr = tvb_get_ptr(tvb, 2, 4);
	ip = tvb_get_ipv4(tvb, 2);
	SET_ADDRESS(&vis_datah->ip, AT_IPv4, 4, ip_addr);


	/* Set tree info */
	if (tree) {
		proto_item *ti;
		proto_tree *bat_vis_entry_tree;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, 7,
							    "VIS Entry: [%s] %s (%s)",
							    val_to_str(vis_datah->type, vis_packettypenames, "Unknown (0x%02x)"),
							    get_hostname(ip), ip_to_str(vis_datah->ip.data));
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, 7, ENC_BIG_ENDIAN);
		}
		bat_vis_entry_tree = proto_item_add_subtree(ti, ett_bat_vis_entry);

		proto_tree_add_item(bat_vis_entry_tree, hf_bat_vis_data_type, tvb, 0, 1, ENC_BIG_ENDIAN);

		switch (vis_datah->type) {
		case DATA_TYPE_NEIGH:
			proto_tree_add_item(bat_vis_entry_tree, hf_bat_vis_tq_v23, tvb, 1, 1, ENC_BIG_ENDIAN);
			break;
		case DATA_TYPE_HNA:
			proto_tree_add_item(bat_vis_entry_tree, hf_bat_vis_netmask, tvb, 1, 1, ENC_BIG_ENDIAN);
			break;
		case DATA_TYPE_SEC_IF:
		default:
			break;
		}
		proto_tree_add_ipv4(bat_vis_entry_tree, hf_bat_vis_data_ip, tvb, 2, 4,  ip);
	}
}

void proto_register_bat(void)
{
	module_t *bat_module;

	static hf_register_info hf[] = {
		{ &hf_bat_batman_version,
		  { "Version", "bat.batman.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_flags,
		  { "Flags", "bat.batman.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_ttl,
		  { "Time to Live", "bat.batman.ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_gwflags,
		  { "Gateway Flags", "bat.batman.gwflags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_seqno,
		  { "Sequence number", "bat.batman.seq",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_gwport,
		  { "Gateway Port", "bat.batman.gwport",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_orig,
		  { "Originator", "bat.batman.orig",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_old_orig,
		  { "Received from", "bat.batman.old_orig",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_tq,
		  { "Transmission Quality", "bat.batman.tq",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_hna_len,
		  { "Number of HNAs", "bat.batman.hna_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_flags_unidirectional,
		  { "Unidirectional", "bat.batman.flags.unidirectional",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_flags_directlink,
		  { "DirectLink", "bat.batman.flags.directlink",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_hna_network,
		  { "HNA Network", "bat.batman.hna_network",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_hna_netmask,
		  { "HNA Netmask", "bat.batman.hna_netmask",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_gw_type,
		  { "Type", "bat.gw.type",
		    FT_UINT8, BASE_DEC, VALS(gw_packettypenames), 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_gw_ip,
		  { "IP", "bat.gw.ip",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_vis_vis_orig,
		  { "Originator", "bat.vis.sender_ip",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_vis_version,
		  { "Version", "bat.vis.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_vis_gwflags,
		  { "Gateway Flags", "bat.vis.gwflags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_max_tq_v22,
		  { "Maximum Transmission Quality", "bat.vis.tq_max",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_max_tq_v23,
		  { "Maximum Transmission Quality", "bat.vis.tq_max",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_vis_data_type,
		  { "Type", "bat.vis.data_type",
		    FT_UINT8, BASE_DEC, VALS(vis_packettypenames), 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_vis_tq_v22,
		  { "Transmission Quality", "bat.vis.tq",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_bat_vis_tq_v23,
		  { "Transmission Quality", "bat.vis.tq",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_bat_vis_netmask,
		  { "Netmask", "bat.vis.netmask",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_bat_vis_data_ip,
		  { "IP", "bat.vis.data_ip",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_bat_batman,
		&ett_bat_batman_flags,
		&ett_bat_batman_gwflags,
		&ett_bat_batman_hna,
		&ett_bat_gw,
		&ett_bat_vis,
		&ett_bat_vis_entry
	};

	proto_bat_plugin = proto_register_protocol(
		"B.A.T.M.A.N. Layer 3 Protocol",
		"BAT",          /* short name */
		"bat"           /* abbrev */
		);

	/* Register our configuration options for B.A.T.M.A.N. */
	bat_module = prefs_register_protocol(proto_bat_plugin, proto_reg_handoff_bat);

	proto_register_field_array(proto_bat_plugin, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	prefs_register_uint_preference(bat_module, "batman.bat.port", "BAT UDP Port",
				       "Set the port for B.A.T.M.A.N. BAT "
				       "messages (if other than the default of 4305)",
				       10, &global_bat_batman_udp_port);
	prefs_register_uint_preference(bat_module, "batman.gw.port", "GW UDP Port",
				       "Set the port for B.A.T.M.A.N. Gateway "
				       "messages (if other than the default of 4306)",
				       10, &global_bat_gw_udp_port);
	prefs_register_uint_preference(bat_module, "batman.vis.port", "VIS UDP Port",
				       "Set the port for B.A.T.M.A.N. VIS "
				       "messages (if other than the default of 4307)",
				       10, &global_bat_vis_udp_port);
}

void proto_reg_handoff_bat(void)
{
	static gboolean inited = FALSE;
	static dissector_handle_t batman_handle;
	static dissector_handle_t gw_handle;
	static dissector_handle_t vis_handle;
	static guint batman_udp_port;
	static guint gw_udp_port;
	static guint vis_udp_port;

	if (!inited) {
		bat_tap = register_tap("batman");
		bat_follow_tap = register_tap("batman_follow");

		batman_handle = create_dissector_handle(dissect_bat_batman, proto_bat_plugin);
		gw_handle = create_dissector_handle(dissect_bat_gw, proto_bat_plugin);
		vis_handle = create_dissector_handle(dissect_bat_vis, proto_bat_plugin);

		ip_handle = find_dissector("ip");
		data_handle = find_dissector("data");

		inited = TRUE;
	} else {
		dissector_delete_uint("udp.port", batman_udp_port, batman_handle);
		dissector_delete_uint("udp.port", gw_udp_port, gw_handle);
		dissector_delete_uint("udp.port", vis_udp_port, vis_handle);
	}

	batman_udp_port = global_bat_batman_udp_port;
	gw_udp_port = global_bat_gw_udp_port;
	vis_udp_port = global_bat_vis_udp_port;
	dissector_add_uint("udp.port", batman_udp_port, batman_handle);
	dissector_add_uint("udp.port", gw_udp_port, gw_handle);
	dissector_add_uint("udp.port", vis_udp_port, vis_handle);
}
