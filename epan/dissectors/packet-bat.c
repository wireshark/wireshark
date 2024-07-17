/* packet-bat.c
 * Routines for B.A.T.M.A.N. Layer 3 dissection
 * Copyright 2008-2010 Sven Eckelmann <sven@narfation.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/addr_resolv.h>
void proto_register_bat(void);
void proto_reg_handoff_bat(void);

static dissector_handle_t batman_handle;
static dissector_handle_t gw_handle;
static dissector_handle_t vis_handle;

#define BAT_BATMAN_PORT  4305
#define BAT_GW_PORT  4306 /* Not IANA registered */
#define BAT_VIS_PORT  4307 /* Not IANA registered */

#define UNIDIRECTIONAL 0x80
#define DIRECTLINK 0x40

struct batman_packet_v5 {
	uint8_t version;  /* batman version field */
	uint8_t flags;    /* 0x80: UNIDIRECTIONAL link, 0x40: DIRECTLINK flag, ... */
	uint8_t ttl;
	uint8_t gwflags;  /* flags related to gateway functions: gateway class */
	uint16_t seqno;
	uint16_t gwport;
	address orig;
	address old_orig;
	uint8_t tq;
	uint8_t hna_len;
};
#define BATMAN_PACKET_V5_SIZE 18

struct gw_packet {
	uint8_t type;
};
#define GW_PACKET_SIZE 1

#define TUNNEL_DATA		 0x01
#define TUNNEL_IP_REQUEST	 0x02
#define TUNNEL_IP_INVALID	 0x03
#define TUNNEL_KEEPALIVE_REQUEST 0x04
#define TUNNEL_KEEPALIVE_REPLY	 0x05

#define DATA_TYPE_NEIGH	 1
#define DATA_TYPE_SEC_IF 2
#define DATA_TYPE_HNA	 3

struct vis_packet_v22 {
	address sender_ip;
	uint8_t version;
	uint8_t gw_class;
	uint16_t tq_max;
};
#define VIS_PACKET_V22_SIZE 8

struct vis_data_v22 {
	uint8_t type;
	uint16_t data;
	address ip;
};
#define VIS_PACKET_V22_DATA_SIZE 7

struct vis_packet_v23 {
	address sender_ip;
	uint8_t version;
	uint8_t gw_class;
	uint8_t tq_max;
};
#define VIS_PACKET_V23_SIZE 7

struct vis_data_v23 {
	uint8_t type;
	uint8_t data;
	address ip;
};
#define VIS_PACKET_V23_DATA_SIZE 6
/* End content from packet-bat.h */

/* trees */
static int ett_bat_batman;
static int ett_bat_batman_flags;
static int ett_bat_batman_gwflags;
static int ett_bat_batman_hna;
static int ett_bat_gw;
static int ett_bat_vis;
static int ett_bat_vis_entry;

/* hfs */
static int hf_bat_batman_version;
static int hf_bat_batman_flags;
static int hf_bat_batman_ttl;
static int hf_bat_batman_gwflags;
static int hf_bat_batman_gwflags_dl_speed;
static int hf_bat_batman_gwflags_ul_speed;
static int hf_bat_batman_seqno;
static int hf_bat_batman_gwport;
static int hf_bat_batman_orig;
static int hf_bat_batman_old_orig;
static int hf_bat_batman_tq;
static int hf_bat_batman_hna_len;
static int hf_bat_batman_hna_network;
static int hf_bat_batman_hna_netmask;

static int hf_bat_gw_type;
static int hf_bat_gw_ip;

static int hf_bat_vis_vis_orig;
static int hf_bat_vis_version;
static int hf_bat_vis_gwflags;
static int hf_bat_max_tq_v22;
static int hf_bat_max_tq_v23;
static int hf_bat_vis_data_type;
static int hf_bat_vis_netmask;
static int hf_bat_vis_tq_v22;
static int hf_bat_vis_tq_v23;
static int hf_bat_vis_data_ip;

/* flags */
static int hf_bat_batman_flags_unidirectional;
static int hf_bat_batman_flags_directlink;

static const value_string gw_packettypenames[] = {
	{ TUNNEL_DATA,		    "DATA" },
	{ TUNNEL_IP_REQUEST,	    "IP_REQUEST" },
	{ TUNNEL_IP_INVALID,	    "IP_INVALID" },
	{ TUNNEL_KEEPALIVE_REQUEST, "KEEPALIVE_REQUEST" },
	{ TUNNEL_KEEPALIVE_REPLY,   "KEEPALIVE_REPLY" },
	{ 0, NULL }
};

static const value_string vis_packettypenames[] = {
	{ DATA_TYPE_NEIGH,  "NEIGH" },
	{ DATA_TYPE_SEC_IF, "SEC_IF" },
	{ DATA_TYPE_HNA,    "HNA" },
	{ 0, NULL }
};

/* supported packet dissectors */
static int dissect_bat_batman_v5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);


static void dissect_bat_vis_v22(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_vis_entry_v22(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_bat_vis_v23(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_vis_entry_v23(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_bat_hna(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* other dissectors */
static dissector_handle_t ip_handle;

static int proto_bat_plugin;
static int proto_bat_gw;
static int proto_bat_vis;

/* tap */
static int bat_tap;
static int bat_follow_tap;

static int dissect_bat_batman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	uint8_t version;
	int offset = 0;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_BATMAN");
	col_clear(pinfo->cinfo, COL_INFO);

	version = tvb_get_uint8(tvb, 0);
	switch (version) {
	case 5:
		while (tvb_reported_length_remaining(tvb, offset) > 0) {
			offset = dissect_bat_batman_v5(tvb, offset, pinfo, tree);
		}
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_data_dissector(tvb, pinfo, tree);
		break;
	}
	return tvb_captured_length(tvb);
}

static void dissect_bat_gwflags(tvbuff_t *tvb, uint8_t gwflags, int offset, proto_item *tgw)
{
	proto_tree *gwflags_tree;
	uint8_t s = (gwflags & 0x80) >> 7;
	uint8_t downbits = (gwflags & 0x78) >> 3;
	uint8_t upbits = (gwflags & 0x07);
	unsigned  down, up;

	down = 32 * (s + 2) * (1 << downbits);
	up = ((upbits + 1) * down) / 8;

	gwflags_tree =  proto_item_add_subtree(tgw, ett_bat_batman_gwflags);
	proto_tree_add_uint(gwflags_tree, hf_bat_batman_gwflags_dl_speed, tvb, offset, 1, down);
	proto_tree_add_uint(gwflags_tree, hf_bat_batman_gwflags_ul_speed, tvb, offset, 1, up);

}

static int dissect_bat_batman_v5(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *tgw;
	proto_tree *bat_batman_tree = NULL;
	struct batman_packet_v5 *batman_packeth;
	uint32_t old_orig, orig;
	int i;
	static int * const batman_flags[] = {
		&hf_bat_batman_flags_unidirectional,
		&hf_bat_batman_flags_directlink,
		NULL
	};

	tvbuff_t *next_tvb;

	batman_packeth = wmem_new(pinfo->pool, struct batman_packet_v5);

	batman_packeth->version = tvb_get_uint8(tvb, offset+0);
	batman_packeth->flags = tvb_get_uint8(tvb, offset+1);
	batman_packeth->ttl = tvb_get_uint8(tvb, offset+2);
	batman_packeth->gwflags = tvb_get_uint8(tvb, offset+3);
	batman_packeth->seqno = tvb_get_ntohs(tvb, offset+4);
	batman_packeth->gwport = tvb_get_ntohs(tvb, offset+6);
	orig = tvb_get_ipv4(tvb, offset+8);
	set_address_tvb(&batman_packeth->orig, AT_IPv4, 4, tvb, offset+8);
	old_orig = tvb_get_ipv4(tvb, offset+12);
	set_address_tvb(&batman_packeth->old_orig, AT_IPv4, 4, tvb, offset+12);
	batman_packeth->tq = tvb_get_uint8(tvb, offset+16);
	batman_packeth->hna_len = tvb_get_uint8(tvb, offset+17);

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", batman_packeth->seqno);

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, offset, BATMAN_PACKET_V5_SIZE,
							    "B.A.T.M.A.N., Orig: %s",
							    address_with_resolution_to_str(pinfo->pool, &batman_packeth->orig));
		bat_batman_tree = proto_item_add_subtree(ti, ett_bat_batman);
	}

	/* items */
	proto_tree_add_item(bat_batman_tree, hf_bat_batman_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(bat_batman_tree, tvb, offset, hf_bat_batman_flags,
					ett_bat_batman_flags, batman_flags, ENC_NA);
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
		next_tvb = tvb_new_subset_length(tvb, offset, 5);

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
	uint32_t hna;
	uint8_t hna_netmask;

	hna = tvb_get_ipv4(tvb, 0);
	hna_netmask = tvb_get_uint8(tvb, 4);


	/* Set tree info */
	if (tree) {
		proto_item *ti;
		proto_tree *bat_batman_hna_tree;

		if (PTREE_DATA(tree)->visible) {
			ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, 5,
							    "B.A.T.M.A.N. HNA: %s/%d",
							    tvb_ip_to_str(pinfo->pool, tvb, 0), hna_netmask);
		} else {
			ti = proto_tree_add_item(tree, proto_bat_plugin, tvb, 0, 5, ENC_NA);
		}
		bat_batman_hna_tree = proto_item_add_subtree(ti, ett_bat_batman_hna);

		proto_tree_add_ipv4(bat_batman_hna_tree, hf_bat_batman_hna_network, tvb, 0, 4, hna);
		proto_tree_add_item(bat_batman_hna_tree, hf_bat_batman_hna_netmask, tvb, 4, 1, ENC_BIG_ENDIAN);
	}
}


static int dissect_bat_gw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	struct gw_packet *gw_packeth;
	uint32_t ip;
	int ip_pos;

	tvbuff_t *next_tvb;
	int length_remaining;
	int offset = 0;

	gw_packeth = wmem_new(pinfo->pool, struct gw_packet);
	gw_packeth->type = tvb_get_uint8(tvb, 0);

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
		col_append_fstr(pinfo->cinfo, COL_INFO, " IP: %s",
				tvb_address_with_resolution_to_str(pinfo->pool, tvb, AT_IPv4, ip_pos));
	}


	/* Set tree info */
	if (tree) {
		proto_item *ti;
		proto_tree *bat_gw_entry_tree;

		ti = proto_tree_add_protocol_format(tree, proto_bat_gw, tvb, 0, 1,
							"B.A.T.M.A.N. GW [%s]",
							val_to_str(gw_packeth->type, gw_packettypenames, "Unknown (0x%02x)"));
		bat_gw_entry_tree = proto_item_add_subtree(ti, ett_bat_gw);

		proto_tree_add_item(bat_gw_entry_tree, hf_bat_gw_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		/*offset += 1;*/

		if (gw_packeth->type != TUNNEL_DATA && ip != 0) {
			proto_tree_add_ipv4(bat_gw_entry_tree, hf_bat_gw_ip, tvb, ip_pos, 4, ip);
			/*offset = ip_pos + 4;*/
		}
	}

	/* Calculate offset even when we got no tree */
	offset = 1;
	if (gw_packeth->type != TUNNEL_DATA && ip != 0)
		offset = ip_pos + 4;

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		if (gw_packeth->type == TUNNEL_DATA) {
			call_dissector(ip_handle, next_tvb, pinfo, tree);
		} else {
			call_data_dissector(next_tvb, pinfo, tree);
		}
	}
	return tvb_captured_length(tvb);
}

static int dissect_bat_vis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	uint8_t version;

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_VIS");

	version = tvb_get_uint8(tvb, 4);
	switch (version) {
	case 22:
		dissect_bat_vis_v22(tvb, pinfo, tree);
		break;
	case 23:
		dissect_bat_vis_v23(tvb, pinfo, tree);
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unsupported Version %d", version);
		call_data_dissector(tvb, pinfo, tree);
		break;
	}
	return tvb_captured_length(tvb);
}

static void dissect_bat_vis_v22(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct vis_packet_v22 *vis_packeth;
	uint32_t sender_ip;
	proto_tree *bat_vis_tree = NULL;

	tvbuff_t *next_tvb;
	int length_remaining, i;
	int offset = 0;

	vis_packeth = wmem_new(pinfo->pool, struct vis_packet_v22);

	sender_ip = tvb_get_ipv4(tvb, 0);
	set_address_tvb(&vis_packeth->sender_ip, AT_IPv4, 4, tvb, 0);
	vis_packeth->version = tvb_get_uint8(tvb, 4);
	vis_packeth->gw_class = tvb_get_uint8(tvb, 5);
	vis_packeth->tq_max = tvb_get_ntohs(tvb, 6);

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_VIS");

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Src: %s",
		     address_with_resolution_to_str(pinfo->pool, &vis_packeth->sender_ip));

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_bat_vis, tvb, 0, VIS_PACKET_V22_SIZE,
							    "B.A.T.M.A.N. Vis, Src: %s",
							    address_with_resolution_to_str(pinfo->pool, &vis_packeth->sender_ip));
		bat_vis_tree = proto_item_add_subtree(ti, ett_bat_vis);

		/* items */
		proto_tree_add_ipv4(bat_vis_tree, hf_bat_vis_vis_orig, tvb, offset, 4, sender_ip);
		offset += 4;

		proto_tree_add_item(bat_vis_tree, hf_bat_vis_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(bat_vis_tree, hf_bat_vis_gwflags, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(bat_vis_tree, hf_bat_max_tq_v22, tvb, offset, 2, ENC_BIG_ENDIAN);
		/*offset += 2;*/
	}

	/* Calculate offset even when we got no tree */
	offset = VIS_PACKET_V22_SIZE;

	tap_queue_packet(bat_tap, pinfo, vis_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);

	for (i = 0; i < length_remaining; i += VIS_PACKET_V22_DATA_SIZE) {
		next_tvb = tvb_new_subset_length(tvb, offset, VIS_PACKET_V22_DATA_SIZE);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		if (bat_vis_tree != NULL) {
			dissect_vis_entry_v22(next_tvb, pinfo, tree);
		}

		offset += VIS_PACKET_V22_DATA_SIZE;
	}

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		call_data_dissector(next_tvb, pinfo, tree);
	}
}

static void dissect_vis_entry_v22(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	struct vis_data_v22 *vis_datah;
	uint32_t ip;

	vis_datah = wmem_new(pinfo->pool, struct vis_data_v22);
	vis_datah->type = tvb_get_uint8(tvb, 0);
	vis_datah->data = tvb_get_ntohs(tvb, 1);
	ip = tvb_get_ipv4(tvb, 3);
	set_address_tvb(&vis_datah->ip, AT_IPv4, 4, tvb, 3);


	/* Set tree info */
	if (tree) {
		proto_item *ti;
		proto_tree *bat_vis_entry_tree;

		ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, 7,
							    "VIS Entry: [%s] %s",
							    val_to_str(vis_datah->type, vis_packettypenames, "Unknown (0x%02x)"),
							    address_with_resolution_to_str(pinfo->pool, &vis_datah->ip));
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
	uint32_t sender_ip;
	proto_tree *bat_vis_tree = NULL;

	tvbuff_t *next_tvb;
	int length_remaining, i;
	int offset = 0;

	vis_packeth = wmem_new(pinfo->pool, struct vis_packet_v23);

	sender_ip = tvb_get_ipv4(tvb, 0);
	set_address_tvb(&vis_packeth->sender_ip, AT_IPv4, 4, tvb, 0);
	vis_packeth->version = tvb_get_uint8(tvb, 4);
	vis_packeth->gw_class = tvb_get_uint8(tvb, 5);
	vis_packeth->tq_max = tvb_get_uint8(tvb, 6);

	/* set protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAT_VIS");

	/* Set info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Src: %s",
		     address_with_resolution_to_str(pinfo->pool, &vis_packeth->sender_ip));

	/* Set tree info */
	if (tree) {
		proto_item *ti;

		ti = proto_tree_add_protocol_format(tree, proto_bat_vis, tvb, 0, VIS_PACKET_V23_SIZE,
							    "B.A.T.M.A.N. Vis, Src: %s",
							    address_with_resolution_to_str(pinfo->pool, &vis_packeth->sender_ip));
		bat_vis_tree = proto_item_add_subtree(ti, ett_bat_vis);

		/* items */
		proto_tree_add_ipv4(bat_vis_tree, hf_bat_vis_vis_orig, tvb, offset, 4, sender_ip);
		offset += 4;

		proto_tree_add_item(bat_vis_tree, hf_bat_vis_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(bat_vis_tree, hf_bat_vis_gwflags, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(bat_vis_tree, hf_bat_max_tq_v23, tvb, offset, 1, ENC_BIG_ENDIAN);
		/*offset += 1;*/
	}

	/* Calculate offset even when we got no tree */
	offset = VIS_PACKET_V23_SIZE;

	tap_queue_packet(bat_tap, pinfo, vis_packeth);

	length_remaining = tvb_reported_length_remaining(tvb, offset);

	for (i = 0; i < length_remaining; i += VIS_PACKET_V23_DATA_SIZE) {
		next_tvb = tvb_new_subset_length(tvb, offset, VIS_PACKET_V23_DATA_SIZE);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		if (bat_vis_tree != NULL) {
			dissect_vis_entry_v23(next_tvb, pinfo, tree);
		}

		offset += VIS_PACKET_V23_DATA_SIZE;
	}

	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (length_remaining > 0) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (have_tap_listener(bat_follow_tap)) {
			tap_queue_packet(bat_follow_tap, pinfo, next_tvb);
		}

		call_data_dissector(next_tvb, pinfo, tree);
	}
}

static void dissect_vis_entry_v23(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	struct vis_data_v23 *vis_datah;
	uint32_t ip;

	vis_datah = wmem_new(pinfo->pool, struct vis_data_v23);
	vis_datah->type = tvb_get_uint8(tvb, 0);
	vis_datah->data = tvb_get_uint8(tvb, 1);
	ip = tvb_get_ipv4(tvb, 2);
	set_address_tvb(&vis_datah->ip, AT_IPv4, 4, tvb, 2);


	/* Set tree info */
	if (tree) {
		proto_item *ti;
		proto_tree *bat_vis_entry_tree;

		ti = proto_tree_add_protocol_format(tree, proto_bat_plugin, tvb, 0, 7,
							    "VIS Entry: [%s] %s",
							    val_to_str(vis_datah->type, vis_packettypenames, "Unknown (0x%02x)"),
							    address_with_resolution_to_str(pinfo->pool, &vis_datah->ip));
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
		{ &hf_bat_batman_gwflags_dl_speed,
		  { "Download Speed", "bat.batman.gwflags.dl_speed",
		    FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_kbit, 0x0,
		    NULL, HFILL }
		},
		{ &hf_bat_batman_gwflags_ul_speed,
		  { "Upload Speed", "bat.batman.gwflags.ul_speed",
		    FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_kbit, 0x0,
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
	static int *ett[] = {
		&ett_bat_batman,
		&ett_bat_batman_flags,
		&ett_bat_batman_gwflags,
		&ett_bat_batman_hna,
		&ett_bat_gw,
		&ett_bat_vis,
		&ett_bat_vis_entry
	};

	proto_bat_plugin = proto_register_protocol("B.A.T.M.A.N. Layer 3 Protocol", "BAT", "bat");
	proto_bat_gw = proto_register_protocol("B.A.T.M.A.N. GW", "BAT GW", "bat.gw");
	proto_bat_vis = proto_register_protocol("B.A.T.M.A.N. Vis", "BAT VIS", "bat.vis");

	batman_handle = register_dissector("bat", dissect_bat_batman, proto_bat_plugin);
	gw_handle = register_dissector("bat.gw", dissect_bat_gw, proto_bat_gw);
	vis_handle = register_dissector("bat.vis", dissect_bat_vis, proto_bat_vis);

	proto_register_field_array(proto_bat_plugin, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	bat_tap = register_tap("batman");
	bat_follow_tap = register_tap("batman_follow");
}

void proto_reg_handoff_bat(void)
{
	ip_handle = find_dissector_add_dependency("ip", proto_bat_gw);

	dissector_add_uint_with_preference("udp.port", BAT_BATMAN_PORT, batman_handle);
	dissector_add_uint_with_preference("udp.port", BAT_GW_PORT, gw_handle);
	dissector_add_uint_with_preference("udp.port", BAT_VIS_PORT, vis_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
