/* packet-nwp.c
 * Routines for NWP dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Neighborhood Watch Protocol (NWP) is an XIA protocol for resolving network
 * addresses to link-layer addresses. Hosts on a LAN send NWP Announcement
 * packets with their host identifiers (HIDs), and neighbors in the LAN
 * respond with NWP Neighbor List packets containing their HIDs and associated
 * link-layer addresses.
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_nwp(void);
void proto_reg_handoff_nwp(void);

static gint proto_nwp		= -1;

/* Header fields for all NWP headers. */
static gint hf_nwp_version	= -1;
static gint hf_nwp_type		= -1;
static gint hf_nwp_hid_count	= -1;
static gint hf_nwp_haddr_len	= -1;

/* Header fields for NWP Announcement packets. */
static gint hf_nwp_ann_haddr	= -1;
static gint hf_nwp_ann_hids	= -1;
static gint hf_nwp_ann_hid	= -1;

/* Header fields for NWP Neighbor List packets. */
static gint hf_nwp_neigh_list	= -1;
static gint hf_nwp_neigh	= -1;
static gint hf_nwp_neigh_hid	= -1;
static gint hf_nwp_neigh_num	= -1;
static gint hf_nwp_neigh_haddr	= -1;

static gint ett_nwp_tree		= -1;
static gint ett_nwp_ann_hid_tree	= -1;
static gint ett_nwp_neigh_list_tree	= -1;
static gint ett_nwp_neigh_tree		= -1;

static expert_field ei_nwp_bad_type = EI_INIT;

static dissector_handle_t nwp_handle;

#define NWP_XID_CHUNK_LEN	4
#define NWP_XID_LEN		20
/* Two characters for every byte + 4 for "hid-" + 1 for "\0" */
#define NWP_HID_STR_LEN		((NWP_XID_LEN * 2) + 5)

/* Room for a string of hardware addresses of the form:
 *
 *  XX:...:XX; XX:...:XX; ...
 *
 * (2 * LEN) bytes for each hardware address, plus (LEN - 1) bytes for colons,
 * plus 2 bytes for "; ". Multiply that by the COUNT of hardware addresses
 * that are present.
 */
#define NWP_HADDRS_STR_LEN(LEN, COUNT)	(((2 * LEN) + (LEN - 1) + 2) * COUNT)

#define NWPH_MIN_LEN		4
#define ETHERTYPE_NWP		0xC0DF
#define NWP_VERSION		0x01

#define NWP_TYPE_ANNOUNCEMENT	0x01
#define NWP_TYPE_NEIGH_LIST	0x02

/* Offsets of fields in NWP Announcements/Neighbor Lists. */
#define NWPH_VERS		0
#define NWPH_TYPE		1
#define NWPH_HIDC		2
#define NWPH_HLEN		3

#define NWPH_NLST		4
#define NWPH_HWAD		4

const value_string nwp_type_vals[] = {
	{ NWP_TYPE_ANNOUNCEMENT,	"NWP Announcement" },
	{ NWP_TYPE_NEIGH_LIST,		"NWP Neighbor List" },
	{ 0,				NULL }
};

static void
add_hid_to_strbuf(tvbuff_t *tvb, wmem_strbuf_t *hid_buf, guint8 offset)
{
	int i;
	for (i = 0; i < NWP_XID_LEN / NWP_XID_CHUNK_LEN; i++) {
		wmem_strbuf_append_printf(hid_buf, "%08x",
			tvb_get_ntohl(tvb, offset));
		offset += NWP_XID_CHUNK_LEN;
	}
}

static void
dissect_nwp_ann(tvbuff_t *tvb, proto_tree *nwp_tree, guint8 hid_count,
	guint8 ha_len)
{
	proto_tree *hid_tree = NULL;
	proto_item *ti = NULL;

	wmem_strbuf_t *buf;
	guint i;
	guint8 offset;

	/* Add hardware address. */
	proto_tree_add_item(nwp_tree, hf_nwp_ann_haddr, tvb, NWPH_HWAD,
		ha_len, ENC_NA);

	/* Add tree for HIDs. */
	ti = proto_tree_add_item(nwp_tree, hf_nwp_ann_hids, tvb,
		NWPH_HWAD + ha_len, hid_count * NWP_XID_LEN, ENC_NA);
	hid_tree = proto_item_add_subtree(ti, ett_nwp_ann_hid_tree);

	buf = wmem_strbuf_sized_new(wmem_packet_scope(),
		NWP_HID_STR_LEN, NWP_HID_STR_LEN);

	/* Add HIDs. */
	offset = NWPH_HWAD + ha_len;
	for (i = 0; i < hid_count; i++) {
		const gchar *hid_str;

		wmem_strbuf_append(buf, "hid-");
		add_hid_to_strbuf(tvb, buf, offset);
		hid_str = wmem_strbuf_get_str(buf);

		proto_tree_add_string_format(hid_tree, hf_nwp_ann_hid, tvb,
			offset, NWP_XID_LEN, hid_str, "%s", hid_str);
		wmem_strbuf_truncate(buf, 0);

		offset += NWP_XID_LEN;
	}
}

/* Neighbor list is of the form:
 *      HID_1 NUM_1 HA_11 HA_12 ... HA_1NUM_1
 *      HID_2 NUM_2 HA_21 HA_22 ... HA_2NUM_2
 *      ...
 *      HID_count NUM_count HA_count1 HA_count2 ... HA_countNUM_count
 *
 *      count == hid_count.
 */
static void
dissect_nwp_nl(tvbuff_t *tvb, proto_tree *nwp_tree, guint8 hid_count,
	guint8 ha_len)
{
	proto_tree *neigh_list_tree = NULL;
	proto_tree *neigh_tree = NULL;
	proto_item *pi = NULL;

	guint i;
	guint8 offset = NWPH_NLST;

	wmem_strbuf_t *hid_buf = wmem_strbuf_sized_new(wmem_packet_scope(),
		NWP_HID_STR_LEN, NWP_HID_STR_LEN);

	/* Set up tree for neighbor list. */
	pi = proto_tree_add_item(nwp_tree, hf_nwp_neigh_list,
		tvb, NWPH_NLST, -1, ENC_NA);
	neigh_list_tree = proto_item_add_subtree(pi, ett_nwp_neigh_list_tree);

	for (i = 0; i < hid_count; i++) {
		const gchar *hid_str;
		guint j;
		guint8 ha_count = tvb_get_guint8(tvb, offset + NWP_XID_LEN);

		/* Set up tree for this individual neighbor. */
		pi = proto_tree_add_none_format(neigh_list_tree, hf_nwp_neigh,
			tvb, offset, NWP_XID_LEN + 1 + ha_len * ha_count,
			"Neighbor %d", i + 1);
		neigh_tree = proto_item_add_subtree(pi, ett_nwp_neigh_tree);

		/* Add HID for this neighbor. */
		wmem_strbuf_append(hid_buf, "hid-");
		add_hid_to_strbuf(tvb, hid_buf, offset);
		hid_str = wmem_strbuf_get_str(hid_buf);
		proto_tree_add_string(neigh_tree, hf_nwp_neigh_hid, tvb,
			offset, NWP_XID_LEN, hid_str);
		wmem_strbuf_truncate(hid_buf, 0);
		offset += NWP_XID_LEN;

		/* Add number of devices this neighbor has. */
		proto_tree_add_item(neigh_tree, hf_nwp_neigh_num, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset++;

		/* Add hardware addresses for the neighbor's devices. */
		for (j = 0; j < ha_count; j++)
			proto_tree_add_item(neigh_tree, hf_nwp_neigh_haddr,
				tvb, offset + (j * ha_len), ha_len, ENC_NA);

		offset += ha_len * ha_count;
	}
}

static gint
dissect_nwp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void *data _U_)
{
	proto_tree *nwp_tree = NULL;

	proto_item *ti = NULL;
	proto_item *type_ti = NULL;

	const gchar *type_str;
	guint8 type, hid_count, ha_len;

	if (tvb_reported_length(tvb) < NWPH_MIN_LEN)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NWP");

	col_clear(pinfo->cinfo, COL_INFO);
	type = tvb_get_guint8(tvb, NWPH_TYPE);
	type_str = val_to_str(type, nwp_type_vals,
		"Unknown NWP packet type (0x%02x)");
	col_add_str(pinfo->cinfo, COL_INFO, type_str);

	/* Construct protocol tree. */
	ti = proto_tree_add_item(tree, proto_nwp, tvb, 0, -1, ENC_NA);
	nwp_tree = proto_item_add_subtree(ti, ett_nwp_tree);

	/* Add NWP version. */
	proto_tree_add_item(nwp_tree, hf_nwp_version, tvb,
		NWPH_VERS, 1, ENC_BIG_ENDIAN);

	/* Add NWP type. */
	type_ti = proto_tree_add_item(nwp_tree, hf_nwp_type, tvb,
		NWPH_TYPE, 1, ENC_BIG_ENDIAN);
	if (!try_val_to_str(type, nwp_type_vals))
		expert_add_info_format(pinfo, type_ti, &ei_nwp_bad_type,
			"%s", type_str);

	/* Get # of HIDs represented in this packet to use later and add it. */
	hid_count = tvb_get_guint8(tvb, NWPH_HIDC);
	proto_tree_add_item(nwp_tree, hf_nwp_hid_count, tvb,
		NWPH_HIDC, 1, ENC_BIG_ENDIAN);

	/* Get hardware address length to use later and add it. */
	ha_len = tvb_get_guint8(tvb, NWPH_HLEN);
	proto_tree_add_item(nwp_tree, hf_nwp_haddr_len, tvb,
		NWPH_HLEN, 1, ENC_BIG_ENDIAN);

	switch (type) {
	case NWP_TYPE_ANNOUNCEMENT:
		dissect_nwp_ann(tvb, nwp_tree, hid_count, ha_len);
		break;
	case NWP_TYPE_NEIGH_LIST:
		dissect_nwp_nl(tvb, nwp_tree, hid_count, ha_len);
		break;
	default:
		break;
	}

	return tvb_captured_length(tvb);
}

void
proto_register_nwp(void)
{
	static hf_register_info hf[] = {

		{ &hf_nwp_version,
		{ "Version", "nwp.version", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_nwp_type,
		{ "Type", "nwp.type", FT_UINT8,
		   BASE_HEX, VALS(nwp_type_vals), 0x0, NULL, HFILL }},

		{ &hf_nwp_hid_count,
		{ "HID Count", "nwp.hid_count", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_nwp_haddr_len,
		{ "Hardware Address Length", "nwp.haddr_len", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_nwp_ann_haddr,
		{ "Hardware Address", "nwp.ann_haddr", FT_BYTES,
		   SEP_COLON, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_ann_hids,
		{ "HIDs", "nwp.ann_hids", FT_NONE,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_ann_hid,
		{ "HID", "nwp.ann_hid", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_neigh_list,
		{ "Neighbor List", "nwp.neigh_list", FT_NONE,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_neigh,
		{ "Neighbor", "nwp.neigh", FT_NONE,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_neigh_hid,
		{ "HID", "nwp.neigh_hid", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_neigh_num,
		{ "Number of Devices", "nwp.neigh_num", FT_UINT8,
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_neigh_haddr,
		{ "Hardware Address", "nwp.neigh_haddr", FT_BYTES,
		   SEP_COLON, NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_nwp_tree,
		&ett_nwp_ann_hid_tree,
		&ett_nwp_neigh_list_tree,
		&ett_nwp_neigh_tree
	};

	static ei_register_info ei[] = {
		{ &ei_nwp_bad_type,
		{ "nwp.bad_type", PI_MALFORMED, PI_ERROR,
		  "Invalid type", EXPFILL }}
	};

	expert_module_t *expert_nwp;

	proto_nwp = proto_register_protocol(
		"Neighborhood Watch Protocol",
		"NWP",
	        "nwp");

	nwp_handle = register_dissector("nwp", dissect_nwp, proto_nwp);
	proto_register_field_array(proto_nwp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_nwp = expert_register_protocol(proto_nwp);
	expert_register_field_array(expert_nwp, ei, array_length(ei));
}

void
proto_reg_handoff_nwp(void)
{
	dissector_add_uint("ethertype", ETHERTYPE_NWP, nwp_handle);
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
