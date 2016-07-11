/* packet-msnip.c   2001 Ronnie Sahlberg <See AUTHORS for email>
 * Routines for IGMP/MSNIP packet disassembly
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*


			MSNIP
	code

	0x23		x
	0x24		x
	0x25		x

	MSNIP " Multicast Source Notification of Interest Protocol
	Defined in draft-ietf-idmr-igmp-msnip-00.txt
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include "packet-igmp.h"

void proto_register_msnip(void);
void proto_reg_handoff_msnip(void);

static int proto_msnip = -1;
static int hf_checksum = -1;
static int hf_checksum_status = -1;
static int hf_type = -1;
static int hf_count = -1;
static int hf_holdtime = -1;
static int hf_groups = -1;
static int hf_maddr = -1;
static int hf_mask = -1;
static int hf_holdtime16 = -1;
static int hf_genid = -1;
static int hf_rec_type = -1;

static int ett_msnip = -1;
static int ett_groups = -1;

#define MC_ALL_IGMPV3_ROUTERS	0xe0000016

#define MSNIP_GM	0x23
#define MSNIP_IS	0x24
#define MSNIP_RMR	0x25
static const value_string msnip_types[] = {
	{MSNIP_GM,	"Multicast Group Map"},
	{MSNIP_IS,	"Multicast Interest Solicitation"},
	{MSNIP_RMR,	"Multicast Receiver Membership Report"},
	{0,					NULL}
};

#define MSNIP_RECTYPE_TRANSMIT	1
#define MSNIP_RECTYPE_HOLD	2
static const value_string msnip_rec_types[] = {
	{MSNIP_RECTYPE_TRANSMIT,	"Request to start transmitting group"},
	{MSNIP_RECTYPE_HOLD,		"Request to hold transmitting group"},
	{0,					NULL}
};

static int
dissect_msnip_rmr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint8 count;

	/* group count */
	count = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(parent_tree, hf_count, tvb, offset, 1, count);
	offset += 1;

	/* checksum */
	igmp_checksum(parent_tree, tvb, hf_checksum, hf_checksum_status, pinfo, 0);
	offset += 2;

	while (count--) {
		proto_tree *tree;
		proto_item *item;
		guint8 rec_type;
		int old_offset = offset;

		item = proto_tree_add_item(parent_tree, hf_groups,
				tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_groups);

		/* record type */
		rec_type = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(tree, hf_rec_type, tvb, offset, 1, rec_type);
		offset += 1;

		/* skip 3 unused bytes */
		offset += 3;

		/* multicast group */
		proto_tree_add_item(tree, hf_maddr, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		if (item) {
			proto_item_set_text(item,"Group: %s %s",
				tvb_ip_to_str(tvb, offset-4),
				val_to_str(rec_type, msnip_rec_types,
					"Unknown Type:0x%02x"));

			proto_item_set_len(item, offset-old_offset);
		}
	}

	return offset;
}

static int
dissect_msnip_is(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{

	/* skip reserved byte */
	offset += 1;

	/* checksum */
	igmp_checksum(parent_tree, tvb, hf_checksum, hf_checksum_status, pinfo, 0);
	offset += 2;

	/* 16 bit holdtime */
	proto_tree_add_uint(parent_tree, hf_holdtime16, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
	offset += 2;

	/* Generation ID */
	proto_tree_add_uint(parent_tree, hf_genid, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
	offset += 2;

	return offset;
}


static int
dissect_msnip_gm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint8 count;

	/* group count */
	count = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(parent_tree, hf_count, tvb, offset, 1, count);
	offset += 1;

	/* checksum */
	igmp_checksum(parent_tree, tvb, hf_checksum, hf_checksum_status, pinfo, 0);
	offset += 2;

	/* holdtime */
	proto_tree_add_uint(parent_tree, hf_holdtime, tvb, offset, 4, count);
	offset += 4;

	while (count--) {
		proto_tree *tree;
		proto_item *item;
		guint8 masklen;
		int old_offset = offset;

		item = proto_tree_add_item(parent_tree, hf_groups,
				tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_groups);

		/* multicast group */
		proto_tree_add_item(tree, hf_maddr, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		/* mask length */
		masklen = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(tree, hf_mask, tvb,
			offset, 1, masklen);
		offset += 1;

		/* skip 3 unused bytes */
		offset += 3;

		if (item) {
			proto_item_set_text(item,"Group: %s/%d",
				tvb_ip_to_str(tvb, offset - 8), masklen);

			proto_item_set_len(item, offset-old_offset);
		}
	}

	return offset;
}


/* This function is only called from the IGMP dissector */
static int
dissect_msnip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	proto_tree *tree;
	proto_item *item;
	guint8 type;
	int offset = 0;
	guint32 dst = g_htonl(MC_ALL_IGMPV3_ROUTERS);

	/* Shouldn't be destined for us */
	if (memcmp(pinfo->dst.data, &dst, 4))
	return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MSNIP");
	col_clear(pinfo->cinfo, COL_INFO);

	item = proto_tree_add_item(parent_tree, proto_msnip, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_msnip);

	type = tvb_get_guint8(tvb, offset);
	col_add_str(pinfo->cinfo, COL_INFO,
			val_to_str(type, msnip_types,
				"Unknown Type:0x%02x"));

	/* type of command */
	proto_tree_add_uint(tree, hf_type, tvb, offset, 1, type);
	offset += 1;

	switch (type) {
	case MSNIP_GM:
		offset = dissect_msnip_gm(tvb, pinfo, tree, offset);
		break;
	case MSNIP_IS:
		offset = dissect_msnip_is(tvb, pinfo, tree, offset);
		break;
	case MSNIP_RMR:
		offset = dissect_msnip_rmr(tvb, pinfo, tree, offset);
		break;
	}

	if (item) {
		proto_item_set_len(item, offset);
	}

	return offset;
}


void
proto_register_msnip(void)
{
	static hf_register_info hf[] = {
		{ &hf_type,
			{ "Type", "msnip.type", FT_UINT8, BASE_HEX,
			  VALS(msnip_types), 0, "MSNIP Packet Type", HFILL }},

		{ &hf_checksum,
			{ "Checksum", "msnip.checksum", FT_UINT16, BASE_HEX,
			  NULL, 0, "MSNIP Checksum", HFILL }},

		{ &hf_checksum_status,
			{ "Checksum Status", "msnip.checksum.status", FT_UINT8, BASE_NONE,
			  VALS(proto_checksum_vals), 0x0, NULL, HFILL }},

		{ &hf_count,
			{ "Count", "msnip.count", FT_UINT8, BASE_DEC,
		  	  NULL, 0, "MSNIP Number of groups", HFILL }},

		{ &hf_holdtime,
			{ "Holdtime", "msnip.holdtime", FT_UINT32, BASE_DEC,
			  NULL, 0, "MSNIP Holdtime in seconds", HFILL }},

		{ &hf_groups,
			{ "Groups", "msnip.groups", FT_NONE, BASE_NONE,
			  NULL, 0, "MSNIP Groups", HFILL }},

		{ &hf_maddr,
			{ "Multicast group", "msnip.maddr", FT_IPv4, BASE_NONE,
			  NULL, 0, "MSNIP Multicast Group", HFILL }},

		{ &hf_mask,
			{ "Netmask", "msnip.netmask", FT_UINT8, BASE_DEC,
			  NULL, 0, "MSNIP Netmask", HFILL }},

		{ &hf_holdtime16,
			{ "Holdtime", "msnip.holdtime16", FT_UINT16, BASE_DEC,
			  NULL, 0, "MSNIP Holdtime in seconds", HFILL }},

		{ &hf_genid,
			{ "Generation ID", "msnip.genid", FT_UINT16, BASE_DEC,
			  NULL, 0, "MSNIP Generation ID", HFILL }},

		{ &hf_rec_type,
			{ "Record Type", "msnip.rec_type", FT_UINT8, BASE_DEC,
			  VALS(msnip_rec_types), 0, "MSNIP Record Type", HFILL }},

	};
	static gint *ett[] = {
		&ett_msnip,
		&ett_groups,
	};

	proto_msnip = proto_register_protocol("MSNIP: Multicast Source Notification of Interest Protocol",
	    "MSNIP", "msnip");
	proto_register_field_array(proto_msnip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_msnip(void)
{
	dissector_handle_t msnip_handle;

	msnip_handle = create_dissector_handle(dissect_msnip, proto_msnip);
	dissector_add_uint("igmp.type", IGMP_TYPE_0x23, msnip_handle);
	dissector_add_uint("igmp.type", IGMP_TYPE_0x24, msnip_handle);
	dissector_add_uint("igmp.type", IGMP_TYPE_0x25, msnip_handle);
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
