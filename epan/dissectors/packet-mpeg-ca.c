/* packet-mpeg-ca.c
 * Routines for MPEG2 (ISO/ISO 13818-1) Conditional Access Table (CA) dissection
 * Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
 *
 * $Id$
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
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-mpeg-sect.h>

#include "packet-mpeg-descriptor.h"

static int proto_mpeg_ca = -1;
static int hf_mpeg_ca_reserved = -1;
static int hf_mpeg_ca_version_number = -1;
static int hf_mpeg_ca_current_next_indicator = -1;
static int hf_mpeg_ca_section_number = -1;
static int hf_mpeg_ca_last_section_number = -1;

static gint ett_mpeg_ca = -1;

#define MPEG_CA_TID				0x01

#define MPEG_CA_RESERVED_MASK			0xFFFFC0
#define MPEG_CA_VERSION_NUMBER_MASK		0x00003E
#define MPEG_CA_CURRENT_NEXT_INDICATOR_MASK	0x000001

static const value_string mpeg_ca_cur_next_vals[] = {

	{ 0x0, "Not yet applicable" },
	{ 0x1, "Currently applicable" },
	{ 0x0, NULL }

};

static void
dissect_mpeg_ca(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	guint offset = 0, length = 0;

	proto_item *ti;
	proto_tree *mpeg_ca_tree;

	/* The TVB should start right after the section_length in the Section packet */

	col_set_str(pinfo->cinfo, COL_INFO, "Conditional Access Table (CA)");

	ti = proto_tree_add_item(tree, proto_mpeg_ca, tvb, offset, -1, ENC_NA);
	mpeg_ca_tree = proto_item_add_subtree(ti, ett_mpeg_ca);

	offset += packet_mpeg_sect_header(tvb, offset, mpeg_ca_tree, &length, NULL);
	length -= 4;

	proto_tree_add_item(mpeg_ca_tree, hf_mpeg_ca_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(mpeg_ca_tree, hf_mpeg_ca_version_number, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(mpeg_ca_tree, hf_mpeg_ca_current_next_indicator, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;

	proto_tree_add_item(mpeg_ca_tree, hf_mpeg_ca_section_number, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(mpeg_ca_tree, hf_mpeg_ca_last_section_number, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* Parse all the programs */
	while (offset < length)
		offset += proto_mpeg_descriptor_dissect(tvb, offset, mpeg_ca_tree);

	offset += packet_mpeg_sect_crc(tvb, pinfo, mpeg_ca_tree, 0, offset);

	proto_item_set_len(ti, offset);
}


void
proto_register_mpeg_ca(void)
{

	static hf_register_info hf[] = {

		{ &hf_mpeg_ca_reserved, {
			"Reserved", "mpeg_ca.reserved",
			FT_UINT24, BASE_HEX, NULL, MPEG_CA_RESERVED_MASK,
                        NULL, HFILL
		} },

		{ &hf_mpeg_ca_version_number, {
			"Version Number", "mpeg_ca.version",
			FT_UINT24, BASE_HEX, NULL, MPEG_CA_VERSION_NUMBER_MASK,
                        NULL, HFILL
		} },

		{ &hf_mpeg_ca_current_next_indicator, {
			"Current/Next Indicator", "mpeg_ca.cur_next_ind",
			FT_UINT24, BASE_HEX, VALS(mpeg_ca_cur_next_vals), MPEG_CA_CURRENT_NEXT_INDICATOR_MASK,
                        NULL, HFILL
		} },

		{ &hf_mpeg_ca_section_number, {
			"Section Number", "mpeg_ca.sect_num",
			FT_UINT8, BASE_DEC, NULL, 0,
                        NULL, HFILL
		} },

		{ &hf_mpeg_ca_last_section_number, {
			"Last Section Number", "mpeg_ca.last_sect_num",
			FT_UINT8, BASE_DEC, NULL, 0,
                        NULL, HFILL
		} },

	};

	static gint *ett[] = {
		&ett_mpeg_ca,
	};

	proto_mpeg_ca = proto_register_protocol("MPEG2 Conditional Access Table", "MPEG CA", "mpeg_ca");

	proto_register_field_array(proto_mpeg_ca, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


void proto_reg_handoff_mpeg_ca(void)
{
	dissector_handle_t mpeg_ca_handle;

	mpeg_ca_handle = create_dissector_handle(dissect_mpeg_ca, proto_mpeg_ca);
	dissector_add_uint("mpeg_sect.tid", MPEG_CA_TID, mpeg_ca_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 noexpandtab:
 * :indentSize=4:tabSize=4:noTabs=false:
 */
