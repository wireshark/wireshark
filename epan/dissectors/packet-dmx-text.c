/* packet-dmx-text.c
 * DMX Text packet disassembly.
 *
 * This dissector is written by
 *
 *  Erwin Rol <erwin@erwinrol.com>
 *  Copyright 2011 Erwin Rol
 *
 *  Wireshark - Network traffic analyzer
 *  Gerald Combs <gerald@wireshark.org>
 *  Copyright 1999 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA  02110-1301, USA.
 */

/*
 * This dissector is based on;
 * American National Standard E1.11 - 2004
 * Entertainment Technology USITT DMX512-A
 * Asynchronous Serial Digital Data Transmission Standard
 * for Controlling Lighting Equipment and Accessories
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_dmx_text(void);

static int proto_dmx_text = -1;

static int hf_dmx_text_page_nr = -1;
static int hf_dmx_text_line_len = -1;
static int hf_dmx_text_string = -1;

static int ett_dmx_text = -1;

static void
dissect_dmx_text(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DMX Text");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree != NULL) {
		guint offset = 0;
		guint size;

		proto_tree *ti = proto_tree_add_item(tree, proto_dmx_text, tvb,
							offset, -1, ENC_NA);
		proto_tree *dmx_text_tree = proto_item_add_subtree(ti, ett_dmx_text);

		proto_tree_add_item(dmx_text_tree, hf_dmx_text_page_nr, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_text_tree, hf_dmx_text_line_len, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		size = tvb_reported_length_remaining(tvb, offset);

		proto_tree_add_item(dmx_text_tree, hf_dmx_text_string, tvb,
							offset, size, ENC_ASCII|ENC_NA);
	}
}

void
proto_register_dmx_text(void)
{
	static hf_register_info hf[] = {
		{ &hf_dmx_text_page_nr,
			{ "Page Number",
				"dmx_text.page_nr",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},
		{ &hf_dmx_text_line_len,
			{ "Line Length",
				"dmx_text.line_length",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},
		{ &hf_dmx_text_string,
			{ "Text String",
				"dmx_text.string",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_dmx_text
	};

	proto_dmx_text = proto_register_protocol("DMX Text Frame", "DMX Text Frame", "dmx-text");
	proto_register_field_array(proto_dmx_text, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("dmx-text", dissect_dmx_text, proto_dmx_text);
}

