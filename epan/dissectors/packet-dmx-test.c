/* packet-dmx-test.c
 * DMX Test packet disassembly.
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

#define DMX_TEST_PACKET_SIZE  512
#define DMX_TEST_VALUE       0x55

void proto_register_dmx_test(void);

static int proto_dmx_test = -1;

static int hf_dmx_test_data = -1;
static int hf_dmx_test_data_good = -1;
static int hf_dmx_test_data_bad = -1;

static int ett_dmx_test = -1;

static void
dissect_dmx_test(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DMX Test Frame");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree != NULL) {
		guint    offset = 0;
		guint    size, i, test_data_is_ok;
		proto_tree *test_data_tree;
		proto_item *item;

		proto_tree *ti = proto_tree_add_item(tree, proto_dmx_test, tvb,
							offset, -1, ENC_NA);
		proto_tree *dmx_test_tree = proto_item_add_subtree(ti, ett_dmx_test);

		size = tvb_reported_length_remaining(tvb, offset);

		item = proto_tree_add_item(dmx_test_tree, hf_dmx_test_data, tvb,
							offset, size, ENC_NA);
		offset += size;

		if (size == DMX_TEST_PACKET_SIZE) {
			test_data_is_ok = TRUE;
			for (i = 0; i < DMX_TEST_PACKET_SIZE; i++) {
				if (tvb_get_guint8(tvb, i) != DMX_TEST_VALUE) {
					test_data_is_ok = FALSE;
					break;
				}
			}
		} else {
			test_data_is_ok = FALSE;
		}

		if (test_data_is_ok) {
			proto_item_append_text(ti, ", Data correct");
			proto_item_append_text(item, " [correct]");

			test_data_tree = proto_item_add_subtree(item, ett_dmx_test);
			item = proto_tree_add_boolean(test_data_tree, hf_dmx_test_data_good, tvb,
							offset, size, TRUE);
			PROTO_ITEM_SET_GENERATED(item);
			item = proto_tree_add_boolean(test_data_tree, hf_dmx_test_data_bad, tvb,
							offset, size, FALSE);
			PROTO_ITEM_SET_GENERATED(item);
		} else {
			proto_item_append_text(ti, ", Data incorrect");
			proto_item_append_text(item, " [incorrect]");

			test_data_tree = proto_item_add_subtree(item, ett_dmx_test);
			item = proto_tree_add_boolean(test_data_tree, hf_dmx_test_data_good, tvb,
							offset, size, FALSE);
			PROTO_ITEM_SET_GENERATED(item);
			item = proto_tree_add_boolean(test_data_tree, hf_dmx_test_data_bad, tvb,
								offset, size, TRUE);
			PROTO_ITEM_SET_GENERATED(item);
		}
	}
}

void
proto_register_dmx_test(void)
{
	static hf_register_info hf[] = {
		{ &hf_dmx_test_data,
			{ "Test Data", "dmx_test.data",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_test_data_good,
			{ "Data Good", "dmx_test.data_good",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"True: test data is correct; False: test data is incorrect", HFILL }},

		{ &hf_dmx_test_data_bad,
			{ "Data Bad", "dmx_test.data_bad",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"True: test data is incorrect; False: test data is correct", HFILL }},
	};

	static gint *ett[] = {
		&ett_dmx_test
	};

	proto_dmx_test = proto_register_protocol("DMX Test Frame", "DMX Test Frame", "dmx-test");
	proto_register_field_array(proto_dmx_test, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("dmx-test", dissect_dmx_test, proto_dmx_test);
}
