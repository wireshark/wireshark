/* packet-chargen.c
 * Routines for chargen packet dissection
 * Copyright 2014, Dario Lombardo <lomato@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Chargen specs taken from RFC 864
 * http://tools.ietf.org/html/rfc864
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/wmem/wmem.h>

#define CHARGEN_PORT_UDP 19
#define CHARGEN_PORT_TCP 19

void proto_register_chargen(void);
void proto_reg_handoff_chargen(void);

static int proto_chargen = -1;

static int hf_chargen_data = -1;

static gint ett_chargen = -1;

/* dissect_chargen - dissects chargen packet data
 * tvb - tvbuff for packet data (IN)
 * pinfo - packet info
 * proto_tree - resolved protocol tree
 */
static void
dissect_chargen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree* chargen_tree;
	proto_item* ti = NULL;
	guint8* data;
	guint32 len;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Chargen");
	col_set_str(pinfo->cinfo, COL_INFO, "Chargen");

	ti = proto_tree_add_item(tree, proto_chargen, tvb, 0, -1, ENC_NA);
	chargen_tree = proto_item_add_subtree(ti, ett_chargen);

	len = tvb_reported_length(tvb);
	data = tvb_get_string_enc(wmem_packet_scope(), tvb, 0, len, ENC_ASCII);

	proto_tree_add_string_format(chargen_tree, hf_chargen_data, tvb, 0,
		len, "Data", "Data (%u): %s", len, data);

/*	proto_tree_add_item(chargen_tree, hf_chargen_data, tvb, 0, -1, ENC_BIG_ENDIAN); */
}

void
proto_register_chargen(void)
{
	static hf_register_info hf[] = {
		{ &hf_chargen_data, {
			"Data", "chargen.data", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }}
		};

	static gint *ett[] = {
		&ett_chargen,
	};

	proto_chargen = proto_register_protocol("Character Generator Protocol", "chargen",
	    "chargen");
	proto_register_field_array(proto_chargen, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_chargen(void)
{
	dissector_handle_t chargen_handle;

	chargen_handle = create_dissector_handle(dissect_chargen, proto_chargen);
	dissector_add_uint("udp.port", CHARGEN_PORT_UDP, chargen_handle);
	dissector_add_uint("tcp.port", CHARGEN_PORT_TCP, chargen_handle);
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
