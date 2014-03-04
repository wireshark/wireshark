/* packet-dmx.c
 * DMX packet disassembly.
 *
 * This dissector is written by
 *
 *  Erwin Rol <erwin@erwinrol.com>
 *  Copyright 2012 Erwin Rol
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

#define DMX_SC_DMX	0x00
#define DMX_SC_TEXT	0x17
#define DMX_SC_TEST	0x55
#define DMX_SC_RDM	0xCC
#define DMX_SC_SIP	0xCF

static const value_string dmx_sc_vals[] = {
	{ DMX_SC_DMX,	"DMX" },
	{ DMX_SC_TEXT,	"Text" },
	{ DMX_SC_TEST,	"Test" },
	{ DMX_SC_RDM,	"RDM" },
	{ DMX_SC_SIP,	"SIP" },
	{ 0, NULL },
};

void proto_register_dmx(void);
void proto_reg_handoff_dmx(void);

static int proto_dmx = -1;

static int hf_dmx_start_code = -1;

static dissector_handle_t rdm_handle;
static dissector_handle_t dmx_chan_handle;
static dissector_handle_t dmx_test_handle;
static dissector_handle_t dmx_text_handle;
static dissector_handle_t dmx_sip_handle;
static dissector_handle_t data_handle;


static void
dissect_dmx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;
	guint     offset = 0;
	guint8    start_code;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DMX");
	col_clear(pinfo->cinfo, COL_INFO);

	start_code = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_dmx_start_code, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset++;

	next_tvb = tvb_new_subset_remaining(tvb, offset);

	switch (start_code) {
	case DMX_SC_DMX:
		call_dissector(dmx_chan_handle, next_tvb, pinfo, tree);
		break;
	case DMX_SC_TEXT:
		call_dissector(dmx_text_handle, next_tvb, pinfo, tree);
		break;
	case DMX_SC_TEST:
		call_dissector(dmx_test_handle, next_tvb, pinfo, tree);
		break;
	case DMX_SC_RDM:
		call_dissector(rdm_handle, next_tvb, pinfo, tree);
		break;
	case DMX_SC_SIP:
		call_dissector(dmx_sip_handle, next_tvb, pinfo, tree);
		break;
	default:
		if (offset < tvb_length(tvb))
			call_dissector(data_handle, next_tvb, pinfo, tree);
		break;
	}
}

void
proto_register_dmx(void)
{
	static hf_register_info hf[] = {
		{ &hf_dmx_start_code,
			{ "Start Code", "dmx.start_code",
				FT_UINT8, BASE_HEX, VALS(dmx_sc_vals), 0x0,
				NULL, HFILL }},
	};

	proto_dmx = proto_register_protocol("DMX", "DMX", "dmx");
	proto_register_field_array(proto_dmx, hf, array_length(hf));
	register_dissector("dmx", dissect_dmx, proto_dmx);
}

void
proto_reg_handoff_dmx(void)
{
	rdm_handle	= find_dissector("rdm");
	dmx_chan_handle = find_dissector("dmx-chan");
	dmx_test_handle = find_dissector("dmx-test");
	dmx_text_handle = find_dissector("dmx-text");
	dmx_sip_handle	= find_dissector("dmx-sip");
	data_handle	= find_dissector("data");
}
