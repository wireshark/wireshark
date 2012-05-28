/* packet-dmx.c
 * DMX packet disassembly.
 *
 * $Id: $
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


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/strutil.h>

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

void proto_reg_handoff_dmx(void);

static int proto_dmx = -1;

static int hf_dmx_start_code = -1;
static int hf_dmx_frame_data = -1;

static int ett_dmx = -1;

static dissector_handle_t rdm_handle;
static dissector_handle_t dmx_chan_handle;
static dissector_handle_t dmx_test_handle;
static dissector_handle_t dmx_text_handle;
static dissector_handle_t dmx_sip_handle;


static void
dissect_dmx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DMX");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree != NULL) {
		unsigned offset = 0;
		guint8 start_code;

		start_code = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_dmx_start_code, tvb,
				offset, 1, ENC_BIG_ENDIAN);
		offset++;

		switch (start_code) {
		case DMX_SC_DMX:
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			call_dissector(dmx_chan_handle, next_tvb, pinfo, tree);
			break;
		case DMX_SC_TEXT:
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			call_dissector(dmx_text_handle, next_tvb, pinfo, tree);
			break;
		case DMX_SC_TEST:
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			call_dissector(dmx_test_handle, next_tvb, pinfo, tree);
			break;
		case DMX_SC_RDM:
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			call_dissector(rdm_handle, next_tvb, pinfo, tree);
			break;
		case DMX_SC_SIP:
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			call_dissector(dmx_sip_handle, next_tvb, pinfo, tree);
			break;
		default:
			if (offset < tvb_length(tvb))
				proto_tree_add_item(tree, hf_dmx_frame_data, tvb,
						offset, -1, ENC_NA);
			break;
		}
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
		{ &hf_dmx_frame_data,
			{ "Frame Data", "dmx.frame_data",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_dmx
	};

	proto_dmx = proto_register_protocol("DMX", "DMX", "dmx");
	proto_register_field_array(proto_dmx, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dmx(void)
{
	static gboolean dmx_initialized = FALSE;
	static dissector_handle_t dmx_handle;

	if (!dmx_initialized) {
		dmx_handle = create_dissector_handle(dissect_dmx, proto_dmx);
		rdm_handle = find_dissector("rdm");
		dmx_test_handle = find_dissector("dmx-chan");
		dmx_test_handle = find_dissector("dmx-test");
		dmx_text_handle = find_dissector("dmx-text");
		dmx_sip_handle = find_dissector("dmx-sip");
		dmx_initialized = TRUE;
	}
}
