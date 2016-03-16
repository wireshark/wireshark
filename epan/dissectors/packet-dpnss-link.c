/* packet-dpnss-link.c
 * Routines for DPNSS/DASS2 link layer dissection
 * Copyright 2009, Rolf Fiedler <rolf.fiedler[at]innoventif[dot]de>
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
/* References:
 * BTNR188
 * ND1301:2001/03  http://www.nicc.org.uk/nicc-public/Public/interconnectstandards/dpnss/nd1301_2004_11.pdf
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>

void proto_register_dpnss_link(void);
void proto_reg_handoff_dpnss_link(void);

static dissector_handle_t dpnss_handle; /* DPNSS UI frame dissector */
#define LINK_HEADER_SIZE 3

static int proto_dpnss_link = -1;

static int hf_dpnss_link_address_framegroup = -1;
static int hf_dpnss_link_address_crbit = -1;
static int hf_dpnss_link_address_extension = -1;
static int hf_dpnss_link_address2_reserved = -1;
static int hf_dpnss_link_address2_dlcId = -1;
static int hf_dpnss_link_address2_dlcIdNr = -1;
static int hf_dpnss_link_address2_extension = -1;
static int hf_dpnss_link_control_frameType = -1;

static const value_string dpnss_link_framegroup_vals[] = {
	{ 0x11, "Information Frame" },
	{ 0x03, "Control Frame" },
	{ 0, NULL }
};

static const value_string dpnss_link_crbit_vals[] = {
	{ 0x0, "Command/Response Bit Cleared" },
	{ 0x1, "Command/Response Bit Set" },
	{ 0, NULL }
};

static const value_string dpnss_link_extend_vals[] = {
	{ 0x0, "Extended to next octet" },
	{ 0x1, "Final octet" },
	{ 0, NULL }
};

static const value_string dpnss_link_reserved_vals[] = {
	{ 0x0, "Reserved" },
	{ 0x1, "Reserved" },
	{ 0, NULL }
};

static const value_string dpnss_link_dlcId_vals[] = {
	{ 0x0, "Real Channel" },
	{ 0x1, "Virtual Channel" },
	{ 0, NULL }
};

#define FRAME_TYPE_UI_EVEN 0x03
#define FRAME_TYPE_UI_ODD  0x13
#define FRAME_TYPE_SABMR   0xef
#define FRAME_TYPE_UA      0x63

static const value_string dpnss_link_frameType_vals[] = {
	{ FRAME_TYPE_UI_EVEN, "UI (even)" },
	{ FRAME_TYPE_UI_ODD,  "UI (odd)" },
	{ FRAME_TYPE_SABMR,   "SABMR" },
	{ FRAME_TYPE_UA,      "UA" },
	{ 0, NULL }
};

static int ett_dpnss_link = -1;

/* Code to actually dissect the packets */
static int
dissect_dpnss_link(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *item;
	proto_tree *dpnss_link_tree;
	guint8      octet;
	tvbuff_t   *protocol_data_tvb;
	guint16     protocol_data_length;
	gboolean    uton;

	uton = pinfo->pseudo_header->l1event.uton;
	/* Make entries in src and dst column */

	col_set_str(pinfo->cinfo, COL_DEF_SRC, uton?"TE":"NT");
	col_set_str(pinfo->cinfo, COL_DEF_DST, uton?"NT":"TE");

	/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DPNSS");

	item = proto_tree_add_item(tree, proto_dpnss_link, tvb, 0, -1, ENC_NA);
	dpnss_link_tree = proto_item_add_subtree(item, ett_dpnss_link);
	proto_tree_add_item(dpnss_link_tree, hf_dpnss_link_address_framegroup,
			    tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(dpnss_link_tree, hf_dpnss_link_address_crbit,
			    tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(dpnss_link_tree, hf_dpnss_link_address_extension,
			    tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(dpnss_link_tree, hf_dpnss_link_address2_reserved,
			    tvb, 1, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(dpnss_link_tree, hf_dpnss_link_address2_dlcId,
			    tvb, 1, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(dpnss_link_tree, hf_dpnss_link_address2_dlcIdNr,
			    tvb, 1, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(dpnss_link_tree, hf_dpnss_link_address2_extension,
			    tvb, 1, 1, ENC_BIG_ENDIAN);
	/*
	 * XXX - DPNSS's layer 2 protocol appears to be Yet Another
	 * HDLC Derivative; should this use the xDLC control field
	 * dissector code?
	 */
	proto_tree_add_item(dpnss_link_tree, hf_dpnss_link_control_frameType,
			    tvb, 2, 1, ENC_BIG_ENDIAN);
	octet = tvb_get_guint8(tvb, 2);
	switch (octet){
	case FRAME_TYPE_UI_EVEN:
	case FRAME_TYPE_UI_ODD:
	    protocol_data_length=tvb_reported_length(tvb)-LINK_HEADER_SIZE;
	    protocol_data_tvb=tvb_new_subset_length(tvb, LINK_HEADER_SIZE,
					     protocol_data_length);
	    if (dpnss_handle && protocol_data_length>0) {
		call_dissector(dpnss_handle, protocol_data_tvb, pinfo, tree);
	    }
	    break;
	default:
	    break;
	}
	return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */
void
proto_register_dpnss_link(void)
{
	static hf_register_info hf[] = {
		{ &hf_dpnss_link_address_framegroup,
		  { "Frame Group", "dpnss_link.framegroup",
		    FT_UINT8, BASE_DEC, VALS(dpnss_link_framegroup_vals), 0xfc,
		    NULL, HFILL }
		},
		{ &hf_dpnss_link_address_crbit,
		  { "C/R Bit", "dpnss_link.crbit",
		    FT_UINT8, BASE_DEC, VALS(dpnss_link_crbit_vals), 0x02,
		    NULL, HFILL }
		},
		{ &hf_dpnss_link_address_extension,
		  { "Extension", "dpnss_link.extension",
		    FT_UINT8, BASE_DEC, VALS(dpnss_link_extend_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_dpnss_link_address2_reserved,
		  { "Reserved", "dpnss_link.reserved",
		    FT_UINT8, BASE_DEC, VALS(dpnss_link_reserved_vals), 0x80,
		    NULL, HFILL }
		},
		{ &hf_dpnss_link_address2_dlcId,
		  { "DLC ID", "dpnss_link.dlcId",
		    FT_UINT8, BASE_DEC, VALS(dpnss_link_dlcId_vals), 0x40,
		    NULL, HFILL }
		},
		{ &hf_dpnss_link_address2_dlcIdNr,
		  { "DLC ID Number", "dpnss_link.dlcIdNr",
		    FT_UINT8, BASE_DEC, NULL, 0x3e,
		    NULL, HFILL }
		},
		{ &hf_dpnss_link_address2_extension,
		  { "Extension", "dpnss_link.extension2",
		    FT_UINT8, BASE_DEC, VALS(dpnss_link_extend_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_dpnss_link_control_frameType,
		  { "Frame Type", "dpnss_link.frameType",
		    FT_UINT8, BASE_DEC, VALS(dpnss_link_frameType_vals), 0xff,
		    NULL, HFILL }
		}
	};

	static gint *ett[] = { &ett_dpnss_link };


	/* Register the protocol name and description */
	proto_dpnss_link = proto_register_protocol("Digital Private Signalling System No 1 Link Layer",
						   "DPNSS Link", "dpnss_link");
	register_dissector("dpnss_link", dissect_dpnss_link, proto_dpnss_link);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_dpnss_link, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dpnss_link(void)
{
	dissector_handle_t dpnss_link_handle;

	dpnss_link_handle = find_dissector("dpnss_link");
	dissector_add_uint("wtap_encap", WTAP_ENCAP_DPNSS, dpnss_link_handle);

	dpnss_handle = find_dissector_add_dependency("dpnss", proto_dpnss_link);
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
