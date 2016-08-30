/*
 *  packet-bctp.c
 *  Q.1990 BICC bearer control tunnelling protocol
 *
 *  (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
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
 *
 * Ref ITU-T Rec. Q.1990 (07/2001)
 */

#include "config.h"

#include <epan/packet.h>

#define PNAME  "BCTP Q.1990"
#define PSNAME "BCTP"
#define PFNAME "bctp"

void proto_register_bctp(void);
void proto_reg_handoff_bctp(void);

static int proto_bctp = -1;
static int hf_bctp_bvei = -1;
static int hf_bctp_bvi = -1;
static int hf_bctp_tpei = -1;
static int hf_bctp_tpi = -1;

static gint ett_bctp = -1;
static dissector_table_t bctp_dissector_table;
static dissector_handle_t text_handle;

/*
static const range_string tpi_vals[] = {
	{0x00,0x17,"spare (binary encoded protocols)"},
	{0x18,0x1f,"reserved for national use (binary encoded protocols)"},
	{0x20,0x20,"IPBCP (text encoded)"},
	{0x21,0x21,"spare (text encoded protocol)"},
	{0x22,0x22,"not used"},
	{0x23,0x37,"spare (text encoded protocols)"},
	{0x38,0x3f,"reserved for national use (text encoded protocols)"},
	{0,0,NULL}
};
*/

static const value_string bvei_vals[] = {
	{0,"No indication"},
	{0,"Version Error Indication, BCTP version not supported"},
	{0,NULL}
};


static int dissect_bctp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_) {
	proto_item* pi = proto_tree_add_item(tree, proto_bctp, tvb,0,2, ENC_NA);
	proto_tree* pt = proto_item_add_subtree(pi,ett_bctp);
	tvbuff_t* sub_tvb = tvb_new_subset_remaining(tvb, 2);
	guint8 tpi = tvb_get_guint8(tvb,1) & 0x3f;

	proto_tree_add_item(pt, hf_bctp_bvei, tvb,0,2, ENC_BIG_ENDIAN);
	proto_tree_add_item(pt, hf_bctp_bvi, tvb,0,2, ENC_BIG_ENDIAN);
	proto_tree_add_item(pt, hf_bctp_tpei, tvb,0,2, ENC_BIG_ENDIAN);
	proto_tree_add_item(pt, hf_bctp_tpi, tvb,0,2, ENC_BIG_ENDIAN);

	if (!dissector_try_uint(bctp_dissector_table, tpi, sub_tvb, pinfo, tree) ) {
		if (tpi <= 0x22) {
			call_data_dissector(sub_tvb, pinfo, tree);
		} else {
			/* tpi > 0x22 */
			call_dissector(text_handle,sub_tvb, pinfo, tree);
		}
	}
	return tvb_captured_length(tvb);
}

void
proto_register_bctp (void)
{
	static hf_register_info hf[] = {
		{&hf_bctp_bvei, {"BVEI", "bctp.bvei", FT_UINT16, BASE_HEX, VALS(bvei_vals), 0x4000, "BCTP Version Error Indicator", HFILL }},
		{&hf_bctp_bvi, {"BVI", "bctp.bvi", FT_UINT16, BASE_HEX, NULL, 0x1F00, "BCTP Version Indicator", HFILL }},
		{&hf_bctp_tpei, {"TPEI", "bctp.tpei", FT_UINT16, BASE_HEX, NULL, 0x0040, "Tunneled Protocol Error Indicator", HFILL }},
		{&hf_bctp_tpi, {"TPI", "bctp.tpi", FT_UINT16, BASE_HEX, NULL, 0x003F, "Tunneled Protocol Indicator", HFILL }},
	};
	static gint *ett[] = {
		&ett_bctp
	};

	proto_bctp = proto_register_protocol(PNAME, PSNAME, PFNAME);
	proto_register_field_array(proto_bctp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("bctp", dissect_bctp, proto_bctp);

	bctp_dissector_table = register_dissector_table("bctp.tpi", "BCTP Tunneled Protocol Indicator", proto_bctp, FT_UINT32, BASE_DEC);
}

void
proto_reg_handoff_bctp(void)
{
	text_handle = find_dissector_add_dependency("data-text-lines", proto_bctp);
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
