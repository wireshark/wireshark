/* packet-vntag.c
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

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>

void proto_register_vntag(void);
void proto_reg_handoff_vntag(void);

static dissector_handle_t ethertype_handle;

static int proto_vntag = -1;

static int hf_vntag_etype = -1;
static int hf_vntag_dir = -1;
static int hf_vntag_ptr = -1;
static int hf_vntag_vif_list_id = -1;
static int hf_vntag_dst = -1;
static int hf_vntag_looped = -1;
static int hf_vntag_r = -1;
static int hf_vntag_version = -1;
static int hf_vntag_src = -1;
/* static int hf_vntag_len = -1; */
static int hf_vntag_trailer = -1;

static gint ett_vntag = -1;

static int
dissect_vntag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint16     encap_proto;
	proto_tree *vntag_tree = NULL;
	ethertype_data_t ethertype_data;

	/* from scapy (http://hg.secdev.org/scapy-com/rev/37acec891993) GPLv2: */
	/* another: http://www.definethecloud.net/access-layer-network-virtualization-vn-tag-and-vepa */
	static const int * fields[] = {
		&hf_vntag_dir,
		&hf_vntag_ptr,
		&hf_vntag_vif_list_id,
		&hf_vntag_dst,
		&hf_vntag_looped,
		&hf_vntag_r,
		&hf_vntag_version,
		&hf_vntag_src,
		NULL
	};

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "VNTAG");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		proto_item *ti = proto_tree_add_item(tree, proto_vntag, tvb, 0, 4, ENC_NA);
		vntag_tree = proto_item_add_subtree(ti, ett_vntag);

		proto_tree_add_bitmask_list(vntag_tree, tvb, 0, 4, fields, ENC_BIG_ENDIAN);
	}

	encap_proto = tvb_get_ntohs(tvb, 4);

	/* copied from packet-vlan.c do we need it also for VNTAG? */
#if 0
	if (encap_proto <= IEEE_802_3_MAX_LEN) {
		gboolean is_802_2;

		/* Is there an 802.2 layer? I can tell by looking at the first 2
		   bytes after the VLAN header. If they are 0xffff, then what
		   follows the VLAN header is an IPX payload, meaning no 802.2.
		   (IPX/SPX is they only thing that can be contained inside a
		   straight 802.3 packet, so presumably the same applies for
		   Ethernet VLAN packets). A non-0xffff value means that there's an
		   802.2 layer inside the VLAN layer */
		is_802_2 = TRUE;

		/* Don't throw an exception for this check (even a BoundsError) */
		if (tvb_captured_length_remaining(tvb, 4) >= 2) {
			if (tvb_get_ntohs(tvb, 4) == 0xffff)
				is_802_2 = FALSE;
		}

		dissect_802_3(encap_proto, is_802_2, tvb, 4, pinfo, tree, vntag_tree, hf_vntag_len, hf_vntag_trailer, 0);
	} else {
#endif
		ethertype_data.etype = encap_proto;
		ethertype_data.offset_after_ethertype = 6;
		ethertype_data.fh_tree = vntag_tree;
		ethertype_data.etype_id = hf_vntag_etype;
		ethertype_data.trailer_id = hf_vntag_trailer;
		ethertype_data.fcs_len = 0;

		call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
#if 0
	}
#endif
	return tvb_captured_length(tvb);
}

void
proto_register_vntag(void)
{
	static hf_register_info hf[] = {
		{ &hf_vntag_etype,
			{ "Type", "vntag.etype", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0, NULL, HFILL }
		},
		{ &hf_vntag_dir,
			{ "Direction", "vntag.dir", FT_UINT32, BASE_DEC, NULL, 0x80000000, NULL, HFILL }
		},
		{ &hf_vntag_ptr,
			{ "Pointer", "vntag.ptr", FT_UINT32, BASE_DEC, NULL, 0x40000000, NULL, HFILL }
		},
		{ &hf_vntag_vif_list_id,
			{ "Downlink Ports", "vntag.vif_list_id", FT_UINT32, BASE_DEC, NULL, 0x30000000, NULL, HFILL }
		},
		{ &hf_vntag_dst,
			{ "Destination", "vntag.dst", FT_UINT32, BASE_DEC, NULL, 0x0FFF0000, NULL, HFILL }
		},
		{ &hf_vntag_looped,
			{ "Looped", "vntag.looped", FT_UINT32, BASE_DEC, NULL, 0x00008000, NULL, HFILL }
		},
		{ &hf_vntag_r,
			{ "Reserved", "vntag.r", FT_UINT32, BASE_DEC, NULL, 0x00004000, NULL, HFILL }
		},
		{ &hf_vntag_version,
			{ "Version", "vntag.version", FT_UINT32, BASE_DEC, NULL, 0x00003000, NULL, HFILL }
		},
		{ &hf_vntag_src,
			{ "Source", "vntag.src", FT_UINT32, BASE_DEC, NULL, 0x00000FFF, NULL, HFILL }
		},

#if 0
		{ &hf_vntag_len,
			{ "Length", "vntag.len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
#endif
		{ &hf_vntag_trailer,
			{ "Trailer", "vntag.trailer", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_vntag
	};

	proto_vntag = proto_register_protocol("VN-Tag", "VNTAG", "vntag");
	proto_register_field_array(proto_vntag, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vntag(void)
{
	dissector_handle_t vntag_handle;

	/* XXX, add 0x8926 define to epan/etypes.h && etype_vals */

	vntag_handle = create_dissector_handle(dissect_vntag, proto_vntag);
	dissector_add_uint("ethertype", ETHERTYPE_VNTAG, vntag_handle);

	ethertype_handle = find_dissector_add_dependency("ethertype", proto_vntag);
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
