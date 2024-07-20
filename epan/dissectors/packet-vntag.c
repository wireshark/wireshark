/* packet-vntag.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/tfs.h>
#include "packet-ieee8023.h"

void proto_register_vntag(void);
void proto_reg_handoff_vntag(void);

static dissector_handle_t vntag_handle;
static dissector_handle_t ethertype_handle;

static int proto_vntag;

static int hf_vntag_etype;
static int hf_vntag_dir;
static int hf_vntag_ptr;
static int hf_vntag_dst;
static int hf_vntag_looped;
static int hf_vntag_r;
static int hf_vntag_version;
static int hf_vntag_src;
static int hf_vntag_len;
static int hf_vntag_trailer;

static int ett_vntag;

static expert_field ei_vntag_len;

static const true_false_string vntag_dir_tfs = {
        "From Bridge",
        "To Bridge"
};
static const true_false_string vntag_ptr_tfs = {
        "vif_list_id",
        "vif_id"
};

static int
dissect_vntag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	uint16_t    encap_proto;
	proto_tree *vntag_tree = NULL;
	ethertype_data_t ethertype_data;

	/* Documentation:
	   https://d2zmdbbm9feqrf.cloudfront.net/2012/usa/pdf/BRKDCT-2340.pdf p.61
	   http://www.definethecloud.net/access-layer-network-virtualization-vn-tag-and-vepa
	 */
	static int * const fields[] = {
		&hf_vntag_dir,
		&hf_vntag_ptr,
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

	/* VNTAG may also carry 802.2 encapsulated data */
	if (encap_proto <= IEEE_802_3_MAX_LEN) {
		bool is_802_2;

		/* Is there an 802.2 layer? I can tell by looking at the first 2
		   bytes after the VLAN header. If they are 0xffff, then what
		   follows the VLAN header is an IPX payload, meaning no 802.2.
		   (IPX/SPX is they only thing that can be contained inside a
		   straight 802.3 packet, so presumably the same applies for
		   Ethernet VLAN packets). A non-0xffff value means that there's an
		   802.2 layer inside the VLAN layer */
		is_802_2 = true;

		/* Don't throw an exception for this check (even a BoundsError) */
		if (tvb_captured_length_remaining(tvb, 6) >= 2) {
			if (tvb_get_ntohs(tvb, 6) == 0xffff)
				is_802_2 = false;
		}

		dissect_802_3(encap_proto, is_802_2, tvb, 6, pinfo, tree, vntag_tree, hf_vntag_len, hf_vntag_trailer, &ei_vntag_len, 0);
	} else {
		proto_tree_add_uint(vntag_tree, hf_vntag_etype, tvb, 4, 2,
		    encap_proto);

		ethertype_data.etype = encap_proto;
		ethertype_data.payload_offset = 6;
		ethertype_data.fh_tree = vntag_tree;
		ethertype_data.trailer_id = hf_vntag_trailer;
		ethertype_data.fcs_len = 0;

		call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
	}
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
			{ "Direction", "vntag.dir", FT_BOOLEAN, 32, TFS(&vntag_dir_tfs), 0x80000000, NULL, HFILL }
		},
		{ &hf_vntag_ptr,
			{ "Pointer", "vntag.ptr", FT_BOOLEAN, 32, TFS(&vntag_ptr_tfs), 0x40000000, NULL, HFILL }
		},
		{ &hf_vntag_dst,
			{ "Destination", "vntag.dst", FT_UINT32, BASE_DEC, NULL, 0x3FFF0000, NULL, HFILL }
		},
		{ &hf_vntag_looped,
			{ "Looped", "vntag.looped", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00008000, NULL, HFILL }
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
		{ &hf_vntag_len,
			{ "Length", "vntag.len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_vntag_trailer,
			{ "Trailer", "vntag.trailer", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

	static int *ett[] = {
		&ett_vntag
	};

	static ei_register_info ei[] = {
		{ &ei_vntag_len, { "vntag.len.past_end", PI_MALFORMED, PI_ERROR, "Length field value goes past the end of the payload", EXPFILL }},
	};
	expert_module_t* expert_vntag;

	proto_vntag = proto_register_protocol("VN-Tag", "VNTAG", "vntag");
	proto_register_field_array(proto_vntag, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_vntag = expert_register_protocol(proto_vntag);
	expert_register_field_array(expert_vntag, ei, array_length(ei));
	vntag_handle = register_dissector("vntag", dissect_vntag, proto_vntag);
}

void
proto_reg_handoff_vntag(void)
{
	dissector_add_uint("ethertype", ETHERTYPE_VNTAG, vntag_handle);

	ethertype_handle = find_dissector_add_dependency("ethertype", proto_vntag);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
