/* packet-vxlan.c
 *
 * Routines for Virtual eXtensible Local Area Network (VXLAN) packet dissection
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Protocol ref:
 * http://tools.ietf.org/html/draft-mahalingam-dutt-dcops-vxlan-00
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>



static int proto_vxlan = -1;

static int hf_vxlan_flags = -1;
static int hf_vxlan_flag_b7 = -1;
static int hf_vxlan_flag_b6 = -1;
static int hf_vxlan_flag_b5 = -1;
static int hf_vxlan_flag_b4 = -1;
static int hf_vxlan_flag_i = -1;
static int hf_vxlan_flag_b2 = -1;
static int hf_vxlan_flag_b1 = -1;
static int hf_vxlan_flag_b0 = -1;
static int hf_vxlan_reserved_24 = -1;
static int hf_vxlan_vni = -1;
static int hf_vxlan_reserved_8 = -1;


static int ett_vxlan = -1;
static int ett_vxlan_flgs = -1;


static dissector_handle_t eth_handle;

static void
dissect_vxlan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *vxlan_tree, *flg_tree;
	proto_item *ti, *flg_item;
	tvbuff_t *next_tvb;
	int offset = 0;

	/* Make entry in Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "VxLAN");

	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_vxlan, tvb, offset, -1, ENC_NA);
	vxlan_tree = proto_item_add_subtree(ti, ett_vxlan);

/*
              0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        VXLAN Header:
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |R|R|R|R|I|R|R|R|            Reserved                           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                VXLAN Network Identifier (VNI) |   Reserved    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
	/* Flags (8 bits) where the I flag MUST be set  to 1 for a valid
     *    VXLAN Network ID (VNI).  The remaining 7 bits (designated "R") are
     *    reserved fields and MUST be set to zero.
	 */
	flg_item = proto_tree_add_item(vxlan_tree, hf_vxlan_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	flg_tree = proto_item_add_subtree(ti, ett_vxlan_flgs);

	proto_tree_add_item(flg_tree, hf_vxlan_flag_b7, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flg_tree, hf_vxlan_flag_b6, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flg_tree, hf_vxlan_flag_b5, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flg_tree, hf_vxlan_flag_b4, tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(flg_tree, hf_vxlan_flag_i, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flg_tree, hf_vxlan_flag_b2, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flg_tree, hf_vxlan_flag_b1, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flg_tree, hf_vxlan_flag_b0, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(vxlan_tree, hf_vxlan_reserved_24, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset+=3;

	proto_tree_add_item(vxlan_tree, hf_vxlan_vni, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset+=3;

	
	proto_tree_add_item(vxlan_tree, hf_vxlan_reserved_8, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	next_tvb = tvb_new_subset_remaining(tvb, offset);
	call_dissector(eth_handle, next_tvb, pinfo, tree);

}


/* Register VxLAN with Wireshark */
void
proto_register_vxlan(void)
{
	static hf_register_info hf[] = {
		{ &hf_vxlan_flags,
			{ "Flags", "vxlan.flags",
				FT_UINT8, BASE_HEX, NULL, 0x00, 
				NULL, HFILL 
			},
		},
		{ &hf_vxlan_flag_b7,
			{ "Reserved(R)", "vxlan.flag_b7",
            FT_BOOLEAN, 8, NULL, 0x80,
			 NULL, HFILL,
			},
		},
		{ &hf_vxlan_flag_b6,
			{ "Reserved(R)", "vxlan.flag_b6",
            FT_BOOLEAN, 8, NULL, 0x40,
			 NULL, HFILL,
			},
		},
		{ &hf_vxlan_flag_b5,
			{ "Reserved(R)", "vxlan.flag_b5",
            FT_BOOLEAN, 8, NULL, 0x20,
			 NULL, HFILL,
			},
		},
		{ &hf_vxlan_flag_b4,
			{ "Reserved(R)", "vxlan.flag_b4",
            FT_BOOLEAN, 8, NULL, 0x10,
			 NULL, HFILL,
			},
		},
		{ &hf_vxlan_flag_i,
			{ "VXLAN Network ID(VNI)", "vxlan.flag_i",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
			 NULL, HFILL,
			},
		},
		{ &hf_vxlan_flag_b2,
			{ "Reserved(R)", "vxlan.flag_b2",
            FT_BOOLEAN, 8, NULL, 0x10,
			 NULL, HFILL,
			},
		},
		{ &hf_vxlan_flag_b1,
			{ "Reserved(R)", "vxlan.flag_b1",
            FT_BOOLEAN, 8, NULL, 0x10,
			 NULL, HFILL,
			},
		},
		{ &hf_vxlan_flag_b0,
			{ "Reserved(R)", "vxlan.flag_b0",
            FT_BOOLEAN, 8, NULL, 0x10,
			 NULL, HFILL,
			},
		},
		{ &hf_vxlan_reserved_24,
			{ "Reserved", "vxlan.reserved24",
				FT_UINT24, BASE_HEX, NULL, 0x00, 
				NULL, HFILL 
			},
		},
		{ &hf_vxlan_vni,
			{ "VXLAN Network Identifier (VNI)", "vxlan.vni",
				FT_UINT24, BASE_DEC, NULL, 0x00, 
				NULL, HFILL 
			},
		},
		{ &hf_vxlan_reserved_8,
			{ "Reserved", "vxlan.reserved8",
				FT_UINT8, BASE_DEC, NULL, 0x00, 
				NULL, HFILL 
			},
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_vxlan,
		&ett_vxlan_flgs,
	};

		/* Register the protocol name and description */
	proto_vxlan = proto_register_protocol("Virtual eXtensible Local Area Network",
			"VXLAN", "vxlan");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_vxlan, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));


}

void
proto_reg_handoff_vxlan(void)
{
    dissector_handle_t vxlan_handle;

	eth_handle = find_dissector("eth");

    vxlan_handle = create_dissector_handle(dissect_vxlan, proto_vxlan);
    dissector_add_handle("udp.port", vxlan_handle);  /* For 'Decode As' */
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */


