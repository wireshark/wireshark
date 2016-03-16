/* packet-vxlan.c
 *
 * Routines for Virtual eXtensible Local Area Network (VXLAN) packet dissection
 * RFC 7348 plus draft-smith-vxlan-group-policy-01
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
#include <epan/tfs.h>

#define UDP_PORT_VXLAN  4789

void proto_register_vxlan(void);
void proto_reg_handoff_vxlan(void);

static int proto_vxlan = -1;

static int hf_vxlan_flags = -1;
static int hf_vxlan_flags_reserved = -1;
static int hf_vxlan_flag_a = -1;
static int hf_vxlan_flag_d = -1;
static int hf_vxlan_flag_i = -1;
static int hf_vxlan_flag_g = -1;
static int hf_vxlan_gbp = -1;
static int hf_vxlan_vni = -1;
static int hf_vxlan_reserved_8 = -1;


static int ett_vxlan = -1;
static int ett_vxlan_flgs = -1;

static const int *flags_fields[] = {
        &hf_vxlan_flag_g,
        &hf_vxlan_flag_d,
        &hf_vxlan_flag_i,
        &hf_vxlan_flag_a,
        &hf_vxlan_flags_reserved,
        NULL
    };

static dissector_handle_t eth_handle;

static int
dissect_vxlan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *vxlan_tree;
    proto_item *ti;
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
           |G|R|R|R|I|R|R|R|R|D|R|R|A|R|R|R|        Group Policy ID        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                VXLAN Network Identifier (VNI) |   Reserved    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
    /* Flags (16 bits) where the I flag MUST be set  to 1 for a valid
     *    VXLAN Network ID (VNI).  The remaining 12 bits (designated "R") are
     *    reserved fields and MUST be set to zero.
     */
    proto_tree_add_bitmask(vxlan_tree, tvb, offset, hf_vxlan_flags,
        ett_vxlan_flgs, flags_fields, ENC_BIG_ENDIAN);
    offset+=2;

    proto_tree_add_item(vxlan_tree, hf_vxlan_gbp, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    proto_tree_add_item(vxlan_tree, hf_vxlan_vni, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset+=3;

    proto_tree_add_item(vxlan_tree, hf_vxlan_reserved_8, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(eth_handle, next_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}


/* Register VxLAN with Wireshark */
void
proto_register_vxlan(void)
{
    static hf_register_info hf[] = {
        { &hf_vxlan_flags,
          { "Flags", "vxlan.flags",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL
          },
        },
        { &hf_vxlan_flags_reserved,
          { "Reserved(R)", "vxlan.flags_reserved",
            FT_BOOLEAN, 16, NULL, 0x77b7,
            NULL, HFILL,
          },
        },
        { &hf_vxlan_flag_g,
          { "GBP Extension", "vxlan.flag_g",
            FT_BOOLEAN, 16, TFS(&tfs_defined_not_defined), 0x8000,
            NULL, HFILL,
          },
        },
        { &hf_vxlan_flag_i,
          { "VXLAN Network ID (VNI)", "vxlan.flag_i",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL,
          },
        },
        { &hf_vxlan_flag_d,
          { "Don't Learn", "vxlan.flag_d",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL,
          },
        },
        { &hf_vxlan_flag_a,
          { "Policy Applied", "vxlan.flag_a",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL,
          },
        },
        { &hf_vxlan_gbp,
          { "Group Policy ID", "vxlan.gbp",
            FT_UINT16, BASE_DEC, NULL, 0x00,
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

    /*
     * RFC 7348 Figures 1 and 2, in the Payload section, say
     *
     * "(Note that the original Ethernet Frame's FCS is not included)"
     *
     * meaning that the inner Ethernet frame does *not* include an
     * FCS.
     */
    eth_handle = find_dissector_add_dependency("eth_withoutfcs", proto_vxlan);

    vxlan_handle = create_dissector_handle(dissect_vxlan, proto_vxlan);
    dissector_add_uint("udp.port", UDP_PORT_VXLAN, vxlan_handle);
    dissector_add_for_decode_as("udp.port", vxlan_handle);

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
