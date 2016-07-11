/* packet-rgmp.c
 * Routines for IGMP/RGMP packet disassembly
 * Copyright 2006 Jaap Keuter
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

/*
 Based on RFC3488

 This is a setup for RGMP dissection, a simple protocol bolted on IGMP.
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-igmp.h"

void proto_register_rgmp(void);
void proto_reg_handoff_rgmp(void);

static int proto_rgmp      = -1;
static int hf_type         = -1;
static int hf_reserved     = -1;
static int hf_checksum     = -1;
static int hf_checksum_status = -1;
static int hf_maddr        = -1;

static int ett_rgmp = -1;

static dissector_handle_t rgmp_handle;

#define MC_RGMP 0xe0000019

static const value_string rgmp_types[] = {
    {IGMP_RGMP_LEAVE, "Leave"},
    {IGMP_RGMP_JOIN,  "Join"},
    {IGMP_RGMP_BYE,   "Bye"},
    {IGMP_RGMP_HELLO, "Hello"},
    {0, NULL}
};

/* This function is only called from the IGMP dissector */
static int
dissect_rgmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    proto_tree *tree;
    proto_item *item;
    guint8 type;
    int offset = 0;
    guint32 dst = g_htonl(MC_RGMP);

    /* Shouldn't be destined for us */
    if (memcmp(pinfo->dst.data, &dst, 4))
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RGMP");
    col_clear(pinfo->cinfo, COL_INFO);

    item = proto_tree_add_item(parent_tree, proto_rgmp, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_rgmp);

    type = tvb_get_guint8(tvb, offset);
    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(type, rgmp_types, "Unknown Type: 0x%02x"));
    proto_tree_add_uint(tree, hf_type, tvb, offset, 1, type);
    offset += 1;

    /* reserved */
    proto_tree_add_item(tree, hf_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    igmp_checksum(tree, tvb, hf_checksum, hf_checksum_status, pinfo, 0);
    offset += 2;

    proto_tree_add_item(tree, hf_maddr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}


void
proto_register_rgmp(void)
{
    static hf_register_info hf[] = {
        { &hf_type,
          { "Type", "rgmp.type", FT_UINT8, BASE_HEX,
            VALS(rgmp_types), 0, "RGMP Packet Type", HFILL }
        },

        { &hf_reserved,
          { "Reserved", "rgmp.reserved", FT_UINT8, BASE_HEX,
            NULL, 0, "RGMP Reserved", HFILL }
        },

        { &hf_checksum,
          { "Checksum", "rgmp.checksum", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },

        { &hf_checksum_status,
          { "Checksum Status", "rgmp.checksum.status", FT_UINT8, BASE_NONE,
            VALS(proto_checksum_vals), 0x0, NULL, HFILL }
        },

        { &hf_maddr,
          { "Multicast group address", "rgmp.maddr", FT_IPv4, BASE_NONE,
            NULL, 0, NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_rgmp
    };

    proto_rgmp = proto_register_protocol("Router-port Group Management Protocol", "RGMP", "rgmp");
    proto_register_field_array(proto_rgmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    rgmp_handle = register_dissector("rgmp", dissect_rgmp, proto_rgmp);
}

void
proto_reg_handoff_rgmp(void)
{
    dissector_add_uint("igmp.type", IGMP_RGMP_HELLO, rgmp_handle);
    dissector_add_uint("igmp.type", IGMP_RGMP_BYE, rgmp_handle);
    dissector_add_uint("igmp.type", IGMP_RGMP_JOIN, rgmp_handle);
    dissector_add_uint("igmp.type", IGMP_RGMP_LEAVE, rgmp_handle);
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
