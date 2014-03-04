/* packet-cisco-metadata.c
 * Routines for dissection of Cisco's MetaData protocol.
 * Copyright 2013 by Vaibhav Katkade (vkatkade[AT]cisco.com)
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#if 0
#include "packet-ieee8023.h"
#endif

void proto_register_cmd(void);
void proto_reg_handoff_cmd(void);

static dissector_handle_t ethertype_handle;

static int proto_cmd = -1;

static int hf_cmd_version = -1;
static int hf_cmd_length = -1;
static int hf_cmd_options = -1;
static int hf_cmd_sgt = -1;

static int hf_eth_type = -1;
static int hf_cmd_trailer = -1;

static gint ett_cmd = -1;

static void
dissect_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint16 encap_proto;
    ethertype_data_t ethertype_data;

    proto_tree *cmd_tree = NULL;
    gint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMD");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        proto_item *ti = proto_tree_add_item(tree, proto_cmd, tvb, 0, 6, ENC_NA);

        cmd_tree = proto_item_add_subtree(ti, ett_cmd);
        proto_tree_add_item(cmd_tree, hf_cmd_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(cmd_tree, hf_cmd_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(cmd_tree, hf_cmd_options, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(cmd_tree, hf_cmd_sgt, tvb, offset, 2, ENC_BIG_ENDIAN);
        /*offset += 2;*/
    }

    encap_proto = tvb_get_ntohs(tvb, 6);

/* This Logic to identify and decode IEEE 802.3 frames is not working correctly. Carry over code from packet-vlan.c
 * Commenting it out for now will display as Unknown for L2 control frames instead of showing a wrong decode.
 */
#if 0
    if (encap_proto <= IEEE_802_3_MAX_LEN) {
        gboolean is_802_2 = TRUE;

        /* Don't throw an exception for this check (even a BoundsError) */
        if (tvb_length_remaining(tvb, 4) >= 2) {
            if (tvb_get_ntohs(tvb, 4) == 0xffff)
                is_802_2 = FALSE;
        }

        dissect_802_3(encap_proto, is_802_2, tvb, 4, pinfo, tree, cmd_tree, hf_eth_type, hf_cmd_trailer, 0);
    } else {
#endif

    ethertype_data.etype = encap_proto;
    ethertype_data.offset_after_ethertype = 8;
    ethertype_data.fh_tree = cmd_tree;
    ethertype_data.etype_id = hf_eth_type;
    ethertype_data.trailer_id = hf_cmd_trailer;
    ethertype_data.fcs_len = 0;

    call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
}

void
proto_register_cmd(void)
{
    static hf_register_info hf[] = {
        { &hf_cmd_version,
            { "Version", "cmd.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_cmd_length,
            { "Length", "cmd.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_cmd_options,
            { "Options", "cmd.options", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_cmd_sgt,
            { "SGT", "cmd.sgt", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_eth_type,
            { "Type", "cmd.type", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0, NULL, HFILL }
        },
        { &hf_cmd_trailer,
            { "Trailer", "cmd.trailer", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_cmd
    };

    proto_cmd = proto_register_protocol("Cisco MetaData", "Cisco MetaData", "cmd");
    proto_register_field_array(proto_cmd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cmd(void)
{
    dissector_handle_t cmd_handle;

    ethertype_handle = find_dissector("ethertype");

    cmd_handle = create_dissector_handle(dissect_cmd, proto_cmd);
    dissector_add_uint("ethertype", ETHERTYPE_CMD, cmd_handle);
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
