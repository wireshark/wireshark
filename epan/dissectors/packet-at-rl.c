/* packet-at-rl.c
 * Dissector for Allied Telesis Resiliency Link Frames
 *
 * Copyright (c) 2024 by Martin Mayer <martin.mayer@m2-it-solutions.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/etypes.h>
#include <epan/packet.h>

void proto_register_at_rl(void);
void proto_reg_handoff_at_rl(void);

static dissector_handle_t at_rl_handle;

static int proto_at_rl;

#define AT_RL_FRAME_LEN 18

/* Fields */
static int hf_at_rl_sequence;
static int hf_at_rl_master;
static int hf_at_rl_padding;
static int hf_at_rl_vcsid;
static int hf_at_rl_role_change;

static int ett_at_rl;

static int
dissect_at_rl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    /* Check if packet is destined to the Allied Telesis address (01:00:CD:FA:1B:AC) */
    uint8_t dst_mac[6] = {0x01, 0x00, 0xCD, 0xFA, 0x1B, 0xAC};
    address dst_addr = ADDRESS_INIT_NONE;
    set_address(&dst_addr, AT_ETHER, sizeof(dst_mac), &dst_mac);

    if(!addresses_equal(&pinfo->dl_dst, &dst_addr))
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AT RL");
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Seq: %u, VCS-ID: %u",
                    tvb_get_uint32(tvb, 0, ENC_BIG_ENDIAN),
                    tvb_get_uint16(tvb, 12, ENC_BIG_ENDIAN));

    /* Frame has fixed length, so we can directly set tree and reported length (padding will most likely be added) */
    tvb_set_reported_length(tvb, AT_RL_FRAME_LEN);

    proto_item *ti = proto_tree_add_item(tree, proto_at_rl, tvb, 0, AT_RL_FRAME_LEN, ENC_NA);
    proto_tree *at_rl_tree = proto_item_add_subtree(ti, ett_at_rl);

    int offset = 0;
    proto_tree_add_item(at_rl_tree, hf_at_rl_sequence, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(at_rl_tree, hf_at_rl_master, tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(at_rl_tree, hf_at_rl_padding, tvb, offset, 2, ENC_NA);
    offset += 2;

    proto_tree_add_item(at_rl_tree, hf_at_rl_vcsid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(at_rl_tree, hf_at_rl_role_change, tvb, offset, 4, ENC_TIME_SECS);

    return AT_RL_FRAME_LEN;
}

void
proto_register_at_rl(void)
{
    static hf_register_info hf[] = {
        { &hf_at_rl_sequence,
            { "Sequence No.", "atrl.sequence",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_at_rl_master,
            { "Active Master", "atrl.master",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_at_rl_padding,
            { "Padding", "atrl.padding",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_at_rl_vcsid,
            { "Virtual Chassis Stack ID", "atrl.vcsid",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_at_rl_role_change,
            { "Last Role Change", "atrl.role_change",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_at_rl
    };

    proto_at_rl = proto_register_protocol ("Allied Telesis Resiliency Link", "AT RL", "atrl");

    proto_register_field_array(proto_at_rl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    at_rl_handle = register_dissector("atrl", dissect_at_rl, proto_at_rl);
}

void
proto_reg_handoff_at_rl(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_ATRL, at_rl_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
