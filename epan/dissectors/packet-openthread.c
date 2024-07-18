/* packet-openthread.c
 * Simple dissector for OpenThread loopback interface
 *
 * Robert Cragie <robert.cragie@arm.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

/* Forward declarations */
void proto_register_openthread(void);
void proto_reg_handoff_openthread(void);

static int proto_openthread;

static dissector_handle_t openthread_handle;
static dissector_handle_t wpan_handle;

static int hf_openthread_channel;
/* static int hf_openthread_psdu; */

static int ett_openthread;

static int
dissect_openthread(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *proto_root;
    proto_tree  *openthread_tree;
    tvbuff_t    *sub_tvb;

    /* Create the protocol tree. */
    proto_root = proto_tree_add_item(tree, proto_openthread, tvb, 0, -1, ENC_NA);
    openthread_tree = proto_item_add_subtree(proto_root, ett_openthread);

    proto_tree_add_item(openthread_tree, hf_openthread_channel, tvb, 0, 1, ENC_NA);
    sub_tvb = tvb_new_subset_length(tvb, 1, tvb_reported_length_remaining(tvb, 3)); /* Note - truncate the last two "phoney" CRC bytes */
    call_dissector(wpan_handle, sub_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

void
proto_register_openthread(void)
{
    static hf_register_info hf[] = {

        /* Generic TLV */
        { &hf_openthread_channel,
            { "Channel",
            "openthread.channel",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },
#if 0
        { &hf_openthread_psdu,
            { "PSDU",
            "openthread.psdu",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        }
#endif
    };

    static int *ett[] = {
        &ett_openthread
    };

    proto_openthread = proto_register_protocol("OpenThread", "OpenThread", "openthread");
    proto_register_field_array(proto_openthread, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    openthread_handle = register_dissector("openthread", dissect_openthread, proto_openthread);
}

void
proto_reg_handoff_openthread(void)
{
    wpan_handle = find_dissector_add_dependency("wpan_nofcs", proto_openthread);
    dissector_add_for_decode_as("udp.port", openthread_handle);
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
