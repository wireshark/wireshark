/* packet-ftdi-mpsse.c
 * Routines for FTDI Multi-Protocol Synchronous Serial Engine dissection
 *
 * Copyright 2020 Tomasz Mon
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

static int proto_ftdi_mpsse = -1;

static gint ett_ftdi_mpsse = -1;

static expert_field ei_undecoded = EI_INIT;

static dissector_handle_t ftdi_mpsse_handle;

void proto_register_ftdi_mpsse(void);

static gint
dissect_ftdi_mpsse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint        offset = 0;
    proto_item *main_item;
    proto_tree *main_tree;

    main_item = proto_tree_add_item(tree, proto_ftdi_mpsse, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_ftdi_mpsse);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FTDI MPSSE");

    proto_tree_add_expert(main_tree, pinfo, &ei_undecoded, tvb, offset, -1);

    return tvb_reported_length(tvb);
}

void
proto_register_ftdi_mpsse(void)
{
    expert_module_t  *expert_module;

    static ei_register_info ei[] = {
        { &ei_undecoded, { "ftdi-mpsse.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_ftdi_mpsse,
    };

    proto_ftdi_mpsse = proto_register_protocol("FTDI Multi-Protocol Synchronous Serial Engine", "FTDI MPSSE", "ftdi-mpsse");
    proto_register_subtree_array(ett, array_length(ett));
    ftdi_mpsse_handle = register_dissector("ftdi-mpsse", dissect_ftdi_mpsse, proto_ftdi_mpsse);

    expert_module = expert_register_protocol(proto_ftdi_mpsse);
    expert_register_field_array(expert_module, ei, array_length(ei));
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
