/* packet-atmtcp.c
 * Routines for ATM over TCP dissection
 * Copyright 2011, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Specification...
 * http://git.kernel.org/?p=linux/kernel/git/next/linux-next.git;a=blob;f=include/linux/atm_tcp.h;hb=HEAD
 * http://git.kernel.org/?p=linux/kernel/git/next/linux-next.git;a=blob;f=drivers/atm/atmtcp.c;hb=HEAD
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_atmtcp(void);
void proto_reg_handoff_atmtcp(void);

static dissector_handle_t atmtcp_handle;

static int proto_atmtcp;
static int hf_atmtcp_vpi;
static int hf_atmtcp_vci;
static int hf_atmtcp_length;

#define ATMTCP_TCP_PORT     2812

static int ett_atmtcp;

#define ATMTCP_HDR_MAGIC        (~0)    /* this length indicates a command */
#define ATMTCP_CTRL_OPEN        1       /* request/reply */
#define ATMTCP_CTRL_CLOSE       2       /* request/reply */

static int
dissect_atmtcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    proto_item *ti;
    proto_tree *atmtcp_tree;
    unsigned    offset = 0;
    int32_t     length;
    tvbuff_t   *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATMTCP");

    col_add_str(pinfo->cinfo, COL_INFO, "ATMTCP");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_atmtcp, tvb, 0, -1, ENC_NA);

        atmtcp_tree = proto_item_add_subtree(ti, ett_atmtcp);

        /* VPI */
        proto_tree_add_item(atmtcp_tree, hf_atmtcp_vpi, tvb, offset, 2, ENC_BIG_ENDIAN);
    }
    offset += 2;


    if (tree) {
        /* VCI */
        proto_tree_add_item(atmtcp_tree, hf_atmtcp_vci, tvb, offset, 2, ENC_BIG_ENDIAN);
    }
    offset += 2;


    if (tree) {
        /* Length  */
        proto_tree_add_item(atmtcp_tree, hf_atmtcp_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    length = tvb_get_ntohl(tvb, offset);
    if(length == ATMTCP_HDR_MAGIC)
    {
        col_append_str(pinfo->cinfo, COL_INFO, " Command");
    }
    else
    {
        col_append_str(pinfo->cinfo, COL_INFO, " Data");
    }
    offset += 4;

    /* Data (for the moment...) */
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, tree);
    return tvb_reported_length(tvb);
}


void
proto_register_atmtcp(void)
{
    static hf_register_info hf[] = {
        { &hf_atmtcp_vpi,
            { "VPI",           "atmtcp.vpi", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Virtual Path Identifier", HFILL }
        },
        { &hf_atmtcp_vci,
            { "VCI",           "atmtcp.vci", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Virtual Channel Identifier", HFILL }
        },
        { &hf_atmtcp_length,
            { "Length",        "atmtcp.length", FT_UINT32, BASE_DEC, NULL, 0x0,
              "length of data", HFILL }
        }
    };


    static int *ett[] = {
        &ett_atmtcp
    };


    proto_atmtcp = proto_register_protocol("ATM over TCP", "ATMTCP", "atmtcp");

    proto_register_field_array(proto_atmtcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    atmtcp_handle = register_dissector("atm.tcp", dissect_atmtcp, proto_atmtcp);
}


void
proto_reg_handoff_atmtcp(void)
{
    dissector_add_uint_with_preference("tcp.port", ATMTCP_TCP_PORT, atmtcp_handle);
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
