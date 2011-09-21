/* packet-atmtcp.c
 * Routines for ATM over TCP dissection
 * Copyright 2011, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Specification...
 * http://git.kernel.org/?p=linux/kernel/git/next/linux-next.git;a=blob;f=include/linux/atm_tcp.h;hb=HEAD
 * http://git.kernel.org/?p=linux/kernel/git/next/linux-next.git;a=blob;f=drivers/atm/atmtcp.c;hb=HEAD
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_reg_handoff_atmtcp(void);

static int proto_atmtcp = -1;
static int hf_atmtcp_vpi = -1;
static int hf_atmtcp_vci = -1;
static int hf_atmtcp_length = -1;

static guint global_atmtcp_tcp_port = 2812;

static gint ett_atmtcp = -1;

static dissector_handle_t data_handle;

#define ATMTCP_HDR_MAGIC        (~0)    /* this length indicates a command */
#define ATMTCP_CTRL_OPEN        1       /* request/reply */
#define ATMTCP_CTRL_CLOSE       2       /* request/reply */

static int
dissect_atmtcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    proto_item *ti;
    proto_tree *atmtcp_tree;
    guint offset=0;
    gint32 length;
    tvbuff_t *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATMTCP");

    col_set_str(pinfo->cinfo, COL_INFO, "ATMTCP");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_atmtcp, tvb, 0, -1, ENC_NA);

        atmtcp_tree = proto_item_add_subtree(ti, ett_atmtcp);

        /* VPI */
        proto_tree_add_item(atmtcp_tree, hf_atmtcp_vpi, tvb, offset, 2, ENC_NA);
    }
    offset += 2;
            

    if (tree) {
        /* VCI */
        proto_tree_add_item(atmtcp_tree, hf_atmtcp_vci, tvb, offset, 2, ENC_NA);
    }
    offset += 2;


    if (tree) {
        /* Length  */
        proto_tree_add_item(atmtcp_tree, hf_atmtcp_length, tvb, offset, 4, ENC_NA);
    }
    length = tvb_get_ntohl(tvb, offset);
    if(length == ATMTCP_HDR_MAGIC)
    {
    	col_append_fstr(pinfo->cinfo, COL_INFO, " Command");
    }
    else
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Data");
    }
    offset += 4;

    /* Data (for the moment...) */
    next_tvb = tvb_new_subset(tvb, offset, -1, -1);
    call_dissector(data_handle, next_tvb, pinfo, tree);
    return tvb_length(tvb);
}


void
proto_register_atmtcp(void)
{
    module_t *atmtcp_module;


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


    static gint *ett[] = {
        &ett_atmtcp
    };


    proto_atmtcp = proto_register_protocol("ATM over TCP", "ATMTCP", "atmtcp");

    proto_register_field_array(proto_atmtcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));


    atmtcp_module = prefs_register_protocol(proto_atmtcp, proto_reg_handoff_atmtcp);

    prefs_register_uint_preference(atmtcp_module, "tcp.port", "ATMTCP TCP Port", 
                                    "ATMTCP TCP port if other than the default",
                                    10, &global_atmtcp_tcp_port);
}


void
proto_reg_handoff_atmtcp(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t atmtcp_handle;
    static int current_port;

    if (!initialized) {
        atmtcp_handle = new_create_dissector_handle(dissect_atmtcp, proto_atmtcp);
        data_handle = find_dissector("data");
        initialized = TRUE;
    } else {
        dissector_delete_uint("tcp.port", current_port, atmtcp_handle);
    }

    current_port = global_atmtcp_tcp_port;

    dissector_add_uint("tcp.port", current_port, atmtcp_handle);
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
