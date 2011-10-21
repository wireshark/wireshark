/* packet-hp-erm.c
 * Routines for the disassembly of  HP ProCurve encapsulated remote mirroring frames
 * (Adapted from packet-cisco-erspan.c)
 *
 * $Id$
 *
 * Copyright 2010 William Meier <wmeier [AT] newsguy.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*
 * For some information on HP Procurve encapsulated remote mirroring see
 *  "Traffic Mirroring" in Appendix B of the HP manual
 *   "Management and Configuration Guide for the ProCurve Series
 *    3500, 3500yl, 5400zl, 6200yl, 6600, and 8200zl Switches (September 2009)"
 *
 * Format:
 *  The above manual indicates that the encapsulatedmirrored frame is transmitted
 *  on the network as a [UDP] packet which has 54 bytes preceding the mirrored frame.
 *  Examining a sample capture shows that this means that the data payload
 *  of the UDP packet consists of a 12 byte "header" followed by the
 *  byes of the mirrored frame.
 *
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#define PROTO_SHORT_NAME "HP_ERM"
#define PROTO_LONG_NAME  "HP encapsulated remote mirroring"

static guint global_hp_erm_udp_port = 0;

static int  proto_hp_erm      = -1;
static gint ett_hp_erm        = -1;
static int  hf_hp_erm_unknown = -1;

static dissector_handle_t eth_withoutfcs_handle;

static void
dissect_hp_erm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *hp_erm_tree;
    tvbuff_t   *eth_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
    col_set_str(pinfo->cinfo, COL_INFO, PROTO_SHORT_NAME ":");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_hp_erm, tvb, 0, -1, ENC_NA);
        hp_erm_tree = proto_item_add_subtree(ti, ett_hp_erm);
        proto_tree_add_item(hp_erm_tree, hf_hp_erm_unknown, tvb, 0, 12, ENC_NA);
    }

    eth_tvb = tvb_new_subset_remaining(tvb, 12);
    call_dissector(eth_withoutfcs_handle, eth_tvb, pinfo, tree);
}

void
proto_register_hp_erm(void)
{
    void proto_reg_handoff_hp_erm(void);

    static hf_register_info hf[] = {

        { &hf_hp_erm_unknown,
          { "Unknown", "hp_erm.unknown", FT_BYTES, BASE_NONE, NULL,
            0x00, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_hp_erm,
    };

    module_t *hp_erm_module;

    proto_hp_erm = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "hp_erm");

    hp_erm_module = prefs_register_protocol(proto_hp_erm, proto_reg_handoff_hp_erm);
    prefs_register_uint_preference(hp_erm_module, "udp.port", "HP_ERM UDP Port",
                                   "Set the UDP port (source or destination) used for HP"
                                   " encapsulated remote mirroring frames;\n"
                                   "0 (default) means that the HP_ERM dissector is not active",
                                   10, &global_hp_erm_udp_port);

    proto_register_field_array(proto_hp_erm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_hp_erm(void)
{
    static dissector_handle_t hp_erm_handle;
    static guint hp_erm_udp_port;
    static gboolean initialized = FALSE;

    if (!initialized) {
        eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
        hp_erm_handle = create_dissector_handle(dissect_hp_erm, proto_hp_erm);
        initialized = TRUE;
    } else {
        if (hp_erm_udp_port != 0)
            dissector_delete_uint("udp.port", hp_erm_udp_port, hp_erm_handle);
    }

    hp_erm_udp_port = global_hp_erm_udp_port;

    if (hp_erm_udp_port != 0)
        dissector_add_uint("udp.port", hp_erm_udp_port, hp_erm_handle);
}

