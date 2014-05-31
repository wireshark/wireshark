/* packet-slowprotocols.c
 * Routines for EtherType (0x8809) Slow Protocols disassembly.
 * IEEE Std 802.3, Annex 57A
 *
 * Copyright 2002 Steve Housley <steve_housley@3com.com>
 * Copyright 2005 Dominique Bastien <dbastien@accedian.com>
 * Copyright 2009 Artem Tamazov <artem.tamazov@telllabs.com>
 * Copyright 2010 Roberto Morro <roberto.morro[AT]tilab.com>
 * Copyright 2014 Philip Rosenberg-Watt <p.rosenberg-watt[at]cablelabs.com.>
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
#include <epan/slow_protocol_subtypes.h>

/* General declarations */
void proto_register_slow_protocols(void);
void proto_reg_handoff_slow_protocols(void);

static dissector_table_t slow_protocols_dissector_table;

static const value_string subtype_vals[] = {
    { LACP_SUBTYPE   , "LACP" },
    { MARKER_SUBTYPE , "Marker Protocol" },
    { OAM_SUBTYPE    , "OAM" },
    { OSSP_SUBTYPE   , "Organization Specific Slow Protocol" },
    { 0, NULL }
};

/* Initialise the protocol and registered fields */
static int proto_slow = -1;

static int hf_slow_subtype = -1;

/* Initialise the subtree pointers */

static gint ett_slow = -1;

static dissector_handle_t dh_data;

/*
 * Name: dissect_slow_protocols
 *
 * Description:
 *    This function is used to dissect the slow protocols defined in IEEE802.3
 *    CSMA/CD. The current slow protocols subtypes are define in Annex 57A of
 *    the 802.3 document. In case of an unsupported slow protocol, we only
 *    fill the protocol and info columns.
 *
 * Input Arguments:
 *    tvb:   buffer associated with the rcv packet (see tvbuff.h).
 *    pinfo: structure associated with the rcv packet (see packet_info.h).
 *    tree:  the protocol tree associated with the rcv packet (see proto.h).
 *
 * Return Values:
 *    None
 */
static void
dissect_slow_protocols(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8      subtype;
    proto_tree *pdu_tree;
    proto_item *pdu_item;
    tvbuff_t   *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Slow Protocols");
    subtype = tvb_get_guint8(tvb, 0);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Subtype = %u", subtype);

    if (tree)
    {
        pdu_item = proto_tree_add_item(tree, proto_slow, tvb, 0, 1, ENC_NA);
        pdu_tree = proto_item_add_subtree(pdu_item, ett_slow);

        /* Subtype */
        proto_tree_add_item(pdu_tree, hf_slow_subtype, tvb, 0, 1, ENC_NA);
    }

    next_tvb = tvb_new_subset_remaining(tvb, 1);
    if (!dissector_try_uint_new(slow_protocols_dissector_table, subtype,
                                next_tvb, pinfo, tree, TRUE, NULL))
        call_dissector(dh_data, next_tvb, pinfo, tree);
}


/* Register the protocol with Wireshark */
void
proto_register_slow_protocols(void)
{
/* Setup list of header fields */

    static hf_register_info hf[] = {
        { &hf_slow_subtype,
          { "Slow Protocols subtype",    "slow.subtype",
            FT_UINT8,    BASE_HEX,    VALS(subtype_vals),    0x0,
            NULL, HFILL }},
    };

    /* Setup protocol subtree array */

    static gint *ett[] = {
        &ett_slow,
    };


    /* Register the protocol name and description */

    proto_slow = proto_register_protocol("Slow Protocols", "802.3 Slow protocols", "slow");

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_slow, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* subdissector code */
    slow_protocols_dissector_table = register_dissector_table("slow.subtype",
                                                              "Slow protocol subtype",
                                                               FT_UINT8, BASE_DEC);
}

void
proto_reg_handoff_slow_protocols(void)
{
    dissector_handle_t slow_protocols_handle;

    slow_protocols_handle = create_dissector_handle(dissect_slow_protocols, proto_slow);
    dissector_add_uint("ethertype", ETHERTYPE_SLOW_PROTOCOLS, slow_protocols_handle);

    dh_data = find_dissector("data");
}
