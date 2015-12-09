/* packet-bofl.c
 * Routines for Wellfleet BOFL dissection
 * Author: Endoh Akira (endoh@netmarks.co.jp)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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
 *
 * The following information was copied from
 * http://www.protocols.com/pbook/bridge.htm#WellfleetBOFL
 *
 * The Wellfleet Breath of Life (BOFL) protocol is used as a line sensing
 * protocol on:
 *
 * - Ethernet LANs to detect transmitter jams.
 * - Synchronous lines running WFLT STD protocols to determine if the line
 *   is up.
 * - Dial backup PPP lines.
 *
 * The frame format of Wellfleet BOFL is shown following the Ethernet header
 * in the following illustration:
 *
 *  Destination   Source    8102    PDU   Sequence   Padding
 *       6           6        2      4       4       n bytes
 */

#include "config.h"

#include <epan/packet.h>

#define ETHER_TYPE_BOFL 0x8102
#define BOFL_MIN_LEN    8

void proto_register_bofl(void);
void proto_reg_handoff_bofl(void);

/* Initialize the protocol and registered fields */
static int proto_bofl       = -1;
static int hf_bofl_pdu      = -1;
static int hf_bofl_sequence = -1;
static int hf_bofl_padding  = -1;

/* Initialize the subtree pointers */
static gint ett_bofl = -1;

/* Code to actually dissect the packets */
static int
dissect_bofl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item  *ti;
    proto_tree  *bofl_tree;
    gint        len;
    guint32     pdu, sequence;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BOFL");

    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_bofl, tvb, 0, -1, ENC_NA);
    bofl_tree = proto_item_add_subtree(ti, ett_bofl);

    pdu = tvb_get_ntohl(tvb, 0);
    col_add_fstr(pinfo->cinfo, COL_INFO,
        "PDU: 0x%08x", pdu);
    proto_tree_add_uint(bofl_tree, hf_bofl_pdu, tvb, 0, 4, pdu);

    sequence = tvb_get_ntohl(tvb, 4);

    col_append_fstr(pinfo->cinfo, COL_INFO,
        " Sequence: %u", sequence);

    proto_tree_add_uint(bofl_tree, hf_bofl_sequence, tvb, 4, 4, sequence);

    len = tvb_reported_length_remaining(tvb, 8);
    if (len > 0)
        proto_tree_add_item(bofl_tree, hf_bofl_padding, tvb, 8, -1, ENC_NA);

    return tvb_captured_length(tvb);
}


void
proto_register_bofl(void)
{
    static hf_register_info hf[] = {
        { &hf_bofl_pdu,
          { "PDU", "bofl.pdu",
            FT_UINT32, BASE_HEX, NULL, 0,
            "PDU; normally equals 0x01010000 or 0x01011111", HFILL }
        },
        { &hf_bofl_sequence,
          { "Sequence", "bofl.sequence",
            FT_UINT32, BASE_DEC, NULL, 0,
            "incremental counter", HFILL }
        },
        { &hf_bofl_padding,
          { "Padding", "bofl.padding",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_bofl,
    };

    proto_bofl = proto_register_protocol("Wellfleet Breath of Life",
                                         "BOFL", "bofl");
    proto_register_field_array(proto_bofl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_bofl(void)
{
    dissector_handle_t bofl_handle;

    bofl_handle = create_dissector_handle(dissect_bofl, proto_bofl);
    dissector_add_uint("ethertype", ETHER_TYPE_BOFL, bofl_handle);
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
