/* packet-bthfp.c
 * Routines for Bluetooth Handsfree Profile (HFP)
 *
 * Copyright 2002, Wolfgang Hansmann <hansmann@cs.uni-bonn.de>
 *
 * Refactored for wireshark checkin
 *   Ronnie Sahlberg 2006
 *
 * $Id$
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

#include <epan/packet.h>

#include "packet-btsdp.h"

static int hf_at_cmd = -1;

static int proto_bthfp = -1;

static gint ett_bthfp = -1;

static void
dissect_bthfp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *st;

    guint length = tvb_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HFP");

    ti = proto_tree_add_item(tree, proto_bthfp, tvb, 0, -1, ENC_NA);
    st = proto_item_add_subtree(ti, ett_bthfp);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s \"%s\"",
                 (pinfo->p2p_dir == P2P_DIR_SENT) ? "Sent" : "Rcvd",
                 tvb_format_text(tvb, 0, length));

    proto_tree_add_item(st, hf_at_cmd, tvb, 0, -1, ENC_ASCII|ENC_NA);
}

void
proto_register_bthfp(void)
{
    static hf_register_info hf[] = {
        { &hf_at_cmd,
          { "AT Cmd", "bthfp.atcmd",
            FT_STRING, BASE_NONE, NULL, 0,
            "AT Command", HFILL}
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_bthfp,
    };

    proto_bthfp = proto_register_protocol("Bluetooth Handsfree Profile", "BT HFP", "bthfp");
    register_dissector("bthfp", dissect_bthfp, proto_bthfp);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_bthfp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bthfp(void)
{
    dissector_handle_t bthfp_handle;

    bthfp_handle = find_dissector("bthfp");

    dissector_add_uint("btrfcomm.service", BTSDP_HFP_SERVICE_UUID, bthfp_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_HFP_GW_SERVICE_UUID, bthfp_handle);
    dissector_add_handle("btrfcomm.channel", bthfp_handle);
}
