/* packet-ipfc.c
 * Routines for Decoding Network_Header for IP-over-FC when we only
 * capture the frame starting at the Network_Header (as opposed to
 * when we have the full FC frame).
 * See RFC 2625.
 * Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/conversation.h>
#include "packet-scsi.h"
#include "packet-fc.h"
#include "packet-ipfc.h"
#include "packet-llc.h"

/* Initialize the protocol and registered fields */
static int proto_ipfc              = -1;
static int hf_ipfc_network_da = -1;
static int hf_ipfc_network_sa = -1;

/* Initialize the subtree pointers */
static gint ett_ipfc = -1;
static dissector_handle_t llc_handle;

void
capture_ipfc (const guchar *pd, int len, packet_counts *ld)
{
  if (!BYTES_ARE_IN_FRAME(0, len, 16)) {
    ld->other++;
    return;
  }

  capture_llc(pd, 16, len, ld);
}

static void
dissect_ipfc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *ipfc_tree;
    int offset = 0;
    tvbuff_t *next_tvb;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IP/FC");

    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_ipfc, tvb, offset, 16,
                                         "IP Over FC Network_Header");
        ipfc_tree = proto_item_add_subtree (ti, ett_ipfc);

        proto_tree_add_string (ipfc_tree, hf_ipfc_network_da, tvb, offset, 8,
                               tvb_fcwwn_to_str (tvb, offset));
        proto_tree_add_string (ipfc_tree, hf_ipfc_network_sa, tvb, offset+8, 8,
                               tvb_fcwwn_to_str (tvb, offset+8));
    }

    next_tvb = tvb_new_subset_remaining (tvb, 16);
    call_dissector(llc_handle, next_tvb, pinfo, tree);
}

/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_ipfc (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_ipfc_network_da,
          {"Network DA", "ipfc.nh.da", FT_STRING, BASE_NONE, NULL,
           0x0, NULL, HFILL}},
        { &hf_ipfc_network_sa,
          {"Network SA", "ipfc.nh.sa", FT_STRING, BASE_NONE, NULL,
           0x0, NULL, HFILL}},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_ipfc,
    };

    /* Register the protocol name and description */
    proto_ipfc = proto_register_protocol("IP Over FC", "IPFC", "ipfc");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ipfc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_ipfc (void)
{
    dissector_handle_t ipfc_handle;

    ipfc_handle = create_dissector_handle (dissect_ipfc, proto_ipfc);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_IP_OVER_FC, ipfc_handle);

    llc_handle = find_dissector ("llc");
}
