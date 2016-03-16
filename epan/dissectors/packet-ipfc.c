/* packet-ipfc.c
 * Routines for Decoding Network_Header for IP-over-FC when we only
 * capture the frame starting at the Network_Header (as opposed to
 * when we have the full FC frame).
 * See RFC 2625.
 * Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
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
#include <epan/capture_dissectors.h>
#include <wiretap/wtap.h>
#include <epan/to_str.h>

#include "packet-llc.h"

void proto_register_ipfc(void);
void proto_reg_handoff_ipfc(void);

/* Initialize the protocol and registered fields */
static int proto_ipfc              = -1;
static int hf_ipfc_network_da = -1;
static int hf_ipfc_network_sa = -1;

/* Initialize the subtree pointers */
static gint ett_ipfc = -1;
static dissector_handle_t llc_handle;

static gboolean
capture_ipfc (const guchar *pd, int offset _U_, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
  if (!BYTES_ARE_IN_FRAME(0, len, 16))
    return FALSE;

  return capture_llc(pd, 16, len, cpinfo, pseudo_header);
}

static int
dissect_ipfc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
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

        proto_tree_add_item (ipfc_tree, hf_ipfc_network_da, tvb, offset, 8, ENC_NA);
        proto_tree_add_item (ipfc_tree, hf_ipfc_network_sa, tvb, offset+8, 8, ENC_NA);
    }

    next_tvb = tvb_new_subset_remaining (tvb, 16);
    call_dissector(llc_handle, next_tvb, pinfo, tree);
    return tvb_captured_length(tvb);
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
          {"Network DA", "ipfc.nh.da", FT_FCWWN, BASE_NONE, NULL,
           0x0, NULL, HFILL}},
        { &hf_ipfc_network_sa,
          {"Network SA", "ipfc.nh.sa", FT_FCWWN, BASE_NONE, NULL,
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

    llc_handle = find_dissector_add_dependency("llc", proto_ipfc);

    register_capture_dissector("wtap_encap", WTAP_ENCAP_IP_OVER_FC, capture_ipfc, proto_ipfc);
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
