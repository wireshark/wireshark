/* packet-ipfc.c
 * Routines for Decoding FC header for IP/FC
 * Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
 *
 * $Id: packet-ipfc.c,v 1.1 2002/12/08 02:32:17 gerald Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include "etypes.h"
#include "packet-fc.h"

/* Initialize the protocol and registered fields */
static int proto_ipfc              = -1;
static int hf_ipfc_network_da = -1;
static int hf_ipfc_network_sa = -1;
static int hf_ipfc_llc = -1;

/* Initialize the subtree pointers */
static gint ett_ipfc = -1;
static dissector_table_t ipfc_dissector_table;
static dissector_handle_t data_handle;

static void
dissect_ipfc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *ipfc_tree;
    int offset = 0;
    tvbuff_t *next_tvb;

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "IP/FC");

    if (tree) {
        ti = proto_tree_add_text (tree, tvb, offset, 16,
                                         "Network Header");
        ipfc_tree = proto_item_add_subtree (ti, ett_ipfc);

        proto_tree_add_string (ipfc_tree, hf_ipfc_network_da, tvb, offset, 8,
                               fcwwn_to_str (tvb_get_ptr (tvb, offset, 8)));
        proto_tree_add_string (ipfc_tree, hf_ipfc_network_sa, tvb, offset+8, 8,
                               fcwwn_to_str (tvb_get_ptr (tvb, offset+8, 8)));
        /* This is a dummy add to just switch to llc */
        proto_tree_add_uint_hidden (ipfc_tree, hf_ipfc_llc, tvb, offset, 16, 0);
    }

    next_tvb = tvb_new_subset (tvb, 16, -1, -1);
    if (!dissector_try_port (ipfc_dissector_table, 0, next_tvb, pinfo, tree)) {
        call_dissector (data_handle, next_tvb, pinfo, tree);
    }
}

/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_ipfc (void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_ipfc_network_da,
          {"Network DA", "ipfc.nethdr.da", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_ipfc_network_sa,
          {"Network SA", "ipfc.nethdr.sa", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_ipfc_llc,
          {"LLC/SNAP", "ipfc.llc", FT_UINT8, BASE_HEX, NULL, 0x0, "",
           HFILL}},
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

    ipfc_dissector_table = register_dissector_table ("ipfc.llc", "IPFC",
                                                     FT_UINT8, BASE_HEX);
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
    dissector_add("fc.ftype", FC_FTYPE_IP, ipfc_handle);

    data_handle = find_dissector ("data");
}

