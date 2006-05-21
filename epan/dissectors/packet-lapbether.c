/* packet-lapbether.c
 * Routines for lapbether frame disassembly
 * Richard Sharpe <rsharpe@ns.aus.com> based on the lapb module by
 * Olivier Abad <oabad@noos.fr>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/etypes.h>

static int proto_lapbether = -1;

static int hf_lapbether_length = -1;

static gint ett_lapbether = -1;

static dissector_handle_t lapb_handle;

static void
dissect_lapbether(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree		*lapbether_tree, *ti;
    int			len;
    tvbuff_t		*next_tvb;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LAPBETHER");
    if (check_col(pinfo->cinfo, COL_INFO))
	col_clear(pinfo->cinfo, COL_INFO);

    len = tvb_get_guint8(tvb, 0) + tvb_get_guint8(tvb, 1) * 256;

    if (tree) {

      ti = proto_tree_add_protocol_format(tree, proto_lapbether, tvb, 0, 2,
					  "LAPBETHER");

      lapbether_tree = proto_item_add_subtree(ti, ett_lapbether);
      proto_tree_add_uint_format(lapbether_tree, hf_lapbether_length, tvb, 0, 2,
				 len, "Length: %u", len);

    }

    next_tvb = tvb_new_subset(tvb, 2, len, len);
    call_dissector(lapb_handle, next_tvb, pinfo, tree);

}

void
proto_register_lapbether(void)
{
    static hf_register_info hf[] = {
      { &hf_lapbether_length,
	{ "Length Field", "lapbether.length", FT_UINT16, BASE_DEC, NULL, 0x0,
	  "LAPBEther Length Field", HFILL }},

    };
    static gint *ett[] = {
        &ett_lapbether,
    };

    proto_lapbether = proto_register_protocol ("Link Access Procedure Balanced Ethernet (LAPBETHER)",
        "LAPBETHER", "lapbether");
    proto_register_field_array (proto_lapbether, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* The registration hand-off routine */
void
proto_reg_handoff_lapbether(void)
{
  dissector_handle_t lapbether_handle;

  /*
   * Get a handle for the LAPB dissector.
   */
  lapb_handle = find_dissector("lapb");

  lapbether_handle = create_dissector_handle(dissect_lapbether,
					     proto_lapbether);
  dissector_add("ethertype", ETHERTYPE_DEC, lapbether_handle);

}
