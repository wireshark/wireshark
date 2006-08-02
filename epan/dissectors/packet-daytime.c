/* packet-daytime.c
 * Routines for Daytime Protocol (RFC 867) packet dissection
 * Copyright 2006, Stephen Fisher <stephentfisher@yahoo.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-time.c
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

#include <epan/packet.h>

static int proto_daytime = -1;
static int hf_daytime_string = -1;

static gint ett_daytime = -1;

/* This dissector works for TCP and UDP daytime packets */
#define DAYTIME_PORT 13

static void
dissect_daytime(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree	*daytime_tree;
  proto_item	*ti;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DAYTIME");

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "DAYTIME %s",
		 pinfo->srcport == pinfo->match_port ? "Response":"Request");
  }

  if (tree) {

    ti = proto_tree_add_item(tree, proto_daytime, tvb, 0, -1, FALSE);
    daytime_tree = proto_item_add_subtree(ti, ett_daytime);

    proto_tree_add_text(daytime_tree, tvb, 0, 0,
			pinfo->srcport==DAYTIME_PORT ? "Type: Response":"Type: Request");
    if (pinfo->srcport == DAYTIME_PORT) {
      proto_tree_add_item(daytime_tree, hf_daytime_string, tvb, 0, -1, FALSE);
    }
  }
}

void
proto_register_daytime(void)
{

  static hf_register_info hf[] = {
    { &hf_daytime_string,
      { "Daytime", "daytime.string",
	FT_STRING, BASE_NONE, NULL, 0x0,
      	"String containing time and date", HFILL }}
  };
  static gint *ett[] = {
    &ett_daytime,
  };

  proto_daytime = proto_register_protocol("Daytime Protocol", "DAYTIME", "daytime");
  proto_register_field_array(proto_daytime, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_daytime(void)
{
  dissector_handle_t daytime_handle;

  daytime_handle = create_dissector_handle(dissect_daytime, proto_daytime);
  dissector_add("udp.port", DAYTIME_PORT, daytime_handle);
  dissector_add("tcp.port", DAYTIME_PORT, daytime_handle);
}
