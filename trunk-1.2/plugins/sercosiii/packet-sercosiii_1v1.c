/* packet-sercosiii_1v1.c
 * Routines for SERCOS III dissection
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/etypes.h>

#include "packet-sercosiii.h"

/* Initialize the protocol and registered fields */
static gint proto_siii = -1;

/* Initialize the subtree pointers */
static gint ett_siii = -1;
static gint ett_siii_header = -1;

/* Main dissector entry */
static void
dissect_siii(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item*  ti;
  proto_tree*  siii_tree;
  guint    type;
  char* tel_ch="?";
  char* tel_type="?";
  guint tel_no = 0;

  /* setup columns */
  if(check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SERCOS III V1.1");
  if(check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  /* check what we got on our hand */
  type = tvb_get_guint8(tvb, 0);
  if(type&0x80) /* primary or secondary channel */
    tel_ch="S";
  else
    tel_ch="P";

  if(type&0x40) /* master data telegram (mdt) or slave telegram (at) */
    tel_type="AT ";
  else
    tel_type="MDT";

  tel_no = type &0xF; /* even though it's reserved (the V1.1 spec states that it is reserved for additional MDT/AT) */

  if(check_col(pinfo->cinfo, COL_INFO))
  {
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s%u Channel=%s", tel_type, tel_no, tel_ch);
  }

  ti = proto_tree_add_item(tree, proto_siii, tvb, 0, -1, FALSE);

  siii_tree = proto_item_add_subtree(ti, ett_siii);

   /* enter the specific dissector for AT or MDT */
  if(type & 0x40)
    dissect_siii_at(tvb, pinfo, siii_tree);
  else
    dissect_siii_mdt(tvb, pinfo, siii_tree);
}

void
proto_register_sercosiii(void)
{
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_siii,
    &ett_siii_header
  };

  /* Register the protocol name and description */
  proto_siii = proto_register_protocol("SERCOS III V1.1",
      "SERCOS III V1.1", "sercosiii");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_subtree_array(ett, array_length(ett));

  dissect_siii_mdt_init(proto_siii);
  dissect_siii_at_init(proto_siii);
  dissect_siii_mdt_devctrl_init(proto_siii);
  dissect_siii_at_devstat_init(proto_siii);
  dissect_siii_svc_init(proto_siii);
  dissect_siii_mst_init(proto_siii);
  dissect_siii_hp_init(proto_siii);

}

void
proto_reg_handoff_sercosiii(void)
{
  dissector_handle_t siii_handle;

  siii_handle = create_dissector_handle(dissect_siii, proto_siii);
  dissector_add("ethertype", ETHERTYPE_SERCOS, siii_handle);
}
