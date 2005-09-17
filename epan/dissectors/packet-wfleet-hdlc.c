/* packet-chdlc.c
 * Routines for Wellfleet HDLC packet disassembly
 * Copied from the Cisco HDLC packet disassembly routines
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/addr_resolv.h>
#include "packet-chdlc.h"
#include "packet-ip.h"

static int proto_wfleet_hdlc = -1;
static int hf_wfleet_hdlc_addr = -1;
static int hf_wfleet_hdlc_cmd = -1;

static gint ett_wfleet_hdlc = -1;

dissector_handle_t eth_withoutfcs_handle;

static const value_string wfleet_hdlc_cmd_vals[] = {
  { 0x03, "Un-numbered I frame"},
  { 0,    NULL}
};

static void
dissect_wfleet_hdlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *fh_tree = NULL;
  tvbuff_t   *next_tvb;
  guint8     addr;
  guint8     cmd;

  if (check_col(pinfo->cinfo, COL_RES_DL_SRC))
    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A");
  if (check_col(pinfo->cinfo, COL_RES_DL_DST))
    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WHDLC");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  addr = tvb_get_guint8(tvb, 0);
  cmd = tvb_get_guint8(tvb, 1);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_wfleet_hdlc, tvb, 0, 2, FALSE);
    fh_tree = proto_item_add_subtree(ti, ett_wfleet_hdlc);

    proto_tree_add_uint(fh_tree, hf_wfleet_hdlc_addr, tvb, 0, 1, addr);
    proto_tree_add_uint(fh_tree, hf_wfleet_hdlc_cmd, tvb, 1, 1, cmd);

  }

  /*
   * Build a tvb of the piece past the first two bytes and call the 
   * ethernet dissector
   */

  next_tvb = tvb_new_subset(tvb, 2, -1, -1);

  call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);

}

void
proto_register_wfleet_hdlc(void)
{
  static hf_register_info hf[] = {
    { &hf_wfleet_hdlc_addr,
      { "Address", "wfleet_hdlc.address", FT_UINT8, BASE_HEX,
        NULL, 0x0, "", HFILL }},
    { &hf_wfleet_hdlc_cmd,
      { "Command", "wfleet_hdlc.command", FT_UINT8, BASE_HEX,
        VALS(wfleet_hdlc_cmd_vals), 0x0, "", HFILL }},
  };
  static gint *ett[] = {
    &ett_wfleet_hdlc,
  };

  proto_wfleet_hdlc = proto_register_protocol("Wellfleet HDLC", "WHDLC", "whdlc");
  proto_register_field_array(proto_wfleet_hdlc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("wfleet_hdlc", dissect_wfleet_hdlc, proto_wfleet_hdlc);

}

void
proto_reg_handoff_wfleet_hdlc(void)
{
  dissector_handle_t wfleet_hdlc_handle;

  wfleet_hdlc_handle = find_dissector("wfleet_hdlc");
  dissector_add("wtap_encap", WTAP_ENCAP_WFLEET_HDLC, wfleet_hdlc_handle);

  /* 
   * Find the eth dissector and save a ref to it
   */

  eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
}
