/* packet-retix-bpdu.c
 * Routines for BPDU (Retix Spanning Tree Protocol) disassembly
 *
 * Copyright 2005 Giles Scott (gscott <AT> arubanetworks dot com>
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

#if 0
#endif
#include <epan/packet.h>
#if 0
#include <epan/llcsaps.h>
#include <epan/ppptypes.h>
#include <epan/chdlctypes.h>
#endif
#include <epan/addr_resolv.h>

void proto_register_retix_bpdu(void);

static gint ett_retix_bpdu = -1;
static int proto_retix_bpdu = -1;

static int hf_retix_bpdu_root_mac = -1;
static int hf_retix_bpdu_bridge_mac = -1;
static int hf_retix_bpdu_max_age = -1;
static int hf_retix_bpdu_hello_time = -1;
static int hf_retix_bpdu_forward_delay = -1;

/* I don't have the spec's for this protcol so it's been reverse engineered
 * It seems quite like 802.1D
 * It looks like the protocol version is specified in the ethernet trailer
 * In the single packet I have the trailer is
 * "RevC CBPDU"
 * There are several fields I've not dissected as I'm not exactly sure what they are
 * What ever happened to Retix anyway?
*/
static int
dissect_retix_bpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree *retix_bpdu_tree;
  proto_tree *ti;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "R-STP");

  ti = proto_tree_add_item(tree, proto_retix_bpdu, tvb, 0, -1, ENC_NA);
  retix_bpdu_tree = proto_item_add_subtree(ti, ett_retix_bpdu);

  proto_tree_add_item(retix_bpdu_tree, hf_retix_bpdu_root_mac, tvb, 0, 6, ENC_NA);

  proto_tree_add_item(retix_bpdu_tree, hf_retix_bpdu_bridge_mac, tvb, 10, 6, ENC_NA);
  col_add_fstr(pinfo->cinfo, COL_INFO, "Bridge MAC %s", tvb_ether_to_str(tvb, 10));

  proto_tree_add_item(retix_bpdu_tree, hf_retix_bpdu_max_age, tvb, 20, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(retix_bpdu_tree, hf_retix_bpdu_hello_time, tvb, 22, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(retix_bpdu_tree, hf_retix_bpdu_forward_delay, tvb, 24, 2, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}


void
proto_register_retix_bpdu(void)
{
  static hf_register_info hf[] = {
    { &hf_retix_bpdu_root_mac,
    { "Root MAC",  "r-stp.root.hw", FT_ETHER, BASE_NONE, NULL, 0x0,
    NULL, HFILL}},

    { &hf_retix_bpdu_bridge_mac,
    { "Bridge MAC", "r-stp.bridge.hw", FT_ETHER, BASE_NONE, NULL, 0x0,
    NULL, HFILL}},

    { &hf_retix_bpdu_max_age,
    { "Max Age", "r-stp.maxage", FT_UINT16, BASE_DEC, NULL, 0x0,
    NULL, HFILL}},

    { &hf_retix_bpdu_hello_time,
    { "Hello Time", "r-stp.hello", FT_UINT16, BASE_DEC, NULL, 0x0,
    NULL, HFILL}},

    { &hf_retix_bpdu_forward_delay,
    { "Forward Delay", "r-stp.forward", FT_UINT16, BASE_DEC, NULL, 0x0,
    NULL, HFILL}},
  };

  static gint *ett[] ={
    &ett_retix_bpdu,
  };

  proto_retix_bpdu = proto_register_protocol("Retix Spanning Tree Protocol", "R-STP", "r-stp");
  proto_register_field_array(proto_retix_bpdu, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("rbpdu", dissect_retix_bpdu, proto_retix_bpdu);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
