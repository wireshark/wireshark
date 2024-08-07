/* packet-chdlc.c
 * Routines for Wellfleet HDLC packet disassembly
 * Copied from the Cisco HDLC packet disassembly routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>

void proto_register_wfleet_hdlc(void);
void proto_reg_handoff_wfleet_hdlc(void);

static int proto_wfleet_hdlc;
static int hf_wfleet_hdlc_addr;
static int hf_wfleet_hdlc_cmd;

static int ett_wfleet_hdlc;

static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t wfleet_hdlc_handle;

static const value_string wfleet_hdlc_cmd_vals[] = {
  { 0x03, "Un-numbered I frame"},
  { 0,    NULL}
};

static int
dissect_wfleet_hdlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *fh_tree = NULL;
  tvbuff_t   *next_tvb;
  uint8_t    addr;
  uint8_t    cmd;

  col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A");
  col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "WHDLC");
  col_clear(pinfo->cinfo, COL_INFO);

  addr = tvb_get_uint8(tvb, 0);
  cmd = tvb_get_uint8(tvb, 1);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_wfleet_hdlc, tvb, 0, 2, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, ett_wfleet_hdlc);

    proto_tree_add_uint(fh_tree, hf_wfleet_hdlc_addr, tvb, 0, 1, addr);
    proto_tree_add_uint(fh_tree, hf_wfleet_hdlc_cmd, tvb, 1, 1, cmd);

  }

  /*
   * Build a tvb of the piece past the first two bytes and call the
   * ethernet dissector
   */

  next_tvb = tvb_new_subset_remaining(tvb, 2);

  call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
  return tvb_captured_length(tvb);
}

void
proto_register_wfleet_hdlc(void)
{
  static hf_register_info hf[] = {
    { &hf_wfleet_hdlc_addr,
      { "Address", "wfleet_hdlc.address", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},
    { &hf_wfleet_hdlc_cmd,
      { "Command", "wfleet_hdlc.command", FT_UINT8, BASE_HEX,
        VALS(wfleet_hdlc_cmd_vals), 0x0, NULL, HFILL }},
  };
  static int *ett[] = {
    &ett_wfleet_hdlc,
  };

  proto_wfleet_hdlc = proto_register_protocol("Wellfleet HDLC", "WHDLC", "whdlc");
  proto_register_field_array(proto_wfleet_hdlc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  wfleet_hdlc_handle = register_dissector("wfleet_hdlc", dissect_wfleet_hdlc, proto_wfleet_hdlc);

}

void
proto_reg_handoff_wfleet_hdlc(void)
{
  dissector_add_uint("wtap_encap", WTAP_ENCAP_WFLEET_HDLC, wfleet_hdlc_handle);

  /*
   * Find the eth dissector and save a ref to it
   */

  eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_wfleet_hdlc);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
