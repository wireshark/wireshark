/* packet-echo.c
 * Routines for ECHO packet disassembly (RFC862)
 *
 * Only useful to mark the packets as ECHO in the summary and in the
 * protocol hierarchy statistics (since not so many fields to decode ;-)
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#define ECHO_PORT  7

void proto_register_echo(void);
void proto_reg_handoff_echo(void);

static dissector_handle_t echo_handle;
static dissector_handle_t wol_handle;
static int proto_echo;

static int hf_echo_data;
static int hf_echo_request;
static int hf_echo_response;

static int ett_echo;

static int dissect_echo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  bool        request;
  proto_tree *echo_tree;
  proto_item *ti, *hidden_item;

  request = (pinfo->destport == pinfo->match_uint);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ECHO");
  col_set_str(pinfo->cinfo, COL_INFO, request ? "Request" : "Response");

  ti = proto_tree_add_item(tree, proto_echo, tvb, 0, -1, ENC_NA);
  echo_tree = proto_item_add_subtree(ti, ett_echo);

  hidden_item = proto_tree_add_boolean(echo_tree,
      request ?  hf_echo_request : hf_echo_response, tvb, 0, 0, 1);
  proto_item_set_hidden(hidden_item);

  proto_tree_add_item(echo_tree, hf_echo_data, tvb, 0, -1, ENC_NA);

  return tvb_captured_length(tvb);
}

static int
dissect_echo_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  /* Wake On Lan is commonly used over UDP port 7 and has strong heuristics,
   * whereas the echo dissector never rejects a packet, so try WOL first.
   * Unfortunately "echo" still ends up in frame.protocols this way.
   */
  if (wol_handle && call_dissector_only(wol_handle, tvb, pinfo, tree, data)) {
    return tvb_captured_length(tvb);
  }
  return dissect_echo(tvb, pinfo, tree, data);
}

void proto_register_echo(void)
{

  static hf_register_info hf[] = {
    { &hf_echo_data,
      { "Echo data", "echo.data", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
    { &hf_echo_request,
      { "Echo request", "echo.request", FT_BOOLEAN, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
    { &hf_echo_response,
      { "Echo response","echo.response", FT_BOOLEAN, BASE_NONE,
        NULL, 0x0, NULL, HFILL }}
  };

  static int *ett[] = {
    &ett_echo
  };

  proto_echo = proto_register_protocol("Echo", "ECHO", "echo");
  proto_register_field_array(proto_echo, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  echo_handle = register_dissector("echo", dissect_echo, proto_echo);
}

void proto_reg_handoff_echo(void)
{
  dissector_add_uint_with_preference("udp.port", ECHO_PORT, create_dissector_handle(dissect_echo_udp, proto_echo));
  dissector_add_uint_with_preference("tcp.port", ECHO_PORT, echo_handle);

  wol_handle = find_dissector_add_dependency("wol", proto_echo);
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
