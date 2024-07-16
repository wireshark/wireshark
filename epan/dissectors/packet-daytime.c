/* packet-daytime.c
 * Routines for Daytime Protocol (RFC 867) packet dissection
 * Copyright 2006, Stephen Fisher (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-time.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>

void proto_register_daytime(void);
void proto_reg_handoff_daytime(void);

static dissector_handle_t daytime_handle;

static int proto_daytime;

static int hf_daytime_string;
static int hf_response_request;

static int ett_daytime;

/* This dissector works for TCP and UDP daytime packets */
#define DAYTIME_PORT 13

static int
dissect_daytime(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree    *daytime_tree;
  proto_item    *ti;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DAYTIME");

  col_add_fstr(pinfo->cinfo, COL_INFO, "DAYTIME %s",
    pinfo->srcport == pinfo->match_uint ? "Response":"Request");

  if (tree) {

    ti = proto_tree_add_item(tree, proto_daytime, tvb, 0, -1, ENC_NA);
    daytime_tree = proto_item_add_subtree(ti, ett_daytime);

    proto_tree_add_boolean(daytime_tree, hf_response_request, tvb, 0, 0, pinfo->srcport==DAYTIME_PORT);
    if (pinfo->srcport == DAYTIME_PORT) {
      proto_tree_add_item(daytime_tree, hf_daytime_string, tvb, 0, -1, ENC_ASCII);
    }
  }
  return tvb_captured_length(tvb);
}

void
proto_register_daytime(void)
{
  static hf_register_info hf[] = {
    { &hf_daytime_string,
      { "Daytime", "daytime.string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "String containing time and date", HFILL }
    },
    { &hf_response_request,
      { "Type", "daytime.response_request",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_response_request), 0x0,
        NULL, HFILL }
    },
  };

  static int *ett[] = {
    &ett_daytime,
  };

  proto_daytime = proto_register_protocol("Daytime Protocol", "DAYTIME", "daytime");
  proto_register_field_array(proto_daytime, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  daytime_handle = register_dissector("daytime", dissect_daytime, proto_daytime);
}

void
proto_reg_handoff_daytime(void)
{
  dissector_add_uint_with_preference("udp.port", DAYTIME_PORT, daytime_handle);
  dissector_add_uint_with_preference("tcp.port", DAYTIME_PORT, daytime_handle);
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
