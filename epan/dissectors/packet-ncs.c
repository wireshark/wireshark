/* packet-ncs.c
 * Routines for Novell Cluster Services
 * Greg Morris <gmorris@novell.com>
 * Copyright (c) Novell, Inc. 2002-2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/ipproto.h>

void proto_register_ncs(void);
void proto_reg_handoff_ncs(void);

static dissector_handle_t ncs_handle;

static int ett_ncs;

static int proto_ncs;

static int hf_panning_id;
static int hf_incarnation;

static int
dissect_ncs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree  *ncs_tree;
  proto_item  *ti;

  ti = proto_tree_add_item(tree, proto_ncs, tvb, 0, -1, ENC_NA);
  ncs_tree = proto_item_add_subtree(ti, ett_ncs);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NCS");
  col_set_str(pinfo->cinfo, COL_INFO, "Novell Cluster Services Heartbeat");

  proto_tree_add_item(ncs_tree, hf_panning_id, tvb, 4, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(ncs_tree, hf_incarnation, tvb, 8, 4, ENC_BIG_ENDIAN);
  return tvb_captured_length(tvb);
}

void
proto_register_ncs(void)
{
  static hf_register_info hf[] = {

    { &hf_panning_id,
      { "Panning ID",           "ncs.pan_id",           FT_UINT32, BASE_HEX,    NULL, 0x0,
        NULL, HFILL }},

    { &hf_incarnation,
      { "Incarnation",          "ncs.incarnation",       FT_UINT32, BASE_HEX,    NULL, 0x0,
        NULL, HFILL }},

  };
  static int *ett[] = {
    &ett_ncs,
  };

  proto_ncs = proto_register_protocol("Novell Cluster Services",
                                      "NCS", "ncs");
  proto_register_field_array(proto_ncs, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ncs_handle = register_dissector("ncs", dissect_ncs, proto_ncs);
}



void
proto_reg_handoff_ncs(void)
{
  dissector_add_uint("ip.proto", IP_PROTO_NCS_HEARTBEAT, ncs_handle);
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
