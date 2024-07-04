/* packet-cl3.c
 * Routines for CableLabs Layer-3 Protocol Dissection
 * Copyright 2019 Jon Dennis <j.dennis[at]cablelabs.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Dissector for IEEE-Registered CableLabs EtherType 0xB4E3
 *
 * IEEE EtherType List
 *   http://standards-oui.ieee.org/ethertype/eth.txt
 *
 * CableLabs Specifications Can Be Found At:
 *   https://www.cablelabs.com/specs
 *   Note: As of writing this, the spec is in the process of being published.
 *         Initially, this will be published under the Dual Channel Wi-Fi spec,
 *         but may split off into its own spec in the future.
 *         Eventually a direct link to the spec should be put here.
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>

#include <epan/etypes.h>

#include <wsutil/str_util.h>


void proto_register_cl3(void);
void proto_reg_handoff_cl3(void);

static dissector_handle_t cl3_handle;

/* persistent handles for this dissector */
static int               proto_cl3;
static dissector_table_t cl3_command_table;
static int               ett_cl3;
static int               hf_cl3_version;
static int               hf_cl3_headerlen;
static int               hf_cl3_subproto;
static int               hf_cl3_payload;
static expert_field      ei_cl3_badheaderlen;
static expert_field      ei_cl3_unsup_ver;


/* Known CL3 (sub-)protocol type strings: */
static const value_string cl3_protocols[] = {
  {0x00DC,          "Dual-Channel Wi-Fi Messaging"     },
  {0, NULL}
};


/* called for each incoming framing matching the CL3 ethertype with a version number of 1: */
static void
dissect_cl3_v1(
  tvbuff_t    *tvb,
  packet_info *pinfo,
  proto_tree  *tree,
  proto_item  *ti,
  proto_tree  *cl3_tree,
  uint16_t     header_length
  ) {

  dissector_handle_t   dh;
  tvbuff_t            *tvb_sub;

  uint16_t subprotocol_id;

  /* ensure the header length is valid for version 1 */
  if (header_length != 4) {
    expert_add_info(pinfo, ti, &ei_cl3_badheaderlen);
  }

  /* parse the sub-protocol id */
  subprotocol_id = tvb_get_ntohs(tvb, 2);

  /* append the subprotocol id to the "packet summary view" fields */
  col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "[Subprotocol 0x%04X]", (unsigned)subprotocol_id);

  /* add elements to the CL3 tree...
     CL3 version 1 fields: (pretty much just the sub protocol id) */
  proto_tree_add_uint(cl3_tree, hf_cl3_subproto, tvb, 2, 2, subprotocol_id);

  /* call CL (sub-)protocol dissector */
  dh = dissector_get_uint_handle(cl3_command_table, subprotocol_id);
  if (dh != NULL) {
    tvb_sub = tvb_new_subset_remaining(tvb, header_length);
    call_dissector(dh, tvb_sub, pinfo, tree);
  }
}

/* called for each incoming framing matching the CL3 ethertype: */
static int
dissect_cl3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {

  proto_item   *ti;
  proto_tree   *cl3_tree;

  uint16_t version;
  uint16_t header_length;
  uint32_t payload_length;

  /* parse the header fields */
  version = header_length = tvb_get_ntohs(tvb, 0);
  version >>= 12;
  header_length >>= 8;
  header_length &= 0x0F;
  header_length *= 4;
  payload_length = tvb_captured_length(tvb) - header_length;

  /* setup the "packet summary view" fields */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CL3");
  col_clear(pinfo->cinfo, COL_INFO);
  col_add_fstr(pinfo->cinfo, COL_INFO, "CableLabs Layer-3 Protocol (Ver %u)", (unsigned)version);

  /* create a tree node for us... */
  ti = proto_tree_add_protocol_format(tree, proto_cl3, tvb, 0, header_length, "CableLabs Layer-3 Protocol (CL3) Version %u", (unsigned)version);
  cl3_tree = proto_item_add_subtree(ti, ett_cl3);

  /* CL3 version agnostic fields: (pretty much just the first byte; like ipv4, version + length) */
  proto_tree_add_item(cl3_tree, hf_cl3_version,    tvb, 0, 1, ENC_NA);
  proto_tree_add_uint_bits_format_value(cl3_tree, hf_cl3_headerlen, tvb, 0 + 4, 4, header_length,
                                        ENC_BIG_ENDIAN, "%u bytes (%u)", header_length, header_length >> 2);

  /* validate the header length... */
  if ((header_length < 1) || (header_length > tvb_captured_length(tvb))) {
    expert_add_info(pinfo, ti, &ei_cl3_badheaderlen);
  }

  /* version-specific dissection... */
  switch (version) {
  case 1:
    dissect_cl3_v1(tvb, pinfo, tree, ti, cl3_tree, header_length);
    break;
  default:
    expert_add_info(pinfo, ti, &ei_cl3_unsup_ver);
    break;
  }

  /* add a byte reference to the payload we are carrying */
  proto_tree_add_item(cl3_tree, hf_cl3_payload, tvb, header_length, payload_length, ENC_NA);

  return tvb_captured_length(tvb);
}


/* initializes this dissector */
void
proto_register_cl3(void) {
  static hf_register_info hf[] = {
    { &hf_cl3_version,
      { "Version",       "cl3.version",
        FT_UINT8,      BASE_DEC,    NULL, 0xF0,
        "The CableLabs layer-3 protocol version number", HFILL }},
    { &hf_cl3_headerlen,
      { "Header Length", "cl3.headerlen",
        FT_UINT8,      BASE_DEC,    NULL, 0x0,
        "The length of the CableLabs layer-3 protocol header", HFILL }},
    { &hf_cl3_subproto,
      { "Subprotocol",   "cl3.subprotocol",
        FT_UINT16,     BASE_HEX,    VALS(cl3_protocols), 0x0,
        "The subprotocol number the CableLabs layer-3 protocol is carrying", HFILL }},
    { &hf_cl3_payload,
      { "CL3 Payload",   "cl3.payload",
        FT_BYTES,      BASE_NONE,   NULL, 0x0,
        "The payload carried by this CableLabs layer-3 protocol packet", HFILL}},
  };
  static int *ett[] = {
    &ett_cl3,
  };
  static ei_register_info ei[] = {
     { &ei_cl3_badheaderlen,   { "cl3.badheaderlen",   PI_MALFORMED, PI_ERROR, "Bad Header Length", EXPFILL }},
     { &ei_cl3_unsup_ver,      { "cl3.unsup_ver",      PI_UNDECODED, PI_WARN,  "Unknown protocol version", EXPFILL }},
  };

  expert_module_t* expert_cl3;

  proto_cl3 = proto_register_protocol("CableLabs Layer 3 Protocol", "CL3", "cl3");

  proto_register_field_array(proto_cl3, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_cl3 = expert_register_protocol(proto_cl3);
  expert_register_field_array(expert_cl3, ei, array_length(ei));

  /* register the dissector */
  cl3_handle = register_dissector("cl3", &dissect_cl3, proto_cl3);

  /* subdissector code... */
  cl3_command_table = register_dissector_table("cl3.subprotocol", "CableLabs Subprotocol", proto_cl3, FT_UINT16, BASE_DEC);
}

/* hooks in our dissector to be called on matching ethertype */
void
proto_reg_handoff_cl3(void) {
  dissector_add_uint("ethertype", ETHERTYPE_CABLELABS, cl3_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
