/* packet-ipnet.c
 * Routines for decoding Solaris IPNET packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/aftypes.h>
#include <wiretap/wtap.h>

void proto_register_ipnet(void);
void proto_reg_handoff_ipnet(void);

static int proto_ipnet;
static int hf_version;
static int hf_family;
static int hf_htype;
static int hf_pktlen;
static int hf_ifindex;
static int hf_grifindex;
static int hf_zsrc;
static int hf_zdst;

static int ett_raw;

static dissector_handle_t ipnet_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;

static const value_string solaris_family_vals[] = {
  { SOLARIS_AF_INET,  "Solaris AF_INET"  },
  { SOLARIS_AF_INET6, "Solaris AF_INET6" },
  { 0, NULL }
};

static const value_string htype_vals[] = {
  { 0, "Inbound"  },
  { 1, "Outbound" },
  { 2, "Local"    },
  { 0, NULL }
};

static int
dissect_ipnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree *fh_tree;
  proto_item *ti;
  tvbuff_t *next_tvb;
  uint32_t pktlen;
  uint8_t family;

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPNET");
  col_set_str(pinfo->cinfo, COL_INFO, "Solaris IPNET");

  /* populate a tree in the second pane with the IPNET header data */
  if(tree) {
    ti = proto_tree_add_item (tree, proto_ipnet, tvb, 0, 24, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, ett_raw);

    proto_tree_add_item(fh_tree, hf_version, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_family, tvb, 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_htype, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_pktlen, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_ifindex, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_grifindex, tvb, 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_zsrc, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_zdst, tvb, 20, 4, ENC_BIG_ENDIAN);
  }

  pktlen = tvb_get_ntohl(tvb, 4);
  next_tvb = tvb_new_subset_remaining(tvb, tvb_captured_length(tvb) - pktlen);

  family = tvb_get_uint8(tvb, 1);
  switch (family) {
  case SOLARIS_AF_INET:
    call_dissector(ip_handle, next_tvb, pinfo, tree);
    break;
  case SOLARIS_AF_INET6:
    call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    break;
  default:
    break;
  }
  return tvb_captured_length(tvb);
}

void
proto_register_ipnet(void)
{
  static hf_register_info hf[] = {
    { &hf_version,      { "Header version",             "ipnet.version",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_family,       { "Address family",             "ipnet.family",
      FT_UINT8, BASE_DEC, VALS(solaris_family_vals), 0x0, NULL, HFILL }},

    { &hf_htype,        { "Hook type",                  "ipnet.htype",
      FT_UINT16, BASE_DEC, VALS(htype_vals), 0x0, NULL, HFILL }},

    { &hf_pktlen,       { "Data length",                "ipnet.pktlen",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_ifindex,      { "Interface index",            "ipnet.ifindex",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_grifindex,    { "Group interface index",      "ipnet.grifindex",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_zsrc,         { "Source Zone ID",             "ipnet.zsrc",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_zdst,         { "Destination Zone ID",        "ipnet.zdst",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
  };
  static int *ett[] = {
    &ett_raw,
  };

  proto_ipnet = proto_register_protocol("Solaris IPNET", "IPNET", "ipnet");
  proto_register_field_array(proto_ipnet, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  ipnet_handle = register_dissector("ipnet", dissect_ipnet, proto_ipnet);
}

void
proto_reg_handoff_ipnet(void)
{
  /*
   * Get handles for the IP and IPv6 dissectors.
   */
  ip_handle = find_dissector_add_dependency("ip", proto_ipnet);
  ipv6_handle = find_dissector_add_dependency("ipv6", proto_ipnet);

  dissector_add_uint("wtap_encap", WTAP_ENCAP_IPNET, ipnet_handle);
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
