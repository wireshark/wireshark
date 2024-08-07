/* packet-ap1394.c
 * Routines for Apple IP-over-IEEE 1394 packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <wsutil/pint.h>
#include <epan/addr_resolv.h>

#include <epan/etypes.h>

void proto_register_ap1394(void);
void proto_reg_handoff_ap1394(void);

static dissector_handle_t ap1394_handle;
static capture_dissector_handle_t ap1394_cap_handle;

static int proto_ap1394;
static int hf_ap1394_dst;
static int hf_ap1394_src;
static int hf_ap1394_type;

static int ett_ap1394;

static dissector_table_t ethertype_subdissector_table;

static bool
capture_ap1394(const unsigned char *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
  uint16_t   etype;

  if (!BYTES_ARE_IN_FRAME(offset, len, 18)) {
    return false;
  }

  /* Skip destination and source addresses */
  offset += 16;

  etype = pntoh16(&pd[offset]);
  offset += 2;
  return try_capture_dissector("ethertype", etype, pd, offset, len, cpinfo, pseudo_header);
}

static int
dissect_ap1394(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *fh_tree = NULL;
  uint16_t   etype;
  tvbuff_t *next_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IP/IEEE1394");
  col_clear(pinfo->cinfo, COL_INFO);

  set_address_tvb(&pinfo->dl_src,   AT_EUI64, 8, tvb, 8);
  copy_address_shallow(&pinfo->src, &pinfo->dl_src);
  set_address_tvb(&pinfo->dl_dst,   AT_EUI64, 8, tvb, 0);
  copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_ap1394, tvb, 0, 18,
                "Apple IP-over-IEEE 1394, Src: %s, Dst: %s",
                address_to_str(pinfo->pool, &pinfo->src), address_to_str(pinfo->pool, &pinfo->dst));
    fh_tree = proto_item_add_subtree(ti, ett_ap1394);
    proto_tree_add_item(fh_tree, hf_ap1394_dst, tvb, 0, 8, ENC_NA);
    proto_tree_add_item(fh_tree, hf_ap1394_src, tvb, 8, 8, ENC_NA);
  }
  etype = tvb_get_ntohs(tvb, 16);
  proto_tree_add_uint(fh_tree, hf_ap1394_type, tvb, 16, 2, etype);
  next_tvb = tvb_new_subset_remaining(tvb, 18);
  if (!dissector_try_uint(ethertype_subdissector_table, etype, next_tvb,
                pinfo, tree))
  {
      call_data_dissector(next_tvb, pinfo, tree);
  }
  return tvb_captured_length(tvb);
}

void
proto_register_ap1394(void)
{
  static hf_register_info hf[] = {
    { &hf_ap1394_dst,
      { "Destination", "ap1394.dst", FT_BYTES, BASE_NONE,
        NULL, 0x0, "Destination address", HFILL }},
    { &hf_ap1394_src,
      { "Source", "ap1394.src", FT_BYTES, BASE_NONE,
        NULL, 0x0, "Source address", HFILL }},
    /* registered here but handled in ethertype.c */
    { &hf_ap1394_type,
      { "Type", "ap1394.type", FT_UINT16, BASE_HEX,
        VALS(etype_vals), 0x0, NULL, HFILL }},
  };
  static int *ett[] = {
    &ett_ap1394,
  };

  proto_ap1394 = proto_register_protocol("Apple IP-over-IEEE 1394", "IP/IEEE1394", "ap1394");
  proto_register_field_array(proto_ap1394, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ap1394_handle = register_dissector("ap1394", dissect_ap1394, proto_ap1394);
  ap1394_cap_handle = register_capture_dissector("ap1394", capture_ap1394, proto_ap1394);
}

void
proto_reg_handoff_ap1394(void)
{
  ethertype_subdissector_table = find_dissector_table("ethertype");

  dissector_add_uint("wtap_encap", WTAP_ENCAP_APPLE_IP_OVER_IEEE1394, ap1394_handle);

  capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_APPLE_IP_OVER_IEEE1394, ap1394_cap_handle);
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
