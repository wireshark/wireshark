/*
 * Copyright (c) 2003 Markus Friedl.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_udpencap(void);
void proto_reg_handoff_udpencap(void);

#define UDPENCAP_PORT 4500

static int proto_udpencap;

static int hf_nat_keepalive;
static int hf_non_esp_marker;

static int ett_udpencap;

static dissector_handle_t udpencap_handle;
static dissector_handle_t esp_handle;
static dissector_handle_t isakmp_handle;

/*
 * UDP Encapsulation of IPsec Packets
 * draft-ietf-ipsec-udp-encaps-06.txt
 */
static int
dissect_udpencap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  tvbuff_t   *next_tvb;
  proto_tree *udpencap_tree;
  proto_item *ti;
  uint32_t    spi;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDPENCAP");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_udpencap, tvb, 0, -1, ENC_NA);
  udpencap_tree = proto_item_add_subtree(ti, ett_udpencap);

  /* 1 byte of 0xFF indicates NAT-keepalive */
  if ((tvb_captured_length(tvb) == 1) && (tvb_get_uint8(tvb, 0) == 0xff)) {
    col_set_str(pinfo->cinfo, COL_INFO, "NAT-keepalive");
    proto_tree_add_item(udpencap_tree, hf_nat_keepalive, tvb, 0, 1, ENC_NA);
  } else {
    /* SPI of zero indicates IKE traffic, otherwise it's ESP */
    spi = tvb_get_ntohl(tvb, 0);
    if (spi == 0) {
      col_set_str(pinfo->cinfo, COL_INFO, "ISAKMP");
      proto_tree_add_item(udpencap_tree, hf_non_esp_marker, tvb, 0, 4, ENC_NA);
      proto_item_set_len(ti, 4);
      next_tvb = tvb_new_subset_remaining(tvb, 4);
      call_dissector(isakmp_handle, next_tvb, pinfo, tree);
    } else {
      col_set_str(pinfo->cinfo, COL_INFO, "ESP");
      proto_item_set_len(ti, 0);
      call_dissector(esp_handle, tvb, pinfo, tree);
    }
  }
  return tvb_captured_length(tvb);
}

void
proto_register_udpencap(void)
{
  static hf_register_info hf[] = {
    { &hf_nat_keepalive, { "NAT-keepalive packet", "udpencap.nat_keepalive",
          FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_non_esp_marker, { "Non-ESP Marker", "udpencap.non_esp_marker",
          FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
  };

  static int *ett[] = {
    &ett_udpencap,
  };

  proto_udpencap = proto_register_protocol("UDP Encapsulation of IPsec Packets", "UDPENCAP", "udpencap");
  proto_register_field_array(proto_udpencap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  udpencap_handle = register_dissector("udpencap", dissect_udpencap, proto_udpencap);
}

void
proto_reg_handoff_udpencap(void)
{

  esp_handle = find_dissector_add_dependency("esp", proto_udpencap);
  isakmp_handle = find_dissector_add_dependency("isakmp", proto_udpencap);

  dissector_add_uint_with_preference("udp.port", UDPENCAP_PORT, udpencap_handle);
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
