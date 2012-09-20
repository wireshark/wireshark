/*
 * Copyright (c) 2003 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 */
#include "config.h"

#include <glib.h>
#include <epan/packet.h>

static int proto_udpencap = -1;
static gint ett_udpencap = -1;

static dissector_handle_t esp_handle;
static dissector_handle_t isakmp_handle;

/*
 * UDP Encapsulation of IPsec Packets
 * draft-ietf-ipsec-udp-encaps-06.txt
 */
static void
dissect_udpencap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t   *next_tvb;
  proto_tree *udpencap_tree = NULL;
  proto_item *ti            = NULL;
  guint32     spi;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDPENCAP");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_udpencap, tvb, 0, -1, ENC_NA);
    udpencap_tree = proto_item_add_subtree(ti, ett_udpencap);
  }

  /* 1 byte of 0xFF indicates NAT-keepalive */
  if ((tvb_length(tvb) == 1) && (tvb_get_guint8(tvb, 0) == 0xff)) {
    col_set_str(pinfo->cinfo, COL_INFO, "NAT-keepalive");
    if (tree)
      proto_tree_add_text(udpencap_tree, tvb, 0, 1, "NAT-keepalive packet");
  } else {
    /* SPI of zero indicates IKE traffic, otherwise it's ESP */
    tvb_memcpy(tvb, (guint8 *)&spi, 0, sizeof(spi));
    if (spi == 0) {
      col_set_str(pinfo->cinfo, COL_INFO, "ISAKMP");
      if (tree) {
        proto_tree_add_text(udpencap_tree, tvb, 0, sizeof(spi),
                "Non-ESP Marker");
        proto_item_set_len(ti, sizeof(spi));
      }
      next_tvb = tvb_new_subset_remaining(tvb, sizeof(spi));
      call_dissector(isakmp_handle, next_tvb, pinfo, tree);
    } else {
      col_set_str(pinfo->cinfo, COL_INFO, "ESP");
      if (tree)
        proto_item_set_len(ti, 0);
      call_dissector(esp_handle, tvb, pinfo, tree);
    }
  }
}

void
proto_register_udpencap(void)
{
  static gint *ett[] = {
    &ett_udpencap,
  };

  proto_udpencap = proto_register_protocol(
        "UDP Encapsulation of IPsec Packets", "UDPENCAP", "udpencap");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_udpencap(void)
{
  dissector_handle_t udpencap_handle;

  esp_handle = find_dissector("esp");
  isakmp_handle = find_dissector("isakmp");

  udpencap_handle = create_dissector_handle(dissect_udpencap, proto_udpencap);
  dissector_add_uint("udp.port", 4500, udpencap_handle);
}
