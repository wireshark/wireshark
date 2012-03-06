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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/ipproto.h>

static int proto_etherip = -1;
static int hf_etherip_ver = -1;

static gint ett_etherip = -1;

static dissector_handle_t eth_withoutfcs_handle;

#ifndef offsetof
#define offsetof(type, member)  ((size_t)(&((type *)0)->member))
#endif


/*
 * RFC 3378: EtherIP: Tunneling Ethernet Frames in IP Datagrams
 *
 *      Bits 0-3:  Protocol version
 *      Bits 4-15: Reserved for future use
 */

struct etheriphdr {
  guint8 ver;                /* version/reserved */
  guint8 pad;                /* required padding byte */
};

#define ETHERIP_VERS_MASK 0x0f


static void
dissect_etherip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct etheriphdr etheriph;
  tvbuff_t *next_tvb;
  proto_tree *etherip_tree;
  proto_item *ti;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETHERIP");

  /* Copy out the etherip header to insure alignment */
  tvb_memcpy(tvb, (guint8 *)&etheriph, 0, sizeof(etheriph));

  /* mask out reserved bits */
  etheriph.ver &= ETHERIP_VERS_MASK;

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_etherip, tvb, 0,
             sizeof(etheriph),
             "EtherIP, Version %d",
             etheriph.ver
             );
    etherip_tree = proto_item_add_subtree(ti, ett_etherip);

    proto_tree_add_uint(etherip_tree, hf_etherip_ver, tvb,
             offsetof(struct etheriphdr, ver), sizeof(etheriph.ver),
             etheriph.ver);
  }

  /* Set the tvbuff for the payload after the header */
  next_tvb = tvb_new_subset_remaining(tvb, sizeof(etheriph));

  call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
}

void
proto_register_etherip(void)
{
  static hf_register_info hf_etherip[] = {
    { &hf_etherip_ver,
      { "Version", "etherip.ver", FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_etherip,
  };

  proto_etherip = proto_register_protocol("Ethernet over IP",
                                          "ETHERIP", "etherip");
  proto_register_field_array(proto_etherip, hf_etherip, array_length(hf_etherip));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("etherip", dissect_etherip, proto_etherip);
}

void
proto_reg_handoff_etherip(void)
{
  dissector_handle_t etherip_handle;

  eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
  etherip_handle = find_dissector("etherip");
  dissector_add_uint("ip.proto", IP_PROTO_ETHERIP, etherip_handle);
}
