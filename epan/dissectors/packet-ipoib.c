/* packet-ipoib.c
 * Routines for decoding IP over InfiniBand (IPoIB) packet disassembly
 * See: http://tools.ietf.org/html/rfc4391#section-6
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>

static int proto_ipoib = -1;
static int hf_type     = -1;
static int hf_reserved = -1;

static gint ett_raw = -1;

static dissector_handle_t arp_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;

static void
dissect_ipoib(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *fh_tree;
  proto_item *ti;
  tvbuff_t   *next_tvb;
  guint16     type;

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPoIB");
  col_set_str(pinfo->cinfo, COL_INFO, "IP over Infiniband");

  /* populate a tree in the second pane with the IPoIB header data */
  if (tree) {
    ti = proto_tree_add_item (tree, proto_ipoib, tvb, 0, 4, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, ett_raw);

    proto_tree_add_item(fh_tree, hf_type, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_reserved, tvb, 2, 2, ENC_BIG_ENDIAN);
  }

  next_tvb = tvb_new_subset_remaining(tvb, 4);

  type = tvb_get_ntohs(tvb, 0);
  switch (type) {
  case ETHERTYPE_IP:
    call_dissector(ip_handle, next_tvb, pinfo, tree);
    break;
  case ETHERTYPE_IPv6:
    call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    break;
  case ETHERTYPE_ARP:
  case ETHERTYPE_REVARP:
    call_dissector(arp_handle, next_tvb, pinfo, tree);
    break;
  default:
    break;
  }
}

void
proto_register_ipoib(void)
{
  static hf_register_info hf[] = {
    { &hf_type,
      { "Type", "ipoib.type",
        FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
        NULL, HFILL }},
    { &hf_reserved,
      { "Reserved",  "ipoib.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }}
  };

  static gint *ett[] = {
    &ett_raw
  };

  proto_ipoib = proto_register_protocol("IP over Infiniband", "IPoIB", "ipoib");
  proto_register_field_array(proto_ipoib, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ipoib(void)
{
  dissector_handle_t ipoib_handle;

  /*
   * Get handles for the ARP, IP and IPv6 dissectors.
   */
  arp_handle  = find_dissector("arp");
  ip_handle   = find_dissector("ip");
  ipv6_handle = find_dissector("ipv6");

  ipoib_handle = create_dissector_handle(dissect_ipoib, proto_ipoib);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_IP_OVER_IB, ipoib_handle);
}
