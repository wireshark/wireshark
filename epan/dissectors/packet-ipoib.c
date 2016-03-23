/* packet-ipoib.c
 * Routines for decoding IP over InfiniBand (IPoIB) packet disassembly
 * See: http://tools.ietf.org/html/rfc4391#section-6
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <wiretap/wtap.h>

void proto_register_ipoib(void);
void proto_reg_handoff_ipoib(void);

static int proto_ipoib          = -1;
static int hf_dgid              = -1;
static int hf_daddr             = -1;
static int hf_daddr_qpn         = -1;
static int hf_grh               = -1;
static int hf_grh_ip_version    = -1;
static int hf_grh_traffic_class = -1;
static int hf_grh_flow_label    = -1;
static int hf_grh_sqpn          = -1;
static int hf_grh_sgid          = -1;
static int hf_type              = -1;
static int hf_reserved          = -1;

static gint ett_raw = -1;
static gint ett_hdr = -1;

static dissector_handle_t arp_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;

static int
dissect_ipoib(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree *fh_tree;
  proto_tree *fh_subtree;
  proto_item *ti;
  tvbuff_t   *next_tvb;
  guint16     type;
  int         grh_size = 0;

  if (pinfo->phdr->pkt_encap == WTAP_ENCAP_IP_OVER_IB_PCAP)
    grh_size = 40;

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPoIB");
  col_set_str(pinfo->cinfo, COL_INFO, "IP over Infiniband");

  /* populate a tree in the second pane with the IPoIB header data */
  if (tree) {
    ti = proto_tree_add_item (tree, proto_ipoib, tvb, 0, grh_size + 4, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, ett_raw);

    /* for PCAP data populate subtree with GRH pseudo header data */
    if (pinfo->phdr->pkt_encap == WTAP_ENCAP_IP_OVER_IB_PCAP) {

      /* Zero means GRH is not valid (unicast). Only destination
         address is set. */
      if (tvb_get_ntohs(tvb, 0) == 0) {
        ti = proto_tree_add_item (fh_tree, hf_daddr, tvb, 20, 20, ENC_NA);
        fh_subtree = proto_item_add_subtree(ti, ett_hdr);

        proto_tree_add_item(fh_subtree, hf_daddr_qpn, tvb, 21, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(fh_subtree, hf_dgid, tvb, 24, 16, ENC_NA);
      } else {
        ti = proto_tree_add_item (fh_tree, hf_grh, tvb, 0, 40, ENC_NA);
        fh_subtree = proto_item_add_subtree(ti, ett_hdr);

        proto_tree_add_item(fh_subtree, hf_grh_ip_version, tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fh_subtree, hf_grh_traffic_class, tvb, 0, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(fh_subtree, hf_grh_flow_label,tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(fh_subtree, hf_grh_sqpn, tvb, 5, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(fh_subtree, hf_grh_sgid, tvb, 8, 16, ENC_NA);
        proto_tree_add_item(fh_subtree, hf_dgid, tvb, 24, 16, ENC_NA);
      }
    }

    proto_tree_add_item(fh_tree, hf_type, tvb, grh_size + 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_reserved, tvb, grh_size + 2, 2, ENC_BIG_ENDIAN);
  }

  next_tvb = tvb_new_subset_remaining(tvb, grh_size + 4);

  type = tvb_get_ntohs(tvb, grh_size + 0);
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
  return tvb_captured_length(tvb);
}

void
proto_register_ipoib(void)
{
  static hf_register_info hf[] = {
    { &hf_daddr,
      { "Destination address", "ipoib.daddr",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
    { &hf_daddr_qpn,
      { "Destination QPN", "ipoib.daddr.qpn",
        FT_UINT24, BASE_HEX, NULL, 0x0,
        NULL, HFILL}},
    { &hf_dgid,
      { "Destination GID", "ipoib.dgid",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_grh,
      { "Global Route Header", "ipoib.grh",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
    { &hf_grh_ip_version, {
       "IP Version", "ipoib.grh.ipver",
       FT_UINT8, BASE_DEC, NULL, 0xF0,
       NULL, HFILL}},
    { &hf_grh_traffic_class, {
       "Traffic Class", "ipoib.grh.tclass",
       FT_UINT16, BASE_DEC, NULL, 0x0FF0,
       NULL, HFILL}},
    { &hf_grh_flow_label, {
       "Flow Label", "ipoib.grh.flowlabel",
       FT_UINT32, BASE_DEC, NULL, 0x000FFFFF,
       NULL, HFILL}},
    { &hf_grh_sqpn,
      { "Source QPN", "ipoib.grh.sqpn",
        FT_UINT24, BASE_HEX, NULL, 0x0,
        NULL, HFILL}},
    { &hf_grh_sgid,
      { "Source GID", "ipoib.grh.sgid",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
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
    &ett_raw,
    &ett_hdr
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
  arp_handle  = find_dissector_add_dependency("arp", proto_ipoib);
  ip_handle   = find_dissector_add_dependency("ip", proto_ipoib);
  ipv6_handle = find_dissector_add_dependency("ipv6", proto_ipoib);

  ipoib_handle = create_dissector_handle(dissect_ipoib, proto_ipoib);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_IP_OVER_IB_SNOOP, ipoib_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_IP_OVER_IB_PCAP, ipoib_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
