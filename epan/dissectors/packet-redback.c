/* packet-redback.c
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 *
 * Start of RedBack SE400/800 tcpdump trace disassembly
 * Copyright 2005 Florian Lohoff <flo@rfc822.org>
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
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include "packet-ip.h"

static int proto_redback = -1;
static gint ett_redback = -1;

static dissector_handle_t ipv4_handle;
static dissector_handle_t eth_handle;
static dissector_handle_t clnp_handle;
static dissector_handle_t arp_handle;

/* wrapper for passing the PIC type to the generic ATM dissector */
static void
dissect_redback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8     l3off, dataoff, proto;
  guint32    context, flags;
  guint64    circuit;
  guint16    length;
  proto_item *ti,*tisub;
  proto_tree *subtree = NULL;
  tvbuff_t   *next_tvb;

  context = tvb_get_ntohl(tvb, 0);
  flags = tvb_get_ntohl(tvb, 4);
  circuit = tvb_get_ntoh64(tvb, 8);

  length = tvb_get_ntohs(tvb, 16);

  proto = (guint8) tvb_get_ntohs(tvb, 18);
  l3off = (guint8) tvb_get_ntohs(tvb, 20);
  dataoff = (guint8) tvb_get_ntohs(tvb, 22);

  ti = proto_tree_add_text(tree, tvb, 0, length, "Redback");

  subtree = proto_item_add_subtree(ti, ett_redback);  
  tisub = proto_tree_add_text (subtree, tvb, 0, 4,
                            "Context: 0x%08x", context);
  tisub = proto_tree_add_text (subtree, tvb, 4, 4,
                            "Flags: 0x%08x", flags);
  tisub = proto_tree_add_text (subtree, tvb, 8, 8,
                            "Circuit: 0x%" PRIx64, circuit);
  tisub = proto_tree_add_text (subtree, tvb, 16, 2,
                            "Length: %u", length);
  tisub = proto_tree_add_text (subtree, tvb, 18, 2,
                            "Protocol: %u", proto);
  tisub = proto_tree_add_text (subtree, tvb, 20, 2,
                            "Layer3 Offset: %u", l3off);
  tisub = proto_tree_add_text (subtree, tvb, 22, 2,
                            "Data Offset: %u", dataoff);
  next_tvb = tvb_new_subset(tvb, l3off, -1, -1);

  /* Mark the gap as "Data" for now */
  if (dataoff > l3off) {
	proto_tree_add_text (subtree, tvb, 24, l3off-24, "Data");	
  }

  /*
   * Just a guess - In case we see a difference in dataoff vs l3off
   * we assume there is an ethernet header. Traces from an OC12 didnt
   * show any header in here
   */
  if (dataoff > l3off) {
    call_dissector(eth_handle, next_tvb, pinfo, tree);
  } else {
    switch(proto) {
      case 0x01:
        /*
	 * IP - We assume IPv6 has a different protocol although
	 * i might be wrong - Havent seen any traces
	 */
        call_dissector(ipv4_handle, next_tvb, pinfo, tree);
        break;
      case 0x02:
	/*
	 * It is CLNP although it seem the Packet Asic fills
	 * some data in the packet so we have a "broken" packet in
	 * the trace
	 */
        call_dissector(clnp_handle, next_tvb, pinfo, tree);
        break;
      case 0x04:
	/* ARP - Always eth header in front */
        call_dissector(eth_handle, next_tvb, pinfo, tree);
        break;
      default:
	tisub = proto_tree_add_text (subtree, tvb, 24, length-24, 
				"Unknown Protocol %u", proto);
        break;
    }
  }
  return;
}

void
proto_register_redback(void)
{
  static gint *ett[] = {
    &ett_redback,
  };

  proto_redback = proto_register_protocol("Redback", "Redback", "redback");
  proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_redback(void)
{
  dissector_handle_t redback_handle;

  ipv4_handle = find_dissector("ip");
  eth_handle = find_dissector("eth_withoutfcs");
  clnp_handle = find_dissector("clnp");
  arp_handle = find_dissector("arp");

  redback_handle = create_dissector_handle(dissect_redback, proto_redback);
  dissector_add("wtap_encap", WTAP_ENCAP_REDBACK, redback_handle);
}


