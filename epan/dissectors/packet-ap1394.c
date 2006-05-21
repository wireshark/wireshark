/* packet-ap1394.c
 * Routines for Apple IP-over-IEEE 1394 packet disassembly
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
#include <epan/addr_resolv.h>
#include <epan/strutil.h>

#include "packet-ap1394.h"
#include <epan/etypes.h>

static int proto_ap1394 = -1;
static int hf_ap1394_dst = -1;
static int hf_ap1394_src = -1;
static int hf_ap1394_type = -1;

static gint ett_ap1394 = -1;

void
capture_ap1394(const guchar *pd, int offset, int len, packet_counts *ld)
{
  guint16    etype;

  if (!BYTES_ARE_IN_FRAME(offset, len, 18)) {
    ld->other++;
    return;
  }

  /* Skip destination and source addresses */
  offset += 16;

  etype = pntohs(&pd[offset]);
  offset += 2;
  capture_ethertype(etype, pd, offset, len, ld);
}

static void
dissect_ap1394(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *fh_tree = NULL;
  const guint8 *src_addr, *dst_addr;
  guint16    etype;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IP/IEEE1394");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  src_addr=tvb_get_ptr(tvb, 8, 8);
  SET_ADDRESS(&pinfo->dl_src,	AT_EUI64, 8, src_addr);
  SET_ADDRESS(&pinfo->src,	AT_EUI64, 8, src_addr);
  dst_addr=tvb_get_ptr(tvb, 0, 8);
  SET_ADDRESS(&pinfo->dl_dst,	AT_EUI64, 8, dst_addr);
  SET_ADDRESS(&pinfo->dst,	AT_EUI64, 8, dst_addr);

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_ap1394, tvb, 0, 18,
		"Apple IP-over-IEEE 1394, Src: %s, Dst: %s",
		bytes_to_str(src_addr, 8), bytes_to_str(dst_addr, 8));
    fh_tree = proto_item_add_subtree(ti, ett_ap1394);
    proto_tree_add_bytes(fh_tree, hf_ap1394_dst, tvb, 0, 8, dst_addr);
    proto_tree_add_bytes(fh_tree, hf_ap1394_src, tvb, 8, 8, src_addr);
  }
  etype = tvb_get_ntohs(tvb, 16);
  ethertype(etype, tvb, 18, pinfo, tree, fh_tree, hf_ap1394_type, -1, 0);
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
      { "Type",	"ap1394.type", FT_UINT16, BASE_HEX,
        VALS(etype_vals), 0x0, "", HFILL }},
  };
  static gint *ett[] = {
    &ett_ap1394,
  };

  proto_ap1394 = proto_register_protocol("Apple IP-over-IEEE 1394", "IP/IEEE1394", "ap1394");
  proto_register_field_array(proto_ap1394, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ap1394(void)
{
  dissector_handle_t ap1394_handle;

  ap1394_handle = create_dissector_handle(dissect_ap1394, proto_ap1394);
  dissector_add("wtap_encap", WTAP_ENCAP_APPLE_IP_OVER_IEEE1394, ap1394_handle);
}
