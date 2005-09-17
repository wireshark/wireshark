/* packet-vlan.c
 * Routines for VLAN 802.1Q ethernet header disassembly
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include "packet-ieee8023.h"
#include "packet-ipx.h"
#include "packet-llc.h"
#include "packet-vlan.h"
#include <epan/etypes.h>

static int proto_vlan = -1;
static int hf_vlan_priority = -1;
static int hf_vlan_cfi = -1;
static int hf_vlan_id = -1;
static int hf_vlan_etype = -1;
static int hf_vlan_len = -1;
static int hf_vlan_trailer = -1;

static gint ett_vlan = -1;

void
capture_vlan(const guchar *pd, int offset, int len, packet_counts *ld ) {
  guint16 encap_proto;
  if ( !BYTES_ARE_IN_FRAME(offset,len,5) ) {
    ld->other++;
    return;
  }
  encap_proto = pntohs( &pd[offset+2] );
  if ( encap_proto <= IEEE_802_3_MAX_LEN) {
    if ( pd[offset+4] == 0xff && pd[offset+5] == 0xff ) {
      capture_ipx(ld);
    } else {
      capture_llc(pd,offset+4,len,ld);
    }
  } else {
    capture_ethertype(encap_proto, pd, offset+4, len, ld);
  }
}

static void
dissect_vlan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *ti;
  guint16 tci,encap_proto;
  volatile gboolean is_802_2;
  proto_tree *volatile vlan_tree;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VLAN");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  tci = tvb_get_ntohs( tvb, 0 );

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "PRI: %d  CFI: %d  ID: %d",
      (tci >> 13), ((tci >> 12) & 1), (tci & 0xFFF));
  }

  vlan_tree = NULL;

  if (tree) {
    ti = proto_tree_add_item(tree, proto_vlan, tvb, 0, 4, FALSE);
    vlan_tree = proto_item_add_subtree(ti, ett_vlan);

    proto_tree_add_uint(vlan_tree, hf_vlan_priority, tvb, 0, 2, tci);
    proto_tree_add_uint(vlan_tree, hf_vlan_cfi, tvb, 0, 2, tci);
    proto_tree_add_uint(vlan_tree, hf_vlan_id, tvb, 0, 2, tci);
  }

  encap_proto = tvb_get_ntohs(tvb, 2);
  if (encap_proto <= IEEE_802_3_MAX_LEN) {
    /* Is there an 802.2 layer? I can tell by looking at the first 2
       bytes after the VLAN header. If they are 0xffff, then what
       follows the VLAN header is an IPX payload, meaning no 802.2.
       (IPX/SPX is they only thing that can be contained inside a
       straight 802.3 packet, so presumably the same applies for
       Ethernet VLAN packets). A non-0xffff value means that there's an
       802.2 layer inside the VLAN layer */
    is_802_2 = TRUE;
    TRY {
	    if (tvb_get_ntohs(tvb, 4) == 0xffff) {
	      is_802_2 = FALSE;
	    }
    }
    CATCH2(BoundsError, ReportedBoundsError) {
	    ; /* do nothing */

    }
    ENDTRY;

    dissect_802_3(encap_proto, is_802_2, tvb, 4, pinfo, tree, vlan_tree,
		  hf_vlan_len, hf_vlan_trailer, 0);
  } else {
    ethertype(encap_proto, tvb, 4, pinfo, tree, vlan_tree,
		       hf_vlan_etype, hf_vlan_trailer, 0);
  }
}

void
proto_register_vlan(void)
{
  static hf_register_info hf[] = {
	{ &hf_vlan_priority, {
		"Priority", "vlan.priority", FT_UINT16, BASE_DEC,
		0, 0xE000, "Priority", HFILL }},
	{ &hf_vlan_cfi, {
		"CFI", "vlan.cfi", FT_UINT16, BASE_DEC,
		0, 0x1000, "CFI", HFILL }},	/* XXX - Boolean? */
	{ &hf_vlan_id, {
		"ID", "vlan.id", FT_UINT16, BASE_DEC,
		0, 0x0FFF, "ID", HFILL }},
	{ &hf_vlan_etype, {
		"Type", "vlan.etype", FT_UINT16, BASE_HEX,
		VALS(etype_vals), 0x0, "Type", HFILL }},
	{ &hf_vlan_len, {
		"Length", "vlan.len", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Length", HFILL }},
	{ &hf_vlan_trailer, {
		"Trailer", "vlan.trailer", FT_BYTES, BASE_NONE,
		NULL, 0x0, "VLAN Trailer", HFILL }}
  };
  static gint *ett[] = {
	&ett_vlan,
  };

  proto_vlan = proto_register_protocol("802.1Q Virtual LAN", "VLAN", "vlan");
  proto_register_field_array(proto_vlan, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vlan(void)
{
  dissector_handle_t vlan_handle;

  vlan_handle = create_dissector_handle(dissect_vlan, proto_vlan);
  dissector_add("ethertype", ETHERTYPE_VLAN, vlan_handle);
}
