/* packet-vlan.c
 * Routines for VLAN 802.1Q ethernet header disassembly
 *
 * $Id: packet-vlan.c,v 1.16 2000/05/31 05:07:53 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include "packet.h"
#include "packet-ipx.h"
#include "packet-llc.h"
#include "etypes.h"

static int proto_vlan = -1;
static int hf_vlan_etype = -1;
static int hf_vlan_priority = -1;
static int hf_vlan_id = -1;
static int hf_vlan_cfi = -1;

static gint ett_vlan = -1;

void
capture_vlan(const u_char *pd, int offset, packet_counts *ld ) {
  guint32 encap_proto;
  if ( !BYTES_ARE_IN_FRAME(offset,5) ) {
    ld->other++;
    return; 
  }
  encap_proto = pntohs( &pd[offset+2] );
  if ( encap_proto <= IEEE_802_3_MAX_LEN) {
    if ( pd[offset+4] == 0xff && pd[offset+5] == 0xff ) {
      capture_ipx(pd,offset+4,ld);
    } else {
      capture_llc(pd,offset+4,ld);
    }
  } else {
    capture_ethertype(encap_proto, offset+4, pd, ld);
  }
}

static void
dissect_vlan(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  proto_tree *ti, *vlan_tree = NULL;
  guint16 tci,encap_proto;
  tvbuff_t *next_tvb;

  if (!BYTES_ARE_IN_FRAME(offset, 2*sizeof(guint16))) {
    return;
  }

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "VLAN");

  tci = pntohs( &pd[offset] );
  encap_proto = pntohs( &pd[offset+2] );

  if (check_col(fd, COL_INFO)) {
    col_add_fstr(fd, COL_INFO, "PRI: %d  CFI: %d  ID: %d",
      (tci >> 13), ((tci >> 12) & 1), (tci & 0xFFF));
  }

  if (tree) {
    ti = proto_tree_add_item(tree, proto_vlan, NullTVB, offset, 4, FALSE);
    vlan_tree = proto_item_add_subtree(ti, ett_vlan);

    proto_tree_add_uint(vlan_tree, hf_vlan_priority, NullTVB, offset, 2, tci);
    proto_tree_add_uint(vlan_tree, hf_vlan_cfi, NullTVB, offset, 2, tci);
    proto_tree_add_uint(vlan_tree, hf_vlan_id, NullTVB, offset, 2, tci);
  }

  next_tvb = tvb_new_subset(pi.compat_top_tvb, offset+4, -1, -1); /* XXX - should TRY() like dissect_eth() */
  if ( encap_proto <= IEEE_802_3_MAX_LEN) {
    if ( pd[offset+4] == 0xff && pd[offset+5] == 0xff ) {
      dissect_ipx(pd,offset+4,fd,tree);
	} else {
      dissect_llc(next_tvb, &pi, tree);
    }
  } else {
    ethertype(encap_proto, pi.compat_top_tvb, offset+4, &pi, tree, vlan_tree, hf_vlan_etype);
  }
}

void
proto_register_vlan(void)
{
  static hf_register_info hf[] = {
	{ &hf_vlan_etype, { 
		"Type", "vlan.etype", FT_UINT16, BASE_HEX, 
		VALS(etype_vals), 0x0, "Type" }},
	{ &hf_vlan_priority, { 
		"Priority", "vlan.priority", FT_UINT16, BASE_BIN, 
		0, 0xE000, "Priority" }},
	{ &hf_vlan_cfi, { 
		"CFI", "vlan.cfi", FT_UINT16, BASE_BIN, 
		0, 0x1000, "CFI" }},
	{ &hf_vlan_id, { 
		"ID", "vlan.id", FT_UINT16, BASE_BIN, 
		0, 0x0FFF, "ID" }},
  };
  static gint *ett[] = {
	&ett_vlan,
  };

  proto_vlan = proto_register_protocol("802.1q Virtual LAN", "vlan");
  proto_register_field_array(proto_vlan, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vlan(void)
{
	dissector_add("ethertype", ETHERTYPE_VLAN, dissect_vlan);
}
