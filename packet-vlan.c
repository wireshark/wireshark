/* packet-vlan.c
 * Routines for VLAN 802.1Q ethernet header disassembly
 *
 * $Id: packet-vlan.c,v 1.3 1999/11/10 05:42:06 guy Exp $
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

static int proto_vlan = -1;
static int hf_vlan_etype = -1;
static int hf_vlan_priority = -1;
static int hf_vlan_id = -1;
static int hf_vlan_cfi = -1;

void
dissect_vlan(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  proto_tree *ti, *vlan_tree = NULL;
  guint16 tci,encap_proto;

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
    ti = proto_tree_add_item(tree, proto_vlan, offset, 4);
    vlan_tree = proto_item_add_subtree(ti, ETT_VLAN);

    proto_tree_add_item(vlan_tree, hf_vlan_priority, offset, 2, tci);
    proto_tree_add_item(vlan_tree, hf_vlan_cfi, offset, 2, tci);
    proto_tree_add_item(vlan_tree, hf_vlan_id, offset, 2, tci);
  }

  ethertype(encap_proto, offset+4, pd, fd, tree, vlan_tree, hf_vlan_etype);
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

  proto_vlan = proto_register_protocol("802.1q Virtual LAN", "vlan");
  proto_register_field_array(proto_vlan, hf, array_length(hf));
}
