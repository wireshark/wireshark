/* ethertype.c
 * Routines for calling the right protocol for the ethertype.
 * This is called by both packet-eth.c (Ethernet II) and packet-llc.c (SNAP)
 *
 * $Id: ethertype.c,v 1.23 2000/01/13 17:59:14 guy Exp $
 *
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
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

#include <glib.h>
#include "packet.h"
#include "etypes.h"

const value_string etype_vals[] = {
    {ETHERTYPE_IP,     "IP"             },
    {ETHERTYPE_IPv6,   "IPv6"           },
    {ETHERTYPE_X25L3,  "X.25 Layer 3"   },
    {ETHERTYPE_ARP,    "ARP"            },
    {ETHERTYPE_REVARP, "RARP"           },
    {ETHERTYPE_ATALK,  "Appletalk"      },
    {ETHERTYPE_AARP,   "AARP"           },
    {ETHERTYPE_IPX,    "Netware IPX/SPX"},
    {ETHERTYPE_VINES,  "Vines"          },
    {ETHERTYPE_TRAIN,   "Netmon Train"  },
    {ETHERTYPE_LOOP,   "Loopback"       }, /* Ethernet Loopback */
    {ETHERTYPE_PPPOED, "PPPoE Discovery"}, 
    {ETHERTYPE_PPPOES, "PPPoE Session"  }, 
    {ETHERTYPE_VLAN,   "802.1Q Virtual LAN" },
    {0,                 NULL            } };

void
capture_ethertype(guint16 etype, int offset,
		const u_char *pd, guint32 cap_len, packet_counts *ld)
{
  switch (etype) {
    case ETHERTYPE_IP:
      capture_ip(pd, offset, cap_len, ld);
      break;
    case ETHERTYPE_IPX:
      capture_ipx(pd, offset, cap_len, ld);
      break;
    case ETHERTYPE_VLAN:
      capture_vlan(pd, offset, cap_len, ld);
      break;
    default:
      ld->other++;
      break;
  }
}

void
ethertype(guint16 etype, int offset,
		const u_char *pd, frame_data *fd, proto_tree *tree, proto_tree
		*fh_tree, int item_id)
{
  if (tree) {
	proto_tree_add_item(fh_tree, item_id, offset - 2, 2, etype);
  }
  switch (etype) {
    case ETHERTYPE_IP:
      dissect_ip(pd, offset, fd, tree);
      break;
    case ETHERTYPE_IPv6:
      dissect_ipv6(pd, offset, fd, tree);
      break;
    case ETHERTYPE_X25L3:
      dissect_x25(pd, offset, fd, tree);
      break;
    case ETHERTYPE_ARP:
      dissect_arp(pd, offset, fd, tree);
      break;
    case ETHERTYPE_REVARP:
      dissect_arp(pd, offset, fd, tree);
      break;
    case ETHERTYPE_ATALK:
      dissect_ddp(pd, offset, fd, tree);
      break;
    case ETHERTYPE_AARP:
      dissect_aarp(pd, offset, fd, tree);
      break;
    case ETHERTYPE_IPX:
      dissect_ipx(pd, offset, fd, tree);
      break;
    case ETHERTYPE_VINES:
      dissect_vines(pd, offset, fd, tree);
      break;
    case ETHERTYPE_LOOP:
      dissect_data(pd, offset, fd, tree);
      if (check_col(fd, COL_PROTOCOL)) { col_add_fstr(fd, COL_PROTOCOL, "LOOP"); }
      break;
    case ETHERTYPE_PPPOED:
      dissect_pppoed(pd, offset, fd, tree);
      break;
    case ETHERTYPE_PPPOES:
      dissect_pppoes(pd, offset, fd, tree);
      break;
    case ETHERTYPE_VLAN:
      dissect_vlan(pd, offset, fd, tree);
      break;
    case ETHERTYPE_SNMP:
      dissect_snmp(pd, offset, fd, tree);
      break;
    default:
      dissect_data(pd, offset, fd, tree);
      if (check_col(fd, COL_PROTOCOL)) { col_add_fstr(fd, COL_PROTOCOL, "0x%04x", etype); }
      break;
  }
}



