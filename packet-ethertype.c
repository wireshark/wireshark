/* ethertype.c
 * Routines for calling the right protocol for the ethertype.
 *
 * $Id: packet-ethertype.c,v 1.1 2000/04/13 18:18:45 gram Exp $
 *
 * Gilbert Ramirez <gram@xiexie.org>
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

static dissector_table_t ethertype_dissector_table;

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
    {ETHERTYPE_MPLS,   "MPLS label switched packet" },
    {ETHERTYPE_MPLS_MULTI,   "MPLS multicast label switched packet" },
    {0,                 NULL            } };

void
capture_ethertype(guint16 etype, int offset,
		const u_char *pd, packet_counts *ld)
{
  switch (etype) {
    case ETHERTYPE_IP:
      capture_ip(pd, offset, ld);
      break;
    case ETHERTYPE_IPX:
      capture_ipx(pd, offset, ld);
      break;
    case ETHERTYPE_VLAN:
      capture_vlan(pd, offset, ld);
      break;
    case ETHERTYPE_VINES:
      capture_vines(pd, offset, ld);
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
	dissector_t	sub_dissector;
	char		*description;
	
	/* Add to proto_tree */
	if (tree) {
		proto_tree_add_item(fh_tree, item_id, offset - 2, 2, etype);
	}

	/* Look for sub-dissector */
	sub_dissector = dissector_lookup( ethertype_dissector_table, etype );

	if (sub_dissector) {
		/* Call sub-dissector */
		sub_dissector(pd, offset, fd, tree);
	}
	else {
		/* Label rest of packet as "Data" */
		dissect_data(pd, offset, fd, tree);

		/* Label protocol */
		switch(etype) {
			case ETHERTYPE_LOOP:
				if (check_col(fd, COL_PROTOCOL)) {
					col_add_fstr(fd, COL_PROTOCOL, "LOOP");
				}
				break;
			    default:
				if (check_col(fd, COL_PROTOCOL)) {
					col_add_fstr(fd, COL_PROTOCOL, "0x%04x", etype);
				}
				break;
		}
		if (check_col(fd, COL_INFO)) {
			description = match_strval(etype, etype_vals);
			if (description) {
				col_add_fstr(fd, COL_INFO, "%s", description);
			}
		}
	}
}


void
proto_register_ethertype(void)
{
	/* subdissector code */
	ethertype_dissector_table = register_dissector_table("ethertype");
}
