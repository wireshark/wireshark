/* packet-udp.c
 * Routines for UDP packet disassembly
 *
 * $Id: packet-udp.c,v 1.7 1998/11/17 04:29:07 gerald Exp $
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

#include <gtk/gtk.h>

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "resolv.h"

void
dissect_udp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
  e_udphdr  uh;
  guint16    uh_sport, uh_dport, uh_ulen, uh_sum;
  GtkWidget *udp_tree, *ti;

  /* To do: Check for {cap len,pkt len} < struct len */
  /* Avoids alignment problems on many architectures. */
  memcpy(&uh, &pd[offset], sizeof(e_udphdr));
  uh_sport = ntohs(uh.uh_sport);
  uh_dport = ntohs(uh.uh_dport);
  uh_ulen  = ntohs(uh.uh_ulen);
  uh_sum   = ntohs(uh.uh_sum);
  
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "UDP");
  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "Source port: %s  Destination port: %s",
	    get_udp_port(uh_sport), get_udp_port(uh_dport));
  
  if (tree) {
    ti = add_item_to_tree(GTK_WIDGET(tree), offset, 8,
      "User Datagram Protocol");
    udp_tree = gtk_tree_new();
    add_subtree(ti, udp_tree, ETT_UDP);
    add_item_to_tree(udp_tree, offset,     2, "Source port: %s", get_udp_port(uh_sport));
    add_item_to_tree(udp_tree, offset + 2, 2, "Destination port: %s", get_udp_port(uh_dport));
    add_item_to_tree(udp_tree, offset + 4, 2, "Length: %d", uh_ulen);
    add_item_to_tree(udp_tree, offset + 6, 2, "Checksum: 0x%04x", uh_sum);
  }

  /* Skip over header */
  offset += 8;

  /* To do: make sure we aren't screwing ourselves with the MIN call. */
  switch (MIN(uh_sport, uh_dport)) {
    case UDP_PORT_BOOTPS:
      dissect_bootp(pd, offset, fd, tree);
      break;
    case UDP_PORT_DNS:
      dissect_dns(pd, offset, fd, tree);
      break;
    case UDP_PORT_RIP:
      /* we should check the source port too (RIP: UDP src and dst port 520) */
      dissect_rip(pd, offset, fd, tree);
      break;
	case UDP_PORT_NBNS:
	  dissect_nbns(pd, offset, fd, tree);
	  break;
    case UDP_PORT_IPX: /* RFC 1234 */
      dissect_ipx(pd, offset, fd, tree);
      break;
    default:
      dissect_data(pd, offset, fd, tree);
  }
}
