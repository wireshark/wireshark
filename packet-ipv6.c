/* packet-ipv6.c
 * Routines for IPv6 packet disassembly 
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
#include <pcap.h>

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "packet-ipv6.h"
#include "etypes.h"

void
dissect_ipv6(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
  GtkWidget *ipv6_tree, *ti;

  e_ipv6_header ipv6;

  memcpy(&ipv6, (void *) &pd[offset], 8); 

  if (fd->win_info[0]) {
      switch(ipv6.next_header){
	  /*
	  case IP_PROTO_ICMP:
          case IP_PROTO_IGMP:
          case IP_PROTO_TCP:
          case IP_PROTO_UDP:
          case IP_PROTO_OSPF:
	  */
          /* Names are set in the associated dissect_* routines */
	  /*    break; */
	 default:
             strcpy(fd->win_info[3], "IPv6");
             sprintf(fd->win_info[4], "IPv6 support is still under development (%d)", ipv6.next_header);
      }
  }
  if (tree) {
    /* !!! specify length */
    ti = add_item_to_tree(GTK_WIDGET(tree), offset, 40,
      "Internet Protocol Version 6");
    ipv6_tree = gtk_tree_new();
    add_subtree(ti, ipv6_tree, ETT_IPv6);

    /* !!! warning: version also contains 4 Bit priority */
    add_item_to_tree(ipv6_tree, offset,      1, "Version: %d Priority: %d", ipv6.version >> 4 , ipv6.version & 15);
    add_item_to_tree(ipv6_tree, offset + 6,  1, "Next Header: %d", ipv6.next_header);
    add_item_to_tree(ipv6_tree, offset + 4,  2, "Payload Length: %d", ntohs(ipv6.payload_length));
  }

  /* start of the new header (could be a extension header) */
  offset += 40;
  switch (ipv6.next_header) {
      case IP_PROTO_ICMP:
          dissect_icmp(pd, offset, fd, tree);
          break;
      case IP_PROTO_IGMP:
          dissect_igmp(pd, offset, fd, tree);
          break;
      case IP_PROTO_TCP:
          dissect_tcp(pd, offset, fd, tree);
          break;
      case IP_PROTO_UDP:
          dissect_udp(pd, offset, fd, tree);
          break;
      case IP_PROTO_OSPF:
          dissect_ospf(pd, offset, fd, tree);
          break;
      default:
          dissect_data(pd, offset, fd, tree);
  }
}

