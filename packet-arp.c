/* packet-arp.c
 * Routines for ARP packet disassembly
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
#include "etypes.h"

void
dissect_arp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
  e_ether_arp *ea;
  guint16      ar_hrd, ar_pro, ar_op;
  gchar       *req_type[] = { "ARP request", "ARP reply",
               "RARP request", "RARP reply" };
  GtkWidget   *arp_tree, *ti;

  /* To do: Check for {cap len,pkt len} < struct len */
  ea = (e_ether_arp *) &pd[offset];
  ar_hrd = ntohs(ea->ar_hrd);
  ar_pro = ntohs(ea->ar_pro);
  /* To do: Check for bounds on ar_op */
  ar_op  = ntohs(ea->ar_op);
  
  if (fd->win_info[0]) { strcpy(fd->win_info[3], "ARP"); }
  
  if (tree) {
    ti = add_item_to_tree(GTK_WIDGET(tree), offset, 28, req_type[ar_op - 1]);
    arp_tree = gtk_tree_new();
    add_subtree(ti, arp_tree, ETT_ARP);
    add_item_to_tree(arp_tree, offset,      2,
      "Hardware type: 0x%04x", ar_hrd);
    add_item_to_tree(arp_tree, offset +  2, 2,
      "Protocol type: 0x%04x", ar_pro);
    add_item_to_tree(arp_tree, offset +  4, 1,
      "Hardware size: 0x%02x", ea->ar_hln);
    add_item_to_tree(arp_tree, offset +  5, 1,
      "Protocol size: 0x%02x", ea->ar_pln);
    add_item_to_tree(arp_tree, offset +  6, 2,
      "Opcode: 0x%04x", ar_op);
    add_item_to_tree(arp_tree, offset +  8, 6,
      "Sender ether: %s", ether_to_str((guint8 *) ea->arp_sha));
    add_item_to_tree(arp_tree, offset + 14, 4,
      "Sender IP: %s", ip_to_str((guint8 *) ea->arp_spa));
    add_item_to_tree(arp_tree, offset + 18, 6,
      "Target ether: %s", ether_to_str((guint8 *) ea->arp_tha));
    add_item_to_tree(arp_tree, offset + 24, 4,
      "Target IP: %s", ip_to_str((guint8 *) ea->arp_tpa));
  }

  if (ar_pro != ETHERTYPE_IP && fd->win_info[0]) {
    sprintf(fd->win_info[4], "h/w %d (%d) prot %d (%d) op 0x%04x",
      ar_hrd, ea->ar_hln, ar_pro, ea->ar_pln, ar_op);
    return;
  }
  switch (ar_op) {
    case ARPOP_REQUEST:
      if (fd->win_info[0]) {
        sprintf(fd->win_info[4], "Who has %s?  Tell %s",
          ip_to_str((guint8 *) ea->arp_tpa), ip_to_str((guint8 *) ea->arp_spa));
      }
      break;
    case ARPOP_REPLY:
      if (fd->win_info[0]) {
        sprintf(fd->win_info[4], "%s is at %s",
          ip_to_str((guint8 *) ea->arp_spa),
          ether_to_str((guint8 *) ea->arp_sha));
      }
      break;
    case ARPOP_RREQUEST:
      if (fd->win_info[0]) {
        strcpy(fd->win_info[3], "RARP");
        sprintf(fd->win_info[4], "Who is %s?  Tell %s",
          ether_to_str((guint8 *) ea->arp_tha), 
          ether_to_str((guint8 *) ea->arp_sha));
      }
      break;
    case ARPOP_RREPLY:
      if (fd->win_info[0]) {
        strcpy(fd->win_info[3], "RARP");
        sprintf(fd->win_info[4], "%s is at %s",
          ether_to_str((guint8 *) ea->arp_sha),
          ip_to_str((guint8 *) ea->arp_spa));
      }
      break;
  }
}
