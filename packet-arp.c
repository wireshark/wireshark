/* packet-arp.c
 * Routines for ARP packet disassembly
 *
 * $Id: packet-arp.c,v 1.6 1998/10/13 05:20:53 guy Exp $
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
  e_ether_arp  ea;
  GtkWidget   *arp_tree, *ti;
  gchar       *op_str;
  static value_string op_vals[] = { {ARPOP_REQUEST,  "ARP request" },
                                    {ARPOP_REPLY,    "ARP reply"   },
                                    {ARPOP_RREQUEST, "RARP request"},
                                    {ARPOP_RREPLY,   "RARP reply"  } };
#define N_OP_VALS	(sizeof op_vals / sizeof op_vals[0])

  /* To do: Check for {cap len,pkt len} < struct len */
  ea.ar_hrd = pntohs(&pd[offset]);
  ea.ar_pro = pntohs(&pd[offset + 2]);
  ea.ar_hln = (guint8) pd[offset + 4];
  ea.ar_pln = (guint8) pd[offset + 5];
  ea.ar_op  = pntohs(&pd[offset + 6]);
  memcpy(&ea.arp_sha, &pd[offset +  8], 6);
  memcpy(&ea.arp_spa, &pd[offset + 14], 4);
  memcpy(&ea.arp_tha, &pd[offset + 18], 6);
  memcpy(&ea.arp_tpa, &pd[offset + 24], 4);
  
  if (fd->win_info[COL_NUM]) { strcpy(fd->win_info[COL_PROTOCOL], "ARP"); }
  
  if (tree) {
    if ((op_str = match_strval(ea.ar_op, op_vals, N_OP_VALS)))
      ti = add_item_to_tree(GTK_WIDGET(tree), offset, 28, op_str);
    else
      ti = add_item_to_tree(GTK_WIDGET(tree), offset, 28,
        "Unknown ARP (opcode 0x%04x)", ea.ar_op);
    arp_tree = gtk_tree_new();
    add_subtree(ti, arp_tree, ETT_ARP);
    add_item_to_tree(arp_tree, offset,      2,
      "Hardware type: 0x%04x", ea.ar_hrd);
    add_item_to_tree(arp_tree, offset +  2, 2,
      "Protocol type: 0x%04x", ea.ar_pro);
    add_item_to_tree(arp_tree, offset +  4, 1,
      "Hardware size: 0x%02x", ea.ar_hln);
    add_item_to_tree(arp_tree, offset +  5, 1,
      "Protocol size: 0x%02x", ea.ar_pln);
    add_item_to_tree(arp_tree, offset +  6, 2,
      "Opcode: 0x%04x (%s)", ea.ar_op, op_str ? op_str : "Unknown");
    add_item_to_tree(arp_tree, offset +  8, 6,
      "Sender ether: %s", ether_to_str((guint8 *) ea.arp_sha));
    add_item_to_tree(arp_tree, offset + 14, 4,
      "Sender IP: %s", ip_to_str((guint8 *) ea.arp_spa));
    add_item_to_tree(arp_tree, offset + 18, 6,
      "Target ether: %s", ether_to_str((guint8 *) ea.arp_tha));
    add_item_to_tree(arp_tree, offset + 24, 4,
      "Target IP: %s", ip_to_str((guint8 *) ea.arp_tpa));
  }

  if (ea.ar_pro != ETHERTYPE_IP && fd->win_info[COL_NUM]) {
    sprintf(fd->win_info[COL_INFO], "h/w %d (%d) prot %d (%d) op 0x%04x",
      ea.ar_hrd, ea.ar_hln, ea.ar_pro, ea.ar_pln, ea.ar_op);
    return;
  }
  switch (ea.ar_op) {
    case ARPOP_REQUEST:
      if (fd->win_info[COL_NUM]) {
        sprintf(fd->win_info[COL_INFO], "Who has %s?  Tell %s",
          ip_to_str((guint8 *) ea.arp_tpa), ip_to_str((guint8 *) ea.arp_spa));
      }
      break;
    case ARPOP_REPLY:
      if (fd->win_info[COL_NUM]) {
        sprintf(fd->win_info[COL_INFO], "%s is at %s",
          ip_to_str((guint8 *) ea.arp_spa),
          ether_to_str((guint8 *) ea.arp_sha));
      }
      break;
    case ARPOP_RREQUEST:
      if (fd->win_info[COL_NUM]) {
        strcpy(fd->win_info[COL_PROTOCOL], "RARP");
        sprintf(fd->win_info[COL_INFO], "Who is %s?  Tell %s",
          ether_to_str((guint8 *) ea.arp_tha), 
          ether_to_str((guint8 *) ea.arp_sha));
      }
      break;
    case ARPOP_RREPLY:
      if (fd->win_info[COL_NUM]) {
        strcpy(fd->win_info[COL_PROTOCOL], "RARP");
        sprintf(fd->win_info[COL_INFO], "%s is at %s",
          ether_to_str((guint8 *) ea.arp_sha),
          ip_to_str((guint8 *) ea.arp_spa));
      }
      break;
  }
}
