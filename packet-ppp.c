/* packet-ppp.c
 * Routines for ppp packet disassembly
 *
 * $Id: packet-ppp.c,v 1.2 1998/09/16 03:22:09 gerald Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 *
 * This file created and by Mike Hall <mlh@io.com>
 * Copyright 1998
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
#include <pcap.h>

#include "packet.h"
#include "ethereal.h"

void
dissect_ppp( const u_char *pd, frame_data *fd, GtkTree *tree ) {
  e_ppphdr   ph;
  GtkWidget *ti, *fh_tree;

  guchar flag, addr, control;
  guint  protocol;

  ph.ppp_flag = pd[0];
  ph.ppp_addr = pd[1];
  ph.ppp_ctl  = pd[2];
  ph.ppp_prot = pntohs(&pd[3]);

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  if(fd->win_info[0]) {
    strcpy(fd->win_info[1], "N/A" );
    strcpy(fd->win_info[2], "N/A" );
    strcpy(fd->win_info[4], "PPP" );
  }

  /* populate a tree in the second pane with the status of the link
     layer (ie none) */
  if(tree) {
    ti = add_item_to_tree( GTK_WIDGET(tree), 0, 5,
      "Point-to-Point Protocol (%d on link, %d captured)", fd->pkt_len,
      fd->cap_len );
    fh_tree = gtk_tree_new();
    add_subtree(ti, fh_tree, ETT_PPP);
    add_item_to_tree(fh_tree, 0, 1, "Flag: %02x", ph.ppp_flag);
    add_item_to_tree(fh_tree, 1, 1, "Address: %02x", ph.ppp_addr);
    add_item_to_tree(fh_tree, 2, 1, "Control: %02x", ph.ppp_ctl);
    add_item_to_tree(fh_tree, 3, 2, "Protocol: %04x", ph.ppp_prot);
  }

  switch (ph.ppp_prot) {
    case 0x0021:
      dissect_ip(pd, 5, fd, tree);
      break;
    default:
      dissect_data(pd, 5, fd, tree);
      break;
  }
}
