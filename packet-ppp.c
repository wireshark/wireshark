/* packet-ppp.c
 * Routines for ppp packet disassembly
 *
 * $Id: packet-ppp.c,v 1.5 1998/10/10 03:32:14 gerald Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <gtk/gtk.h>
#include <stdio.h>
#include <pcap.h>

#include "ethereal.h"
#include "packet.h"

void
dissect_ppp( const u_char *pd, frame_data *fd, GtkTree *tree ) {
  e_ppphdr   ph;
  GtkWidget *ti, *fh_tree;

  ph.ppp_addr = pd[0];
  ph.ppp_ctl  = pd[1];
  ph.ppp_prot = pntohs(&pd[2]);

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  if(fd->win_info[COL_NUM]) {
    strcpy(fd->win_info[COL_SOURCE], "N/A" );
    strcpy(fd->win_info[COL_DESTINATION], "N/A" );
    strcpy(fd->win_info[COL_PROTOCOL], "N/A" );
    strcpy(fd->win_info[COL_INFO], "PPP" );
  }

  /* populate a tree in the second pane with the status of the link
     layer (ie none) */
  if(tree) {
    ti = add_item_to_tree( GTK_WIDGET(tree), 0, 4,
      "Point-to-Point Protocol (%d on link, %d captured)", fd->pkt_len,
      fd->cap_len );
    fh_tree = gtk_tree_new();
    add_subtree(ti, fh_tree, ETT_PPP);
    add_item_to_tree(fh_tree, 0, 1, "Address: %02x", ph.ppp_addr);
    add_item_to_tree(fh_tree, 1, 1, "Control: %02x", ph.ppp_ctl);
    add_item_to_tree(fh_tree, 2, 2, "Protocol: %04x", ph.ppp_prot);
  }

  switch (ph.ppp_prot) {
    case 0x0021:
      dissect_ip(pd, 4, fd, tree);
      break;
    default:
      dissect_data(pd, 4, fd, tree);
      break;
  }
}
