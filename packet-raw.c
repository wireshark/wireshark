/* packet-raw.c
 * Routines for raw packet disassembly
 *
 * $Id: packet-raw.c,v 1.4 1998/10/10 03:32:15 gerald Exp $
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
dissect_raw( const u_char *pd, frame_data *fd, GtkTree *tree ) {
  GtkWidget *ti, *fh_tree;

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  if(fd->win_info[COL_NUM]) {
    strcpy(fd->win_info[COL_SOURCE], "N/A" );
    strcpy(fd->win_info[COL_DESTINATION], "N/A" );
    strcpy(fd->win_info[COL_INFO], "Raw packet data" );
  }

  /* populate a tree in the second pane with the status of the link
     layer (ie none) */
  if(tree) {
    ti = add_item_to_tree( GTK_WIDGET(tree), 0, 0,
			   "Raw packet data (%d on link, %d captured)",
			   fd->pkt_len, fd->cap_len );
    fh_tree = gtk_tree_new();
    add_subtree(ti, fh_tree, ETT_RAW);
    add_item_to_tree(fh_tree, 0, 0, "No link information available");
  }

  /* So far, the only time we get raw connection types are with Linux and
   * Irix PPP connections.  We can't tell what type of data is coming down
   * the line, so our safest bet is IP. - GCC
   */
   
  /* Currently, the Linux 2.1.xxx PPP driver passes back some of the header
   * sometimes.  This check should be removed when 2.2 is out.
   */
  if (pd[0] == 0xff && pd[1] == 0x03)
    dissect_ip(pd, 4, fd, tree);
  else
    dissect_ip(pd, 0, fd, tree);
}
    
