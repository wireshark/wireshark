/* packet-ppp.c
 * Routines for ppp packet disassembly
 *
 * $Id: packet-ppp.c,v 1.7 1998/11/12 00:06:36 gram Exp $
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

#include "ethereal.h"
#include "packet.h"

/* Protocol types, from Linux "ppp_defs.h" and

	http://www.isi.edu/in-notes/iana/assignments/ppp-numbers

 */
#define PPP_IP		0x21	/* Internet Protocol */
#define PPP_AT		0x29	/* AppleTalk Protocol */
#define PPP_IPX		0x2b	/* IPX protocol */
#define	PPP_VJC_COMP	0x2d	/* VJ compressed TCP */
#define	PPP_VJC_UNCOMP	0x2f	/* VJ uncompressed TCP */
#define	PPP_VINES	0x35	/* Banyan Vines */
#define PPP_IPV6	0x57	/* Internet Protocol Version 6 */
#define PPP_COMP	0xfd	/* compressed packet */
#define PPP_IPCP	0x8021	/* IP Control Protocol */
#define PPP_ATCP	0x8029	/* AppleTalk Control Protocol */
#define PPP_IPXCP	0x802b	/* IPX Control Protocol */
#define PPP_CCP		0x80fd	/* Compression Control Protocol */
#define PPP_LCP		0xc021	/* Link Control Protocol */
#define PPP_PAP		0xc023	/* Password Authentication Protocol */
#define PPP_LQR		0xc025	/* Link Quality Report protocol */
#define PPP_CHAP	0xc223	/* Cryptographic Handshake Auth. Protocol */
#define PPP_CBCP	0xc029	/* Callback Control Protocol */

void
dissect_ppp( const u_char *pd, frame_data *fd, GtkTree *tree ) {
  e_ppphdr   ph;
  GtkWidget *ti, *fh_tree;
  static const value_string ppp_vals[] = {
    {PPP_IP,     "IP"             },
    {PPP_AT,     "Appletalk"      },
    {PPP_IPX,    "Netware IPX/SPX"},
    {PPP_VINES,  "Vines"          },
    {PPP_IPV6,   "IPv6"           },
    {0,           NULL            } };

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
      "Point-to-Point Protocol" );
    fh_tree = gtk_tree_new();
    add_subtree(ti, fh_tree, ETT_PPP);
    add_item_to_tree(fh_tree, 0, 1, "Address: %02x", ph.ppp_addr);
    add_item_to_tree(fh_tree, 1, 1, "Control: %02x", ph.ppp_ctl);
    add_item_to_tree(fh_tree, 2, 2, "Protocol: %s (0x%04x)",
      val_to_str(ph.ppp_prot, ppp_vals, "Unknown"), ph.ppp_prot);
  }

  switch (ph.ppp_prot) {
    case PPP_IP:
      dissect_ip(pd, 4, fd, tree);
      break;
    case PPP_AT:
      dissect_ddp(pd, 4, fd, tree);
      break;
    case PPP_IPX:
      dissect_ipx(pd, 4, fd, tree);
      break;
    case PPP_VINES:
      dissect_vines(pd, 4, fd, tree);
      break;
    case PPP_IPV6:
      dissect_ipv6(pd, 4, fd, tree);
      break;
    default:
      dissect_data(pd, 4, fd, tree);
      if (fd->win_info[COL_NUM]) { sprintf(fd->win_info[COL_PROTOCOL], "0x%04x", ph.ppp_prot); }
      break;
  }
}
