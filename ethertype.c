/* ethertype.c
 * Routines for calling the right protocol for the ethertype.
 * This is called by both packet-eth.c (Ethernet II) and packet-llc.c (SNAP)
 *
 * $Id: ethertype.c,v 1.5 1998/10/10 03:32:06 gerald Exp $
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

#include <gtk/gtk.h>

#include <stdio.h>

#include <pcap.h>

#include "ethereal.h"
#include "packet.h"
#include "etypes.h"

void
ethertype(guint16 etype, int offset,
		const u_char *pd, frame_data *fd, GtkTree *tree, GtkWidget
		*fh_tree)
{
  gchar      etype_str[][10] = {"IP", "ARP", "RARP", "AppleTalk", "AARP"};

  switch (etype) {
    case ETHERTYPE_IP:
      if (tree) {
        add_item_to_tree(fh_tree, offset - 2, 2, "Type: IP (0x%04x)",
          etype);
      }
      dissect_ip(pd, offset, fd, tree);
      break;
    case ETHERTYPE_IPv6:
      if (tree) {
        add_item_to_tree(fh_tree, offset - 2, 2, "Type: IPv6 (0x%04x)",
          etype);
      }
      dissect_ipv6(pd, offset, fd, tree);
      break;
    case ETHERTYPE_ARP:
      if (tree) {
        add_item_to_tree(fh_tree, offset - 2, 2,
          "Type: ARP (0x%04x)", etype);
      }
      dissect_arp(pd, offset, fd, tree);
      break;
    case ETHERTYPE_REVARP:
      if (tree) {
        add_item_to_tree(fh_tree, offset - 2, 2,
          "Type: RARP (0x%04x)", etype);
      }
      dissect_arp(pd, offset, fd, tree);
      break;
    case ETHERTYPE_ATALK:
      if (tree) {
        add_item_to_tree(fh_tree, offset - 2, 2,
          "Type: AppleTalk (0x%04x)", etype);
      }
      if (fd->win_info[COL_NUM]) { strcpy(fd->win_info[COL_PROTOCOL], etype_str[3]); }
      break;
    case ETHERTYPE_AARP:
      if (tree) {
        add_item_to_tree(fh_tree, offset - 2, 2,
          "Type: AARP (0x%04x)", etype);
      }
      if (fd->win_info[COL_NUM]) { strcpy(fd->win_info[COL_PROTOCOL], etype_str[4]); }
      break;
    case ETHERTYPE_IPX:
      if (tree) {
        add_item_to_tree(fh_tree, offset - 2, 2,
          "Type: Netware IPX/SPX (0x%04x)", etype);
      }
      dissect_ipx(pd, offset, fd, tree);
      break;
    case ETHERTYPE_VINES:
      if (tree) {
        add_item_to_tree(fh_tree, offset - 2, 2,
          "Type Vines (0x%04x)", etype);
      }
      dissect_vines(pd, offset, fd, tree);
      break;
    default:
      if (tree) {
        add_item_to_tree(fh_tree, offset - 2, 2,
          "Type: Unknown (0x%04x)", etype);
		  dissect_data(pd, offset, fd, tree);
	  }
      if (fd->win_info[COL_NUM]) { sprintf(fd->win_info[COL_PROTOCOL], "0x%04x", etype); }
      break;
  }
 }
