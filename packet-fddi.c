/* packet-fddi.c
 * Routines for FDDI packet disassembly
 *
 * Laurent Deniel <deniel@worldnet.fr>
 *
 * $Id: packet-fddi.c,v 1.2 1998/10/10 18:23:43 gerald Exp $
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

#include <pcap.h>

#include "ethereal.h"
#include "packet.h"
#include "resolv.h"

/* FDDI Frame Control values */

#define FDDI_FC_VOID		0x00		/* Void frame */
#define FDDI_FC_NRT		0x80		/* Nonrestricted token */
#define FDDI_FC_RT		0xc0		/* Restricted token */
#define FDDI_FC_MAC		0xc0		/* MAC frame */
#define FDDI_FC_SMT		0x40		/* SMT frame */
#define FDDI_FC_SMT_INFO	0x41		/* SMT Info */
#define FDDI_FC_SMT_NSA		0x4F		/* SMT Next station adrs */
#define FDDI_FC_SMT_MIN		FDDI_FC_SMT_INFO
#define FDDI_FC_SMT_MAX		FDDI_FC_SMT_NSA
#define FDDI_FC_MAC_MIN		0xc1
#define FDDI_FC_MAC_BEACON	0xc2		/* MAC Beacon frame */
#define FDDI_FC_MAC_CLAIM	0xc3		/* MAC Claim frame */
#define FDDI_FC_MAC_MAX		0xcf
#define FDDI_FC_LLC_ASYNC	0x50		/* Async. LLC frame */
#define FDDI_FC_LLC_ASYNC_MIN	FDDI_FC_LLC_ASYNC
#define FDDI_FC_LLC_ASYNC_DEF	0x54
#define FDDI_FC_LLC_ASYNC_MAX	0x5f
#define FDDI_FC_LLC_SYNC	0xd0		/* Sync. LLC frame */
#define FDDI_FC_LLC_SYNC_MIN	FDDI_FC_LLC_SYNC
#define FDDI_FC_LLC_SYNC_MAX	0xd7
#define FDDI_FC_IMP_ASYNC	0x60		/* Implementor Async. */
#define FDDI_FC_IMP_ASYNC_MIN	FDDI_FC_IMP_ASYNC
#define FDDI_FC_IMP_ASYNC_MAX	0x6f
#define FDDI_FC_IMP_SYNC	0xe0		/* Implementor Synch. */

#define FDDI_HEADER_SIZE	13

/* field positions */

#define FDDI_P_FC		0
#define FDDI_P_DHOST		1
#define FDDI_P_SHOST		7

void dissect_fddi(const u_char *pd, frame_data *fd, GtkTree *tree) 
{

  int        offset = 0, fc;
  GtkWidget *fh_tree, *ti;

  if (fd->cap_len < FDDI_HEADER_SIZE) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  fc = (int) pd[FDDI_P_FC];

  if (fd->win_info[0]) {
    strcpy(fd->win_info[2], get_ether_name((u_char *)&pd[FDDI_P_DHOST]));
    strcpy(fd->win_info[1], get_ether_name((u_char *)&pd[FDDI_P_SHOST]));
    strcpy(fd->win_info[4], "FDDI");
  }

  if (tree) {
    ti = add_item_to_tree(GTK_WIDGET(tree), 0, offset,
			  "FDDI %s (%d on wire, %d captured)",
			  (fc >= FDDI_FC_LLC_ASYNC_MIN && fc <= FDDI_FC_LLC_ASYNC_MAX) ?
			  "Async LLC" : "unsupported FC",
			  fd->pkt_len, fd->cap_len);

      fh_tree = gtk_tree_new();
      add_subtree(ti, fh_tree, ETT_FDDI);
      add_item_to_tree(fh_tree, FDDI_P_FC, 1, "Frame Control: 0x%02x", fc);
      add_item_to_tree(fh_tree, FDDI_P_DHOST, 6, "Destination: %s (%s)",
		       ether_to_str((guint8 *) &pd[FDDI_P_DHOST]),
		       get_ether_name((u_char *) &pd[FDDI_P_DHOST]));
      add_item_to_tree(fh_tree, FDDI_P_SHOST, 6, "Source: %s (%s)",
		       ether_to_str((guint8 *) &pd[FDDI_P_SHOST]),
		       get_ether_name((u_char *)&pd[FDDI_P_SHOST]));
    }

  offset = FDDI_HEADER_SIZE;

  switch (fc) {

    /* From now, only 802.2 SNAP (Async. LCC frame) is supported */

    case FDDI_FC_LLC_ASYNC + 0  :
    case FDDI_FC_LLC_ASYNC + 1  :
    case FDDI_FC_LLC_ASYNC + 2  :
    case FDDI_FC_LLC_ASYNC + 3  :
    case FDDI_FC_LLC_ASYNC + 4  :
    case FDDI_FC_LLC_ASYNC + 5  :
    case FDDI_FC_LLC_ASYNC + 6  :
    case FDDI_FC_LLC_ASYNC + 7  :
    case FDDI_FC_LLC_ASYNC + 8  :
    case FDDI_FC_LLC_ASYNC + 9  :
    case FDDI_FC_LLC_ASYNC + 10 :
    case FDDI_FC_LLC_ASYNC + 11 :
    case FDDI_FC_LLC_ASYNC + 12 :
    case FDDI_FC_LLC_ASYNC + 13 :
    case FDDI_FC_LLC_ASYNC + 14 :
    case FDDI_FC_LLC_ASYNC + 15 :
      dissect_llc(pd, offset, fd, tree);
      return;
      
    default :
      dissect_data(pd, offset, fd, tree);
      return;

  } /* fc */

} /* dissect_fddi */

