/* packet-null.c
 * Routines for null packet disassembly
 *
 * $Id: packet-null.c,v 1.7 1999/03/23 03:14:41 gram Exp $
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
#include <sys/types.h>
#endif

#include <glib.h>
#include <sys/socket.h>

#include "packet.h"

/* Null/loopback structs and definitions */

typedef struct _e_nullhdr {
  guint8  null_next;
  guint8  null_len;
  guint16 null_family;
} e_nullhdr;

void
capture_null( const u_char *pd, guint32 cap_len, packet_counts *ld ) {
  e_nullhdr  nh;

  memcpy((char *)&nh.null_family, (char *)&pd[2], sizeof(nh.null_family));

  /* 
  From what I've read in various sources, this is supposed to be an
  address family, e.g. AF_INET.  However, a FreeBSD ISDN PPP dump that
  Andreas Klemm sent to ethereal-dev has a packet type of DLT_NULL, and
  the family bits look like PPP's protocol field.  A dump of the loopback
  interface on my Linux box also has a link type of DLT_NULL (as it should
  be), but the family bits look like ethernet's protocol type.  To
  further  confuse matters, nobody seems to be paying attention to byte
  order.
  - gcc
  */  
   
  switch (nh.null_family) {
    case 0x0008:
    case 0x0800:
    case 0x0021:
    case 0x2100:
      capture_ip(pd, 4, cap_len, ld);
      break;
    default:
      ld->other++;
      break;
  }
}

void
dissect_null( const u_char *pd, frame_data *fd, proto_tree *tree ) {
  e_nullhdr  nh;
  proto_tree *fh_tree;
  proto_item *ti;

  nh.null_next   = pd[0];
  nh.null_len    = pd[1];
  memcpy((char *)&nh.null_family, (char *)&pd[2], sizeof(nh.null_family));

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  if(check_col(fd, COL_RES_DL_SRC))
    col_add_str(fd, COL_RES_DL_SRC, "N/A" );
  if(check_col(fd, COL_RES_DL_DST))
    col_add_str(fd, COL_RES_DL_DST, "N/A" );
  if(check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "N/A" );
  if(check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, "Null/Loopback" );

  /* populate a tree in the second pane with the status of the link
     layer (ie none) */
  if(tree) {
    ti = proto_tree_add_item(tree, 0, 4, "Null/Loopback" );
    fh_tree = proto_tree_new();
    proto_item_add_subtree(ti, fh_tree, ETT_NULL);
    proto_tree_add_item(fh_tree, 0, 1, "Next: %02x", nh.null_next);
    proto_tree_add_item(fh_tree, 1, 1, "Length: %02x", nh.null_len);
    proto_tree_add_item(fh_tree, 2, 2, "Family: %04x", nh.null_family);
  }

  /* 
  From what I've read in various sources, this is supposed to be an
  address family, e.g. AF_INET.  However, a FreeBSD ISDN PPP dump that
  Andreas Klemm sent to ethereal-dev has a packet type of DLT_NULL, and
  the family bits look like PPP's protocol field.  A dump of the loopback
  interface on my Linux box also has a link type of DLT_NULL (as it should
  be), but the family bits look like ethernet's protocol type.  To
  further  confuse matters, nobody seems to be paying attention to byte
  order.
  - gcc
  */  
   
  switch (nh.null_family) {
    case 0x0008:
    case 0x0800:
    case 0x0021:
    case 0x2100:
      dissect_ip(pd, 4, fd, tree);
      break;
    default:
      dissect_data(pd, 4, fd, tree);
      break;
  }
}
