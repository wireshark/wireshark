/* packet-raw.c
 * Routines for raw packet disassembly
 *
 * $Id: packet-raw.c,v 1.14 2000/05/11 08:15:40 gram Exp $
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

#include <glib.h>
#include "packet.h"
#include "packet-ip.h"

static gint ett_raw = -1;

void
capture_raw( const u_char *pd, packet_counts *ld ) {

  /* So far, the only time we get raw connection types are with Linux and
   * Irix PPP connections.  We can't tell what type of data is coming down
   * the line, so our safest bet is IP. - GCC
   */
   
  /* Currently, the Linux 2.1.xxx PPP driver passes back some of the header
   * sometimes.  This check should be removed when 2.2 is out.
   */
  if (pd[0] == 0xff && pd[1] == 0x03)
    capture_ip(pd, 4, ld);
  else
    capture_ip(pd, 0, ld);
}

void
dissect_raw( const u_char *pd, frame_data *fd, proto_tree *tree ) {
  proto_tree *fh_tree;
  proto_item *ti;

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  if(check_col(fd, COL_RES_DL_SRC))
    col_add_str(fd, COL_RES_DL_SRC, "N/A" );
  if(check_col(fd, COL_RES_DL_DST))
    col_add_str(fd, COL_RES_DL_DST, "N/A" );
  if(check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "N/A" );
  if(check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, "Raw packet data" );

  /* populate a tree in the second pane with the status of the link
     layer (ie none) */
  if(tree) {
    ti = proto_tree_add_text(tree, NullTVB, 0, 0, "Raw packet data" );
    fh_tree = proto_item_add_subtree(ti, ett_raw);
    proto_tree_add_text(fh_tree, NullTVB, 0, 0, "No link information available");
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

void
proto_register_raw(void)
{
  static gint *ett[] = {
    &ett_raw,
  };

  proto_register_subtree_array(ett, array_length(ett));
}
