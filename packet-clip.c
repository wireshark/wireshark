/* packet-clip.c
 * Routines for clip packet disassembly
 *
 * $Id: packet-clip.c,v 1.8 2000/05/25 14:55:22 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 *
 * This file created by Thierry Andry <Thierry.Andry@advalvas.be>
 * from nearly-the-same packet-raw.c created by Mike Hall <mlh@io.com>
 * Copyright 1999
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
#include "packet-clip.h"
#include "packet-ip.h"

static gint ett_clip = -1;

void
capture_clip( const u_char *pd, packet_counts *ld ) {

    capture_ip(pd, 0, ld);
}

void
dissect_clip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree	*fh_tree;
  proto_item	*ti;
  const guint8	*this_pd;
  int		this_offset;

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  if(check_col(pinfo->fd, COL_RES_DL_SRC))
    col_add_str(pinfo->fd, COL_RES_DL_SRC, "N/A" );
  if(check_col(pinfo->fd, COL_RES_DL_DST))
    col_add_str(pinfo->fd, COL_RES_DL_DST, "N/A" );
  if(check_col(pinfo->fd, COL_PROTOCOL))
    col_add_str(pinfo->fd, COL_PROTOCOL, "CLIP" );
  if(check_col(pinfo->fd, COL_INFO))
    col_add_str(pinfo->fd, COL_INFO, "Classical IP frame" );

  /* populate a tree in the second pane with the status of the link
     layer (ie none)

     XXX - the ATM on Linux code includes a patch to "tcpdump"
     that compares the first few bytes of the packet with the
     LLC header that Classical IP frames may have and, if there's
     a SNAP LLC header at the beginning of the packet, it gets
     the packet type from that header and uses that, otherwise
     it treats the packet as being raw IP with no link-level
     header. */
  if(tree) {
    ti = proto_tree_add_text(tree, tvb, 0, 0, "Classical IP frame" );
    fh_tree = proto_item_add_subtree(ti, ett_clip);
    proto_tree_add_text(fh_tree, tvb, 0, 0, "No link information available");
  }
  tvb_compat(tvb, &this_pd, &this_offset);
  dissect_ip(this_pd, this_offset, pinfo->fd, tree);
}

void
proto_register_clip(void)
{
  static gint *ett[] = {
    &ett_clip,
  };

  proto_register_subtree_array(ett, array_length(ett));
}
