/* packet-ascend.c
 * Routines for decoding Lucent/Ascend packet traces
 *
 * $Id: packet-ascend.c,v 1.1 1999/09/11 05:32:33 gerald Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

#include "wiretap/ascend.h"

void
dissect_ascend( const u_char *pd, frame_data *fd, proto_tree *tree ) {
  proto_tree *fh_tree;
  proto_item *ti;
  ascend_pkthdr header;
  static const value_string encaps_vals[] = {
    {ASCEND_PFX_ETHER, "Ethernet"    },
    {ASCEND_PFX_PPP_X, "PPP Transmit"},
    {ASCEND_PFX_PPP_R, "PPP Receive" },
    {0,                NULL          } };

  memcpy(&header, pd, ASCEND_PKTHDR_OFFSET);

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  if(check_col(fd, COL_RES_DL_SRC))
    col_add_str(fd, COL_RES_DL_SRC, "N/A" );
  if(check_col(fd, COL_RES_DL_DST))
    col_add_str(fd, COL_RES_DL_DST, "N/A" );
  if(check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "N/A" );
  if(check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, "Lucent/Ascend packet trace" );

  /* populate a tree in the second pane with the status of the link
     layer (ie none) */
  if(tree) {
    ti = proto_tree_add_text(tree, 0, 0, "Lucent/Ascend packet trace" );
    fh_tree = proto_item_add_subtree(ti, ETT_RAW);
    proto_tree_add_text(fh_tree, 0, 0, "Link type: %s", val_to_str(header.type,
      encaps_vals, "Unknown (%d)"));
    proto_tree_add_text(fh_tree, 0, 0, "Username: %s", header.user);
    proto_tree_add_text(fh_tree, 0, 0, "Session: %d", header.sess);
    proto_tree_add_text(fh_tree, 0, 0, "Task: %08X", header.task);
  }

  /* The header is metadata, so we copy the packet data to the front */
  /* XXX Maybe we should leave it in, and mark it as metadata, so that
     it can be filtered upon? */
  memmove(pd, pd + ASCEND_PKTHDR_OFFSET, fd->cap_len);
  switch (header.type) {
    case ASCEND_PFX_ETHER:
      dissect_eth(pd, 0, fd, tree);
      break;
    case ASCEND_PFX_PPP_X:
    case ASCEND_PFX_PPP_R:
      dissect_ppp(pd, fd, tree);
      break;
  }
}

