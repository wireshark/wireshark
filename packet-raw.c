/* packet-raw.c
 * Routines for raw packet disassembly
 *
 * $Id: packet-raw.c,v 1.19 2000/11/17 21:00:35 gram Exp $
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

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-raw.h"
#include "packet-ip.h"
#include "packet-ppp.h"

static gint ett_raw = -1;

static const char zeroes[10];

void
capture_raw(const u_char *pd, packet_counts *ld)
{
  /* So far, the only time we get raw connection types are with Linux and
   * Irix PPP connections.  We can't tell what type of data is coming down
   * the line, so our safest bet is IP. - GCC
   */
   
  /* Currently, the Linux 2.1.xxx PPP driver passes back some of the header
   * sometimes.  This check should be removed when 2.2 is out.
   */
  if (BYTES_ARE_IN_FRAME(0,2) && pd[0] == 0xff && pd[1] == 0x03) {
    capture_ppp(pd, 0, ld);
  }
  /* The Linux ISDN driver sends a fake MAC address before the PPP header
   * on its ippp interfaces... */
  else if (BYTES_ARE_IN_FRAME(0,8) && pd[6] == 0xff && pd[7] == 0x03) {
    capture_ppp(pd, 6, ld);
  }
  /* ...except when it just puts out one byte before the PPP header... */
  else if (BYTES_ARE_IN_FRAME(0,3) && pd[1] == 0xff && pd[2] == 0x03) {
    capture_ppp(pd, 1, ld);
  }
  /* ...and if the connection is currently down, it sends 10 bytes of zeroes
   * instead of a fake MAC address and PPP header. */
  else if (BYTES_ARE_IN_FRAME(0,10) && memcmp(pd, zeroes, 10) == 0) {
    capture_ip(pd, 10, ld);
  }
  else {
    capture_ip(pd, 0, ld);
  }
}

void
dissect_raw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree	*fh_tree;
  proto_item	*ti;
  tvbuff_t	*next_tvb;
  const guint8	*next_pd;
  int		next_offset;

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  if(check_col(pinfo->fd, COL_RES_DL_SRC))
    col_add_str(pinfo->fd, COL_RES_DL_SRC, "N/A" );
  if(check_col(pinfo->fd, COL_RES_DL_DST))
    col_add_str(pinfo->fd, COL_RES_DL_DST, "N/A" );
  if(check_col(pinfo->fd, COL_PROTOCOL))
    col_add_str(pinfo->fd, COL_PROTOCOL, "N/A" );
  if(check_col(pinfo->fd, COL_INFO))
    col_add_str(pinfo->fd, COL_INFO, "Raw packet data" );

  /* populate a tree in the second pane with the status of the link
     layer (ie none) */
  if (tree) {
    ti = proto_tree_add_text(tree, tvb, 0, 0, "Raw packet data" );
    fh_tree = proto_item_add_subtree(ti, ett_raw);
    proto_tree_add_text(fh_tree, tvb, 0, 0, "No link information available");
  }

  /* So far, the only time we get raw connection types are with Linux and
   * Irix PPP connections.  We can't tell what type of data is coming down
   * the line, so our safest bet is IP. - GCC
   */
   
  /* Currently, the Linux 2.1.xxx PPP driver passes back some of the header
   * sometimes.  This check should be removed when 2.2 is out.
   */
  if (tvb_get_ntohs(tvb, 0) == 0xff03) {
	dissect_ppp(tvb, pinfo, tree);
	return;
  }
  /* The Linux ISDN driver sends a fake MAC address before the PPP header
   * on its ippp interfaces... */
  else if (tvb_get_ntohs(tvb, 6) == 0xff03) {
	next_tvb = tvb_new_subset(tvb, 6, -1, -1);
	dissect_ppp(next_tvb, pinfo, tree);
	return;
  }
  /* ...except when it just puts out one byte before the PPP header... */
  else if (tvb_get_ntohs(tvb, 1) == 0xff03) {
	next_tvb = tvb_new_subset(tvb, 1, -1, -1);
	dissect_ppp(next_tvb, pinfo, tree);
	return;
  }
  /* ...and if the connection is currently down, it sends 10 bytes of zeroes
   * instead of a fake MAC address and PPP header. */
  else if (memcmp(tvb_get_ptr(tvb, 0, 10), zeroes, 10) == 0) {
	tvb_compat(tvb, &next_pd, &next_offset);
	dissect_ip(next_pd, next_offset + 10, pinfo->fd, tree);
	return;
  }
  else {
	tvb_compat(tvb, &next_pd, &next_offset);
	dissect_ip(next_pd, next_offset, pinfo->fd, tree);
	return;
  }
  g_assert_not_reached();
}

void
proto_register_raw(void)
{
  static gint *ett[] = {
    &ett_raw,
  };

  proto_register_subtree_array(ett, array_length(ett));
}
