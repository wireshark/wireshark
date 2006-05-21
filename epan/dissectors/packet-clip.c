/* packet-clip.c
 * Routines for clip packet disassembly
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#include <glib.h>
#include <epan/packet.h>
#include "packet-clip.h"
#include "packet-ip.h"

static gint ett_clip = -1;

static dissector_handle_t ip_handle;

void
capture_clip( const guchar *pd, int len, packet_counts *ld ) {

    capture_ip(pd, 0, len, ld);
}

static void
dissect_clip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree	*fh_tree;
  proto_item	*ti;

  pinfo->current_proto = "CLIP";

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  if(check_col(pinfo->cinfo, COL_RES_DL_SRC))
    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A" );
  if(check_col(pinfo->cinfo, COL_RES_DL_DST))
    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A" );
  if(check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CLIP" );
  if(check_col(pinfo->cinfo, COL_INFO))
    col_set_str(pinfo->cinfo, COL_INFO, "Classical IP frame" );

  /* populate a tree in the second pane with the status of the link
     layer (ie none)

     XXX - the Linux Classical IP code supports both LLC Encapsulation,
     which puts an LLC header and possibly a SNAP header in front of
     the network-layer header, and VC Based Multiplexing, which puts
     no headers in front of the network-layer header.

     The ATM on Linux code includes a patch to "tcpdump"
     that compares the first few bytes of the packet with the
     LLC header that Classical IP frames may have and, if there's
     a SNAP LLC header at the beginning of the packet, it gets
     the packet type from that header and uses that, otherwise
     it treats the packet as being raw IP with no link-level
     header, in order to handle both of those.

     This code, however, won't handle LLC Encapsulation.  We've
     not yet seen a capture taken on a machine using LLC Encapsulation,
     however.  If we see one, we can modify the code.

     A future version of libpcap, however, will probably use DLT_LINUX_SLL
     for both of those cases, to avoid the headache of having to
     generate capture-filter code to handle both of those cases. */
  if(tree) {
    ti = proto_tree_add_text(tree, tvb, 0, 0, "Classical IP frame" );
    fh_tree = proto_item_add_subtree(ti, ett_clip);
    proto_tree_add_text(fh_tree, tvb, 0, 0, "No link information available");
  }
  call_dissector(ip_handle, tvb, pinfo, tree);
}

void
proto_register_clip(void)
{
  static gint *ett[] = {
    &ett_clip,
  };

  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_clip(void)
{
  dissector_handle_t clip_handle;

  /*
   * Get a handle for the IP dissector.
   */
  ip_handle = find_dissector("ip");

  clip_handle = create_dissector_handle(dissect_clip, -1);
      /* XXX - no protocol, can't be disabled */
  dissector_add("wtap_encap", WTAP_ENCAP_LINUX_ATM_CLIP, clip_handle);
}
