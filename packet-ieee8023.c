/* packet-ieee8023.c
 * Routine for dissecting 802.3 (as opposed to D/I/X Ethernet) packets.
 *
 * $Id: packet-ieee8023.c,v 1.6 2003/10/01 07:11:44 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
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
#include "packet-ieee8023.h"
#include "packet-eth.h"

static dissector_handle_t ipx_handle;
static dissector_handle_t llc_handle;

void
dissect_802_3(int length, gboolean is_802_2, tvbuff_t *tvb,
	      int offset_after_length, packet_info *pinfo, proto_tree *tree,
	      proto_tree *fh_tree, int length_id, int trailer_id,
	      int fcs_len)
{
  tvbuff_t		*volatile next_tvb;
  tvbuff_t		*volatile trailer_tvb;

  if (fh_tree)
    proto_tree_add_uint(fh_tree, length_id, tvb, offset_after_length - 2, 2,
			length);

  /* Give the next dissector only 'length' number of bytes */
  TRY {
    next_tvb = tvb_new_subset(tvb, offset_after_length, length, length);
    trailer_tvb = tvb_new_subset(tvb, offset_after_length + length, -1, -1);
  }
  CATCH2(BoundsError, ReportedBoundsError) {
    /* Either:

	  the packet doesn't have "length" bytes worth of
	  captured data left in it - or it may not even have
	  "length" bytes worth of data in it, period -
	  so the "tvb_new_subset()" creating "next_tvb"
	  threw an exception

       or

	  the packet has exactly "length" bytes worth of
	  captured data left in it, so the "tvb_new_subset()"
	  creating "trailer_tvb" threw an exception.

       In either case, this means that all the data in the frame
       is within the length value, so we give all the data to the
       next protocol and have no trailer. */
    next_tvb = tvb_new_subset(tvb, offset_after_length, -1, length);
    trailer_tvb = NULL;
  }
  ENDTRY;

  /* Dissect the payload either as IPX or as an LLC frame.
     Catch BoundsError and ReportedBoundsError, so that if the
     reported length of "next_tvb" was reduced by some dissector
     before an exception was thrown, we can still put in an item
     for the trailer. */
  TRY {
    if (is_802_2)
      call_dissector(llc_handle, next_tvb, pinfo, tree);
    else
      call_dissector(ipx_handle, next_tvb, pinfo, tree);
  }
  CATCH2(BoundsError, ReportedBoundsError) {
    /* Well, somebody threw an exception.  Add the trailer, if appropriate. */
    add_ethernet_trailer(fh_tree, trailer_id, tvb, trailer_tvb, fcs_len);

    /* Rethrow the exception, so the "Short Frame" or "Mangled Frame"
       indication can be put into the tree. */
    RETHROW;

    /* XXX - RETHROW shouldn't return. */
    g_assert_not_reached();
  }
  ENDTRY;

  add_ethernet_trailer(fh_tree, trailer_id, tvb, trailer_tvb, fcs_len);
}

void
proto_reg_handoff_ieee802_3(void)
{
  /*
   * Get handles for the IPX and LLC dissectors.
   */
  ipx_handle = find_dissector("ipx");
  llc_handle = find_dissector("llc");
}
