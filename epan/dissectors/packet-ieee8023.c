/* packet-ieee8023.c
 * Routine for dissecting 802.3 (as opposed to D/I/X Ethernet) packets.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-ieee8023.h"
#include "packet-eth.h"
#include "packet-frame.h"

static dissector_handle_t ipx_handle;
static dissector_handle_t llc_handle;
static dissector_handle_t ccsds_handle;

void
dissect_802_3(volatile int length, gboolean is_802_2, tvbuff_t *tvb,
	      int offset_after_length, packet_info *pinfo, proto_tree *tree,
	      proto_tree *fh_tree, int length_id, int trailer_id,
	      int fcs_len)
{
  proto_item		*length_it;
  tvbuff_t		*volatile next_tvb = NULL;
  tvbuff_t		*volatile trailer_tvb = NULL;
  const char		*saved_proto;
  gint			captured_length, reported_length;
  void			*pd_save;

  length_it = proto_tree_add_uint(fh_tree, length_id, tvb,
                                  offset_after_length - 2, 2, length);

  /* Get the length of the payload.
     If the FCS length is positive, remove the FCS.
     (If it's zero, there's no FCS; if it's negative, we don't know whether
     there's an FCS, so we'll guess based on the length of the trailer.) */
  reported_length = tvb_reported_length_remaining(tvb, offset_after_length);
  if (fcs_len > 0) {
    if (reported_length >= fcs_len)
      reported_length -= fcs_len;
  }

  /* Make sure the length in the 802.3 header doesn't go past the end of
     the payload. */
  if (length > reported_length) {
    length = reported_length;
    expert_add_info_format(pinfo, length_it, PI_MALFORMED, PI_ERROR,
        "Length field value goes past the end of the payload");
  }

  /* Give the next dissector only 'length' number of bytes. */
  captured_length = tvb_length_remaining(tvb, offset_after_length);
  if (captured_length > length)
    captured_length = length;
  next_tvb = tvb_new_subset(tvb, offset_after_length, captured_length, length);
  TRY {
    trailer_tvb = tvb_new_subset_remaining(tvb, offset_after_length + length);
  }
  CATCH2(BoundsError, ReportedBoundsError) {
    /* The packet has exactly "length" bytes worth of captured data
       left in it, so the "tvb_new_subset()" creating "trailer_tvb"
       threw an exception.

       This means that all the data in the frame is within the length
       value (assuming our offset isn't past the end of the tvb), so
       we give all the data to the next protocol and have no trailer. */
    trailer_tvb = NULL;
  }
  ENDTRY;

  /* Dissect the payload either as IPX or as an LLC frame.
     Catch BoundsError and ReportedBoundsError, so that if the
     reported length of "next_tvb" was reduced by some dissector
     before an exception was thrown, we can still put in an item
     for the trailer. */
  saved_proto = pinfo->current_proto;
  pd_save = pinfo->private_data;
  TRY {
    if (is_802_2)
      call_dissector(llc_handle, next_tvb, pinfo, tree);
    else {
      /* Check if first three bits of payload are 0x7.
         If so, then payload is IPX.  If not, then it's CCSDS.
         Refer to packet-eth.c for setting of is_802_2 variable. */
      if (tvb_get_bits8(next_tvb, 0, 3) == 7)
        call_dissector(ipx_handle, next_tvb, pinfo, tree);
      else
        call_dissector(ccsds_handle, next_tvb, pinfo, tree);
    }
  }
  CATCH(BoundsError) {
   /* Somebody threw BoundsError, which means that dissecting the payload
      found that the packet was cut off by a snapshot length before the
      end of the payload.  The trailer comes after the payload, so *all*
      of the trailer is cut off - don't bother adding the trailer, just
      rethrow the exception so it gets reported. */
   RETHROW;
  }
  CATCH_ALL {
    /* Well, somebody threw an exception other than BoundsError.
       Show the exception, and then drive on to show the trailer,
       restoring the protocol value that was in effect before we
       called the subdissector. */

    /*  Restore the private_data structure in case one of the
     *  called dissectors modified it (and, due to the exception,
     *  was unable to restore it).
     */
    pinfo->private_data = pd_save;

    show_exception(next_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
    pinfo->current_proto = saved_proto;
  }
  ENDTRY;

  add_ethernet_trailer(pinfo, tree, fh_tree, trailer_id, tvb, trailer_tvb, fcs_len);
}

void
proto_reg_handoff_ieee802_3(void)
{
  /*
   * Get handles for the subdissectors.
   */
  ipx_handle = find_dissector("ipx");
  llc_handle = find_dissector("llc");
  ccsds_handle = find_dissector("ccsds");
}
