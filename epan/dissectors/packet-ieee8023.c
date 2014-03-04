/* packet-ieee8023.c
 * Routine for dissecting 802.3 (as opposed to D/I/X Ethernet) packets.
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
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/show_exception.h>
#include "packet-ieee8023.h"
#include "packet-eth.h"

void proto_reg_handoff_ieee802_3(void);

static dissector_handle_t ipx_handle;
static dissector_handle_t llc_handle;
static dissector_handle_t ccsds_handle;

void
dissect_802_3(volatile int length, gboolean is_802_2, tvbuff_t *tvb,
	      int offset_after_length, packet_info *pinfo, proto_tree *tree,
	      proto_tree *fh_tree, int length_id, int trailer_id, expert_field* ei_len,
	      int fcs_len)
{
  proto_item		*length_it;
  tvbuff_t		*volatile next_tvb = NULL;
  tvbuff_t		*trailer_tvb = NULL;
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
    expert_add_info(pinfo, length_it, ei_len);
  }

  /* Give the next dissector only 'length' number of bytes. */
  captured_length = tvb_length_remaining(tvb, offset_after_length);
  if (captured_length > length)
    captured_length = length;
  next_tvb = tvb_new_subset(tvb, offset_after_length, captured_length, length);

  /* Dissect the payload either as IPX or as an LLC frame.
     Catch non-fatal exceptions, so that if the reported length
     of "next_tvb" was reduced by some dissector before an
     exception was thrown, we can still put in an item for
     the trailer. */
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
  CATCH_NONFATAL_ERRORS {
    /* Somebody threw an exception that means that there was a problem
       dissecting the payload; that means that a dissector was found,
       so we don't need to dissect the payload as data or update the
       protocol or info columns.

       Just show the exception and then drive on to show the trailer,
       after noting that a dissector was found and restoring the
       protocol value that was in effect before we called the subdissector. */
    pinfo->private_data = pd_save;

    show_exception(next_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
  }
  ENDTRY;

  /* Restore the protocol value, so that any exception thrown by
     tvb_new_subset_remaining() refers to the protocol for which
     this is a trailer, and restore the private_data structure in
     case one of the called dissectors modified it. */
  pinfo->private_data = pd_save;
  pinfo->current_proto = saved_proto;

  /* Construct a tvbuff for the trailer; if the trailer is past the
     end of the captured data, this will throw a BoundsError, which
     is what we want, as it'll report that the packet was cut short. */
  trailer_tvb = tvb_new_subset_remaining(tvb, offset_after_length + length);

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
