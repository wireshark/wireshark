/* packet-vlan.c
 * Routines for VLAN 802.1Q ethernet header disassembly
 *
 * $Id: packet-vlan.c,v 1.27 2001/01/03 10:34:42 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include "packet.h"
#include "packet-ipx.h"
#include "packet-llc.h"
#include "etypes.h"

static int proto_vlan = -1;
static int hf_vlan_priority = -1;
static int hf_vlan_cfi = -1;
static int hf_vlan_id = -1;
static int hf_vlan_etype = -1;
static int hf_vlan_len = -1;
static int hf_vlan_trailer = -1;

static gint ett_vlan = -1;

static dissector_handle_t llc_handle;

void
capture_vlan(const u_char *pd, int offset, packet_counts *ld ) {
  guint32 encap_proto;
  if ( !BYTES_ARE_IN_FRAME(offset,5) ) {
    ld->other++;
    return; 
  }
  encap_proto = pntohs( &pd[offset+2] );
  if ( encap_proto <= IEEE_802_3_MAX_LEN) {
    if ( pd[offset+4] == 0xff && pd[offset+5] == 0xff ) {
      capture_ipx(pd,offset+4,ld);
    } else {
      capture_llc(pd,offset+4,ld);
    }
  } else {
    capture_ethertype(encap_proto, offset+4, pd, ld);
  }
}

static void
dissect_vlan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *ti;
  guint16 tci,encap_proto;
  volatile gboolean is_802_2;
  tvbuff_t *volatile next_tvb;
  tvbuff_t *volatile trailer_tvb;
  proto_tree *volatile vlan_tree;
  guint	length_before, length;

  CHECK_DISPLAY_AS_DATA(proto_vlan, tvb, pinfo, tree);

  pinfo->current_proto = "VLAN";

  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_set_str(pinfo->fd, COL_PROTOCOL, "VLAN");

  tci = tvb_get_ntohs( tvb, 0 );
  encap_proto = tvb_get_ntohs( tvb, 2 );

  if (check_col(pinfo->fd, COL_INFO)) {
    col_add_fstr(pinfo->fd, COL_INFO, "PRI: %d  CFI: %d  ID: %d",
      (tci >> 13), ((tci >> 12) & 1), (tci & 0xFFF));
  }

  vlan_tree = NULL;

  if (tree) {
    ti = proto_tree_add_item(tree, proto_vlan, tvb, 0, 4, FALSE);
    vlan_tree = proto_item_add_subtree(ti, ett_vlan);

    proto_tree_add_uint(vlan_tree, hf_vlan_priority, tvb, 0, 2, tci);
    proto_tree_add_uint(vlan_tree, hf_vlan_cfi, tvb, 0, 2, tci);
    proto_tree_add_uint(vlan_tree, hf_vlan_id, tvb, 0, 2, tci);
  }

  if ( encap_proto <= IEEE_802_3_MAX_LEN) {
    /* Give the next dissector only 'encap_proto' number of bytes */
    proto_tree_add_uint(vlan_tree, hf_vlan_len, tvb, 2, 2, encap_proto);
    TRY {
       next_tvb = tvb_new_subset(tvb, 4, encap_proto, encap_proto);
       trailer_tvb = tvb_new_subset(tvb, 4 + encap_proto, -1, -1);
    }
    CATCH2(BoundsError, ReportedBoundsError) {
      /* Either:

           the packet doesn't have "encap_proto" bytes worth of
           captured data left in it - or it may not even have
           "encap_proto" bytes worth of data in it, period -
           so the "tvb_new_subset()" creating "next_tvb"
           threw an exception

         or

           the packet has exactly "encap_proto" bytes worth of
           captured data left in it, so the "tvb_new_subset()"
           creating "trailer_tvb" threw an exception.

         In either case, this means that all the data in the frame
         is within the length value, so we give all the data to the
         next protocol and have no trailer. */
      next_tvb = tvb_new_subset(tvb, 4, -1, encap_proto);
      trailer_tvb = NULL;
    }
    ENDTRY;

    /* Is there an 802.2 layer? I can tell by looking at the first 2
       bytes after the VLAN header. If they are 0xffff, then what
       follows the VLAN header is an IPX payload, meaning no 802.2.
       (IPX/SPX is they only thing that can be contained inside a
       straight 802.3 packet, so presumably the same applies for
       Ethernet VLAN packets). A non-0xffff value means that there's an
       802.2 layer inside the VLAN layer */
    is_802_2 = TRUE;
    TRY {
	    if (tvb_get_ntohs(next_tvb, 2) == 0xffff) {
	      is_802_2 = FALSE;
	    }
    }
    CATCH2(BoundsError, ReportedBoundsError) {
	    ; /* do nothing */

    }
    ENDTRY;
    if (is_802_2 ) {
      /* 802.2 LLC */
      call_dissector(llc_handle, next_tvb, pinfo, tree);
    } else {
      dissect_ipx(next_tvb, pinfo, tree);
    }
  } else {
    length_before = tvb_reported_length(tvb);
    length = ethertype(encap_proto, tvb, 4, pinfo, tree, vlan_tree,
		       hf_vlan_etype) + 4;
    if (length < length_before) {
      /*
       * Create a tvbuff for the padding.
       */
      TRY {
	trailer_tvb = tvb_new_subset(tvb, length, -1, -1);
      }
      CATCH2(BoundsError, ReportedBoundsError) {
	/* The packet doesn't have "length" bytes worth of captured
	   data left in it.  No trailer to display. */
	trailer_tvb = NULL;
      }
      ENDTRY;
    } else {
      /* No padding. */
      trailer_tvb = NULL;
    }
  }

  /* If there's some bytes left over, mark them. */
  if (trailer_tvb && tree) {
    int trailer_length;
    const guint8    *ptr;

    trailer_length = tvb_length(trailer_tvb);
    if (trailer_length > 0) {
      ptr = tvb_get_ptr(trailer_tvb, 0, trailer_length);
      proto_tree_add_bytes(vlan_tree, hf_vlan_trailer, trailer_tvb, 0,
			   trailer_length, ptr);
    }
  }
}

void
proto_register_vlan(void)
{
  static hf_register_info hf[] = {
	{ &hf_vlan_priority, { 
		"Priority", "vlan.priority", FT_UINT16, BASE_BIN, 
		0, 0xE000, "Priority" }},
	{ &hf_vlan_cfi, { 
		"CFI", "vlan.cfi", FT_UINT16, BASE_BIN, 
		0, 0x1000, "CFI" }},	/* XXX - Boolean? */
	{ &hf_vlan_id, { 
		"ID", "vlan.id", FT_UINT16, BASE_BIN, 
		0, 0x0FFF, "ID" }},
	{ &hf_vlan_etype, { 
		"Type", "vlan.etype", FT_UINT16, BASE_HEX, 
		VALS(etype_vals), 0x0, "Type" }},
	{ &hf_vlan_len, {
		"Length", "vlan.len", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Length" }},
	{ &hf_vlan_trailer, {
		"Trailer", "vlan.trailer", FT_BYTES, BASE_NONE,
		NULL, 0x0, "VLAN Trailer" }}
  };
  static gint *ett[] = {
	&ett_vlan,
  };

  proto_vlan = proto_register_protocol("802.1q Virtual LAN", "VLAN", "vlan");
  proto_register_field_array(proto_vlan, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vlan(void)
{
  /*
   * Get a handle for the LLC dissector.
   */
  llc_handle = find_dissector("llc");

  dissector_add("ethertype", ETHERTYPE_VLAN, dissect_vlan);
}
