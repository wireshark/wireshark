/* packet-arcnet.c
 * Routines for arcnet dissection
 * Copyright 2001-2002, Peter Fales <ethereal@fales-lorenz.net>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include "packet-arcnet.h"
#include <epan/arcnet_pids.h>
#include "packet-ip.h"

/* Initialize the protocol and registered fields */
static int proto_arcnet = -1;
static int hf_arcnet_src = -1;
static int hf_arcnet_dst = -1;
static int hf_arcnet_offset = -1;
static int hf_arcnet_protID = -1;
static int hf_arcnet_exception_flag = -1;
static int hf_arcnet_split_flag = -1;
static int hf_arcnet_sequence = -1;

/* Initialize the subtree pointers */
static gint ett_arcnet = -1;

static dissector_table_t arcnet_dissector_table;
static dissector_handle_t data_handle;

void
capture_arcnet (const guchar *pd, int len, packet_counts *ld,
		gboolean has_offset, gboolean has_exception)
{
  int offset = has_offset ? 4 : 2;

  if (!BYTES_ARE_IN_FRAME(offset, len, 1)) {
    ld->other++;
    return;
  }

  switch (pd[offset]) {

  case ARCNET_PROTO_IP_1051:
    /* No fragmentation stuff in the header */
    capture_ip(pd, offset + 1, len, ld);
    break;

  case ARCNET_PROTO_IP_1201:
    /*
     * There's fragmentation stuff in the header.
     *
     * XXX - on at least some versions of NetBSD, it appears that we
     * might we get ARCNET frames, not reassembled packets; we should
     * perhaps bump "ld->other" for all but the first frame of a packet.
     *
     * XXX - but on FreeBSD it appears that we get reassembled packets
     * on input (but apparently we get frames on output - or maybe
     * we get the packet *and* all its frames!); how to tell the
     * difference?  It looks from the FreeBSD reassembly code as if
     * the reassembled packet arrives with the header for the first
     * frame.  It also looks as if, on output, we first get the
     * full packet, with a header containing none of the fragmentation
     * stuff, and then get the frames.
     *
     * On Linux, we get only reassembled packets, and the exception
     * frame stuff is hidden - there's a split flag and sequence
     * number, but it appears that it will never have the exception
     * frame stuff.
     *
     * XXX - what about OpenBSD?  And, for that matter, what about
     * Windows?  (I suspect Windows supplies reassembled frames,
     * as WinPcap, like PF_PACKET sockets, taps into the networking
     * stack just as other protocols do.)
     */
    offset++;
    if (!BYTES_ARE_IN_FRAME(offset, len, 1)) {
      ld->other++;
      return;
    }
    if (has_exception && pd[offset] == 0xff) {
      /* This is an exception packet.  The flag value there is the
         "this is an exception flag" packet; the next two bytes
         after it are padding, and another copy of the packet
         type appears after the padding. */
      offset += 4;
    }
    capture_ip(pd, offset + 3, len, ld);
    break;

  case ARCNET_PROTO_ARP_1051:
  case ARCNET_PROTO_ARP_1201:
    /*
     * XXX - do we have to worry about fragmentation for ARP?
     */
    ld->arp++;
    break;

  case ARCNET_PROTO_IPX:
    ld->ipx++;
    break;

  default:
    ld->other++;
    break;
  }
}

static void
dissect_arcnet_common (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
		       gboolean has_offset, gboolean has_exception)
{
  int offset = 0;
  guint8 dst, src, protID, split_flag;
  tvbuff_t *next_tvb;
  proto_item *ti = NULL;
  proto_tree *arcnet_tree = NULL;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "ARCNET");

  col_set_str(pinfo->cinfo, COL_INFO, "ARCNET");

  src = tvb_get_guint8 (tvb, 0);
  dst = tvb_get_guint8 (tvb, 1);
  SET_ADDRESS(&pinfo->dl_src,	AT_ARCNET, 1, tvb_get_ptr(tvb, 0, 1));
  SET_ADDRESS(&pinfo->src,	AT_ARCNET, 1, tvb_get_ptr(tvb, 0, 1));
  SET_ADDRESS(&pinfo->dl_dst,	AT_ARCNET, 1, tvb_get_ptr(tvb, 1, 1));
  SET_ADDRESS(&pinfo->dst,	AT_ARCNET, 1, tvb_get_ptr(tvb, 1, 1));

  ti = proto_tree_add_item (tree, proto_arcnet, tvb, 0, -1, ENC_BIG_ENDIAN);

  arcnet_tree = proto_item_add_subtree (ti, ett_arcnet);

  proto_tree_add_uint (arcnet_tree, hf_arcnet_src, tvb, offset, 1, src);
  offset++;

  proto_tree_add_uint (arcnet_tree, hf_arcnet_dst, tvb, offset, 1, dst);
  offset++;

  if (has_offset) {
    proto_tree_add_item (arcnet_tree, hf_arcnet_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
  }

  protID = tvb_get_guint8 (tvb, offset);
  proto_tree_add_uint (arcnet_tree, hf_arcnet_protID, tvb, offset, 1, protID);
  offset++;

  switch (protID) {

  case ARCNET_PROTO_IP_1051:
  case ARCNET_PROTO_ARP_1051:
  case ARCNET_PROTO_DIAGNOSE:
  case ARCNET_PROTO_BACNET:	/* XXX - no fragmentation? */
    /* No fragmentation stuff in the header */
    break;

  default:
    /*
     * Show the fragmentation stuff - flag and sequence ID.
     *
     * XXX - on at least some versions of NetBSD, it appears that
     * we might get ARCNET frames, not reassembled packets; if so,
     * we should reassemble them.
     *
     * XXX - but on FreeBSD it appears that we get reassembled packets
     * on input (but apparently we get frames on output - or maybe
     * we get the packet *and* all its frames!); how to tell the
     * difference?  It looks from the FreeBSD reassembly code as if
     * the reassembled packet arrives with the header for the first
     * frame.  It also looks as if, on output, we first get the
     * full packet, with a header containing none of the fragmentation
     * stuff, and then get the frames.
     *
     * On Linux, we get only reassembled packets, and the exception
     * frame stuff is hidden - there's a split flag and sequence
     * number, but it appears that it will never have the exception
     * frame stuff.
     *
     * XXX - what about OpenBSD?  And, for that matter, what about
     * Windows?  (I suspect Windows supplies reassembled frames,
     * as WinPcap, like PF_PACKET sockets, taps into the networking
     * stack just as other protocols do.)
     */
    split_flag = tvb_get_guint8 (tvb, offset);
    if (has_exception && split_flag == 0xff) {
      /* This is an exception packet.  The flag value there is the
         "this is an exception flag" packet; the next two bytes
         after it are padding. */
	  proto_tree_add_uint (arcnet_tree, hf_arcnet_exception_flag, tvb, offset, 1,
			     split_flag);
      offset++;

      proto_tree_add_text (arcnet_tree, tvb, offset, 2, "Padding");
      offset += 2;

      /* Another copy of the packet type appears after the padding. */
      proto_tree_add_item (arcnet_tree, hf_arcnet_protID, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;

      /* And after that comes the real split flag. */
      split_flag = tvb_get_guint8 (tvb, offset);
    }

    proto_tree_add_uint (arcnet_tree, hf_arcnet_split_flag, tvb, offset, 1,
			   split_flag);
    offset++;

    proto_tree_add_item (arcnet_tree, hf_arcnet_sequence, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    break;
  }

  /* Set the length of the ARCNET header protocol tree item. */
  proto_item_set_len(ti, offset);

  next_tvb = tvb_new_subset_remaining (tvb, offset);

  if (!dissector_try_uint (arcnet_dissector_table, protID,
			   next_tvb, pinfo, tree))
    {
	  col_add_fstr (pinfo->cinfo, COL_PROTOCOL, "0x%04x", protID);
      call_dissector (data_handle, next_tvb, pinfo, tree);
    }

}

/*
 * BSD-style ARCNET headers - they don't have the offset field from the
 * ARCNET hardware packet, but we might get an exception frame header.
 */
static void
dissect_arcnet (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  dissect_arcnet_common (tvb, pinfo, tree, FALSE, TRUE);
}

/*
 * Linux-style ARCNET headers - they *do* have the offset field from the
 * ARCNET hardware packet, but we should never see an exception frame
 * header.
 */
static void
dissect_arcnet_linux (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  dissect_arcnet_common (tvb, pinfo, tree, TRUE, ENC_BIG_ENDIAN);
}

static const value_string arcnet_prot_id_vals[] = {
  {ARCNET_PROTO_IP_1051,          "RFC 1051 IP"},
  {ARCNET_PROTO_ARP_1051,         "RFC 1051 ARP"},
  {ARCNET_PROTO_IP_1201,          "RFC 1201 IP"},
  {ARCNET_PROTO_ARP_1201,         "RFC 1201 ARP"},
  {ARCNET_PROTO_RARP_1201,        "RFC 1201 RARP"},
  {ARCNET_PROTO_IPX,              "IPX"},
  {ARCNET_PROTO_NOVELL_EC,        "Novell of some sort"},
  {ARCNET_PROTO_IPv6,             "IPv6"},
  {ARCNET_PROTO_ETHERNET,         "Encapsulated Ethernet"},
  {ARCNET_PROTO_DATAPOINT_BOOT,   "Datapoint boot"},
  {ARCNET_PROTO_DATAPOINT_MOUNT,  "Datapoint mount"},
  {ARCNET_PROTO_POWERLAN_BEACON,  "PowerLAN beacon"},
  {ARCNET_PROTO_POWERLAN_BEACON2, "PowerLAN beacon2"},
  {ARCNET_PROTO_APPLETALK,        "Appletalk"},
  {ARCNET_PROTO_BANYAN,           "Banyan VINES"},
  {ARCNET_PROTO_DIAGNOSE,         "Diagnose"},
  {ARCNET_PROTO_BACNET,           "BACnet"},
  {0,                             NULL}
};

void
proto_register_arcnet (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_arcnet_src,
     {"Source", "arcnet.src",
      FT_UINT8, BASE_HEX, NULL, 0,
      "Source ID", HFILL}
     },
    {&hf_arcnet_dst,
     {"Dest", "arcnet.dst",
      FT_UINT8, BASE_HEX, NULL, 0,
      "Dest ID", HFILL}
     },
    {&hf_arcnet_offset,
     {"Offset", "arcnet.offset",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL}
     },
    {&hf_arcnet_protID,
     {"Protocol ID", "arcnet.protID",
      FT_UINT8, BASE_HEX, VALS(arcnet_prot_id_vals), 0,
      "Proto type", HFILL}
     },
    {&hf_arcnet_split_flag,
     {"Split Flag", "arcnet.split_flag",
      FT_UINT8, BASE_DEC, NULL, 0,
      NULL, HFILL}
     },
    {&hf_arcnet_exception_flag,
     {"Exception Flag", "arcnet.exception_flag",
      FT_UINT8, BASE_HEX, NULL, 0,
      NULL, HFILL}
     },
    {&hf_arcnet_sequence,
     {"Sequence", "arcnet.sequence",
      FT_UINT16, BASE_DEC, NULL, 0,
      "Sequence number", HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_arcnet,
  };

  arcnet_dissector_table = register_dissector_table ("arcnet.protocol_id",
						     "ARCNET Protocol ID",
						     FT_UINT8, BASE_HEX);

/* Register the protocol name and description */
  proto_arcnet = proto_register_protocol ("ARCNET", "ARCNET", "arcnet");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_arcnet, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}


void
proto_reg_handoff_arcnet (void)
{
  dissector_handle_t arcnet_handle, arcnet_linux_handle;

  arcnet_handle = create_dissector_handle (dissect_arcnet, proto_arcnet);
  dissector_add_uint ("wtap_encap", WTAP_ENCAP_ARCNET, arcnet_handle);

  arcnet_linux_handle = create_dissector_handle (dissect_arcnet_linux,
						 proto_arcnet);
  dissector_add_uint ("wtap_encap", WTAP_ENCAP_ARCNET_LINUX, arcnet_linux_handle);
  data_handle = find_dissector ("data");
}
