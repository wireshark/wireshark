/* packet-isl.c
 * Routines for Cisco ISL Ethernet header disassembly
 *
 * $Id: packet-isl.c,v 1.20 2001/01/03 06:55:29 guy Exp $
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
#include "packet-isl.h"
#include "packet-eth.h"
#include "packet-tr.h"
#include "etypes.h"

/*
 * See
 *
 *	http://www.cisco.com/warp/public/741/4.html
 *
 * and
 *
 *	http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm
 *
 * for information on ISL.
 */
static int proto_isl = -1;
static int hf_isl_dst = -1;
static int hf_isl_type = -1;
static int hf_isl_user_eth = -1;
static int hf_isl_user = -1;
static int hf_isl_src = -1;
static int hf_isl_addr = -1;
static int hf_isl_len = -1;
static int hf_isl_hsa = -1;
static int hf_isl_vlan_id = -1;
static int hf_isl_bpdu = -1;
static int hf_isl_index = -1;
static int hf_isl_crc = -1;
static int hf_isl_src_vlan_id = -1;
static int hf_isl_explorer = -1;
static int hf_isl_dst_route_descriptor = -1;
static int hf_isl_src_route_descriptor = -1;
static int hf_isl_fcs_not_incl = -1;
static int hf_isl_esize = -1;

static gint ett_isl = -1;

#define	ISL_HEADER_SIZE	26

#define	TYPE_ETHER	0x0
#define	TYPE_TR		0x1
#define	TYPE_FDDI	0x2
#define	TYPE_ATM	0x3

void
capture_isl(const u_char *pd, int offset, packet_counts *ld)
{
  guint8 type;

  if (!BYTES_ARE_IN_FRAME(offset, ISL_HEADER_SIZE)) {
    ld->other++;
    return;
  }

  type = (pd[offset+5] >> 4)&0x0F;

  switch (type) {

  case TYPE_ETHER:
    offset += 14+12;	/* skip the header */
    capture_eth(pd, offset, ld);
    break;

  case TYPE_TR:
    offset += 14+17;	/* skip the header */
    capture_tr(pd, offset, ld);
    break;

  default:
    ld->other++;
    break;
  }
}

static const value_string type_vals[] = {
	{TYPE_ETHER, "Ethernet"},
	{TYPE_TR,    "Token-Ring"},
	{TYPE_FDDI,  "FDDI"},
	{TYPE_ATM,   "ATM"},
	{0,          NULL}
};

static const value_string ether_user_vals[] = {
	{0x0, "Normal priority"},
	{0x1, "Priority 1"},
	{0x2, "Priority 2"},
	{0x3, "Highest priority"},
	{0,   NULL}
};

static const true_false_string bpdu_tfs = {
	"Yes",
	"No"
};

static const true_false_string explorer_tfs = {
	"Explorer frame",
	"Data frame"
};

static void
dissect_isl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *fh_tree = NULL;
  proto_item *ti;
  guint8 type;
  guint16 length;
  gint crc_offset;
  gint captured_length;
  tvbuff_t *next_tvb;
  const guint8 *compat_pd;
  int compat_offset;

  CHECK_DISPLAY_AS_DATA(proto_isl, tvb, pinfo, tree);

  pinfo->current_proto = "ISL";
  
  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_set_str(pinfo->fd, COL_PROTOCOL, "ISL");
  if (check_col(pinfo->fd, COL_INFO))
    col_clear(pinfo->fd, COL_INFO);

  type = (tvb_get_guint8(tvb, 5) >> 4)&0x0F;

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_isl, tvb, 0, ISL_HEADER_SIZE,
		"ISL");
    fh_tree = proto_item_add_subtree(ti, ett_isl);
    proto_tree_add_item(fh_tree, hf_isl_dst, tvb, 0, 6, FALSE);
    proto_tree_add_item_hidden(fh_tree, hf_isl_addr, tvb, 0, 6, FALSE);
    proto_tree_add_item(fh_tree, hf_isl_type, tvb, 5, 1, FALSE);
    switch (type) {

    case TYPE_ETHER:
      proto_tree_add_item(fh_tree, hf_isl_user_eth, tvb, 5, 1, FALSE);
      break;

    default:
      /* XXX - the spec appears to indicate that the "User" field is
         used for TYPE_TR to distinguish between types of packets. */
      proto_tree_add_item(fh_tree, hf_isl_user, tvb, 5, 1, FALSE);
      break;
    }
    proto_tree_add_item(fh_tree, hf_isl_src, tvb, 6, 6, FALSE);
    proto_tree_add_item_hidden(fh_tree, hf_isl_addr, tvb, 6, 6, FALSE);
  }
  length = tvb_get_ntohs(tvb, 12);
  if (tree) {
    proto_tree_add_uint(fh_tree, hf_isl_len, tvb, 12, 2, length);

    /* This part looks sort of like a SNAP-encapsulated LLC header... */
    proto_tree_add_text(fh_tree, tvb, 14, 1, "DSAP: 0x%X", tvb_get_guint8(tvb, 14));
    proto_tree_add_text(fh_tree, tvb, 15, 1, "SSAP: 0x%X", tvb_get_guint8(tvb, 15));
    proto_tree_add_text(fh_tree, tvb, 16, 1, "Control: 0x%X", tvb_get_guint8(tvb, 16));

    /* ...but this is the manufacturer's ID portion of the source address
       field (which is, admittedly, an OUI). */
    proto_tree_add_item(fh_tree, hf_isl_hsa, tvb, 17, 3, FALSE);
  }
  if (check_col(pinfo->fd, COL_INFO))
    col_add_fstr(pinfo->fd, COL_INFO, "VLAN ID: 0x%04X",
		 tvb_get_ntohs(tvb, 20) >> 1);
  if (tree) {
    proto_tree_add_item(fh_tree, hf_isl_vlan_id, tvb, 20, 2, FALSE);
    proto_tree_add_item(fh_tree, hf_isl_bpdu, tvb, 20, 2, FALSE);
    proto_tree_add_item(fh_tree, hf_isl_index, tvb, 22, 2, FALSE);

    /* Now for the encapsulated frame's CRC, which is at the *end* of the
       packet; "length" is the length of the frame, not including the
       first 14 bytes of the frame, but including the encapsulated
       frame's CRC, which is 4 bytes long, so the offset of the
       encapsulated CRC is "length + 14 - 4".

       We check for the CRC and display it only if we have that data,
       rather than throwing an exception before we've dissected any
       of the rest of the frame. */
    crc_offset = length + 14 - 4;
    if (tvb_bytes_exist(tvb, crc_offset, 4))
      proto_tree_add_item(fh_tree, hf_isl_crc, tvb, crc_offset, 4, FALSE);
  }

  switch (type) {

  case TYPE_ETHER:
    /* The length of the encapsulated frame is the length from the
       header, minus 12 bytes for the part of the ISL header that
       follows the length and 4 bytes for the encapsulated frame
       CRC. */
    if (length >= 12+4) {
      /* Well, we at least had that much data in the frame.  Try
         dissecting what's left as an Ethernet frame. */
      length -= 12+4;

      /* Trim the captured length. */
      captured_length = tvb_length_remaining(tvb, ISL_HEADER_SIZE);
      if (captured_length > 4) {
        /* Subtract the encapsulated frame CRC. */
        captured_length -= 4;

        /* Make sure it's not bigger than the actual length. */
        if (captured_length > length)
          captured_length = length;

        next_tvb = tvb_new_subset(tvb, ISL_HEADER_SIZE, captured_length, length);

        /* Set "pinfo"'s payload and captured-payload lengths to the values
           we calculated.

           XXX - when all dissectors are tvbuffified we shouldn't have to
           do this any more. */
        tvb_compat(next_tvb, &compat_pd, &compat_offset);
        pinfo->len = compat_offset + length;
        pinfo->captured_len = compat_offset + captured_length;

        dissect_eth(next_tvb, pinfo, tree);
      }
    }
    break;

  case TYPE_TR:
    if (tree) {
      proto_tree_add_item(fh_tree, hf_isl_src_vlan_id, tvb, 24, 2, FALSE);
      proto_tree_add_item(fh_tree, hf_isl_explorer, tvb, 24, 2, FALSE);
      proto_tree_add_item(fh_tree, hf_isl_dst_route_descriptor, tvb, 26, 2, FALSE);
      proto_tree_add_item(fh_tree, hf_isl_src_route_descriptor, tvb, 28, 2, FALSE);
      proto_tree_add_item(fh_tree, hf_isl_fcs_not_incl, tvb, 30, 1, FALSE);
      proto_tree_add_item(fh_tree, hf_isl_esize, tvb, 30, 1, FALSE);
    }
    next_tvb = tvb_new_subset(tvb, 31, -1, -1);
    dissect_tr(next_tvb, pinfo, tree);
    break;

  default:
    next_tvb = tvb_new_subset(tvb, ISL_HEADER_SIZE, -1, -1);
    dissect_data(next_tvb, 0, pinfo, tree);
    break;
  }
}
    
void
proto_register_isl(void)
{
  static hf_register_info hf[] = {
	{ &hf_isl_dst,
	{ "Destination",	"isl.dst", FT_ETHER, BASE_NONE, NULL, 0x0,
		"Destination Address" }},
	{ &hf_isl_type,
	{ "Type",		"isl.type", FT_UINT8, BASE_NONE,
		VALS(type_vals), 0xF0, "Type" }},
	{ &hf_isl_user_eth,
	{ "User",		"isl.user_eth", FT_UINT8, BASE_NONE,
		VALS(ether_user_vals), 0x0F, "Priority (for Ethernet)" }},
	{ &hf_isl_user,
	{ "User",		"isl.user", FT_UINT8, BASE_HEX, NULL, 0x0F,
		"User-defined bits" }},
	{ &hf_isl_src,
	{ "Source",		"isl.src", FT_ETHER, BASE_NONE, NULL, 0x0,
		"Source Hardware Address" }},
	{ &hf_isl_addr,
	{ "Source or Destination Address", "isl.addr", FT_ETHER, BASE_NONE, NULL, 0x0,
		"Source or Destination Hardware Address" }},
	{ &hf_isl_len,
	{ "Length",		"isl.len", FT_UINT16, BASE_DEC, NULL, 0x0,
		"" }},
	{ &hf_isl_hsa,
	{ "HSA",		"isl.hsa", FT_UINT24, BASE_HEX, NULL, 0x0,
		"High bits of source address" }},
	{ &hf_isl_vlan_id,
	{ "VLAN ID",		"isl.vlan_id", FT_UINT16, BASE_HEX, NULL,
		0xFFFE, "Virtual LAN ID" }},
	{ &hf_isl_bpdu,
	{ "BPDU",		"isl.bpdu", FT_BOOLEAN, 16,
		TFS(&bpdu_tfs), 0x0001, "BPDU indicator" }},
	{ &hf_isl_index,
	{ "Index",		"isl.index", FT_UINT16, BASE_DEC, NULL, 0x0,
		"Port index of packet source" }},
	{ &hf_isl_crc,
	{ "CRC",		"isl.crc", FT_UINT32, BASE_HEX, NULL, 0x0,
		"CRC field of encapsulated frame" }},
	{ &hf_isl_src_vlan_id,
	{ "Source VLAN ID",	"isl.src_vlan_id", FT_UINT16, BASE_HEX, NULL,
		0xFFFE, "Source Virtual LAN ID" }},
	{ &hf_isl_explorer,
	{ "Explorer",		"isl.explorer", FT_BOOLEAN, 16,
		TFS(&explorer_tfs), 0x0001, "Explorer" }},
	{ &hf_isl_dst_route_descriptor,
	{ "Destination route descriptor",	"isl.dst_route_desc",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"Route descriptor to be used for forwarding" }},
	{ &hf_isl_src_route_descriptor,
	{ "Source-route descriptor",	"isl.src_route_desc",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"Route descriptor to be used for source learning" }},
	{ &hf_isl_fcs_not_incl,
	{ "FCS Not Included",	"isl.fcs_not_incl", FT_BOOLEAN, 9,
		NULL, 0x40, "FCS not included" }},
	{ &hf_isl_esize,
	{ "Esize",	"isl.esize", FT_UINT8, BASE_DEC, NULL,
		0x3F, "Frame size for frames less than 64 bytes" }},
  };
  static gint *ett[] = {
	&ett_isl,
  };

  proto_isl = proto_register_protocol("Cisco ISL", "ISL", "isl");
  proto_register_field_array(proto_isl, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("isl", dissect_isl);
}
