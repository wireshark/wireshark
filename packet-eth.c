/* packet-eth.c
 * Routines for ethernet packet disassembly
 *
 * $Id: packet-eth.c,v 1.33 2000/05/11 08:15:08 gram Exp $
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

#include <glib.h>
#include "packet.h"
#include "etypes.h"
#include "resolv.h"
#include "packet-ipx.h"
#include "packet-isl.h"
#include "packet-llc.h"

extern const value_string etype_vals[];

/* protocols and header fields */
static int proto_eth = -1;
static int hf_eth_dst = -1;
static int hf_eth_src = -1;
static int hf_eth_len = -1;
static int hf_eth_type = -1;
static int hf_eth_addr = -1;

static gint ett_ieee8023 = -1;
static gint ett_ether2 = -1;

#define ETH_HEADER_SIZE	14

/* These are the Netware-ish names for the different Ethernet frame types.
	EthernetII: The ethernet with a Type field instead of a length field
	Ethernet802.2: An 802.3 header followed by an 802.3 header
	Ethernet802.3: A raw 802.3 packet. IPX/SPX can be the only payload.
			There's not 802.2 hdr in this.
	EthernetSNAP: Basically 802.2, just with 802.2SNAP. For our purposes,
		there's no difference between 802.2 and 802.2SNAP, since we just
		pass it down to dissect_llc(). -- Gilbert
*/
#define ETHERNET_II 	0
#define ETHERNET_802_2	1
#define ETHERNET_802_3	2
#define ETHERNET_SNAP	3

void
capture_eth(const u_char *pd, int offset, packet_counts *ld)
{
  guint16    etype, length;
  int     ethhdr_type;	/* the type of ethernet frame */

  if (!BYTES_ARE_IN_FRAME(offset, ETH_HEADER_SIZE)) {
    ld->other++;
    return;
  }
  
  etype = pntohs(&pd[offset+12]);

	/* either ethernet802.3 or ethernet802.2 */
  if (etype <= IEEE_802_3_MAX_LEN) {
    length = etype;

    /* Is there an 802.2 layer? I can tell by looking at the first 2
       bytes after the 802.3 header. If they are 0xffff, then what
       follows the 802.3 header is an IPX payload, meaning no 802.2.
       (IPX/SPX is they only thing that can be contained inside a
       straight 802.3 packet). A non-0xffff value means that there's an
       802.2 layer inside the 802.3 layer */
    if (pd[offset+14] == 0xff && pd[offset+15] == 0xff) {
      ethhdr_type = ETHERNET_802_3;
    }
    else {
      ethhdr_type = ETHERNET_802_2;
    }

    /* Oh, yuck.  Cisco ISL frames require special interpretation of the
       destination address field; fortunately, they can be recognized by
       checking the first 5 octets of the destination address, which are
       01-00-0C-00-00 for ISL frames. */
    if (pd[offset] == 0x01 && pd[offset+1] == 0x00 && pd[offset+2] == 0x0C
	&& pd[offset+3] == 0x00 && pd[offset+4] == 0x00) {
      capture_isl(pd, offset, ld);
      return;
    }

    /* Convert the LLC length from the 802.3 header to a total
       frame length, by adding in the size of any data that preceded
       the Ethernet header, and adding in the Ethernet header size,
       and set the payload and captured-payload lengths to the minima
       of the total length and the frame lengths. */
    length += offset + ETH_HEADER_SIZE;
    if (pi.len > length)
      pi.len = length;
    if (pi.captured_len > length)
      pi.captured_len = length;
  } else {
    ethhdr_type = ETHERNET_II;
  }
  offset += ETH_HEADER_SIZE;

  switch (ethhdr_type) {
    case ETHERNET_802_3:
      capture_ipx(pd, offset, ld);
      break;
    case ETHERNET_802_2:
      capture_llc(pd, offset, ld);
      break;
    case ETHERNET_II:
      capture_ethertype(etype, offset, pd, ld);
      break;
  }
}

void
dissect_eth(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
  int        orig_captured_len;
  guint16    etype, length;
  proto_tree *fh_tree = NULL;
  proto_item *ti;
  int        ethhdr_type;	/* the type of ethernet frame */

  if (!BYTES_ARE_IN_FRAME(offset, ETH_HEADER_SIZE)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  orig_captured_len = pi.captured_len;

  SET_ADDRESS(&pi.dl_src, AT_ETHER, 6, &pd[offset+6]);
  SET_ADDRESS(&pi.src, AT_ETHER, 6, &pd[offset+6]);
  SET_ADDRESS(&pi.dl_dst, AT_ETHER, 6, &pd[offset+0]);
  SET_ADDRESS(&pi.dst, AT_ETHER, 6, &pd[offset+0]);

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "Ethernet");

  etype = pntohs(&pd[offset+12]);

	/* either ethernet802.3 or ethernet802.2 */
  if (etype <= IEEE_802_3_MAX_LEN) {
    length = etype;

    /* Is there an 802.2 layer? I can tell by looking at the first 2
       bytes after the 802.3 header. If they are 0xffff, then what
       follows the 802.3 header is an IPX payload, meaning no 802.2.
       (IPX/SPX is they only thing that can be contained inside a
       straight 802.3 packet). A non-0xffff value means that there's an
       802.2 layer inside the 802.3 layer */
    if (pd[offset+14] == 0xff && pd[offset+15] == 0xff) {
      ethhdr_type = ETHERNET_802_3;
    }
    else {
      ethhdr_type = ETHERNET_802_2;
    }

    /* Oh, yuck.  Cisco ISL frames require special interpretation of the
       destination address field; fortunately, they can be recognized by
       checking the first 5 octets of the destination address, which are
       01-00-0C-00-00 for ISL frames. */
    if (pd[offset] == 0x01 && pd[offset+1] == 0x00 && pd[offset+2] == 0x0C
	&& pd[offset+3] == 0x00 && pd[offset+4] == 0x00) {
      dissect_isl(pd, offset, fd, tree);
      return;
    }

    if (check_col(fd, COL_INFO)) {
      col_add_fstr(fd, COL_INFO, "IEEE 802.3 %s",
		(ethhdr_type == ETHERNET_802_3 ? "Raw " : ""));
    }
    if (tree) {

	ti = proto_tree_add_protocol_format(tree, proto_eth, NullTVB, offset, ETH_HEADER_SIZE,
		"IEEE 802.3 %s", (ethhdr_type == ETHERNET_802_3 ? "Raw " : ""));

	fh_tree = proto_item_add_subtree(ti, ett_ieee8023);

	proto_tree_add_item(fh_tree, hf_eth_dst, NullTVB, offset+0, 6, &pd[offset+0]);
	proto_tree_add_item(fh_tree, hf_eth_src, NullTVB, offset+6, 6, &pd[offset+6]);

/* add items for eth.addr filter */
	proto_tree_add_item_hidden(fh_tree, hf_eth_addr, NullTVB, offset + 0, 6, &pd[offset+0]);
	proto_tree_add_item_hidden(fh_tree, hf_eth_addr, NullTVB, offset + 6, 6, &pd[offset+6]);

	proto_tree_add_item(fh_tree, hf_eth_len, NullTVB, offset+12, 2, length);
    }

    /* Convert the LLC length from the 802.3 header to a total
       frame length, by adding in the size of any data that preceded
       the Ethernet header, and adding in the Ethernet header size,
       and set the payload and captured-payload lengths to the minima
       of the total length and the frame lengths. */
    length += offset + ETH_HEADER_SIZE;
    if (pi.len > length)
      pi.len = length;
    if (pi.captured_len > length)
      pi.captured_len = length;
  } else {
    ethhdr_type = ETHERNET_II;
    if (check_col(fd, COL_INFO))
      col_add_str(fd, COL_INFO, "Ethernet II");
    if (tree) {

	ti = proto_tree_add_protocol_format(tree, proto_eth, NullTVB, offset, ETH_HEADER_SIZE,
		"Ethernet II");

	fh_tree = proto_item_add_subtree(ti, ett_ether2);

	proto_tree_add_item(fh_tree, hf_eth_dst, NullTVB, offset+0, 6, &pd[offset+0]);
	proto_tree_add_item(fh_tree, hf_eth_src, NullTVB, offset+6, 6, &pd[offset+6]);
/* add items for eth.addr filter */
	proto_tree_add_item_hidden(fh_tree, hf_eth_addr, NullTVB, offset + 0, 6, &pd[offset+0]);
	proto_tree_add_item_hidden(fh_tree, hf_eth_addr, NullTVB, offset + 6, 6, &pd[offset+6]);
    }
  }
  offset += ETH_HEADER_SIZE;

  switch (ethhdr_type) {
    case ETHERNET_802_3:
      dissect_ipx(pd, offset, fd, tree);
      break;
    case ETHERNET_802_2:
      dissect_llc(pd, offset, fd, tree);
      break;
    case ETHERNET_II:
      ethertype(etype, offset, pd, fd, tree, fh_tree, hf_eth_type);
      break;
  }
}

void
proto_register_eth(void)
{
	static hf_register_info hf[] = {

		{ &hf_eth_dst,
		{ "Destination",	"eth.dst", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Destination Hardware Address" }},

		{ &hf_eth_src,
		{ "Source",		"eth.src", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Source Hardware Address" }},

		{ &hf_eth_len,
		{ "Length",		"eth.len", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		/* registered here but handled in ethertype.c */
		{ &hf_eth_type,
		{ "Type",		"eth.type", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
			"" }},
		{ &hf_eth_addr,
		{ "Source or Destination Address", "eth.addr", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Source or Destination Hardware Address" }}

	};
	static gint *ett[] = {
		&ett_ieee8023,
		&ett_ether2,
	};

	proto_eth = proto_register_protocol ("Ethernet", "eth" );
	proto_register_field_array(proto_eth, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
