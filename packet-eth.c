/* packet-eth.c
 * Routines for ethernet packet disassembly
 *
 * $Id: packet-eth.c,v 1.11 1999/07/08 03:18:20 gram Exp $
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

extern const value_string etype_vals[];

/* protocols and header fields */
int proto_eth = -1;
int hf_eth_dst = -1;
int hf_eth_dst_vendor = -1;
int hf_eth_src = -1;
int hf_eth_src_vendor = -1;
int hf_eth_len = -1;
int hf_eth_type = -1;

#define IEEE_802_3_MAX_LEN 1500

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
capture_eth(const u_char *pd, guint32 cap_len, packet_counts *ld) {
  guint16 etype;
  int        offset = 14;
  int   	ethhdr_type;	/* the type of ethernet frame */
  
  etype = (pd[12] << 8) | pd[13];

	/* either ethernet802.3 or ethernet802.2 */
  if (etype <= IEEE_802_3_MAX_LEN) {

  /* Is there an 802.2 layer? I can tell by looking at the first 2
     bytes after the 802.3 header. If they are 0xffff, then what
     follows the 802.3 header is an IPX payload, meaning no 802.2.
     (IPX/SPX is they only thing that can be contained inside a
     straight 802.3 packet). A non-0xffff value means that there's an
     802.2 layer inside the 802.3 layer */
    if (pd[14] == 0xff && pd[15] == 0xff) {
      ethhdr_type = ETHERNET_802_3;
    }
    else {
      ethhdr_type = ETHERNET_802_2;
    }
  } else {
    ethhdr_type = ETHERNET_II;
  }

  switch (ethhdr_type) {
    case ETHERNET_802_3:
      ld->other++;	/* IPX */
      break;
    case ETHERNET_802_2:
      capture_llc(pd, offset, cap_len, ld);
      break;
    case ETHERNET_II:
      capture_ethertype(etype, offset, pd, cap_len, ld);
      break;
  }
}

void
dissect_eth(const u_char *pd, frame_data *fd, proto_tree *tree) {
  guint16    etype, length;
  int        offset = 14;
  proto_tree *fh_tree = NULL;
  proto_item *ti;
  int   	ethhdr_type;	/* the type of ethernet frame */

  if (check_col(fd, COL_RES_DL_DST))
    col_add_str(fd, COL_RES_DL_DST, get_ether_name((u_char *)&pd[0]));
  if (check_col(fd, COL_RES_DL_SRC))
    col_add_str(fd, COL_RES_DL_SRC, get_ether_name((u_char *)&pd[6]));
  if (check_col(fd, COL_UNRES_DL_DST))
    col_add_str(fd, COL_UNRES_DL_DST, ether_to_str((u_char *)&pd[0]));
  if (check_col(fd, COL_UNRES_DL_SRC))
    col_add_str(fd, COL_UNRES_DL_SRC, ether_to_str((u_char *)&pd[6]));
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "N/A");
  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, "Ethernet II");

  etype = (pd[12] << 8) | pd[13];

	/* either ethernet802.3 or ethernet802.2 */
  if (etype <= IEEE_802_3_MAX_LEN) {
    length = etype;

  /* Is there an 802.2 layer? I can tell by looking at the first 2
     bytes after the 802.3 header. If they are 0xffff, then what
     follows the 802.3 header is an IPX payload, meaning no 802.2.
     (IPX/SPX is they only thing that can be contained inside a
     straight 802.3 packet). A non-0xffff value means that there's an
     802.2 layer inside the 802.3 layer */
    if (pd[14] == 0xff && pd[15] == 0xff) {
      ethhdr_type = ETHERNET_802_3;
    }
    else {
      ethhdr_type = ETHERNET_802_2;
    }

    if (check_col(fd, COL_INFO))
      col_add_str(fd, COL_INFO, "802.3");
    if (tree) {

	ti = proto_tree_add_item_format(tree, proto_eth, 0, offset,
		NULL, "IEEE 802.3 %s", (ethhdr_type == ETHERNET_802_3 ? "Raw " : ""));

	fh_tree = proto_item_add_subtree(ti, ETT_IEEE8023);

	proto_tree_add_item(fh_tree, hf_eth_dst, 0, 6, &pd[0]);
	proto_tree_add_item_hidden(fh_tree, hf_eth_dst_vendor, 0, 3, &pd[0]);
	proto_tree_add_item(fh_tree, hf_eth_src, 6, 6, &pd[6]);
	proto_tree_add_item_hidden(fh_tree, hf_eth_src_vendor, 6, 3, &pd[6]);
	proto_tree_add_item(fh_tree, hf_eth_len, 12, 2, length);
    }

  } else {
    ethhdr_type = ETHERNET_II;
    if (tree) {

	ti = proto_tree_add_item_format(tree, proto_eth, 0, 14, NULL,
		"Ethernet II");

	fh_tree = proto_item_add_subtree(ti, ETT_ETHER2);

	proto_tree_add_item_format(fh_tree, hf_eth_dst, 0, 6, &pd[0],
		"Destination: %s (%s)", ether_to_str((guint8 *) &pd[0]),
		get_ether_name((u_char *) &pd[0]));

	proto_tree_add_item_format(fh_tree, hf_eth_src, 6, 6, &pd[6],
		"Source: %s (%s)", ether_to_str((guint8 *) &pd[6]),
		get_ether_name((u_char *) &pd[6]));

    }
  }

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
	const hf_register_info hf[] = {
		{ "Destination",	"eth.dst", &hf_eth_dst, FT_ETHER, NULL },
		{ "Source",		"eth.src", &hf_eth_src, FT_ETHER, NULL },
		{ "Destination Hardware Vendor", "eth.dst_vendor", &hf_eth_dst_vendor, FT_ETHER, NULL },
		{ "Source Hardware Vendor", "eth.src_vendor", &hf_eth_src_vendor, FT_ETHER, NULL },
		{ "Length",		"eth.len", &hf_eth_len, FT_UINT16, NULL },

		/* registered here but handled in ethertype.c */	
		{ "Type",		"eth.type", &hf_eth_type, FT_VALS_UINT16, VALS(etype_vals) }
	};

	proto_eth = proto_register_protocol ("Ethernet", "eth" );
	proto_register_field_array(proto_eth, hf, array_length(hf));
}
