/* packet-eth.c
 * Routines for ethernet packet disassembly
 *
 * $Id$
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
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/addr_resolv.h>
#include "packet-eth.h"
#include "packet-ieee8023.h"
#include "packet-ipx.h"
#include "packet-isl.h"
#include "packet-llc.h"
#include <epan/crc32.h>
#include <epan/tap.h>

/* Interpret packets as FW1 monitor file packets if they look as if they are */
static gboolean eth_interpret_as_fw1_monitor = FALSE;

/* protocols and header fields */
static int proto_eth = -1;
static int hf_eth_dst = -1;
static int hf_eth_src = -1;
static int hf_eth_len = -1;
static int hf_eth_type = -1;
static int hf_eth_addr = -1;
static int hf_eth_trailer = -1;

static gint ett_ieee8023 = -1;
static gint ett_ether2 = -1;

static dissector_handle_t fw1_handle;
static heur_dissector_list_t heur_subdissector_list;

static int eth_tap = -1;

#define ETH_HEADER_SIZE	14

/* These are the Netware-ish names for the different Ethernet frame types.
	EthernetII: The ethernet with a Type field instead of a length field
	Ethernet802.2: An 802.3 header followed by an 802.2 header
	Ethernet802.3: A raw 802.3 packet. IPX/SPX can be the only payload.
			There's no 802.2 hdr in this.
	EthernetSNAP: Basically 802.2, just with 802.2SNAP. For our purposes,
		there's no difference between 802.2 and 802.2SNAP, since we just
		pass it down to the LLC dissector. -- Gilbert
*/
#define ETHERNET_II 	0
#define ETHERNET_802_2	1
#define ETHERNET_802_3	2
#define ETHERNET_SNAP	3

void
capture_eth(const guchar *pd, int offset, int len, packet_counts *ld)
{
  guint16    etype, length;
  int     ethhdr_type;	/* the type of ethernet frame */

  if (!BYTES_ARE_IN_FRAME(offset, len, ETH_HEADER_SIZE)) {
    ld->other++;
    return;
  }

  etype = pntohs(&pd[offset+12]);

  if (etype <= IEEE_802_3_MAX_LEN) {
    /* Oh, yuck.  Cisco ISL frames require special interpretation of the
       destination address field; fortunately, they can be recognized by
       checking the first 5 octets of the destination address, which are
       01-00-0C-00-00 or 0C-00-0C-00-00 for ISL frames. */
    if ((pd[offset] == 0x01 || pd[offset] == 0x0C) && pd[offset+1] == 0x00
        && pd[offset+2] == 0x0C && pd[offset+3] == 0x00
	&& pd[offset+4] == 0x00) {
      capture_isl(pd, offset, len, ld);
      return;
    }
  }

  /*
   * If the type/length field is <= the maximum 802.3 length,
   * and is not zero, this is an 802.3 frame, and it's a length
   * field; it might be an Novell "raw 802.3" frame, with no
   * 802.2 LLC header, or it might be a frame with an 802.2 LLC
   * header.
   *
   * If the type/length field is > the maximum 802.3 length,
   * this is an Ethernet II frame, and it's a type field.
   *
   * If the type/length field is zero (ETHERTYPE_UNK), this is
   * a frame used internally by the Cisco MDS switch to contain
   * Fibre Channel ("Vegas").  We treat that as an Ethernet II
   * frame; the dissector for those frames registers itself with
   * an ethernet type of ETHERTYPE_UNK.
   */
  if (etype <= IEEE_802_3_MAX_LEN && etype != ETHERTYPE_UNK) {
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

    /* Convert the LLC length from the 802.3 header to a total
       frame length, by adding in the size of any data that preceded
       the Ethernet header, and adding in the Ethernet header size,
       and set the payload and captured-payload lengths to the minima
       of the total length and the frame lengths. */
    length += offset + ETH_HEADER_SIZE;
    if (len > length)
      len = length;
  } else {
    ethhdr_type = ETHERNET_II;
  }
  offset += ETH_HEADER_SIZE;

  switch (ethhdr_type) {
    case ETHERNET_802_3:
      capture_ipx(ld);
      break;
    case ETHERNET_802_2:
      capture_llc(pd, offset, len, ld);
      break;
    case ETHERNET_II:
      capture_ethertype(etype, pd, offset, len, ld);
      break;
  }
}

static void
dissect_eth_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
	int fcs_len)
{
  proto_item		*ti;
  eth_hdr 		*volatile ehdr;
  volatile gboolean	is_802_2;
  proto_tree		*volatile fh_tree = NULL;
  const guint8		*src_addr, *dst_addr;
  static eth_hdr 	ehdrs[4];
  static int		ehdr_num=0;
  proto_tree		*volatile tree;

  ehdr_num++;
  if(ehdr_num>=4){
     ehdr_num=0;
  }
  ehdr=&ehdrs[ehdr_num];

  tree=parent_tree;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Ethernet");

  src_addr=tvb_get_ptr(tvb, 6, 6);
  SET_ADDRESS(&pinfo->dl_src,	AT_ETHER, 6, src_addr);
  SET_ADDRESS(&pinfo->src,	AT_ETHER, 6, src_addr);
  SET_ADDRESS(&ehdr->src, 	AT_ETHER, 6, src_addr);
  dst_addr=tvb_get_ptr(tvb, 0, 6);
  SET_ADDRESS(&pinfo->dl_dst,	AT_ETHER, 6, dst_addr);
  SET_ADDRESS(&pinfo->dst,	AT_ETHER, 6, dst_addr);
  SET_ADDRESS(&ehdr->dst, 	AT_ETHER, 6, dst_addr);

  ehdr->type = tvb_get_ntohs(tvb, 12);

  /*
   * In case the packet is a non-Ethernet packet inside
   * Ethernet framing, allow heuristic dissectors to take
   * a first look before we assume that it's actually an
   * Ethernet packet.
   */
  if (dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, parent_tree))
    goto end_of_eth;

  if (ehdr->type <= IEEE_802_3_MAX_LEN) {
    /* Oh, yuck.  Cisco ISL frames require special interpretation of the
       destination address field; fortunately, they can be recognized by
       checking the first 5 octets of the destination address, which are
       01-00-0C-00-00 for ISL frames. */
    if (	(tvb_get_guint8(tvb, 0) == 0x01 ||
		 tvb_get_guint8(tvb, 0) == 0x0C) &&
		tvb_get_guint8(tvb, 1) == 0x00 &&
		tvb_get_guint8(tvb, 2) == 0x0C &&
		tvb_get_guint8(tvb, 3) == 0x00 &&
		tvb_get_guint8(tvb, 4) == 0x00 ) {
      dissect_isl(tvb, pinfo, parent_tree, fcs_len);
      goto end_of_eth;
    }
  }

  /*
   * If the type/length field is <= the maximum 802.3 length,
   * and is not zero, this is an 802.3 frame, and it's a length
   * field; it might be an Novell "raw 802.3" frame, with no
   * 802.2 LLC header, or it might be a frame with an 802.2 LLC
   * header.
   *
   * If the type/length field is > the maximum 802.3 length,
   * this is an Ethernet II frame, and it's a type field.
   *
   * If the type/length field is zero (ETHERTYPE_UNK), this is
   * a frame used internally by the Cisco MDS switch to contain
   * Fibre Channel ("Vegas").  We treat that as an Ethernet II
   * frame; the dissector for those frames registers itself with
   * an ethernet type of ETHERTYPE_UNK.
   */
  if (ehdr->type <= IEEE_802_3_MAX_LEN && ehdr->type != ETHERTYPE_UNK) {
    /* Is there an 802.2 layer? I can tell by looking at the first 2
       bytes after the 802.3 header. If they are 0xffff, then what
       follows the 802.3 header is an IPX payload, meaning no 802.2.
       (IPX/SPX is they only thing that can be contained inside a
       straight 802.3 packet). A non-0xffff value means that there's an
       802.2 layer inside the 802.3 layer */
    is_802_2 = TRUE;
    TRY {
	    if (tvb_get_ntohs(tvb, 14) == 0xffff) {
	      is_802_2 = FALSE;
	    }
    }
    CATCH2(BoundsError, ReportedBoundsError) {
	    ; /* do nothing */

    }
    ENDTRY;

    if (check_col(pinfo->cinfo, COL_INFO)) {
      col_add_fstr(pinfo->cinfo, COL_INFO, "IEEE 802.3 Ethernet %s",
		(is_802_2 ? "" : "Raw "));
    }
    if (tree) {
      ti = proto_tree_add_protocol_format(tree, proto_eth, tvb, 0, ETH_HEADER_SIZE,
		"IEEE 802.3 Ethernet %s", (is_802_2 ? "" : "Raw "));

      fh_tree = proto_item_add_subtree(ti, ett_ieee8023);
    }

    /* if IP is not referenced from any filters we dont need to worry about
       generating any tree items.  We must do this after we created the actual
       protocol above so that proto hier stat still works though.
    */
    if(!proto_field_is_referenced(parent_tree, proto_eth)){
      tree=NULL;
      fh_tree=NULL;
    }

    proto_tree_add_ether(fh_tree, hf_eth_dst, tvb, 0, 6, dst_addr);
    proto_tree_add_ether(fh_tree, hf_eth_src, tvb, 6, 6, src_addr);

/* add items for eth.addr filter */
    proto_tree_add_ether_hidden(fh_tree, hf_eth_addr, tvb, 0, 6, dst_addr);
    proto_tree_add_ether_hidden(fh_tree, hf_eth_addr, tvb, 6, 6, src_addr);

    dissect_802_3(ehdr->type, is_802_2, tvb, ETH_HEADER_SIZE, pinfo, parent_tree, fh_tree,
		  hf_eth_len, hf_eth_trailer, fcs_len);
  } else {
    if (eth_interpret_as_fw1_monitor) {
	if ((dst_addr[0] == 'i') || (dst_addr[0] == 'I') ||
	    (dst_addr[0] == 'o') || (dst_addr[0] == 'O')) {
	  call_dissector(fw1_handle, tvb, pinfo, parent_tree);
	  goto end_of_eth;
	}
    }

    if (check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "Ethernet II");
    if (parent_tree) {
      ti = proto_tree_add_protocol_format(parent_tree, proto_eth, tvb, 0, ETH_HEADER_SIZE,
		"Ethernet II, Src: %s (%s), Dst: %s (%s)",
		get_ether_name(src_addr), ether_to_str(src_addr), get_ether_name(dst_addr), ether_to_str(dst_addr));

      fh_tree = proto_item_add_subtree(ti, ett_ether2);
    }

    proto_tree_add_ether(fh_tree, hf_eth_dst, tvb, 0, 6, dst_addr);
    proto_tree_add_ether(fh_tree, hf_eth_src, tvb, 6, 6, src_addr);
/* add items for eth.addr filter */
    proto_tree_add_ether_hidden(fh_tree, hf_eth_addr, tvb, 0, 6, dst_addr);
    proto_tree_add_ether_hidden(fh_tree, hf_eth_addr, tvb, 6, 6, src_addr);

    ethertype(ehdr->type, tvb, ETH_HEADER_SIZE, pinfo, parent_tree, fh_tree, hf_eth_type,
          hf_eth_trailer, fcs_len);
  }

end_of_eth:
  tap_queue_packet(eth_tap, pinfo, ehdr);
  return;
}

/*
 * Add an Ethernet trailer - which, for some captures, might be the FCS
 * rather than a pad-to-60-bytes trailer.
 *
 * If fcs_len is 0, we assume the frame has no FCS; if it's 4, we assume
 * it has an FCS; if it's anything else (such as -1, which means "maybe
 * it does, maybe it doesn't"), we try to infer whether it has an FCS.
 */
void
add_ethernet_trailer(proto_tree *fh_tree, int trailer_id, tvbuff_t *tvb,
		     tvbuff_t *trailer_tvb, int fcs_len)
{
  /* If there're some bytes left over, show those bytes as a trailer.

     However, if the Ethernet frame was claimed to have had 64 or more
     bytes - i.e., it was at least an FCS worth of data longer than
     the minimum payload size - assume the last 4 bytes of the trailer
     are an FCS. */
  if (trailer_tvb && fh_tree) {
    guint trailer_length, trailer_reported_length;
    gboolean has_fcs = FALSE;

    trailer_length = tvb_length(trailer_tvb);
    trailer_reported_length = tvb_reported_length(trailer_tvb);
    if (fcs_len != 0) {
      /* If fcs_len is 4, we assume we definitely have an FCS.
         Otherwise, then, if the frame is big enough that, if we
         have a trailer, it probably inclues an FCS, and we have
         enough space in the trailer for the FCS, we assume we
         have an FCS.

	 "Big enough" means 64 bytes or more; any frame that big
	 needs no trailer, as there's no need to pad an Ethernet
	 packet past 60 bytes.

	 The trailer must be at least 4 bytes long to have enough
	 space for an FCS. */

      if (fcs_len == 4 || (tvb_reported_length(tvb) >= 64 &&
			   trailer_reported_length >= 4)) {
	/* Either we know we have an FCS, or we believe we have an FCS. */
	if (trailer_length < trailer_reported_length) {
	  /* The packet is claimed to have enough data for a 4-byte FCS,
	     but we didn't capture all of the packet.
	     Slice off the 4-byte FCS from the reported length, and
	     trim the captured length so it's no more than the reported
	     length; that will slice off what of the FCS, if any, is
	     in the captured packet. */
	  trailer_reported_length -= 4;
	  if (trailer_length > trailer_reported_length)
	    trailer_length = trailer_reported_length;
	  has_fcs = TRUE;
	} else {
	  /* We captured all of the packet, including what appears to
	     be a 4-byte FCS.  Slice it off. */
	  trailer_length -= 4;
	  trailer_reported_length -= 4;
	  has_fcs = TRUE;
	}
      }
    }
    if (trailer_length != 0) {
      tvb_ensure_bytes_exist(tvb, 0, trailer_length);
      proto_tree_add_item(fh_tree, trailer_id, trailer_tvb, 0,
			  trailer_length, FALSE);
    }
    if (has_fcs) {
      guint32 sent_fcs = tvb_get_ntohl(trailer_tvb, trailer_length);
      guint32 fcs = crc32_802_tvb(tvb, tvb_length(tvb) - 4);
      if (fcs == sent_fcs) {
	proto_tree_add_text(fh_tree, trailer_tvb, trailer_length, 4,
			    "Frame check sequence: 0x%08x [correct]",
			    sent_fcs);
      } else {
	proto_tree_add_text(fh_tree, trailer_tvb, trailer_length, 4,
			    "Frame check sequence: 0x%08x [incorrect, should be 0x%08x]",
			    sent_fcs, fcs);
      }
    }
  }
}

/* Called for the Ethernet Wiretap encapsulation type; pass the FCS length
   reported to us. */
static void
dissect_eth_maybefcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_eth_common(tvb, pinfo, tree, pinfo->pseudo_header->eth.fcs_len);
}

/* Called by other dissectors  This one's for encapsulated Ethernet
   packets that don't include an FCS. */
static void
dissect_eth_withoutfcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_eth_common(tvb, pinfo, tree, 0);
}

/* ...and this one's for encapsulated packets that do. */
static void
dissect_eth_withfcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_eth_common(tvb, pinfo, tree, 4);
}

void
proto_register_eth(void)
{
	static hf_register_info hf[] = {

		{ &hf_eth_dst,
		{ "Destination",	"eth.dst", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Destination Hardware Address", HFILL }},

		{ &hf_eth_src,
		{ "Source",		"eth.src", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Source Hardware Address", HFILL }},

		{ &hf_eth_len,
		{ "Length",		"eth.len", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		/* registered here but handled in ethertype.c */
		{ &hf_eth_type,
		{ "Type",		"eth.type", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
			"", HFILL }},
		{ &hf_eth_addr,
		{ "Source or Destination Address", "eth.addr", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Source or Destination Hardware Address", HFILL }},

                { &hf_eth_trailer,
		{ "Trailer", "eth.trailer", FT_BYTES, BASE_NONE, NULL, 0x0,
			"Ethernet Trailer or Checksum", HFILL }},

	};
	static gint *ett[] = {
		&ett_ieee8023,
		&ett_ether2,
	};
	module_t *eth_module;

	proto_eth = proto_register_protocol("Ethernet", "Ethernet", "eth");
	proto_register_field_array(proto_eth, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	register_heur_dissector_list("eth", &heur_subdissector_list);

	/* Register configuration preferences */
	eth_module = prefs_register_protocol(proto_eth, NULL);
	prefs_register_bool_preference(eth_module, "interpret_as_fw1_monitor",
            "Attempt to interpret as FireWall-1 monitor file",
            "Whether packets should be interpreted as coming from CheckPoint FireWall-1 monitor file if they look as if they do",
            &eth_interpret_as_fw1_monitor);

	register_dissector("eth_withoutfcs", dissect_eth_withoutfcs, proto_eth);
	register_dissector("eth_withfcs", dissect_eth_withfcs, proto_eth);
	eth_tap = register_tap("eth");
}

void
proto_reg_handoff_eth(void)
{
	dissector_handle_t eth_maybefcs_handle, eth_withoutfcs_handle;

	/*
	 * Get a handle for the Firewall-1 dissector.
	 */
	fw1_handle = find_dissector("fw1");

	eth_maybefcs_handle = create_dissector_handle(dissect_eth_maybefcs,
	    proto_eth);
	dissector_add("wtap_encap", WTAP_ENCAP_ETHERNET, eth_maybefcs_handle);

	eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
	dissector_add("ethertype", ETHERTYPE_ETHBRIDGE, eth_withoutfcs_handle);
	dissector_add("chdlctype", ETHERTYPE_ETHBRIDGE, eth_withoutfcs_handle);
	dissector_add("gre.proto", ETHERTYPE_ETHBRIDGE, eth_withoutfcs_handle);
}
