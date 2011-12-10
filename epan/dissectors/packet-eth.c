/* packet-eth.c
 * Routines for ethernet packet disassembly
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
#include "packet-sll.h"
#include "packet-usb.h"
#include <epan/crc32-tvb.h>
#include <epan/tap.h>
#include <epan/expert.h>

/* Assume all packets have an FCS */
static gboolean eth_assume_padding = TRUE;
static gboolean eth_assume_fcs = FALSE;
static gboolean eth_check_fcs = TRUE;
/* Interpret packets as FW1 monitor file packets if they look as if they are */
static gboolean eth_interpret_as_fw1_monitor = FALSE;
/* Preference settings defining conditions for which the CCSDS dissector is called */
static gboolean ccsds_heuristic_length = FALSE;
static gboolean ccsds_heuristic_version = FALSE;
static gboolean ccsds_heuristic_header = FALSE;
static gboolean ccsds_heuristic_bit = FALSE;

/* protocols and header fields */
static int proto_eth = -1;
static int hf_eth_dst = -1;
static int hf_eth_src = -1;
static int hf_eth_len = -1;
static int hf_eth_type = -1;
static int hf_eth_invalid_lentype = -1;
static int hf_eth_addr = -1;
static int hf_eth_lg = -1;
static int hf_eth_ig = -1;
static int hf_eth_padding = -1;
static int hf_eth_trailer = -1;
static int hf_eth_fcs = -1;
static int hf_eth_fcs_good = -1;
static int hf_eth_fcs_bad = -1;

static gint ett_ieee8023 = -1;
static gint ett_ether2 = -1;
static gint ett_ether = -1;
static gint ett_addr = -1;
static gint ett_eth_fcs = -1;

static dissector_handle_t fw1_handle;
static dissector_handle_t data_handle;
static heur_dissector_list_t heur_subdissector_list;
static heur_dissector_list_t eth_trailer_subdissector_list;

static int eth_tap = -1;

#define ETH_HEADER_SIZE    14

static const true_false_string ig_tfs = {
    "Group address (multicast/broadcast)",
    "Individual address (unicast)"
};
static const true_false_string lg_tfs = {
    "Locally administered address (this is NOT the factory default)",
    "Globally unique address (factory default)"
};

/* These are the Netware-ish names for the different Ethernet frame types.
    EthernetII: The ethernet with a Type field instead of a length field
    Ethernet802.2: An 802.3 header followed by an 802.2 header
    Ethernet802.3: A raw 802.3 packet. IPX/SPX can be the only payload.
            There's no 802.2 hdr in this.
    EthernetSNAP: Basically 802.2, just with 802.2SNAP. For our purposes,
        there's no difference between 802.2 and 802.2SNAP, since we just
        pass it down to the LLC dissector. -- Gilbert
*/
#define ETHERNET_II     0
#define ETHERNET_802_2  1
#define ETHERNET_802_3  2
#define ETHERNET_SNAP   3

void
capture_eth(const guchar *pd, int offset, int len, packet_counts *ld)
{
  guint16 etype, length;
  int ethhdr_type;          /* the type of ethernet frame */

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
   * If the type/length field is >= the minimum Ethernet II length,
   * this is an Ethernet II frame, and it's a type field.
   *
   * If the type/length field is > maximum 802.3 length and < minimum
   * Ethernet II length, then this is an invalid packet.
   *
   * If the type/length field is zero (ETHERTYPE_UNK), this is
   * a frame used internally by the Cisco MDS switch to contain
   * Fibre Channel ("Vegas").  We treat that as an Ethernet II
   * frame; the dissector for those frames registers itself with
   * an ethernet type of ETHERTYPE_UNK.
   */
  if (etype > IEEE_802_3_MAX_LEN && etype < ETHERNET_II_MIN_LEN) {
    ld->other++;
    return;
  }

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

static gboolean check_is_802_2(tvbuff_t *tvb, int fcs_len);

static void
dissect_eth_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
    int fcs_len)
{
  proto_item        *ti = NULL;
  eth_hdr           *ehdr;
  gboolean          is_802_2;
  proto_tree        *fh_tree = NULL;
  const guint8      *src_addr, *dst_addr;
  static eth_hdr    ehdrs[4];
  static int        ehdr_num=0;
  proto_tree        *tree;
  proto_item        *addr_item;
  proto_tree        *addr_tree=NULL;

  ehdr_num++;
  if(ehdr_num>=4){
     ehdr_num=0;
  }
  ehdr=&ehdrs[ehdr_num];

  tree=parent_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Ethernet");

  src_addr=tvb_get_ptr(tvb, 6, 6);
  SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, src_addr);
  SET_ADDRESS(&pinfo->src, AT_ETHER, 6, src_addr);
  SET_ADDRESS(&ehdr->src, AT_ETHER, 6, src_addr);
  dst_addr=tvb_get_ptr(tvb, 0, 6);
  SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dst_addr);
  SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dst_addr);
  SET_ADDRESS(&ehdr->dst, AT_ETHER, 6, dst_addr);

  ehdr->type = tvb_get_ntohs(tvb, 12);

  tap_queue_packet(eth_tap, pinfo, ehdr);

  /*
   * In case the packet is a non-Ethernet packet inside
   * Ethernet framing, allow heuristic dissectors to take
   * a first look before we assume that it's actually an
   * Ethernet packet.
   */
  if (dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, parent_tree))
    return;

  if (ehdr->type <= IEEE_802_3_MAX_LEN) {
    /* Oh, yuck.  Cisco ISL frames require special interpretation of the
       destination address field; fortunately, they can be recognized by
       checking the first 5 octets of the destination address, which are
       01-00-0C-00-00 for ISL frames. */
    if ((tvb_get_guint8(tvb, 0) == 0x01 ||
      tvb_get_guint8(tvb, 0) == 0x0C) &&
      tvb_get_guint8(tvb, 1) == 0x00 &&
      tvb_get_guint8(tvb, 2) == 0x0C &&
      tvb_get_guint8(tvb, 3) == 0x00 &&
      tvb_get_guint8(tvb, 4) == 0x00) {
      dissect_isl(tvb, pinfo, parent_tree, fcs_len);
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
   * If the type/length field is >= the minimum Ethernet II length,
   * this is an Ethernet II frame, and it's a type field.
   *
   * If the type/length field is > maximum 802.3 length and < minimum
   * Ethernet II length, then this is an invalid packet.
   *
   * If the type/length field is zero (ETHERTYPE_UNK), this is
   * a frame used internally by the Cisco MDS switch to contain
   * Fibre Channel ("Vegas").  We treat that as an Ethernet II
   * frame; the dissector for those frames registers itself with
   * an ethernet type of ETHERTYPE_UNK.
   */
  if (ehdr->type > IEEE_802_3_MAX_LEN && ehdr->type < ETHERNET_II_MIN_LEN) {
    tvbuff_t *next_tvb;

    col_add_fstr(pinfo->cinfo, COL_INFO,
        "Ethernet Unknown: Invalid length/type: 0x%04x (%d)",
        ehdr->type, ehdr->type);
    ti = proto_tree_add_protocol_format(tree, proto_eth, tvb, 0, ETH_HEADER_SIZE,
        "Ethernet Unknown, Src: %s (%s), Dst: %s (%s)",
        get_ether_name(src_addr), ether_to_str(src_addr),
        get_ether_name(dst_addr), ether_to_str(dst_addr));
    fh_tree = proto_item_add_subtree(ti, ett_ether);
    addr_item = proto_tree_add_ether(fh_tree, hf_eth_dst, tvb, 0, 6, dst_addr);
    if (addr_item)
        addr_tree = proto_item_add_subtree(addr_item, ett_addr);
    proto_tree_add_ether(addr_tree, hf_eth_addr, tvb, 0, 6, dst_addr);
    proto_tree_add_item(addr_tree, hf_eth_lg, tvb, 0, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(addr_tree, hf_eth_ig, tvb, 0, 3, ENC_BIG_ENDIAN);

    addr_item = proto_tree_add_ether(fh_tree, hf_eth_src, tvb, 6, 6, src_addr);
    if (addr_item)
        addr_tree = proto_item_add_subtree(addr_item, ett_addr);
    proto_tree_add_ether(addr_tree, hf_eth_addr, tvb, 6, 6, src_addr);
    proto_tree_add_item(addr_tree, hf_eth_lg, tvb, 6, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(addr_tree, hf_eth_ig, tvb, 6, 3, ENC_BIG_ENDIAN);

    ti = proto_tree_add_item(fh_tree, hf_eth_invalid_lentype, tvb, 12, 2, ENC_BIG_ENDIAN);
    expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN,
        "Invalid length/type: 0x%04x (%d)", ehdr->type, ehdr->type);
    next_tvb = tvb_new_subset_remaining(tvb, 14);
    call_dissector(data_handle, next_tvb, pinfo, parent_tree);
    return;
  }

  if (ehdr->type <= IEEE_802_3_MAX_LEN && ehdr->type != ETHERTYPE_UNK) {

    is_802_2 = check_is_802_2(tvb, fcs_len);

     col_add_fstr(pinfo->cinfo, COL_INFO, "IEEE 802.3 Ethernet %s",
        (is_802_2 ? "" : "Raw "));
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

    addr_item=proto_tree_add_ether(fh_tree, hf_eth_dst, tvb, 0, 6, dst_addr);
    if(addr_item){
        addr_tree = proto_item_add_subtree(addr_item, ett_addr);
    }
    proto_tree_add_ether(addr_tree, hf_eth_addr, tvb, 0, 6, dst_addr);
    proto_tree_add_item(addr_tree, hf_eth_lg, tvb, 0, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(addr_tree, hf_eth_ig, tvb, 0, 3, ENC_BIG_ENDIAN);

    addr_item=proto_tree_add_ether(fh_tree, hf_eth_src, tvb, 6, 6, src_addr);
    if(addr_item){
        addr_tree = proto_item_add_subtree(addr_item, ett_addr);
    }
    proto_tree_add_ether(addr_tree, hf_eth_addr, tvb, 6, 6, src_addr);
    proto_tree_add_item(addr_tree, hf_eth_lg, tvb, 6, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(addr_tree, hf_eth_ig, tvb, 6, 3, ENC_BIG_ENDIAN);

    dissect_802_3(ehdr->type, is_802_2, tvb, ETH_HEADER_SIZE, pinfo,
        parent_tree, fh_tree, hf_eth_len, hf_eth_trailer, fcs_len);
  } else {
    if (eth_interpret_as_fw1_monitor) {
        if ((dst_addr[0] == 'i') || (dst_addr[0] == 'I') ||
            (dst_addr[0] == 'o') || (dst_addr[0] == 'O')) {
            call_dissector(fw1_handle, tvb, pinfo, parent_tree);
            return;
        }
    }

    col_set_str(pinfo->cinfo, COL_INFO, "Ethernet II");
    if (parent_tree) {
        if (PTREE_DATA(parent_tree)->visible) {
            ti = proto_tree_add_protocol_format(parent_tree, proto_eth, tvb, 0, ETH_HEADER_SIZE,
                "Ethernet II, Src: %s (%s), Dst: %s (%s)",
                get_ether_name(src_addr), ether_to_str(src_addr),
                get_ether_name(dst_addr), ether_to_str(dst_addr));
      }
      else {
            ti = proto_tree_add_item(parent_tree, proto_eth, tvb, 0, ETH_HEADER_SIZE, ENC_NA);
      }
      fh_tree = proto_item_add_subtree(ti, ett_ether2);
    }

    addr_item=proto_tree_add_ether(fh_tree, hf_eth_dst, tvb, 0, 6, dst_addr);
    if(addr_item){
        addr_tree = proto_item_add_subtree(addr_item, ett_addr);
    }
    proto_tree_add_ether(addr_tree, hf_eth_addr, tvb, 0, 6, dst_addr);
    proto_tree_add_item(addr_tree, hf_eth_lg, tvb, 0, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(addr_tree, hf_eth_ig, tvb, 0, 3, ENC_BIG_ENDIAN);

    addr_item=proto_tree_add_ether(fh_tree, hf_eth_src, tvb, 6, 6, src_addr);
    if(addr_item){
        addr_tree = proto_item_add_subtree(addr_item, ett_addr);
        if (tvb_get_guint8(tvb, 6) & 0x01) {
            expert_add_info_format(pinfo, addr_item, PI_PROTOCOL, PI_WARN,
                "Source MAC must not be a group address: IEEE 802.3-2002, Section 3.2.3(b)");
        }
    }
    proto_tree_add_ether(addr_tree, hf_eth_addr, tvb, 6, 6, src_addr);
    proto_tree_add_item(addr_tree, hf_eth_lg, tvb, 6, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(addr_tree, hf_eth_ig, tvb, 6, 3, ENC_BIG_ENDIAN);

    ethertype(ehdr->type, tvb, ETH_HEADER_SIZE, pinfo, parent_tree, fh_tree, hf_eth_type,
          hf_eth_trailer, fcs_len);
  }
}

/* -------------- */
static gboolean check_is_802_2(tvbuff_t *tvb, int fcs_len)
{
  volatile gboolean is_802_2;
  volatile int length;
  gint captured_length, reported_length;

  is_802_2 = TRUE;

    /* Is there an 802.2 layer? I can tell by looking at the first 2
       bytes after the 802.3 header. If they are 0xffff, then what
       follows the 802.3 header is an IPX payload, meaning no 802.2.
       A non-0xffff value means that there's an 802.2 layer or CCSDS
       layer inside the 802.3 layer */

  TRY {
    if (tvb_get_ntohs(tvb, 14) == 0xffff) {
        is_802_2 = FALSE;
    }
    /* Is this a CCSDS payload instead of an 802.2 (LLC)?
       Check the conditions enabled by the user for CCSDS presence */
    else if (ccsds_heuristic_length || ccsds_heuristic_version ||
             ccsds_heuristic_header || ccsds_heuristic_bit) {
      gboolean CCSDS_len = TRUE;
      gboolean CCSDS_ver = TRUE;
      gboolean CCSDS_head = TRUE;
      gboolean CCSDS_bit = TRUE;
      /* See if the reported payload size matches the
         size contained in the CCSDS header. */
      if (ccsds_heuristic_length) {
        /* The following technique to account for FCS
           is copied from packet-ieee8023.c dissect_802_3() */
        length = tvb_get_ntohs(tvb, 12);
        reported_length = tvb_reported_length_remaining(tvb, ETH_HEADER_SIZE);
        if (fcs_len > 0) {
          if (reported_length >= fcs_len)
            reported_length -= fcs_len;
        }
        /* Make sure the length in the 802.3 header doesn't go past the end of
           the payload. */
        if (length > reported_length) {
          length = reported_length;
        }
        /* Only allow inspection of 'length' number of bytes. */
        captured_length = tvb_length_remaining(tvb, ETH_HEADER_SIZE);
        if (captured_length > length)
          captured_length = length;

        /* Check if payload is large enough to contain a CCSDS header */
        if (captured_length >= 6) {
          /* Compare length to packet length contained in CCSDS header. */
          if (length != 7 + tvb_get_ntohs(tvb, ETH_HEADER_SIZE + 4))
            CCSDS_len = FALSE;
        }
      }
      /* Check if CCSDS Version number (first 3 bits of payload) is zero */
      if ((ccsds_heuristic_version) && (tvb_get_bits8(tvb, 8*ETH_HEADER_SIZE, 3)!=0))
        CCSDS_ver = FALSE;
      /* Check if Secondary Header Flag (4th bit of payload) is set to one. */
      if ((ccsds_heuristic_header) && (tvb_get_bits8(tvb, 8*ETH_HEADER_SIZE + 4, 1)!=1))
        CCSDS_head = FALSE;
      /* Check if spare bit (1st bit of 7th word of payload) is zero. */
      if ((ccsds_heuristic_bit) && (tvb_get_bits8(tvb, 8*ETH_HEADER_SIZE + 16*6, 1)!=0))
        CCSDS_bit = FALSE;
      /* If all the conditions are true, don't interpret payload as an 802.2 (LLC).
       * Additional check in packet-802.3.c will distinguish between
       * IPX and CCSDS packets*/
      if (CCSDS_len && CCSDS_ver && CCSDS_head && CCSDS_bit)
        is_802_2 = FALSE;
    }
  }
  CATCH2(BoundsError, ReportedBoundsError) {
        ; /* do nothing */

  }
  ENDTRY;
  return is_802_2;
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
add_ethernet_trailer(packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
    int trailer_id, tvbuff_t *tvb, tvbuff_t *trailer_tvb, int fcs_len)
{
  /* If there're some bytes left over, it could be a combination of:
     - padding to meet the minimum 64 byte frame length
     - an FCS, if present (if fcs_len is 0, we know it's not present;
       if fcs_len is 4, we know it's present; if fcs_len is -1, we
       need some heuristics to determine whether it's present)
     - information inserted by TAPs or other network monitoring equipment.
    
     If we don't know whether the FCS is present, then, if we don't have a
     network monitoring trailer, and if the Ethernet frame was claimed to
     have had 64 or more bytes - i.e., it was at least an FCS worth of data
     longer than the minimum payload size - we could assume the last 4 bytes
     of the trailer are an FCS. */
  proto_item *item;
  proto_tree *checksum_tree;

  if (trailer_tvb && fh_tree) {
    guint trailer_length, trailer_reported_length;
    guint padding_length = 0;
    gboolean has_fcs = FALSE;
    tvbuff_t *real_trailer_tvb;

    trailer_length = tvb_length(trailer_tvb);
    trailer_reported_length = tvb_reported_length(trailer_tvb);

    /* There can not have been padding when the length of the frame (including the 
       trailer) is less than 60 bytes. */
    if (eth_assume_padding && pinfo->fd->pkt_len>=60) {
        /* Calculate the amount of padding needed for a minimum sized frame */
        if ( (pinfo->fd->pkt_len - trailer_reported_length) < 60 )
            padding_length = 60 - (pinfo->fd->pkt_len - trailer_reported_length);

        /* Add the padding to the tree, unless it should be treated as 
           part of the trailer and therefor be handed over to (one of) 
           the ethernet-trailer dissectors */
        if (padding_length > 0) {
            tvb_ensure_bytes_exist(tvb, 0, padding_length);
            proto_tree_add_item(fh_tree, hf_eth_padding, trailer_tvb, 0,
                padding_length, FALSE);
            trailer_length -= padding_length;
            trailer_reported_length -= padding_length;
        }
    }
    real_trailer_tvb = tvb_new_subset_remaining(trailer_tvb, padding_length);

    /* Call all ethernet trailer dissectors to dissect the trailer if
       we actually have a trailer.  */
    if (tvb_reported_length(real_trailer_tvb) != 0) {
      if (dissector_try_heuristic(eth_trailer_subdissector_list, 
                                   real_trailer_tvb, pinfo, tree) ) 
        return;
    }
    
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
      proto_tree_add_item(fh_tree, trailer_id, real_trailer_tvb, 0,
        trailer_length, FALSE);
    }
    if (has_fcs) {
      guint32 sent_fcs = tvb_get_ntohl(real_trailer_tvb, trailer_length);
      if(eth_check_fcs){
        guint32 fcs = crc32_802_tvb(tvb, tvb_length(tvb) - 4);
        if (fcs == sent_fcs) {
          item = proto_tree_add_uint_format(fh_tree, hf_eth_fcs, real_trailer_tvb,
                                            trailer_length, 4, sent_fcs,
                                            "Frame check sequence: 0x%08x [correct]", sent_fcs);
          checksum_tree = proto_item_add_subtree(item, ett_eth_fcs);
          item = proto_tree_add_boolean(checksum_tree, hf_eth_fcs_good, tvb,
                                        trailer_length, 2, TRUE);
          PROTO_ITEM_SET_GENERATED(item);
          item = proto_tree_add_boolean(checksum_tree, hf_eth_fcs_bad, tvb,
                                        trailer_length, 2, FALSE);
          PROTO_ITEM_SET_GENERATED(item);
        } else {
          item = proto_tree_add_uint_format(fh_tree, hf_eth_fcs, real_trailer_tvb,
                                            trailer_length, 4, sent_fcs,
                                            "Frame check sequence: 0x%08x [incorrect, should be 0x%08x]",
                                            sent_fcs, fcs);
          checksum_tree = proto_item_add_subtree(item, ett_eth_fcs);
          item = proto_tree_add_boolean(checksum_tree, hf_eth_fcs_good, tvb,
                                        trailer_length, 2, FALSE);
          PROTO_ITEM_SET_GENERATED(item);
          item = proto_tree_add_boolean(checksum_tree, hf_eth_fcs_bad, tvb,
                                        trailer_length, 2, TRUE);
          PROTO_ITEM_SET_GENERATED(item);
          expert_add_info_format(pinfo, item, PI_CHECKSUM, PI_ERROR, "Bad checksum");
          col_append_str(pinfo->cinfo, COL_INFO, " [ETHERNET FRAME CHECK SEQUENCE INCORRECT]");
        }
      }else{
        item = proto_tree_add_uint_format(fh_tree, hf_eth_fcs, real_trailer_tvb,
                                          trailer_length, 4, sent_fcs,
                                          "Frame check sequence: 0x%08x [validiation disabled]", sent_fcs);
        checksum_tree = proto_item_add_subtree(item, ett_eth_fcs);
        item = proto_tree_add_boolean(checksum_tree, hf_eth_fcs_good, tvb,
                                      trailer_length, 2, FALSE);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_boolean(checksum_tree, hf_eth_fcs_bad, tvb,
                                      trailer_length, 2, FALSE);
        PROTO_ITEM_SET_GENERATED(item);
      }
      trailer_length += 4;
    }
    proto_tree_set_appendix(fh_tree, tvb, tvb_length(tvb) - trailer_length, trailer_length);
  }
}

/* Called for the Ethernet Wiretap encapsulation type; pass the FCS length
   reported to us, or, if the "assume_fcs" preference is set, pass 4. */
static void
dissect_eth_maybefcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_eth_common(tvb, pinfo, tree,
                     eth_assume_fcs ? 4 :
                     pinfo->pseudo_header->eth.fcs_len);
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
        { "Destination", "eth.dst", FT_ETHER, BASE_NONE, NULL, 0x0,
            "Destination Hardware Address", HFILL }},

        { &hf_eth_src,
        { "Source", "eth.src", FT_ETHER, BASE_NONE, NULL, 0x0,
            "Source Hardware Address", HFILL }},

        { &hf_eth_len,
        { "Length", "eth.len", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        /* registered here but handled in packet-ethertype.c */
        { &hf_eth_type,
        { "Type", "eth.type", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
            NULL, HFILL }},

        { &hf_eth_invalid_lentype,
        { "Invalid length/type", "eth.invalid_lentype", FT_UINT16, BASE_HEX_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_eth_addr,
        { "Address", "eth.addr", FT_ETHER, BASE_NONE, NULL, 0x0,
            "Source or Destination Hardware Address", HFILL }},

        { &hf_eth_padding,
        { "Padding", "eth.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
            "Ethernet Padding", HFILL }},

        { &hf_eth_trailer,
        { "Trailer", "eth.trailer", FT_BYTES, BASE_NONE, NULL, 0x0,
            "Ethernet Trailer or Checksum", HFILL }},

        { &hf_eth_fcs,
        { "Frame check sequence", "eth.fcs", FT_UINT16, BASE_HEX, NULL, 0x0,
            "Ethernet checksum", HFILL }},

        { &hf_eth_fcs_good,
        { "FCS Good", "eth.fcs_good", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "True: checksum matches packet content; False: doesn't match content or not checked", HFILL }},

        { &hf_eth_fcs_bad,
        { "FCS Bad", "eth.fcs_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "True: checksum doesn't matche packet content; False: does match content or not checked", HFILL }},

        { &hf_eth_lg,
        { "LG bit", "eth.lg", FT_BOOLEAN, 24,
            TFS(&lg_tfs), 0x020000,
            "Specifies if this is a locally administered or globally unique (IEEE assigned) address", HFILL }},

        { &hf_eth_ig,
        { "IG bit", "eth.ig", FT_BOOLEAN, 24,
            TFS(&ig_tfs), 0x010000,
            "Specifies if this is an individual (unicast) or group (broadcast/multicast) address", HFILL }}
    };
    static gint *ett[] = {
        &ett_ieee8023,
        &ett_ether2,
        &ett_ether,
        &ett_addr,
        &ett_eth_fcs
    };
    module_t *eth_module;

    proto_eth = proto_register_protocol("Ethernet", "Ethernet", "eth");
    proto_register_field_array(proto_eth, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* subdissector code */
    register_heur_dissector_list("eth", &heur_subdissector_list);
    register_heur_dissector_list("eth.trailer", &eth_trailer_subdissector_list);

    /* Register configuration preferences */
    eth_module = prefs_register_protocol(proto_eth, NULL);

    prefs_register_bool_preference(eth_module, "assume_padding",
            "Assume short frames which include a trailer contain padding",
            "Some devices add trailing data to frames. When this setting is checked "
            "the Ethernet dissector will assume there has been added padding to the "
            "frame before the trailer was added. Uncheck if a device added a trailer "
            "before the frame was padded.",
            &eth_assume_padding);

    prefs_register_bool_preference(eth_module, "assume_fcs",
            "Assume packets have FCS",
            "Some Ethernet adapters and drivers include the FCS at the end of a packet, others do not.  "
            "The Ethernet dissector attempts to guess whether a captured packet has an FCS, "
            "but it cannot always guess correctly.",
            &eth_assume_fcs);

    prefs_register_bool_preference(eth_module, "check_fcs",
            "Validate the Ethernet checksum if possible",
            "Whether to validate the Frame Check Sequence",
            &eth_check_fcs);

    prefs_register_bool_preference(eth_module, "interpret_as_fw1_monitor",
            "Attempt to interpret as FireWall-1 monitor file",
            "Whether packets should be interpreted as coming from CheckPoint FireWall-1 monitor file if they look as if they do",
            &eth_interpret_as_fw1_monitor);

    prefs_register_static_text_preference(eth_module, "ccsds_heuristic",
            "These are the conditions to match a payload against in order to determine if this\n"
            "is a CCSDS (Consultative Committee for Space Data Systems) packet within\n"
            "an 802.3 packet. A packet is considered as a possible CCSDS packet only if\n"
            "one or more of the conditions are checked.",
            "Describe the conditions that must be true for the CCSDS dissector to be called");

    prefs_register_bool_preference(eth_module, "ccsds_heuristic_length",
            "CCSDS Length in header matches payload size",
            "Set the condition that must be true for the CCSDS dissector to be called",
            &ccsds_heuristic_length);

    prefs_register_bool_preference(eth_module, "ccsds_heuristic_version",
            "CCSDS Version # is zero",
            "Set the condition that must be true for the CCSDS dissector to be called",
            &ccsds_heuristic_version);

    prefs_register_bool_preference(eth_module, "ccsds_heuristic_header",
            "CCSDS Secondary Header Flag is set",
            "Set the condition that must be true for the CCSDS dissector to be called",
            &ccsds_heuristic_header);

    prefs_register_bool_preference(eth_module, "ccsds_heuristic_bit",
            "CCSDS Spare bit is cleared",
            "Set the condition that must be true for the CCSDS dissector to be called",
            &ccsds_heuristic_bit);

    register_dissector("eth_withoutfcs", dissect_eth_withoutfcs, proto_eth);
    register_dissector("eth_withfcs", dissect_eth_withfcs, proto_eth);
    register_dissector("eth", dissect_eth_maybefcs, proto_eth);
    eth_tap = register_tap("eth");
}

void
proto_reg_handoff_eth(void)
{
    dissector_handle_t eth_maybefcs_handle, eth_withoutfcs_handle;

    /* Get a handle for the Firewall-1 dissector. */
    fw1_handle = find_dissector("fw1");

    /* Get a handle for the generic data dissector. */
    data_handle = find_dissector("data");

    eth_maybefcs_handle = find_dissector("eth");
    dissector_add_uint("wtap_encap", WTAP_ENCAP_ETHERNET, eth_maybefcs_handle);

    eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
    dissector_add_uint("ethertype", ETHERTYPE_ETHBRIDGE, eth_withoutfcs_handle);
    dissector_add_uint("chdlctype", ETHERTYPE_ETHBRIDGE, eth_withoutfcs_handle);
    dissector_add_uint("gre.proto", ETHERTYPE_ETHBRIDGE, eth_withoutfcs_handle);

    dissector_add_uint("sll.ltype", LINUX_SLL_P_ETHERNET, eth_withoutfcs_handle);
    dissector_add_uint("usb.bulk", IF_CLASS_CDC_DATA, eth_withoutfcs_handle);

    /*
     * This is to handle the output for the Cisco CMTS "cable intercept"
     * command - it encapsulates Ethernet frames in UDP packets, but
     * the UDP port is user-defined.
     */
    dissector_add_handle("udp.port", eth_withoutfcs_handle);
}
