/* packet-eth.c
 * Routines for ethernet packet disassembly
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

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/conversation_table.h>
#include <epan/dissector_filters.h>
#include <epan/capture_dissectors.h>
#include <wsutil/pint.h>
#include "packet-eth.h"
#include "packet-gre.h"
#include "packet-ieee8023.h"
#include "packet-ipx.h"
#include "packet-isl.h"
#include "packet-llc.h"
#include "packet-sll.h"
#include "packet-juniper.h"
#include "packet-sflow.h"
#include "packet-l2tp.h"
#include "packet-vxlan.h"
#include <epan/crc32-tvb.h>
#include <wiretap/erf.h>

void proto_register_eth(void);
void proto_reg_handoff_eth(void);

/* Assume all packets have an FCS */
static gboolean eth_assume_padding = TRUE;
static guint eth_trailer_length = 0;
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
static int hf_eth_dst_resolved = -1;
static int hf_eth_src = -1;
static int hf_eth_src_resolved = -1;
static int hf_eth_len = -1;
static int hf_eth_type = -1;
static int hf_eth_invalid_lentype = -1;
static int hf_eth_addr = -1;
static int hf_eth_addr_resolved = -1;
static int hf_eth_lg = -1;
static int hf_eth_ig = -1;
static int hf_eth_padding = -1;
static int hf_eth_trailer = -1;
static int hf_eth_fcs = -1;
static int hf_eth_fcs_status = -1;

static gint ett_ieee8023 = -1;
static gint ett_ether2 = -1;
static gint ett_ether = -1;
static gint ett_addr = -1;

static expert_field ei_eth_invalid_lentype = EI_INIT;
static expert_field ei_eth_src_not_group = EI_INIT;
static expert_field ei_eth_fcs_bad = EI_INIT;
static expert_field ei_eth_len = EI_INIT;

static dissector_handle_t fw1_handle;
static dissector_handle_t ethertype_handle;
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


static const char* eth_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
  if ((filter == CONV_FT_SRC_ADDRESS) && (conv->src_address.type == AT_ETHER))
    return "eth.src";

  if ((filter == CONV_FT_DST_ADDRESS) && (conv->dst_address.type == AT_ETHER))
    return "eth.dst";

  if ((filter == CONV_FT_ANY_ADDRESS) && (conv->src_address.type == AT_ETHER))
    return "eth.addr";

  return CONV_FILTER_INVALID;
}

static ct_dissector_info_t eth_ct_dissector_info = {&eth_conv_get_filter_type};

static int
eth_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
  conv_hash_t *hash = (conv_hash_t*) pct;
  const eth_hdr *ehdr=(const eth_hdr *)vip;

  add_conversation_table_data(hash, &ehdr->src, &ehdr->dst, 0, 0, 1, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts, &eth_ct_dissector_info, PT_NONE);

  return 1;
}

static const char* eth_host_get_filter_type(hostlist_talker_t* host, conv_filter_type_e filter)
{
  if ((filter == CONV_FT_ANY_ADDRESS) && (host->myaddress.type == AT_ETHER))
    return "eth.addr";

  return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t eth_host_dissector_info = {&eth_host_get_filter_type};

static int
eth_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
  conv_hash_t *hash = (conv_hash_t*) pit;
  const eth_hdr *ehdr=(const eth_hdr *)vip;

  /* Take two "add" passes per packet, adding for each direction, ensures that all
     packets are counted properly (even if address is sending to itself)
     XXX - this could probably be done more efficiently inside hostlist_table */
  add_hostlist_table_data(hash, &ehdr->src, 0, TRUE, 1, pinfo->fd->pkt_len, &eth_host_dissector_info, PT_NONE);
  add_hostlist_table_data(hash, &ehdr->dst, 0, FALSE, 1, pinfo->fd->pkt_len, &eth_host_dissector_info, PT_NONE);

  return 1;
}

static gboolean
eth_filter_valid(packet_info *pinfo)
{
    return (pinfo->dl_src.type == AT_ETHER);
}

static gchar*
eth_build_filter(packet_info *pinfo)
{
    return g_strdup_printf("eth.addr eq %s and eth.addr eq %s",
                address_to_str(pinfo->pool, &pinfo->dl_src),
                address_to_str(pinfo->pool, &pinfo->dl_dst));
}


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

gboolean
capture_eth(const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
  guint16 etype, length;
  int ethhdr_type;          /* the type of ethernet frame */

  if (!BYTES_ARE_IN_FRAME(offset, len, ETH_HEADER_SIZE))
    return FALSE;

  etype = pntoh16(&pd[offset+12]);

  if (etype <= IEEE_802_3_MAX_LEN) {
    /* Oh, yuck.  Cisco ISL frames require special interpretation of the
       destination address field; fortunately, they can be recognized by
       checking the first 5 octets of the destination address, which are
       01-00-0C-00-00 or 0C-00-0C-00-00 for ISL frames. */
    if ((pd[offset] == 0x01 || pd[offset] == 0x0C) && pd[offset+1] == 0x00
        && pd[offset+2] == 0x0C && pd[offset+3] == 0x00
        && pd[offset+4] == 0x00) {
      return capture_isl(pd, offset, len, cpinfo, pseudo_header);
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
  if (etype > IEEE_802_3_MAX_LEN && etype < ETHERNET_II_MIN_LEN)
    return FALSE;

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
      return capture_ipx(pd, offset, len, cpinfo, pseudo_header);
    case ETHERNET_802_2:
      return capture_llc(pd, offset, len, cpinfo, pseudo_header);
    case ETHERNET_II:
      return try_capture_dissector("ethertype", etype, pd, offset, len, cpinfo, pseudo_header);
  }

  return FALSE;
}

static gboolean check_is_802_2(tvbuff_t *tvb, int fcs_len);

static proto_tree *
dissect_eth_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
    int fcs_len)
{
  proto_item        *ti = NULL;
  eth_hdr           *ehdr;
  gboolean          is_802_2;
  proto_tree        *fh_tree = NULL;
  const guint8      *src_addr, *dst_addr;
  const char        *src_addr_name, *dst_addr_name;
  static eth_hdr    ehdrs[4];
  static int        ehdr_num=0;
  proto_tree        *tree;
  proto_item        *addr_item;
  proto_tree        *addr_tree=NULL;
  ethertype_data_t  ethertype_data;
  heur_dtbl_entry_t *hdtbl_entry = NULL;

  ehdr_num++;
  if(ehdr_num>=4){
     ehdr_num=0;
  }
  ehdr=&ehdrs[ehdr_num];

  tree=parent_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Ethernet");

  set_address_tvb(&pinfo->dl_dst, AT_ETHER, 6, tvb, 0);
  copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);
  copy_address_shallow(&ehdr->dst, &pinfo->dl_dst);
  dst_addr = (const guint8*)pinfo->dst.data;
  dst_addr_name = get_ether_name(dst_addr);

  set_address_tvb(&pinfo->dl_src, AT_ETHER, 6, tvb, 6);
  copy_address_shallow(&pinfo->src, &pinfo->dl_src);
  copy_address_shallow(&ehdr->src, &pinfo->dl_src);
  src_addr = (const guint8*)pinfo->src.data;
  src_addr_name = get_ether_name(src_addr);

  ehdr->type = tvb_get_ntohs(tvb, 12);

  tap_queue_packet(eth_tap, pinfo, ehdr);

  /*
   * In case the packet is a non-Ethernet packet inside
   * Ethernet framing, allow heuristic dissectors to take
   * a first look before we assume that it's actually an
   * Ethernet packet.
   */
  if (dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, parent_tree, &hdtbl_entry, NULL))
    return fh_tree;

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
      return fh_tree;
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
        "Ethernet Unknown, Src: %s, Dst: %s",
        address_with_resolution_to_str(wmem_packet_scope(), &pinfo->src),
        address_with_resolution_to_str(wmem_packet_scope(), &pinfo->dst));
    fh_tree = proto_item_add_subtree(ti, ett_ether);
    addr_item = proto_tree_add_ether(fh_tree, hf_eth_dst, tvb, 0, 6, dst_addr);
    if (addr_item)
        addr_tree = proto_item_add_subtree(addr_item, ett_addr);
    addr_item=proto_tree_add_string(addr_tree, hf_eth_dst_resolved, tvb, 0, 6,
        dst_addr_name);
    PROTO_ITEM_SET_GENERATED(addr_item);
    PROTO_ITEM_SET_HIDDEN(addr_item);
    proto_tree_add_ether(addr_tree, hf_eth_addr, tvb, 0, 6, dst_addr);
    addr_item=proto_tree_add_string(addr_tree, hf_eth_addr_resolved, tvb, 0, 6,
        dst_addr_name);
    PROTO_ITEM_SET_GENERATED(addr_item);
    PROTO_ITEM_SET_HIDDEN(addr_item);
    proto_tree_add_item(addr_tree, hf_eth_lg, tvb, 0, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(addr_tree, hf_eth_ig, tvb, 0, 3, ENC_BIG_ENDIAN);

    addr_item = proto_tree_add_ether(fh_tree, hf_eth_src, tvb, 6, 6, src_addr);
    if (addr_item)
        addr_tree = proto_item_add_subtree(addr_item, ett_addr);
    addr_item=proto_tree_add_string(addr_tree, hf_eth_src_resolved, tvb, 6, 6,
        src_addr_name);
    PROTO_ITEM_SET_GENERATED(addr_item);
    PROTO_ITEM_SET_HIDDEN(addr_item);
    proto_tree_add_ether(addr_tree, hf_eth_addr, tvb, 6, 6, src_addr);
    addr_item=proto_tree_add_string(addr_tree, hf_eth_addr_resolved, tvb, 6, 6,
        src_addr_name);
    PROTO_ITEM_SET_GENERATED(addr_item);
    PROTO_ITEM_SET_HIDDEN(addr_item);
    proto_tree_add_item(addr_tree, hf_eth_lg, tvb, 6, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(addr_tree, hf_eth_ig, tvb, 6, 3, ENC_BIG_ENDIAN);

    ti = proto_tree_add_item(fh_tree, hf_eth_invalid_lentype, tvb, 12, 2, ENC_BIG_ENDIAN);
    expert_add_info_format(pinfo, ti, &ei_eth_invalid_lentype,
        "Invalid length/type: 0x%04x (%d)", ehdr->type, ehdr->type);
    next_tvb = tvb_new_subset_remaining(tvb, 14);
    call_data_dissector(next_tvb, pinfo, parent_tree);
    return fh_tree;
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

    /* if IP is not referenced from any filters we don't need to worry about
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
    addr_item=proto_tree_add_string(addr_tree, hf_eth_dst_resolved, tvb, 0, 6,
        dst_addr_name);
    PROTO_ITEM_SET_GENERATED(addr_item);
    PROTO_ITEM_SET_HIDDEN(addr_item);
    proto_tree_add_ether(addr_tree, hf_eth_addr, tvb, 0, 6, dst_addr);
    addr_item=proto_tree_add_string(addr_tree, hf_eth_addr_resolved, tvb, 0, 6,
        dst_addr_name);
    PROTO_ITEM_SET_GENERATED(addr_item);
    PROTO_ITEM_SET_HIDDEN(addr_item);
    proto_tree_add_item(addr_tree, hf_eth_lg, tvb, 0, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(addr_tree, hf_eth_ig, tvb, 0, 3, ENC_BIG_ENDIAN);

    addr_item=proto_tree_add_ether(fh_tree, hf_eth_src, tvb, 6, 6, src_addr);
    if(addr_item){
        addr_tree = proto_item_add_subtree(addr_item, ett_addr);
    }
    addr_item=proto_tree_add_string(addr_tree, hf_eth_src_resolved, tvb, 6, 6,
        src_addr_name);
    PROTO_ITEM_SET_GENERATED(addr_item);
    PROTO_ITEM_SET_HIDDEN(addr_item);
    proto_tree_add_ether(addr_tree, hf_eth_addr, tvb, 6, 6, src_addr);
    addr_item=proto_tree_add_string(addr_tree, hf_eth_addr_resolved, tvb, 6, 6,
        src_addr_name);
    PROTO_ITEM_SET_GENERATED(addr_item);
    PROTO_ITEM_SET_HIDDEN(addr_item);
    proto_tree_add_item(addr_tree, hf_eth_lg, tvb, 6, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(addr_tree, hf_eth_ig, tvb, 6, 3, ENC_BIG_ENDIAN);

    dissect_802_3(ehdr->type, is_802_2, tvb, ETH_HEADER_SIZE, pinfo,
        parent_tree, fh_tree, hf_eth_len, hf_eth_trailer, &ei_eth_len, fcs_len);
  } else {
    if (eth_interpret_as_fw1_monitor) {
        if ((dst_addr[0] == 'i') || (dst_addr[0] == 'I') ||
            (dst_addr[0] == 'o') || (dst_addr[0] == 'O')) {
            call_dissector(fw1_handle, tvb, pinfo, parent_tree);
            return fh_tree;
        }
    }

    col_set_str(pinfo->cinfo, COL_INFO, "Ethernet II");
    if (parent_tree) {
        if (PTREE_DATA(parent_tree)->visible) {
            ti = proto_tree_add_protocol_format(parent_tree, proto_eth, tvb, 0, ETH_HEADER_SIZE,
                "Ethernet II, Src: %s, Dst: %s",
                address_with_resolution_to_str(wmem_packet_scope(), &pinfo->src),
                address_with_resolution_to_str(wmem_packet_scope(), &pinfo->dst));
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
    addr_item=proto_tree_add_string(addr_tree, hf_eth_dst_resolved, tvb, 0, 6,
        dst_addr_name);
    PROTO_ITEM_SET_GENERATED(addr_item);
    PROTO_ITEM_SET_HIDDEN(addr_item);
    proto_tree_add_ether(addr_tree, hf_eth_addr, tvb, 0, 6, dst_addr);
    addr_item=proto_tree_add_string(addr_tree, hf_eth_addr_resolved, tvb, 0, 6,
        dst_addr_name);
    PROTO_ITEM_SET_GENERATED(addr_item);
    PROTO_ITEM_SET_HIDDEN(addr_item);
    proto_tree_add_item(addr_tree, hf_eth_lg, tvb, 0, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(addr_tree, hf_eth_ig, tvb, 0, 3, ENC_BIG_ENDIAN);

    addr_item=proto_tree_add_ether(fh_tree, hf_eth_src, tvb, 6, 6, src_addr);
    if(addr_item){
        addr_tree = proto_item_add_subtree(addr_item, ett_addr);
        if (tvb_get_guint8(tvb, 6) & 0x01) {
            expert_add_info(pinfo, addr_item, &ei_eth_src_not_group);
        }
    }
    addr_item=proto_tree_add_string(addr_tree, hf_eth_src_resolved, tvb, 6, 6,
        src_addr_name);
    PROTO_ITEM_SET_GENERATED(addr_item);
    PROTO_ITEM_SET_HIDDEN(addr_item);
    proto_tree_add_ether(addr_tree, hf_eth_addr, tvb, 6, 6, src_addr);
    addr_item=proto_tree_add_string(addr_tree, hf_eth_addr_resolved, tvb, 6, 6,
        src_addr_name);
    PROTO_ITEM_SET_GENERATED(addr_item);
    PROTO_ITEM_SET_HIDDEN(addr_item);
    proto_tree_add_item(addr_tree, hf_eth_lg, tvb, 6, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(addr_tree, hf_eth_ig, tvb, 6, 3, ENC_BIG_ENDIAN);

    ethertype_data.etype = ehdr->type;
    ethertype_data.offset_after_ethertype = ETH_HEADER_SIZE;
    ethertype_data.fh_tree = fh_tree;
    ethertype_data.etype_id = hf_eth_type;
    ethertype_data.trailer_id = hf_eth_trailer;
    ethertype_data.fcs_len = fcs_len;

    call_dissector_with_data(ethertype_handle, tvb, pinfo, parent_tree, &ethertype_data);
  }
  return fh_tree;
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
        captured_length = tvb_captured_length_remaining(tvb, ETH_HEADER_SIZE);
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
  CATCH_BOUNDS_ERRORS {
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
  heur_dtbl_entry_t *hdtbl_entry;

  if (trailer_tvb) {
    guint trailer_length, trailer_reported_length;
    guint padding_length = 0;
    gboolean has_fcs = FALSE;
    tvbuff_t *real_trailer_tvb;

    trailer_length = tvb_captured_length(trailer_tvb);
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
                padding_length, ENC_NA);
            trailer_length -= padding_length;
            trailer_reported_length -= padding_length;
        }
    }

    if (fcs_len != 0) {
      /* If fcs_len is 4, we assume we definitely have an FCS.
         Otherwise, then, if the frame is big enough that, if we
         have a trailer, it probably includes an FCS, and we have
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

    /* Create a new tvb without the padding and/or the (assumed) fcs */
    if (fcs_len==4)
      real_trailer_tvb = tvb_new_subset(trailer_tvb, padding_length,
                                trailer_length, trailer_reported_length);
    else
      real_trailer_tvb = tvb_new_subset_remaining(trailer_tvb, padding_length);

    /* Call all ethernet trailer dissectors to dissect the trailer if
       we actually have a trailer.  */
    if (tvb_reported_length(real_trailer_tvb) != 0) {
      if (dissector_try_heuristic(eth_trailer_subdissector_list,
                                   real_trailer_tvb, pinfo, tree, &hdtbl_entry, NULL) ) {
        /* If we're not sure that there is a FCS, all trailer data
           has been given to the ethernet-trailer dissector, so
           stop dissecting here */
        if (fcs_len!=4)
            return;
      } else {
        /* No luck with the trailer dissectors, so just display the
           extra bytes as general trailer */
        if (trailer_length != 0) {
          tvb_ensure_bytes_exist(tvb, 0, trailer_length);
          proto_tree_add_item(fh_tree, trailer_id, real_trailer_tvb, 0,
            trailer_length, ENC_NA);
        }
      }
    }

    if (has_fcs) {
      guint32 sent_fcs = tvb_get_ntohl(trailer_tvb, padding_length+trailer_length);
      if(eth_check_fcs){
        guint32 fcs = crc32_802_tvb(tvb, tvb_captured_length(tvb) - 4);
        proto_tree_add_checksum(fh_tree, trailer_tvb, padding_length+trailer_length, hf_eth_fcs, hf_eth_fcs_status, &ei_eth_fcs_bad, pinfo, fcs, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

        if (fcs != sent_fcs) {
          col_append_str(pinfo->cinfo, COL_INFO, " [ETHERNET FRAME CHECK SEQUENCE INCORRECT]");
        }
      }else{
        proto_tree_add_checksum(fh_tree, trailer_tvb, padding_length+trailer_length, hf_eth_fcs, hf_eth_fcs_status, &ei_eth_fcs_bad, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
      }
      trailer_length += 4;
    }
    proto_tree_set_appendix(fh_tree, tvb, tvb_captured_length(tvb) - padding_length - trailer_length, padding_length + trailer_length);
  }
}

/* Called for the Ethernet Wiretap encapsulation type; pass the FCS length
   reported to us, or, if the "assume_fcs" preference is set, pass 4. */
static int
dissect_eth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct eth_phdr   *eth = (struct eth_phdr *)data;
  proto_tree        *fh_tree;

  /* Some devices slice the packet and add their own trailer before
     putting the frame on the network. Make sure these packets get
     a proper trailer (even though the sliced frame might not
     properly dissect. */
  if ( (eth_trailer_length > 0) && (eth_trailer_length < tvb_captured_length(tvb)) ) {
    tvbuff_t *next_tvb;
    guint total_trailer_length;

    /*
     * XXX - this overrides Wiretap saying "this packet definitely has
     * no FCS".
     */
    total_trailer_length = eth_trailer_length + (eth_assume_fcs ? 4 : 0);

    /* Dissect the tvb up to, but not including the trailer */
    next_tvb = tvb_new_subset(tvb, 0,
                              tvb_captured_length(tvb) - total_trailer_length,
                              tvb_reported_length(tvb) - total_trailer_length);
    fh_tree = dissect_eth_common(next_tvb, pinfo, tree, 0);

    /* Now handle the ethernet trailer and optional FCS */
    next_tvb = tvb_new_subset_remaining(tvb, tvb_captured_length(tvb) - total_trailer_length);
    /*
     * XXX - this overrides Wiretap saying "this packet definitely has
     * no FCS".
     */
    add_ethernet_trailer(pinfo, tree, fh_tree, hf_eth_trailer, tvb, next_tvb,
                         eth_assume_fcs ? 4 : eth->fcs_len);
  } else {
    /*
     * XXX - this overrides Wiretap saying "this packet definitely has
     * no FCS".
     */
    dissect_eth_common(tvb, pinfo, tree, eth_assume_fcs ? 4 : eth->fcs_len);
  }
  return tvb_captured_length(tvb);
}

/* Called by other dissectors  This one's for encapsulated Ethernet
   packets that don't include an FCS. */
static int
dissect_eth_withoutfcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_eth_common(tvb, pinfo, tree, 0);
  return tvb_captured_length(tvb);
}

/* ...and this one's for encapsulated packets that do. */
static int
dissect_eth_withfcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_eth_common(tvb, pinfo, tree, 4);
  return tvb_captured_length(tvb);
}

/* ...and this one's for encapsulated packets that might or might not. */
static int
dissect_eth_maybefcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_eth_common(tvb, pinfo, tree, eth_assume_fcs ? 4 : -1);
  return tvb_captured_length(tvb);
}

void
proto_register_eth(void)
{
  static hf_register_info hf[] = {

    { &hf_eth_dst,
      { "Destination", "eth.dst", FT_ETHER, BASE_NONE, NULL, 0x0,
        "Destination Hardware Address", HFILL }},

    { &hf_eth_dst_resolved,
      { "Destination (resolved)", "eth.dst_resolved", FT_STRING, BASE_NONE,
        NULL, 0x0, "Destination Hardware Address (resolved)", HFILL }},

    { &hf_eth_src,
      { "Source", "eth.src", FT_ETHER, BASE_NONE, NULL, 0x0,
        "Source Hardware Address", HFILL }},

    { &hf_eth_src_resolved,
      { "Source (resolved)", "eth.src_resolved", FT_STRING, BASE_NONE,
        NULL, 0x0, "Source Hardware Address (resolved)", HFILL }},

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

    { &hf_eth_addr_resolved,
      { "Address (resolved)", "eth.addr_resolved", FT_STRING, BASE_NONE,
        NULL, 0x0, "Source or Destination Hardware Address (resolved)",
        HFILL }},

    { &hf_eth_padding,
      { "Padding", "eth.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
        "Ethernet Padding", HFILL }},

    { &hf_eth_trailer,
      { "Trailer", "eth.trailer", FT_BYTES, BASE_NONE, NULL, 0x0,
        "Ethernet Trailer or Checksum", HFILL }},

    { &hf_eth_fcs,
      { "Frame check sequence", "eth.fcs", FT_UINT32, BASE_HEX, NULL, 0x0,
        "Ethernet checksum", HFILL }},

    { &hf_eth_fcs_status,
      { "FCS Status", "eth.fcs.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
        NULL, HFILL }},

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
  };

  static ei_register_info ei[] = {
    { &ei_eth_invalid_lentype, { "eth.invalid_lentype.expert", PI_PROTOCOL, PI_WARN, "Invalid length/type", EXPFILL }},
    { &ei_eth_src_not_group, { "eth.src_not_group", PI_PROTOCOL, PI_WARN, "Source MAC must not be a group address: IEEE 802.3-2002, Section 3.2.3(b)", EXPFILL }},
    { &ei_eth_fcs_bad, { "eth.fcs_bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
    { &ei_eth_len, { "eth.len.past_end", PI_MALFORMED, PI_ERROR, "Length field value goes past the end of the payload", EXPFILL }},
  };

  module_t *eth_module;
  expert_module_t* expert_eth;

  proto_eth = proto_register_protocol("Ethernet", "Ethernet", "eth");
  proto_register_field_array(proto_eth, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_eth = expert_register_protocol(proto_eth);
  expert_register_field_array(expert_eth, ei, array_length(ei));

  /* subdissector code */
  heur_subdissector_list = register_heur_dissector_list("eth", proto_eth);
  eth_trailer_subdissector_list = register_heur_dissector_list("eth.trailer", proto_eth);

  /* Register configuration preferences */
  eth_module = prefs_register_protocol(proto_eth, NULL);

  prefs_register_bool_preference(eth_module, "assume_padding",
                                 "Assume short frames which include a trailer contain padding",
                                 "Some devices add trailing data to frames. When this setting is checked "
                                 "the Ethernet dissector will assume there has been added padding to the "
                                 "frame before the trailer was added. Uncheck if a device added a trailer "
                                 "before the frame was padded.",
                                 &eth_assume_padding);

  prefs_register_uint_preference(eth_module, "trailer_length",
                                 "Fixed ethernet trailer length",
                                 "Some TAPs add a fixed length ethernet trailer at the end "
                                 "of the frame, but before the (optional) FCS. Make sure it "
                                 "gets interpreted correctly.",
                                 10, &eth_trailer_length);

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
  register_dissector("eth_maybefcs", dissect_eth_maybefcs, proto_eth);
  eth_tap = register_tap("eth");

  register_conversation_table(proto_eth, TRUE, eth_conversation_packet, eth_hostlist_packet);
  register_conversation_filter("eth", "Ethernet", eth_filter_valid, eth_build_filter);
}

void
proto_reg_handoff_eth(void)
{
  dissector_handle_t eth_handle, eth_withoutfcs_handle, eth_maybefcs_handle;

  /* Get a handle for the Firewall-1 dissector. */
  fw1_handle = find_dissector_add_dependency("fw1", proto_eth);

  /* Get a handle for the ethertype dissector. */
  ethertype_handle = find_dissector_add_dependency("ethertype", proto_eth);

  eth_handle = create_dissector_handle(dissect_eth, proto_eth);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_ETHERNET, eth_handle);

  eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
  eth_maybefcs_handle = find_dissector("eth_maybefcs");
  dissector_add_uint("ethertype", ETHERTYPE_ETHBRIDGE, eth_withoutfcs_handle);

  dissector_add_uint("erf.types.type", ERF_TYPE_ETH, eth_maybefcs_handle);
  dissector_add_uint("erf.types.type", ERF_TYPE_COLOR_ETH, eth_maybefcs_handle);
  dissector_add_uint("erf.types.type", ERF_TYPE_DSM_COLOR_ETH, eth_maybefcs_handle);
  dissector_add_uint("erf.types.type", ERF_TYPE_COLOR_HASH_ETH, eth_maybefcs_handle);

  dissector_add_uint("chdlc.protocol", ETHERTYPE_ETHBRIDGE, eth_withoutfcs_handle);
  dissector_add_uint("gre.proto", ETHERTYPE_ETHBRIDGE, eth_withoutfcs_handle);
  dissector_add_uint("gre.proto", GRE_MIKROTIK_EOIP, eth_withoutfcs_handle);
  dissector_add_uint("juniper.proto", JUNIPER_PROTO_ETHER, eth_withoutfcs_handle);
  dissector_add_uint("sflow_245.header_protocol", SFLOW_245_HEADER_ETHERNET, eth_withoutfcs_handle);
  dissector_add_uint("l2tp.pw_type", L2TPv3_PROTOCOL_ETH, eth_withoutfcs_handle);
  dissector_add_uint("vxlan.next_proto", VXLAN_ETHERNET, eth_withoutfcs_handle);
  dissector_add_uint("sll.ltype", LINUX_SLL_P_ETHERNET, eth_withoutfcs_handle);

  /*
   * This is to handle the output for the Cisco CMTS "cable intercept"
   * command - it encapsulates Ethernet frames in UDP packets, but
   * the UDP port is user-defined.
   */
  dissector_add_for_decode_as("udp.port", eth_withoutfcs_handle);

  dissector_add_for_decode_as("pcli.payload", eth_withoutfcs_handle);

  register_capture_dissector("wtap_encap", WTAP_ENCAP_ETHERNET, capture_eth, proto_eth);
  register_capture_dissector("atm_lane", TRAF_ST_LANE_802_3, capture_eth, proto_eth);
  register_capture_dissector("atm_lane", TRAF_ST_LANE_802_3_MC, capture_eth, proto_eth);
  register_capture_dissector("ppi", 1 /* DLT_EN10MB */, capture_eth, proto_eth);
  register_capture_dissector("sll.ltype", LINUX_SLL_P_ETHERNET, capture_eth, proto_eth);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
