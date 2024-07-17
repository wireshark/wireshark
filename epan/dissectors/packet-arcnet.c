/* packet-arcnet.c
 * Routines for arcnet dissection
 * Copyright 2001-2002, Peter Fales <ethereal@fales-lorenz.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/address_types.h>
#include <epan/arcnet_pids.h>
#include <epan/to_str.h>
#include "packet-ip.h"
#include "packet-arp.h"

void proto_register_arcnet(void);
void proto_reg_handoff_arcnet(void);

static dissector_handle_t arcnet_handle;
static dissector_handle_t arcnet_linux_handle;
static capture_dissector_handle_t arcnet_cap_handle;
static capture_dissector_handle_t arcnet_cap_has_ex_handle;

/* Initialize the protocol and registered fields */
static int proto_arcnet;
static int hf_arcnet_src;
static int hf_arcnet_dst;
static int hf_arcnet_offset;
static int hf_arcnet_protID;
static int hf_arcnet_exception_flag;
static int hf_arcnet_split_flag;
static int hf_arcnet_sequence;
static int hf_arcnet_padding;

/* Initialize the subtree pointers */
static int ett_arcnet;

static int arcnet_address_type = -1;

static dissector_table_t arcnet_dissector_table;

static capture_dissector_handle_t ip_cap_handle;
static capture_dissector_handle_t arp_cap_handle;

/* Cache protocol for packet counting */
static int proto_ipx;

static int arcnet_str_len(const address* addr _U_)
{
  return 5;
}

static int arcnet_to_str(const address* addr, char *buf, int buf_len _U_)
{
  *buf++ = '0';
  *buf++ = 'x';
  buf = bytes_to_hexstr(buf, (const uint8_t *)addr->data, 1);
  *buf = '\0'; /* NULL terminate */

  return arcnet_str_len(addr);
}

static const char* arcnet_col_filter_str(const address* addr _U_, bool is_src)
{
  if (is_src)
    return "arcnet.src";

  return "arcnet.dst";
}

static int arcnet_len(void)
{
  return 1;
}

static bool
capture_arcnet_common(const unsigned char *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header, bool has_exception)
{
  if (!BYTES_ARE_IN_FRAME(offset, len, 1)) {
    return false;
  }

  switch (pd[offset]) {

  case ARCNET_PROTO_IP_1051:
    /* No fragmentation stuff in the header */
    return call_capture_dissector(ip_cap_handle, pd, offset + 1, len, cpinfo, pseudo_header);

  case ARCNET_PROTO_IP_1201:
    /*
     * There's fragmentation stuff in the header.
     *
     * XXX - on at least some versions of NetBSD, it appears that we
     * might we get ARCNET frames, not reassembled packets; we should
     * perhaps bump "counts->other" for all but the first frame of a packet.
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
      return false;
    }
    if (has_exception && pd[offset] == 0xff) {
      /* This is an exception packet.  The flag value there is the
         "this is an exception flag" packet; the next two bytes
         after it are padding, and another copy of the packet
         type appears after the padding. */
      offset += 4;
    }
    return call_capture_dissector(ip_cap_handle, pd, offset + 3, len, cpinfo, pseudo_header);

  case ARCNET_PROTO_ARP_1051:
  case ARCNET_PROTO_ARP_1201:
    /*
     * XXX - do we have to worry about fragmentation for ARP?
     */
    return call_capture_dissector(arp_cap_handle, pd, offset + 1, len, cpinfo, pseudo_header);

  case ARCNET_PROTO_IPX:
    capture_dissector_increment_count(cpinfo, proto_ipx);
    break;

  default:
    return false;
  }

  return true;
}

static bool
capture_arcnet (const unsigned char *pd, int offset _U_, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
  return capture_arcnet_common(pd, 4, len, cpinfo, pseudo_header, false);
}

static bool
capture_arcnet_has_exception(const unsigned char *pd, int offset _U_, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
  return capture_arcnet_common(pd, 2, len, cpinfo, pseudo_header, true);
}

static void
dissect_arcnet_common (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
                       bool has_offset, bool has_exception)
{
  int offset = 0;
  uint8_t dst, src, protID, split_flag;
  tvbuff_t *next_tvb;
  proto_item *ti;
  proto_tree *arcnet_tree;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "ARCNET");

  col_set_str(pinfo->cinfo, COL_INFO, "ARCNET");

  src = tvb_get_uint8 (tvb, 0);
  dst = tvb_get_uint8 (tvb, 1);
  set_address_tvb(&pinfo->dl_src,   arcnet_address_type, 1, tvb, 0);
  copy_address_shallow(&pinfo->src, &pinfo->dl_src);
  set_address_tvb(&pinfo->dl_dst,   arcnet_address_type, 1, tvb, 1);
  copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);

  ti = proto_tree_add_item (tree, proto_arcnet, tvb, 0, -1, ENC_NA);

  arcnet_tree = proto_item_add_subtree (ti, ett_arcnet);

  proto_tree_add_uint (arcnet_tree, hf_arcnet_src, tvb, offset, 1, src);
  offset++;

  proto_tree_add_uint (arcnet_tree, hf_arcnet_dst, tvb, offset, 1, dst);
  offset++;

  if (has_offset) {
    proto_tree_add_item (arcnet_tree, hf_arcnet_offset, tvb, offset, 2, ENC_NA);
    offset += 2;
  }

  protID = tvb_get_uint8 (tvb, offset);
  proto_tree_add_uint (arcnet_tree, hf_arcnet_protID, tvb, offset, 1, protID);
  offset++;

  switch (protID) {

  case ARCNET_PROTO_IP_1051:
  case ARCNET_PROTO_ARP_1051:
  case ARCNET_PROTO_DIAGNOSE:
  case ARCNET_PROTO_BACNET:     /* XXX - no fragmentation? */
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
    split_flag = tvb_get_uint8 (tvb, offset);
    if (has_exception && split_flag == 0xff) {
      /* This is an exception packet.  The flag value there is the
         "this is an exception flag" packet; the next two bytes
         after it are padding. */
      proto_tree_add_uint (arcnet_tree, hf_arcnet_exception_flag, tvb, offset, 1,
                           split_flag);
      offset++;

      proto_tree_add_item(arcnet_tree, hf_arcnet_padding, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      /* Another copy of the packet type appears after the padding. */
      proto_tree_add_item (arcnet_tree, hf_arcnet_protID, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;

      /* And after that comes the real split flag. */
      split_flag = tvb_get_uint8 (tvb, offset);
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
      call_data_dissector(next_tvb, pinfo, tree);
    }

}

/*
 * BSD-style ARCNET headers - they don't have the offset field from the
 * ARCNET hardware packet, but we might get an exception frame header.
 */
static int
dissect_arcnet (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  dissect_arcnet_common (tvb, pinfo, tree, false, true);
  return tvb_captured_length(tvb);
}

/*
 * Linux-style ARCNET headers - they *do* have the offset field from the
 * ARCNET hardware packet, but we should never see an exception frame
 * header.
 */
static int
dissect_arcnet_linux (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  dissect_arcnet_common (tvb, pinfo, tree, true, false);
  return tvb_captured_length(tvb);
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
    {&hf_arcnet_padding,
     {"Padding", "arcnet.padding",
      FT_UINT16, BASE_HEX, NULL, 0,
      NULL, HFILL}
     },
  };

/* Setup protocol subtree array */
  static int *ett[] = {
    &ett_arcnet,
  };

/* Register the protocol name and description */
  proto_arcnet = proto_register_protocol ("ARCNET", "ARCNET", "arcnet");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_arcnet, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  arcnet_dissector_table = register_dissector_table ("arcnet.protocol_id", "ARCNET Protocol ID",
                                                     proto_arcnet, FT_UINT8, BASE_HEX);

  arcnet_address_type = address_type_dissector_register("AT_ARCNET", "ARCNET Address", arcnet_to_str, arcnet_str_len, NULL, arcnet_col_filter_str, arcnet_len, NULL, NULL);

  arcnet_handle = register_dissector("arcnet", dissect_arcnet, proto_arcnet);
  arcnet_linux_handle = register_dissector("arcnet_linux", dissect_arcnet_linux, proto_arcnet);

  arcnet_cap_handle = register_capture_dissector("arcnet_linux", capture_arcnet, proto_arcnet);
  arcnet_cap_has_ex_handle = register_capture_dissector("arcnet", capture_arcnet_has_exception, proto_arcnet);
}


void
proto_reg_handoff_arcnet (void)
{
  dissector_add_uint ("wtap_encap", WTAP_ENCAP_ARCNET, arcnet_handle);
  dissector_add_uint ("wtap_encap", WTAP_ENCAP_ARCNET_LINUX, arcnet_linux_handle);

  proto_ipx = proto_get_id_by_filter_name("ipx");

  capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_ARCNET_LINUX, arcnet_cap_handle);
  capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_ARCNET, arcnet_cap_has_ex_handle);

  ip_cap_handle = find_capture_dissector("ip");
  arp_cap_handle = find_capture_dissector("arp");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
