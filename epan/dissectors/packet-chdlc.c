/* packet-chdlc.c
 * Routines for Cisco HDLC packet disassembly
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/prefs.h>
#include <epan/chdlctypes.h>
#include <epan/nlpid.h>
#include <epan/addr_resolv.h>
#include "packet-chdlc.h"
#include "packet-ppp.h"
#include "packet-ip.h"

/*
 * See section 4.3.1 of RFC 1547, and
 *
 *	http://www.nethelp.no/net/cisco-hdlc.txt
 */

static int proto_chdlc = -1;
static int hf_chdlc_addr = -1;
static int hf_chdlc_proto = -1;

static gint ett_chdlc = -1;

static int proto_slarp = -1;
static int hf_slarp_ptype = -1;
static int hf_slarp_address = -1;
static int hf_slarp_mysequence = -1;
static int hf_slarp_yoursequence = -1;

static gint ett_slarp = -1;

static dissector_handle_t data_handle;

/*
 * Protocol types for the Cisco HDLC format.
 *
 * As per the above, according to RFC 1547, these are "standard 16 bit
 * Ethernet protocol type code[s]", but 0x8035 is Reverse ARP, and
 * that is (at least according to the Linux ISDN code) not the
 * same as Cisco SLARP.
 *
 * In addition, 0x2000 is apparently the Cisco Discovery Protocol, but
 * on Ethernet those are encapsulated inside SNAP with an OUI of
 * OUI_CISCO, not OUI_ENCAP_ETHER.
 *
 * We thus have a separate dissector table for Cisco HDLC types.
 * We could perhaps have that table hold only type values that
 * wouldn't be in the Ethernet dissector table, and check that
 * table first and the Ethernet dissector table if that fails.
 */
#define CISCO_SLARP	0x8035	/* Cisco SLARP protocol */

static dissector_table_t subdissector_table;

static const value_string chdlc_address_vals[] = {
	{CHDLC_ADDR_UNICAST,   "Unicast"},
	{CHDLC_ADDR_MULTICAST, "Multicast"},
	{0,                    NULL}
};

const value_string chdlc_vals[] = {
	{0x2000,               "Cisco Discovery Protocol"},
	{ETHERTYPE_IP,         "IP"},
	{ETHERTYPE_IPv6,       "IPv6"},
	{CISCO_SLARP,          "SLARP"},
	{ETHERTYPE_DEC_LB,     "DEC LanBridge"},
	{CHDLCTYPE_BPDU,       "Spanning Tree BPDU"},
	{ETHERTYPE_ATALK,      "Appletalk"},
	{ETHERTYPE_AARP,       "AARP"},
	{ETHERTYPE_IPX,        "Netware IPX/SPX"},
	{ETHERTYPE_ETHBRIDGE,  "Transparent Ethernet bridging" },
	{CHDLCTYPE_OSI,        "OSI" },
	{ETHERTYPE_MPLS,       "MPLS unicast"},
	{ETHERTYPE_MPLS_MULTI, "MPLS multicast"},
	{0,                     NULL}
};

void
capture_chdlc( const guchar *pd, int offset, int len, packet_counts *ld ) {
  if (!BYTES_ARE_IN_FRAME(offset, len, 4)) {
    ld->other++;
    return;
  }
  switch (pntohs(&pd[offset + 2])) {
    case ETHERTYPE_IP:
      capture_ip(pd, offset + 4, len, ld);
      break;
    default:
      ld->other++;
      break;
  }
}

void
chdlctype(guint16 chdlc_type, tvbuff_t *tvb, int offset_after_chdlctype,
	  packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
	  int chdlctype_id)
{
  tvbuff_t   *next_tvb;
  int padbyte = 0;

  if (tree) {
    proto_tree_add_uint(fh_tree, chdlctype_id, tvb,
			offset_after_chdlctype - 2, 2, chdlc_type);
  }

  padbyte = tvb_get_guint8(tvb, offset_after_chdlctype);
  if (chdlc_type == CHDLCTYPE_OSI &&
    !( padbyte == NLPID_ISO8473_CLNP || /* older Juniper SW does not send a padbyte */
       padbyte == NLPID_ISO9542_ESIS ||
       padbyte == NLPID_ISO10589_ISIS)) {
    /* There is a Padding Byte for CLNS protocols over Cisco HDLC */
    proto_tree_add_text(fh_tree, tvb, offset_after_chdlctype, 1, "CLNS Padding: 0x%02x",
        padbyte);
    next_tvb = tvb_new_subset_remaining(tvb, offset_after_chdlctype + 1);
  } else {
    next_tvb = tvb_new_subset_remaining(tvb, offset_after_chdlctype);
  }

  /* do lookup with the subdissector table */
  if (!dissector_try_uint(subdissector_table, chdlc_type, next_tvb, pinfo, tree)) {
	col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "0x%04x", chdlc_type);
    call_dissector(data_handle,next_tvb, pinfo, tree);
  }
}

static gint chdlc_fcs_decode = 0; /* 0 = No FCS, 1 = 16 bit FCS, 2 = 32 bit FCS */

static void
dissect_chdlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *fh_tree = NULL;
  guint8     addr;
  guint16    proto;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CHDLC");
  col_clear(pinfo->cinfo, COL_INFO);

  switch (pinfo->p2p_dir) {

  case P2P_DIR_SENT:
    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DTE");
    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DCE");
    break;

  case P2P_DIR_RECV:
    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DCE");
    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DTE");
    break;

  default:
    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A");
    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");
    break;
  }

  addr = tvb_get_guint8(tvb, 0);
  proto = tvb_get_ntohs(tvb, 2);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_chdlc, tvb, 0, 4, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, ett_chdlc);

    proto_tree_add_uint(fh_tree, hf_chdlc_addr, tvb, 0, 1, addr);
  }

  decode_fcs(tvb, fh_tree, chdlc_fcs_decode, 2);

  chdlctype(proto, tvb, 4, pinfo, tree, fh_tree, hf_chdlc_proto);
}

void
proto_register_chdlc(void)
{
  static hf_register_info hf[] = {
    { &hf_chdlc_addr,
      { "Address", "chdlc.address", FT_UINT8, BASE_HEX,
        VALS(chdlc_address_vals), 0x0, NULL, HFILL }},
    { &hf_chdlc_proto,
      { "Protocol", "chdlc.protocol", FT_UINT16, BASE_HEX,
        VALS(chdlc_vals), 0x0, NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_chdlc,
  };

  module_t *chdlc_module;

  proto_chdlc = proto_register_protocol("Cisco HDLC", "CHDLC", "chdlc");
  proto_register_field_array(proto_chdlc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

/* subdissector code */
  subdissector_table = register_dissector_table("chdlctype",
	"Cisco HDLC frame type", FT_UINT16, BASE_HEX);

  register_dissector("chdlc", dissect_chdlc, proto_chdlc);

  /* Register the preferences for the chdlc protocol */
  chdlc_module = prefs_register_protocol(proto_chdlc, NULL);

  prefs_register_enum_preference(chdlc_module,
	"fcs_type",
	"CHDLC Frame Checksum Type",
	"The type of CHDLC frame checksum (none, 16-bit, 32-bit)",
	&chdlc_fcs_decode,
	fcs_options, ENC_BIG_ENDIAN);

}

void
proto_reg_handoff_chdlc(void)
{
  dissector_handle_t chdlc_handle;

  data_handle = find_dissector("data");
  chdlc_handle = find_dissector("chdlc");
  dissector_add_uint("wtap_encap", WTAP_ENCAP_CHDLC, chdlc_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_CHDLC_WITH_PHDR, chdlc_handle);
}

#define SLARP_REQUEST	0
#define SLARP_REPLY	1
#define SLARP_LINECHECK	2

static const value_string slarp_ptype_vals[] = {
	{SLARP_REQUEST,   "Request"},
	{SLARP_REPLY,     "Reply"},
	{SLARP_LINECHECK, "Line keepalive"},
	{0,               NULL}
};

static void
dissect_slarp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *slarp_tree = NULL;
  guint32 code;
  guint32 addr;
  guint32 mysequence;
  guint32 yoursequence;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SLARP");
  col_clear(pinfo->cinfo, COL_INFO);

  code = tvb_get_ntohl(tvb, 0);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_slarp, tvb, 0, 14, ENC_NA);
    slarp_tree = proto_item_add_subtree(ti, ett_slarp);
  }

  switch (code) {

  case SLARP_REQUEST:
  case SLARP_REPLY:
	addr = tvb_get_ipv4(tvb, 4);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s, from %s, mask %s",
		     val_to_str(code, slarp_ptype_vals, "Unknown (%d)"),
		     get_hostname(addr), tvb_ip_to_str(tvb, 8));
    if (tree) {
      proto_tree_add_uint(slarp_tree, hf_slarp_ptype, tvb, 0, 4, code);
      proto_tree_add_item(slarp_tree, hf_slarp_address, tvb, 4, 4, ENC_BIG_ENDIAN);
      proto_tree_add_text(slarp_tree, tvb, 8, 4,
			  "Netmask: %s", tvb_ip_to_str(tvb, 8));
    }
    break;

  case SLARP_LINECHECK:
    mysequence = tvb_get_ntohl(tvb, 4);
    yoursequence = tvb_get_ntohl(tvb, 8);
	col_add_fstr(pinfo->cinfo, COL_INFO,
		     "%s, outgoing sequence %u, returned sequence %u",
		     val_to_str(code, slarp_ptype_vals, "Unknown (%d)"),
		     mysequence, yoursequence);
    if (tree) {
      proto_tree_add_uint(slarp_tree, hf_slarp_ptype, tvb, 0, 4, code);
      proto_tree_add_uint(slarp_tree, hf_slarp_mysequence, tvb, 4, 4,
			  mysequence);
      proto_tree_add_uint(slarp_tree, hf_slarp_mysequence, tvb, 8, 4,
			  yoursequence);
    }
    break;

  default:
    col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown packet type 0x%08X", code);
    if (tree) {
      proto_tree_add_uint(slarp_tree, hf_slarp_ptype, tvb, 0, 4, code);
      call_dissector(data_handle, tvb_new_subset_remaining(tvb, 4), pinfo,
		     slarp_tree);
    }
    break;
  }
}

void
proto_register_slarp(void)
{
  static hf_register_info hf[] = {
    { &hf_slarp_ptype,
      { "Packet type", "slarp.ptype", FT_UINT32, BASE_DEC,
        VALS(slarp_ptype_vals), 0x0, NULL, HFILL }},
    { &hf_slarp_address,
      { "Address", "slarp.address", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
    /* XXX - need an FT_ for netmasks, which is like FT_IPV4 but doesn't
       get translated to a host name. */
    { &hf_slarp_mysequence,
      { "Outgoing sequence number", "slarp.mysequence", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_slarp_yoursequence,
      { "Returned sequence number", "slarp.yoursequence", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_slarp,
  };

  proto_slarp = proto_register_protocol("Cisco SLARP", "SLARP", "slarp");
  proto_register_field_array(proto_slarp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_slarp(void)
{
  dissector_handle_t slarp_handle;

  slarp_handle = create_dissector_handle(dissect_slarp, proto_slarp);
  dissector_add_uint("chdlctype", CISCO_SLARP, slarp_handle);
}
