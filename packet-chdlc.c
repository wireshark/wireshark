/* packet-chdlc.c
 * Routines for Cisco HDLC packet disassembly
 *
 * $Id: packet-chdlc.c,v 1.7 2001/12/03 03:59:33 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>
#include "packet.h"
#include "etypes.h"
#include "resolv.h"
#include "packet-chdlc.h"
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
 * Perhaps we should set up a protocol table for those protocols
 * that differ between Ethernet and Cisco HDLC, and have the PPP
 * code first try that table and, if it finds nothing in that
 * table, call "ethertype()".  (Unfortunately, that means that -
 * assuming we had a Cisco SLARP dissector - said dissector were
 * disabled, SLARP packets would be dissected as Reverse ARP
 * packets, not as data.)
 */
#define CISCO_SLARP	0x8035	/* Cisco SLARP protocol */

static dissector_table_t subdissector_table;

static const value_string chdlc_address_vals[] = {
	{CHDLC_ADDR_UNICAST,   "Unicast"},
	{CHDLC_ADDR_MULTICAST, "Multicast"},
	{0,                    NULL}
};

const value_string chdlc_vals[] = {
	{0x2000,              "Cisco Discovery Protocol"},
	{ETHERTYPE_IP,        "IP"},
	{CISCO_SLARP,         "SLARP"},
	{ETHERTYPE_DEC_LB,    "DEC LanBridge"},
	{ETHERTYPE_ATALK,     "Appletalk"},
	{ETHERTYPE_AARP,      "AARP"},
	{ETHERTYPE_IPX,       "Netware IPX/SPX"},
	{ETHERTYPE_ETHBRIDGE, "Transparent Ethernet bridging" },
	{0,                   NULL}
};

void
capture_chdlc( const u_char *pd, int offset, int len, packet_counts *ld ) {
  if (!BYTES_ARE_IN_FRAME(offset, len, 2)) {
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
chdlctype(guint16 chdlctype, tvbuff_t *tvb, int offset_after_chdlctype,
	  packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
	  int chdlctype_id)
{
  tvbuff_t   *next_tvb;

  if (tree) {
    proto_tree_add_uint(fh_tree, chdlctype_id, tvb,
			offset_after_chdlctype - 2, 2, chdlctype);
  }

  next_tvb = tvb_new_subset(tvb, offset_after_chdlctype, -1, -1);

  /* do lookup with the subdissector table */
  if (!dissector_try_port(subdissector_table, chdlctype, next_tvb, pinfo, tree)) {
    if (check_col(pinfo->fd, COL_PROTOCOL))
      col_add_fstr(pinfo->fd, COL_PROTOCOL, "0x%04x", chdlctype);
    call_dissector(data_handle,next_tvb, pinfo, tree);
  }
}

static void
dissect_chdlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *fh_tree = NULL;
  guint8     addr;
  guint16    proto;

  if (check_col(pinfo->fd, COL_RES_DL_SRC))
    col_set_str(pinfo->fd, COL_RES_DL_SRC, "N/A");
  if (check_col(pinfo->fd, COL_RES_DL_DST))
    col_set_str(pinfo->fd, COL_RES_DL_DST, "N/A");
  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_set_str(pinfo->fd, COL_PROTOCOL, "CHDLC");
  if (check_col(pinfo->fd, COL_INFO))
    col_clear(pinfo->fd, COL_INFO);

  addr = tvb_get_guint8(tvb, 0);
  proto = tvb_get_ntohs(tvb, 2);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_chdlc, tvb, 0, 4, FALSE);
    fh_tree = proto_item_add_subtree(ti, ett_chdlc);

    proto_tree_add_uint(fh_tree, hf_chdlc_addr, tvb, 0, 1, addr);
  }

  chdlctype(proto, tvb, 4, pinfo, tree, fh_tree, hf_chdlc_proto);
}

void
proto_register_chdlc(void)
{
  static hf_register_info hf[] = {
    { &hf_chdlc_addr,
      { "Address", "chdlc.address", FT_UINT8, BASE_HEX,
        VALS(chdlc_address_vals), 0x0, "", HFILL }},
    { &hf_chdlc_proto,
      { "Protocol", "chdlc.protocol", FT_UINT16, BASE_HEX,
        VALS(chdlc_vals), 0x0, "", HFILL }},
  };
  static gint *ett[] = {
    &ett_chdlc,
  };

  proto_chdlc = proto_register_protocol("Cisco HDLC", "CHDLC", "chdlc");
  proto_register_field_array(proto_chdlc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

/* subdissector code */
  subdissector_table = register_dissector_table("chdlctype");

  register_dissector("chdlc", dissect_chdlc, proto_chdlc);
}

void
proto_reg_handoff_chdlc(void)
{
  dissector_handle_t chdlc_handle;

  data_handle = find_dissector("data");
  chdlc_handle = find_dissector("chdlc");
  dissector_add("wtap_encap", WTAP_ENCAP_CHDLC, chdlc_handle);
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
  guint32 mysequence;
  guint32 yoursequence;

  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_set_str(pinfo->fd, COL_PROTOCOL, "SLARP");
  if (check_col(pinfo->fd, COL_INFO))
    col_clear(pinfo->fd, COL_INFO);

  code = tvb_get_ntohl(tvb, 0);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_slarp, tvb, 0, 14, FALSE);
    slarp_tree = proto_item_add_subtree(ti, ett_slarp);
  }

  switch (code) {

  case SLARP_REQUEST:
  case SLARP_REPLY:
    if (check_col(pinfo->fd, COL_INFO)) {
      col_add_fstr(pinfo->fd, COL_INFO, "%s, from %s, mask %s",
        match_strval(code, slarp_ptype_vals),
        get_hostname(htonl(tvb_get_ntohl(tvb, 4))),
        ip_to_str(tvb_get_ptr(tvb, 8, 4)));
    }
    if (tree) {
      proto_tree_add_uint(slarp_tree, hf_slarp_ptype, tvb, 0, 4, code);
      proto_tree_add_item(slarp_tree, hf_slarp_address, tvb, 4, 4, FALSE);
      proto_tree_add_text(slarp_tree, tvb, 8, 4,
			  "Netmask: %s", ip_to_str(tvb_get_ptr(tvb, 8, 4)));
    }
    break;

  case SLARP_LINECHECK:
    mysequence = tvb_get_ntohl(tvb, 4);
    yoursequence = tvb_get_ntohl(tvb, 8);
    if (check_col(pinfo->fd, COL_INFO)) {
      col_add_fstr(pinfo->fd, COL_INFO,
        "%s, outgoing sequence %u, returned sequence %u",
	match_strval(code, slarp_ptype_vals),
        mysequence, yoursequence);
    }
    if (tree) {
      proto_tree_add_uint(slarp_tree, hf_slarp_ptype, tvb, 0, 4, code);
      proto_tree_add_uint(slarp_tree, hf_slarp_mysequence, tvb, 4, 4,
			  mysequence);
      proto_tree_add_uint(slarp_tree, hf_slarp_mysequence, tvb, 8, 4,
			  yoursequence);
    }
    break;

  default:
    if (check_col(pinfo->fd, COL_INFO))
      col_add_fstr(pinfo->fd, COL_INFO, "Unknown packet type 0x%08X", code);
    if (tree) {
      proto_tree_add_uint(slarp_tree, hf_slarp_ptype, tvb, 0, 4, code);
      call_dissector(data_handle,tvb_new_subset(tvb, 4,-1,tvb_reported_length_remaining(tvb,4)), pinfo, slarp_tree);
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
        VALS(slarp_ptype_vals), 0x0, "", HFILL }},
    { &hf_slarp_address,
      { "Address", "slarp.address", FT_IPv4, BASE_NONE,
        NULL, 0x0, "", HFILL }},
    /* XXX - need an FT_ for netmasks, which is like FT_IPV4 but doesn't
       get translated to a host name. */
    { &hf_slarp_mysequence,
      { "Outgoing sequence number", "slarp.mysequence", FT_UINT32, BASE_DEC,
        NULL, 0x0, "", HFILL }},
    { &hf_slarp_yoursequence,
      { "Returned sequence number", "slarp.yoursequence", FT_UINT32, BASE_DEC,
        NULL, 0x0, "", HFILL }},
  };
  static gint *ett[] = {
    &ett_chdlc,
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
  dissector_add("chdlctype", CISCO_SLARP, slarp_handle);
}
