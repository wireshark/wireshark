/* packet-aarp.c
 * Routines for Appletalk ARP packet disassembly
 *
 * $Id$
 *
 * Simon Wilkinson <sxw@dcs.ed.ac.uk>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/emem.h>
#include <epan/etypes.h>

static int proto_aarp = -1;
static int hf_aarp_hard_type = -1;
static int hf_aarp_proto_type = -1;
static int hf_aarp_hard_size = -1;
static int hf_aarp_proto_size = -1;
static int hf_aarp_opcode = -1;
static int hf_aarp_src_hw = -1;
static int hf_aarp_src_hw_mac = -1;
static int hf_aarp_src_proto = -1;
static int hf_aarp_src_proto_id = -1;
static int hf_aarp_dst_hw = -1;
static int hf_aarp_dst_hw_mac = -1;
static int hf_aarp_dst_proto = -1;
static int hf_aarp_dst_proto_id = -1;

static gint ett_aarp = -1;

#ifndef AARP_REQUEST
#define AARP_REQUEST 	0x0001
#endif
#ifndef AARP_REPLY
#define AARP_REPLY	0x0002
#endif
#ifndef AARP_PROBE
#define AARP_PROBE	0x0003
#endif

/* The following is screwed up shit to deal with the fact that
   the linux kernel edits the packet inline. */
#define AARP_REQUEST_SWAPPED    0x0100
#define AARP_REPLY_SWAPPED  0x0200
#define AARP_PROBE_SWAPPED  0x0300

static const value_string op_vals[] = {
  {AARP_REQUEST,  "request" },
  {AARP_REPLY,    "reply"   },
  {AARP_PROBE,    "probe"   },
  {AARP_REQUEST_SWAPPED,  "request" },
  {AARP_REPLY_SWAPPED,    "reply"   },
  {AARP_PROBE_SWAPPED,    "probe"   },
  {0,             NULL           } };

/* AARP protocol HARDWARE identifiers. */
#define AARPHRD_ETHER 	1		/* Ethernet 10Mbps		*/
#define	AARPHRD_TR	2		/* Token Ring			*/

static const value_string hrd_vals[] = {
  {AARPHRD_ETHER,   "Ethernet"       },
  {AARPHRD_TR,      "Token Ring"     },
  {0,               NULL             } };

/*
 * Given the hardware address type and length, check whether an address
 * is an Ethernet address - the address must be of type "Ethernet" or
 * "Token Ring", and the length must be 6 bytes.
 */
#define AARP_HW_IS_ETHER(ar_hrd, ar_hln) \
	(((ar_hrd) == AARPHRD_ETHER || (ar_hrd) == AARPHRD_TR) \
  				&& (ar_hln) == 6)

/*
 * Given the protocol address type and length, check whether an address
 * is an Appletalk address - the address must be of type "Appletalk",
 * and the length must be 4 bytes.
 */
#define AARP_PRO_IS_ATALK(ar_pro, ar_pln) \
	((ar_pro) == ETHERTYPE_ATALK && (ar_pln) == 4)

static gchar *
tvb_atalkid_to_str(tvbuff_t *tvb, gint offset)
{
  gint node;
  gchar *cur;

  cur=ep_alloc(16);
  node=tvb_get_guint8(tvb, offset)<<8|tvb_get_guint8(tvb, offset+1);
  g_snprintf(cur, 16, "%d.%d",node,tvb_get_guint8(tvb, offset+2));
  return cur;
}

static gchar *
tvb_aarphrdaddr_to_str(tvbuff_t *tvb, gint offset, int ad_len, guint16 type)
{
  if (AARP_HW_IS_ETHER(type, ad_len)) {
    /* Ethernet address (or Token Ring address, which is the same type
       of address). */
    return tvb_ether_to_str(tvb, offset);
  }
  return tvb_bytes_to_str(tvb, offset, ad_len);
}

static gchar *
tvb_aarpproaddr_to_str(tvbuff_t *tvb, gint offset, int ad_len, guint16 type)
{
  if (AARP_PRO_IS_ATALK(type, ad_len)) {
    /* Appletalk address.  */
    return tvb_atalkid_to_str(tvb, offset);
  }
  return tvb_bytes_to_str(tvb, offset, ad_len);
}

/* Offsets of fields within an AARP packet. */
#define	AR_HRD		0
#define	AR_PRO		2
#define	AR_HLN		4
#define	AR_PLN		5
#define	AR_OP		6
#define MIN_AARP_HEADER_SIZE	8

static void
dissect_aarp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  guint16     ar_hrd;
  guint16     ar_pro;
  guint8      ar_hln;
  guint8      ar_pln;
  guint16     ar_op;
  proto_tree  *aarp_tree;
  proto_item  *ti;
  const gchar *op_str;
  int         sha_offset, spa_offset, tha_offset, tpa_offset;
  gchar       *sha_str, *spa_str, /* *tha_str, */ *tpa_str;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AARP");
  col_clear(pinfo->cinfo, COL_INFO);

  ar_hrd = tvb_get_ntohs(tvb, AR_HRD);
  ar_pro = tvb_get_ntohs(tvb, AR_PRO);
  ar_hln = tvb_get_guint8(tvb, AR_HLN);
  ar_pln = tvb_get_guint8(tvb, AR_PLN);
  ar_op  = tvb_get_ntohs(tvb, AR_OP);

  /* Get the offsets of the addresses. */
  sha_offset = MIN_AARP_HEADER_SIZE;
  spa_offset = sha_offset + ar_hln;
  tha_offset = spa_offset + ar_pln;
  tpa_offset = tha_offset + ar_hln;

  /* Extract the addresses.  */
  sha_str = tvb_aarphrdaddr_to_str(tvb, sha_offset, ar_hln, ar_hrd);
  spa_str = tvb_aarpproaddr_to_str(tvb, spa_offset, ar_pln, ar_pro);
#if 0
  /* TODO: tha_str is currently not shown nor parsed */
  tha_str = tvb_aarphrdaddr_to_str(tvb, tha_offset, ar_hln, ar_hrd);
#endif
  tpa_str = tvb_aarpproaddr_to_str(tvb, tpa_offset, ar_pln, ar_pro);

  switch (ar_op) {
    case AARP_REQUEST:
    case AARP_REQUEST_SWAPPED:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Who has %s?  Tell %s", tpa_str, spa_str);
      break;
    case AARP_REPLY:
    case AARP_REPLY_SWAPPED:
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s is at %s", spa_str, sha_str);
      break;
    case AARP_PROBE:
    case AARP_PROBE_SWAPPED:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Is there a %s", tpa_str);
      break;
    default:
      col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown AARP opcode 0x%04x", ar_op);
      break;
  }

  if (tree) {
    if ((op_str = match_strval(ar_op, op_vals)))
      ti = proto_tree_add_protocol_format(tree, proto_aarp, tvb, 0,
				      MIN_AARP_HEADER_SIZE + 2*ar_hln +
				      2*ar_pln, "AppleTalk Address Resolution Protocol (%s)", op_str);
    else
      ti = proto_tree_add_protocol_format(tree, proto_aarp, tvb, 0,
				      MIN_AARP_HEADER_SIZE + 2*ar_hln +
				      2*ar_pln,
				      "AppleTalk Address Resolution Protocol (opcode 0x%04x)", ar_op);
    aarp_tree = proto_item_add_subtree(ti, ett_aarp);
    proto_tree_add_uint(aarp_tree, hf_aarp_hard_type, tvb, AR_HRD, 2,
			       ar_hrd);
    proto_tree_add_uint(aarp_tree, hf_aarp_proto_type, tvb, AR_PRO, 2,
			       ar_pro);
    proto_tree_add_uint(aarp_tree, hf_aarp_hard_size, tvb, AR_HLN, 1,
			       ar_hln);
    proto_tree_add_uint(aarp_tree, hf_aarp_proto_size, tvb, AR_PLN, 1,
			       ar_pln);
    proto_tree_add_uint(aarp_tree, hf_aarp_opcode, tvb, AR_OP, 2,
			       ar_op);
    if (ar_hln != 0) {
      proto_tree_add_item(aarp_tree,
	AARP_HW_IS_ETHER(ar_hrd, ar_hln) ? hf_aarp_src_hw_mac : hf_aarp_src_hw,
	tvb, sha_offset, ar_hln, FALSE);
    }

    if (ar_pln != 0) {
      if (AARP_PRO_IS_ATALK(ar_pro, ar_pln)) {
        proto_tree_add_bytes_format_value(aarp_tree, hf_aarp_src_proto_id, tvb,
					  spa_offset, ar_pln, NULL,
					  "%s", spa_str);
      } else {
        proto_tree_add_bytes_format_value(aarp_tree, hf_aarp_src_proto, tvb,
					  spa_offset, ar_pln, NULL,
					  "%s", spa_str);
      }
    }

    if (ar_hln != 0) {
      proto_tree_add_item(aarp_tree,
	AARP_HW_IS_ETHER(ar_hrd, ar_hln) ? hf_aarp_dst_hw_mac : hf_aarp_dst_hw,
	tvb, tha_offset, ar_hln, FALSE);
    }

    if (ar_pln != 0) {
      if (AARP_PRO_IS_ATALK(ar_pro, ar_pln)) {
        proto_tree_add_bytes_format_value(aarp_tree, hf_aarp_dst_proto_id, tvb,
					  tpa_offset, ar_pln,
					  NULL, "%s", tpa_str);
      } else {
        proto_tree_add_bytes_format_value(aarp_tree, hf_aarp_dst_proto, tvb,
					  tpa_offset, ar_pln,
					  NULL, "%s", tpa_str);
      }
    }
  }
}

void
proto_register_aarp(void)
{
  static hf_register_info hf[] = {
    { &hf_aarp_hard_type,
      { "Hardware type",		"aarp.hard.type",
	FT_UINT16,	BASE_HEX,	VALS(hrd_vals),	0x0,
      	NULL, HFILL }},

    { &hf_aarp_proto_type,
      { "Protocol type",		"aarp.proto.type",
	FT_UINT16,	BASE_HEX, 	VALS(etype_vals),	0x0,
      	NULL, HFILL }},

    { &hf_aarp_hard_size,
      { "Hardware size",		"aarp.hard.size",
	FT_UINT8,	BASE_DEC, 	NULL,	0x0,
      	NULL, HFILL }},

    { &hf_aarp_proto_size,
      { "Protocol size",		"aarp.proto.size",
	FT_UINT8,	BASE_DEC, 	NULL,	0x0,
      	NULL, HFILL }},

    { &hf_aarp_opcode,
      { "Opcode",			"aarp.opcode",
	FT_UINT16,	BASE_DEC,	VALS(op_vals),	0x0,
      	NULL, HFILL }},

    { &hf_aarp_src_hw,
      { "Sender hardware address",	"aarp.src.hw",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	NULL, HFILL }},

    { &hf_aarp_src_hw_mac,
      { "Sender MAC address",		"aarp.src.hw_mac",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	NULL, HFILL }},

    { &hf_aarp_src_proto,
      { "Sender protocol address",	"aarp.src.proto",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	NULL, HFILL }},

    { &hf_aarp_src_proto_id,
      { "Sender ID",			"aarp.src.proto_id",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	NULL, HFILL }},

    { &hf_aarp_dst_hw,
      { "Target hardware address",	"aarp.dst.hw",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	NULL, HFILL }},

    { &hf_aarp_dst_hw_mac,
      { "Target MAC address",		"aarp.dst.hw_mac",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	NULL, HFILL }},

    { &hf_aarp_dst_proto,
      { "Target protocol address",	"aarp.dst.proto",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      NULL, HFILL }},

    { &hf_aarp_dst_proto_id,
      { "Target ID",			"aarp.dst.proto_id",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_aarp,
  };

  proto_aarp = proto_register_protocol("Appletalk Address Resolution Protocol",
				       "AARP",
				       "aarp");
  proto_register_field_array(proto_aarp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aarp(void)
{
  dissector_handle_t aarp_handle;

  aarp_handle = create_dissector_handle(dissect_aarp, proto_aarp);
  dissector_add_uint("ethertype", ETHERTYPE_AARP, aarp_handle);
  dissector_add_uint("chdlctype", ETHERTYPE_AARP, aarp_handle);
}
