/* packet-gre.c
 * Routines for the Generic Routing Encapsulation (GRE) protocol
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
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
#include "packet-wccp.h"
#include <epan/in_cksum.h>
#include <epan/etypes.h>
#include <epan/greproto.h>
#include <epan/ipproto.h>
#include <epan/llcsaps.h>

/*
 * See RFC 1701 "Generic Routing Encapsulation (GRE)", RFC 1702
 * "Generic Routing Encapsulation over IPv4 networks", RFC 2637
 * "Point-to-Point Tunneling Protocol (PPTP)", RFC 2784 "Generic
 * Routing Encapsulation (GRE)", RFC 2890 "Key and Sequence
 * Number Extensions to GRE" and draft-ietf-mpls-in-ip-or-gre-07.txt
 * "Encapsulating MPLS in IP or Generic Routing Encapsulation (GRE)".
 */

static int proto_gre = -1;
static int hf_gre_proto = -1;
static int hf_gre_key = -1;

static gint ett_gre = -1;
static gint ett_gre_flags = -1;
static gint ett_gre_wccp2_redirect_header = -1;
static gint ett_3gpp2_attribs = -1;

static dissector_table_t gre_dissector_table;
static dissector_handle_t data_handle;

/* bit positions for flags in header */
#define GH_B_C		0x8000
#define GH_B_R		0x4000
#define GH_B_K		0x2000
#define GH_B_S		0x1000
#define GH_B_s		0x0800
#define GH_B_RECUR	0x0700
#define GH_P_A		0x0080	/* only in special PPTPized GRE header */
#define GH_P_FLAGS	0x0078	/* only in special PPTPized GRE header */
#define GH_R_FLAGS	0x00F8
#define GH_B_VER	0x0007

static void add_flags_and_ver(proto_tree *, guint16, tvbuff_t *, int, int);
static void dissect_gre_wccp2_redirect_header(tvbuff_t *, int, proto_tree *);

static const value_string typevals[] = {
	{ ETHERTYPE_PPP,       "PPP" },
	{ ETHERTYPE_IP,        "IP" },
	{ SAP_OSINL5,          "OSI"},
	{ GRE_WCCP,            "WCCP"},
	{ GRE_NHRP,            "NHRP"},
	{ ETHERTYPE_IPX,       "IPX"},
	{ ETHERTYPE_ETHBRIDGE, "Transparent Ethernet bridging" },
	{ ETHERTYPE_RAW_FR,    "Frame Relay"},
	{ ETHERTYPE_IPv6,      "IPv6" },
	{ ETHERTYPE_MPLS,      "MPLS label switched packet" },
	{ ETHERTYPE_CDMA2000_A10_UBS,"CDMA2000 A10 Unstructured byte stream" },
        { ETHERTYPE_3GPP2,       "CDMA2000 A10 3GPP2 Packet" },
	{ 0,                   NULL }
};

#define ID_3GPP2_SDI_FLAG 1
#define ID_3GPP2_FLOW_CTRL 2
#define ID_3GPP2_FLOW_DISCRIMINATOR 3
#define ID_3GPP2_SEG 4

static const value_string segvals[] = {
   { 0x00, "Packet Started" },
   { 0x01, "Packet Continuing" },
   { 0x02, "Packet Ended" },
   { 0,    NULL }
};

static int
dissect_gre_3gpp2_attribs(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  gboolean	last_attrib = FALSE;

  proto_item* ti = 
      proto_tree_add_text(tree, tvb, offset, 0, "3GPP2 Attributes");

  proto_tree* atree = proto_item_add_subtree(ti, ett_3gpp2_attribs);

  while(last_attrib != TRUE)
  {
     guint8 attrib_id = tvb_get_guint8(tvb, offset);
     guint8 attrib_length = tvb_get_guint8(tvb, offset + 1);

     offset += 2;
     last_attrib = (attrib_id & 0x80)?TRUE:FALSE;
     attrib_id &= 0x7F;

     switch(attrib_id)
     {
        case ID_3GPP2_FLOW_DISCRIMINATOR:
             {
              guint8 flow_disc = tvb_get_guint8(tvb, offset);
              proto_tree_add_text
                (atree, tvb, offset, 1, "Flow Discriminator: %d (0x%02x)", 
                        (int)flow_disc,
                        (int)flow_disc);
             }
             break;
        case ID_3GPP2_SDI_FLAG:
             {
              guint8 sdi_attr = tvb_get_guint8(tvb, offset);
              proto_tree_add_text
                 (atree, tvb, offset, 2, "1x SDB/HRPD DoS Indicator: %s",
                      decode_boolean_bitfield(sdi_attr, 0x80, 8,
                                              "Set", "Not Set"));
             }
             break;
        case ID_3GPP2_SEG:
             {
              guint8 seg_ind = tvb_get_guint8(tvb, offset);
              seg_ind = (seg_ind >> 6) & 0x03;
              proto_tree_add_text
                 (atree, tvb, offset, 2, "Segmentation Indicator: %s",
                      val_to_str(seg_ind, segvals, "0x%02X - Unknown"));
             }
             break;
        case ID_3GPP2_FLOW_CTRL:
             {
              guint8 flow_control = tvb_get_guint8(tvb, offset);
              proto_tree_add_text
                 (atree, tvb, offset, 2, "Flow Control Indicator: %s",
                      decode_boolean_bitfield(flow_control, 0x80, 8,
                                              "XOFF", "XON"));
              proto_tree_add_text
                 (atree, tvb, offset, 2, "Duration Indicator: %s",
                      decode_boolean_bitfield(flow_control, 0x40, 8,
                                              "INDEFINITE", "TEMPORARY"));
             }
             break;
     }

     offset += attrib_length;
  } 

  return offset;
}

static void
dissect_gre(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int		offset = 0;
  guint16	flags_and_ver;
  guint16	type;
  gboolean	is_ppp = FALSE;
  gboolean	is_wccp2 = FALSE;
  guint 	len = 4;
  proto_item 	*ti;
  proto_tree 	*gre_tree = NULL;
  guint16	sre_af;
  guint8	sre_length;
  tvbuff_t	*next_tvb;

  flags_and_ver = tvb_get_ntohs(tvb, offset);
  type = tvb_get_ntohs(tvb, offset + sizeof(flags_and_ver));

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GRE");

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "Encapsulated %s",
		 val_to_str(type, typevals, "0x%04X (unknown)"));
  }

  if (flags_and_ver & GH_B_C || flags_and_ver & GH_B_R)
    len += 4;
  if (flags_and_ver & GH_B_K)
    len += 4;
  if (flags_and_ver & GH_B_S)
    len += 4;
  switch (type) {

  case ETHERTYPE_PPP:
    if (flags_and_ver & GH_P_A)
      len += 4;
    is_ppp = TRUE;
    break;
  case ETHERTYPE_3GPP2: 
  case ETHERTYPE_CDMA2000_A10_UBS:
    if (flags_and_ver & GH_P_A)
      len += 4;
   is_ppp = TRUE;
   break;

  case GRE_WCCP:
    /* WCCP2 puts an extra 4 octets into the header, but uses the same
       encapsulation type; if it looks as if the first octet of the packet
       isn't the beginning of an IPv4 header, assume it's WCCP2. */
    if ((tvb_get_guint8(tvb, offset + sizeof(flags_and_ver) + sizeof(type)) & 0xF0) != 0x40) {
      len += 4;
      is_wccp2 = TRUE;
    }
    break;
  }

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_gre, tvb, offset, len,
      "Generic Routing Encapsulation (%s)",
      val_to_str(type, typevals, "0x%04X - unknown"));
    gre_tree = proto_item_add_subtree(ti, ett_gre);
    add_flags_and_ver(gre_tree, flags_and_ver, tvb, offset, is_ppp);
  }
  offset += sizeof(flags_and_ver);

  if (tree) {
    proto_tree_add_uint(gre_tree, hf_gre_proto, tvb, offset, sizeof(type), type);
  }
  offset += sizeof(type);

  if (flags_and_ver & GH_B_C || flags_and_ver & GH_B_R) {
    if (tree) {
      guint length, reported_length;
      vec_t cksum_vec[1];
      guint16 cksum, computed_cksum;

      cksum = tvb_get_ntohs(tvb, offset);
      length = tvb_length(tvb);
      reported_length = tvb_reported_length(tvb);
      if ((flags_and_ver & GH_B_C) && !pinfo->fragmented
		&& length >= reported_length) {
	/* The Checksum Present bit is set, and the packet isn't part of a
	   fragmented datagram and isn't truncated, so we can checksum it. */

	cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, reported_length);
	cksum_vec[0].len = reported_length;
	computed_cksum = in_cksum(cksum_vec, 1);
	if (computed_cksum == 0) {
	  proto_tree_add_text(gre_tree, tvb, offset, 2,
			"Checksum: 0x%04x [correct]", cksum);
	} else {
	  proto_tree_add_text(gre_tree, tvb, offset, 2,
			"Checksum: 0x%04x [incorrect, should be 0x%04x]",
			cksum, in_cksum_shouldbe(cksum, computed_cksum));
	}
      } else {
	proto_tree_add_text(gre_tree, tvb, offset, 2,
			  "Checksum: 0x%04x", cksum);
      }
    }
    offset += 2;
  }

  if (flags_and_ver & GH_B_C || flags_and_ver & GH_B_R) {
    if (tree) {
      proto_tree_add_text(gre_tree, tvb, offset, 2,
			  "Offset: %u", tvb_get_ntohs(tvb, offset));
    }
    offset += 2;
  }

  if (flags_and_ver & GH_B_K) {
    if (is_ppp && type!=ETHERTYPE_CDMA2000_A10_UBS) {
      if (tree) {
	proto_tree_add_text(gre_tree, tvb, offset, 2,
			    "Payload length: %u", tvb_get_ntohs(tvb, offset));
      }
      offset += 2;
      if (tree) {
	proto_tree_add_text(gre_tree, tvb, offset, 2,
			    "Call ID: %u", tvb_get_ntohs(tvb, offset));
      }
      offset += 2;
    }
    else {
      if (tree)
	proto_tree_add_item(gre_tree, hf_gre_key, tvb, offset, 4, FALSE);
      offset += 4;
    }
  }

  if (flags_and_ver & GH_B_S) {
    if (tree) {
      proto_tree_add_text(gre_tree, tvb, offset, 4,
			  "Sequence number: %u", tvb_get_ntohl(tvb, offset));
    }
    offset += 4;
  }

  if (is_ppp && flags_and_ver & GH_P_A) {
    if (tree) {
      proto_tree_add_text(gre_tree, tvb, offset, 4,
			  "Acknowledgement number: %u", tvb_get_ntohl(tvb, offset));
    }
    offset += 4;
  }

  if (flags_and_ver & GH_B_R) {
    for (;;) {
      sre_af = tvb_get_ntohs(tvb, offset);
      if (tree) {
        proto_tree_add_text(gre_tree, tvb, offset, sizeof(guint16),
  			  "Address family: %u", sre_af);
      }
      offset += sizeof(guint16);
      if (tree) {
        proto_tree_add_text(gre_tree, tvb, offset, 1,
			  "SRE offset: %u", tvb_get_guint8(tvb, offset));
      }
      offset += sizeof(guint8);
      sre_length = tvb_get_guint8(tvb, offset);
      if (tree) {
        proto_tree_add_text(gre_tree, tvb, offset, sizeof(guint8),
			  "SRE length: %u", sre_length);
      }
      offset += sizeof(guint8);
      if (sre_af == 0 && sre_length == 0)
	break;
      offset += sre_length;
    }
  }

  if (type == GRE_WCCP) {
    if (is_wccp2) {
      if (tree)
        dissect_gre_wccp2_redirect_header(tvb, offset, gre_tree);
      offset += 4;
    }
  }

  if(type == ETHERTYPE_3GPP2) {
     offset = dissect_gre_3gpp2_attribs(tvb, offset, gre_tree);
  }
  

  /* If the S bit is not set, this packet might not have a payload, so
     check whether there's any data left, first.

     XXX - the S bit isn't in RFC 2784, which deprecates that bit
     and some other bits in RFC 1701 and says that they should be
     zero for RFC 2784-compliant GRE; as such, the absence of the
     S bit doesn't necessarily mean there's no payload.  */
  if (!(flags_and_ver & GH_B_S)) {
    if (tvb_reported_length_remaining(tvb, offset) <= 0)
      return;	/* no payload */
  }
  next_tvb = tvb_new_subset(tvb, offset, -1, -1);
  if (!dissector_try_port(gre_dissector_table, type, next_tvb, pinfo, tree))
    call_dissector(data_handle,next_tvb, pinfo, gre_tree);
}

static void
add_flags_and_ver(proto_tree *tree, guint16 flags_and_ver, tvbuff_t *tvb,
    int offset, int is_ppp)
{
  proto_item *	ti;
  proto_tree *	fv_tree;
  int		nbits = sizeof(flags_and_ver) * 8;

  ti = proto_tree_add_text(tree, tvb, offset, 2,
			   "Flags and version: %#04x", flags_and_ver);
  fv_tree = proto_item_add_subtree(ti, ett_gre_flags);

  proto_tree_add_text(fv_tree, tvb, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_C, nbits,
					      "Checksum", "No checksum"));
  proto_tree_add_text(fv_tree, tvb, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_R, nbits,
					      "Routing", "No routing"));
  proto_tree_add_text(fv_tree, tvb, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_K, nbits,
					      "Key", "No key"));
  proto_tree_add_text(fv_tree, tvb, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_S, nbits,
					      "Sequence number", "No sequence number"));
  proto_tree_add_text(fv_tree, tvb, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_s, nbits,
					      "Strict source route", "No strict source route"));
  proto_tree_add_text(fv_tree, tvb, offset, sizeof(flags_and_ver), "%s",
		      decode_numeric_bitfield(flags_and_ver, GH_B_RECUR, nbits,
					      "Recursion control: %u"));
  if (is_ppp) {
    proto_tree_add_text(fv_tree, tvb, offset, sizeof(flags_and_ver), "%s",
			decode_boolean_bitfield(flags_and_ver, GH_P_A, nbits,
						"Acknowledgment number", "No acknowledgment number"));
    proto_tree_add_text(fv_tree, tvb, offset, sizeof(flags_and_ver), "%s",
			decode_numeric_bitfield(flags_and_ver, GH_P_FLAGS, nbits,
						"Flags: %u"));
  }
  else {
    proto_tree_add_text(fv_tree, tvb, offset, sizeof(flags_and_ver), "%s",
			decode_numeric_bitfield(flags_and_ver, GH_R_FLAGS, nbits,
						"Flags: %u"));
  }

  proto_tree_add_text(fv_tree, tvb, offset, sizeof(flags_and_ver), "%s",
		      decode_numeric_bitfield(flags_and_ver, GH_B_VER, nbits,
					      "Version: %u"));
 }

static void
dissect_gre_wccp2_redirect_header(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  proto_item *	ti;
  proto_tree *	rh_tree;
  guint8	rh_flags;

  ti = proto_tree_add_text(tree, tvb, offset, 4, "Redirect header");
  rh_tree = proto_item_add_subtree(ti, ett_gre_wccp2_redirect_header);

  rh_flags = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(rh_tree, tvb, offset, 1, "%s",
		      decode_boolean_bitfield(rh_flags, 0x80, 8,
				      "Dynamic service", "Well-known service"));
  proto_tree_add_text(rh_tree, tvb, offset, 1, "%s",
		      decode_boolean_bitfield(rh_flags, 0x40, 8,
			      "Alternative bucket used", "Alternative bucket not used"));

  proto_tree_add_text(rh_tree, tvb, offset + 1, 1, "Service ID: %s",
      val_to_str(tvb_get_guint8(tvb, offset + 1), service_id_vals, "Unknown (0x%02X)"));
  if (rh_flags & 0x40)
    proto_tree_add_text(rh_tree, tvb, offset + 2, 1, "Alternative bucket index: %u",
			tvb_get_guint8(tvb, offset + 2));
  proto_tree_add_text(rh_tree, tvb, offset + 3, 1, "Primary bucket index: %u",
			tvb_get_guint8(tvb, offset + 3));
}

void
proto_register_gre(void)
{
	static hf_register_info hf[] = {
		{ &hf_gre_proto,
		  { "Protocol Type", "gre.proto", FT_UINT16, BASE_HEX, VALS(typevals), 0x0,
			"The protocol that is GRE encapsulated", HFILL }
		},
		{ &hf_gre_key,
		  { "GRE Key", "gre.key", FT_UINT32, BASE_HEX, NULL, 0x0,
			"", HFILL }
		},
	};
	static gint *ett[] = {
		&ett_gre,
		&ett_gre_flags,
		&ett_gre_wccp2_redirect_header,
		&ett_3gpp2_attribs,
	};

	proto_gre = proto_register_protocol("Generic Routing Encapsulation",
										"GRE", "gre");
	proto_register_field_array(proto_gre, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	gre_dissector_table = register_dissector_table("gre.proto",
												   "GRE protocol type", FT_UINT16, BASE_HEX);
}

void
proto_reg_handoff_gre(void)
{
	dissector_handle_t gre_handle;

	gre_handle = create_dissector_handle(dissect_gre, proto_gre);
	dissector_add("ip.proto", IP_PROTO_GRE, gre_handle);
	data_handle = find_dissector("data");
}
