/* packet-gre.c
 * Routines for the Generic Routing Encapsulation (GRE) protocol
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * $Id: packet-gre.c,v 1.25 2000/08/13 14:08:11 deniel Exp $
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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <glib.h>
#include "packet.h"
#include "packet-ip.h"
#include "packet-ppp.h"
#include "packet-ipx.h"

static int proto_gre = -1;
static int hf_gre_proto = -1;

static gint ett_gre = -1;
static gint ett_gre_flags = -1;

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

#define GRE_PPP		0x880B
#define	GRE_IP		0x0800
#define GRE_WCCP	0x883E
#define GRE_IPX		0x8137

static void add_flags_and_ver(proto_tree *, guint16, int, int);

static const value_string typevals[] = {
	{ GRE_PPP,  "PPP" },
	{ GRE_IP,   "IP" },
	{ GRE_WCCP, "WCCP"},
	{ GRE_IPX,  "IPX"},
	{ 0,        NULL  }
};

static void
dissect_gre(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  
  guint16	flags_and_ver = pntohs(pd + offset);
  guint16	type	      = pntohs(pd + offset + sizeof(flags_and_ver));
  guint16	sre_af;
  guint8	sre_length;
  tvbuff_t	*next_tvb;

  OLD_CHECK_DISPLAY_AS_DATA(proto_gre, pd, offset, fd, tree);

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "GRE");
	
  if (check_col(fd, COL_INFO)) {
    col_add_fstr(fd, COL_INFO, "Encapsulated %s",
        val_to_str(type, typevals, "0x%04X (unknown)"));
  }
		
  if (IS_DATA_IN_FRAME(offset) && tree) {
    gboolean		is_ppp = FALSE;
    gboolean		is_wccp2 = FALSE;
    proto_item *	ti;
    proto_tree *	gre_tree;
    guint 		len = 4;

    if (flags_and_ver & GH_B_C || flags_and_ver & GH_B_R)
      len += 4;
    if (flags_and_ver & GH_B_K)
      len += 4;
    if (flags_and_ver & GH_B_S)
      len += 4;
    switch (type) {

    case GRE_PPP:
      if (flags_and_ver & GH_P_A)
        len += 4;
      is_ppp = TRUE;
      break;

    case GRE_WCCP:
      /* WCCP2 apparently puts an extra 4 octets into the header, but uses
         the same encapsulation type; if it looks as if the first octet of
	 the packet isn't the beginning of an IPv4 header, assume it's
	 WCCP2. */
      if ((pd[offset + sizeof(flags_and_ver) + sizeof(type)] & 0xF0) != 0x40) {
	len += 4;
	is_wccp2 = TRUE;
      }
      break;
    }

    ti = proto_tree_add_protocol_format(tree, proto_gre, NullTVB, offset, len,
      "Generic Routing Encapsulation (%s)",
      val_to_str(type, typevals, "0x%04X - unknown"));
    gre_tree = proto_item_add_subtree(ti, ett_gre);
    add_flags_and_ver(gre_tree, flags_and_ver, offset, is_ppp);

    offset += sizeof(flags_and_ver);

    proto_tree_add_uint(gre_tree, hf_gre_proto, NullTVB, offset, sizeof(type), type);
    offset += sizeof(type);

    if (flags_and_ver & GH_B_C || flags_and_ver & GH_B_R) {
      guint16 checksum = pntohs(pd + offset);
      proto_tree_add_text(gre_tree, NullTVB, offset, sizeof(checksum),
			  "Checksum: %u", checksum);
      offset += sizeof(checksum);
    }
    
    if (flags_and_ver & GH_B_C || flags_and_ver & GH_B_R) {
      guint16 rtoffset = pntohs(pd + offset);
      proto_tree_add_text(gre_tree, NullTVB, offset, sizeof(rtoffset),
			  "Offset: %u", rtoffset);
      offset += sizeof(rtoffset);
    }

    if (flags_and_ver & GH_B_K) {
      if (is_ppp) {
	guint16	paylen;
	guint16 callid;
	
	paylen = pntohs(pd + offset);
	proto_tree_add_text(gre_tree, NullTVB, offset, sizeof(paylen),
			    "Payload length: %u", paylen);
	offset += sizeof(paylen);

	callid = pntohs(pd + offset);
	proto_tree_add_text(gre_tree, NullTVB, offset, sizeof(callid),
			    "Call ID: %u", callid);
	offset += sizeof(callid);
      }
      else {
	guint32 key = pntohl(pd + offset);
	proto_tree_add_text(gre_tree, NullTVB, offset, sizeof(key),
			    "Key: %u", key);
	offset += sizeof(key);
      }
    }
    
    if (flags_and_ver & GH_B_S) {
      guint32 seqnum = pntohl(pd + offset);
      proto_tree_add_text(gre_tree, NullTVB, offset, sizeof(seqnum),
			  "Sequence number: %u", seqnum);
      offset += sizeof(seqnum);
    }

    if (is_ppp && flags_and_ver & GH_P_A) {
      guint32 acknum = pntohl(pd + offset);
      proto_tree_add_text(gre_tree, NullTVB, offset, sizeof(acknum),
			  "Acknowledgement number: %u", acknum);
      offset += sizeof(acknum);
    }

    if (flags_and_ver & GH_B_R) {
      for (;;) {
      	sre_af = pntohs(pd + offset);
        proto_tree_add_text(gre_tree, NullTVB, offset, sizeof(guint16),
  			  "Address family: %u", sre_af);
        offset += sizeof(guint16);
        proto_tree_add_text(gre_tree, NullTVB, offset, 1,
			  "SRE offset: %u", pd[offset++]);
	sre_length = pd[offset];
        proto_tree_add_text(gre_tree, NullTVB, offset, sizeof(guint8),
			  "SRE length: %u", sre_length);
	offset += sizeof(guint8);
	if (sre_af == 0 && sre_length == 0)
	  break;
	offset += sre_length;
      }
    }

    switch (type) {
      case GRE_PPP:
	next_tvb = tvb_create_from_top(offset);
        dissect_ppp(next_tvb, &pi, tree);
 	break;
      case GRE_IP:
        dissect_ip(pd, offset, fd, tree);
        break;
      case GRE_WCCP:
        if (is_wccp2) {
          proto_tree_add_text(gre_tree, NullTVB, offset, sizeof(guint32), "WCCPv2 Data");
          offset += 4;
        }
        dissect_ip(pd, offset, fd, tree);
        break;
      case GRE_IPX:
	next_tvb = tvb_create_from_top(offset);
        dissect_ipx(next_tvb, &pi, tree);
        break;
      default:
	next_tvb = tvb_create_from_top(offset);
	dissect_data(next_tvb, &pi, gre_tree);
	break;
    }
  }
}

static void
add_flags_and_ver(proto_tree *tree, guint16 flags_and_ver, int offset, int is_ppp) {

  proto_item *	ti;
  proto_tree *	fv_tree;
  int		nbits = sizeof(flags_and_ver) * 8;
  
  ti = proto_tree_add_text(tree, NullTVB, offset, 2, 
			   "Flags and version: %#04x", flags_and_ver);
  fv_tree = proto_item_add_subtree(ti, ett_gre_flags);
  
  proto_tree_add_text(fv_tree, NullTVB, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_C, nbits,
					      "Checksum", "No checksum"));
  proto_tree_add_text(fv_tree, NullTVB, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_R, nbits,
					      "Routing", "No routing"));
  proto_tree_add_text(fv_tree, NullTVB, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_K, nbits,
					      "Key", "No key"));
  proto_tree_add_text(fv_tree, NullTVB, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_S, nbits,
					      "Sequence number", "No sequence number"));
  proto_tree_add_text(fv_tree, NullTVB, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_s, nbits,
					      "Strict source route", "No strict source route"));
  proto_tree_add_text(fv_tree, NullTVB, offset, sizeof(flags_and_ver), "%s",
		      decode_numeric_bitfield(flags_and_ver, GH_B_RECUR, nbits,
					      "Recursion control: %u"));
  if (is_ppp) {
    proto_tree_add_text(fv_tree, NullTVB, offset, sizeof(flags_and_ver), "%s",
			decode_boolean_bitfield(flags_and_ver, GH_P_A, nbits,
						"Acknowledgment number", "No acknowledgment number"));
    proto_tree_add_text(fv_tree, NullTVB, offset, sizeof(flags_and_ver), "%s",
			decode_numeric_bitfield(flags_and_ver, GH_P_FLAGS, nbits,
						"Flags: %u"));
  }
  else {
    proto_tree_add_text(fv_tree, NullTVB, offset, sizeof(flags_and_ver), "%s",
			decode_numeric_bitfield(flags_and_ver, GH_R_FLAGS, nbits,
						"Flags: %u"));
  }

  proto_tree_add_text(fv_tree, NullTVB, offset, sizeof(flags_and_ver), "%s",
		      decode_numeric_bitfield(flags_and_ver, GH_B_VER, nbits,
					      "Version: %u"));
 }
 
void
proto_register_gre(void)
{
	static hf_register_info hf[] = {
		{ &hf_gre_proto,
			{ "Protocol Type", "gre.proto", FT_UINT16, BASE_HEX, VALS(typevals), 0x0,
				"The protocol that is GRE encapsulated"}
		},
	};
	static gint *ett[] = {
		&ett_gre,
		&ett_gre_flags,
	};

        proto_gre = proto_register_protocol("Generic Routing Encapsulation", "gre");
        proto_register_field_array(proto_gre, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_gre(void)
{
	old_dissector_add("ip.proto", IP_PROTO_GRE, dissect_gre);
}
