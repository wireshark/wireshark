/* packet-gre.c
 * Routines for the Generic Routing Encapsulation (GRE) protocol
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * $Id: packet-gre.c,v 1.3 1999/07/13 02:52:51 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

static int calc_len(guint16, int);
static void add_flags_and_ver(proto_tree *, guint16, int, int);

void
dissect_gre(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  
  guint16	flags_and_ver = pntohs(pd + offset);
  guint16	type	      = pntohs(pd + offset + sizeof(flags_and_ver));
  static const value_string typevals[] = {
    { GRE_PPP, "PPP" },
    { 0,       NULL  }
  };

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "GRE");
	
  if (check_col(fd, COL_INFO)) {
    if (type == GRE_PPP)
      col_add_str(fd, COL_INFO, "Encapsulated PPP");
    else
      col_add_str(fd, COL_INFO, "Encapsulated unknown");
  }
		
  if (fd->cap_len > offset && tree) {
    int			is_ppp;
    proto_item *	ti;
    proto_tree *	gre_tree;

    if (type == GRE_PPP) {
      is_ppp = 1;
      ti = proto_tree_add_text(tree, offset, calc_len(flags_and_ver, 1),
	"Generic Routing Encapsulation (PPP)");
      gre_tree = proto_item_add_subtree(ti, ETT_GRE);
      add_flags_and_ver(gre_tree, flags_and_ver, offset, 1);
    }
    else {
      is_ppp = 0;
      ti = proto_tree_add_text(tree, offset, calc_len(flags_and_ver, 1),
	"Generic Routing Encapsulation");
      gre_tree = proto_item_add_subtree(ti, ETT_GRE);
      add_flags_and_ver(gre_tree, flags_and_ver, offset, 0);
    }

    offset += sizeof(flags_and_ver);

    proto_tree_add_text(gre_tree, offset, sizeof(type),
			"Protocol Type: %s (%#04x)",
			val_to_str(type, typevals, "Unknown"), type);
    offset += sizeof(type);    

    if (flags_and_ver & GH_B_C || flags_and_ver & GH_B_R) {
      guint16 checksum = pntohs(pd + offset);
      proto_tree_add_text(gre_tree, offset, sizeof(checksum),
			  "Checksum: %u", checksum);
      offset += sizeof(checksum);
    }
    
    if (flags_and_ver & GH_B_C || flags_and_ver & GH_B_R) {
      guint16 rtoffset = pntohs(pd + offset);
      proto_tree_add_text(gre_tree, offset, sizeof(rtoffset),
			  "Offset: %u", rtoffset);
      offset += sizeof(rtoffset);
    }

    if (flags_and_ver & GH_B_K) {
      if (is_ppp) {
	guint16	paylen;
	guint16 callid;
	
	paylen = pntohs(pd + offset);
	proto_tree_add_text(gre_tree, offset, sizeof(paylen),
			    "Payload length: %u", paylen);
	offset += sizeof(paylen);

	callid = pntohs(pd + offset);
	proto_tree_add_text(gre_tree, offset, sizeof(callid),
			    "Call ID: %u", callid);
	offset += sizeof(callid);
      }
      else {
	guint32 key = pntohl(pd + offset);
	proto_tree_add_text(gre_tree, offset, sizeof(key),
			    "Key: %u", key);
	offset += sizeof(key);
      }
    }
    
    if (flags_and_ver & GH_B_S) {
      guint32 seqnum = pntohl(pd + offset);
      proto_tree_add_text(gre_tree, offset, sizeof(seqnum),
			  "Sequence number: %u", seqnum);
      offset += sizeof(seqnum);
    }

    if (is_ppp && flags_and_ver & GH_P_A) {
      guint32 acknum = pntohl(pd + offset);
      proto_tree_add_text(gre_tree, offset, sizeof(acknum),
			  "Acknowledgement number: %u", acknum);
      offset += sizeof(acknum);
    }

    if (flags_and_ver & GH_B_R) {
      proto_tree_add_text(gre_tree, offset, sizeof(guint16),
			  "Address family: %u", pntohs(pd + offset));
      offset += sizeof(guint16);
      proto_tree_add_text(gre_tree, offset, 1,
			  "SRE offset: %u", pd[offset++]);
      proto_tree_add_text(gre_tree, offset, 1,
			  "SRE length: %u", pd[offset++]);
    }

    switch (type) {
       case GRE_PPP:
 	dissect_payload_ppp(pd, offset, fd, tree);
 	break;
      default:
	dissect_data(pd, offset, fd, gre_tree);
    }
  }
}

static int
calc_len(guint16 flags_and_ver, int is_ppp) {
  
  int	len = 4;
  
  if (flags_and_ver & GH_B_C || flags_and_ver & GH_B_R) len += 4;
  if (flags_and_ver & GH_B_K) len += 4;
  if (flags_and_ver & GH_B_S) len += 4;
  if (is_ppp && flags_and_ver & GH_P_A) len += 4;
  
  return len;
}

static void
add_flags_and_ver(proto_tree *tree, guint16 flags_and_ver, int offset, int is_ppp) {

  proto_item *	ti;
  proto_tree *	fv_tree;
  int		nbits = sizeof(flags_and_ver) * 8;
  
  ti = proto_tree_add_text(tree, offset, 2, 
			   "Flags and version: %#08x", flags_and_ver);
  fv_tree = proto_item_add_subtree(ti, ETT_GRE_FLAGS);
  
  proto_tree_add_text(fv_tree, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_C, nbits,
					      "Checksum", "No checksum"));
  proto_tree_add_text(fv_tree, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_R, nbits,
					      "Routing", "No routing"));
  proto_tree_add_text(fv_tree, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_K, nbits,
					      "Key", "No key"));
  proto_tree_add_text(fv_tree, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_S, nbits,
					      "Sequence number", "No sequence number"));
  proto_tree_add_text(fv_tree, offset, sizeof(flags_and_ver), "%s",
		      decode_boolean_bitfield(flags_and_ver, GH_B_s, nbits,
					      "Strict source route", "No strict source route"));
  proto_tree_add_text(fv_tree, offset, sizeof(flags_and_ver), "%s",
		      decode_numeric_bitfield(flags_and_ver, GH_B_RECUR, nbits,
					      "Recursion control: %u"));
  if (is_ppp) {
    proto_tree_add_text(fv_tree, offset, sizeof(flags_and_ver), "%s",
			decode_boolean_bitfield(flags_and_ver, GH_P_A, nbits,
						"Acknowledgment number", "No acknowledgment number"));
    proto_tree_add_text(fv_tree, offset, sizeof(flags_and_ver), "%s",
			decode_numeric_bitfield(flags_and_ver, GH_P_FLAGS, nbits,
						"Flags: %u"));
  }
  else {
    proto_tree_add_text(fv_tree, offset, sizeof(flags_and_ver), "%s",
			decode_numeric_bitfield(flags_and_ver, GH_R_FLAGS, nbits,
						"Flags: %u"));
  }

  proto_tree_add_text(fv_tree, offset, sizeof(flags_and_ver), "%s",
		      decode_numeric_bitfield(flags_and_ver, GH_B_VER, nbits,
					      "Version: %u"));
 }
 
