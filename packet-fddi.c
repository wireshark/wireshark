/* packet-fddi.c
 * Routines for FDDI packet disassembly
 *
 * Laurent Deniel <deniel@worldnet.fr>
 *
 * $Id: packet-fddi.c,v 1.40 2000/11/16 07:35:37 guy Exp $
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

#include <stdio.h>
#include <glib.h>
#include "bitswap.h"
#include "packet.h"
#include "packet-fddi.h"
#include "packet-llc.h"
#include "resolv.h"

static int proto_fddi = -1;
static int hf_fddi_fc = -1;
static int hf_fddi_dst = -1;
static int hf_fddi_src = -1;
static int hf_fddi_addr = -1;

static gint ett_fddi = -1;

/* FDDI Frame Control values */

#define FDDI_FC_VOID		0x00		/* Void frame */
#define FDDI_FC_NRT		0x80		/* Nonrestricted token */
#define FDDI_FC_RT		0xc0		/* Restricted token */
#define FDDI_FC_MAC		0xc0		/* MAC frame */
#define FDDI_FC_SMT		0x40		/* SMT frame */
#define FDDI_FC_SMT_INFO	0x41		/* SMT Info */
#define FDDI_FC_SMT_NSA		0x4F		/* SMT Next station adrs */
#define FDDI_FC_SMT_MIN		FDDI_FC_SMT_INFO
#define FDDI_FC_SMT_MAX		FDDI_FC_SMT_NSA
#define FDDI_FC_MAC_MIN		0xc1
#define FDDI_FC_MAC_BEACON	0xc2		/* MAC Beacon frame */
#define FDDI_FC_MAC_CLAIM	0xc3		/* MAC Claim frame */
#define FDDI_FC_MAC_MAX		0xcf
#define FDDI_FC_LLC_ASYNC	0x50		/* Async. LLC frame */
#define FDDI_FC_LLC_ASYNC_MIN	FDDI_FC_LLC_ASYNC
#define FDDI_FC_LLC_ASYNC_DEF	0x54
#define FDDI_FC_LLC_ASYNC_MAX	0x5f
#define FDDI_FC_LLC_SYNC	0xd0		/* Sync. LLC frame */
#define FDDI_FC_LLC_SYNC_MIN	FDDI_FC_LLC_SYNC
#define FDDI_FC_LLC_SYNC_MAX	0xd7
#define FDDI_FC_IMP_ASYNC	0x60		/* Implementor Async. */
#define FDDI_FC_IMP_ASYNC_MIN	FDDI_FC_IMP_ASYNC
#define FDDI_FC_IMP_ASYNC_MAX	0x6f
#define FDDI_FC_IMP_SYNC	0xe0		/* Implementor Synch. */

#define FDDI_FC_CLFF		0xF0		/* Class/Length/Format bits */
#define FDDI_FC_ZZZZ		0x0F		/* Control bits */

/*
 * Async frame ZZZZ bits:
 */
#define FDDI_FC_ASYNC_R		0x08		/* Reserved */
#define FDDI_FC_ASYNC_PRI	0x07		/* Priority */

#define FDDI_HEADER_SIZE	13

/* field positions */

#define FDDI_P_FC		0
#define FDDI_P_DHOST		1
#define FDDI_P_SHOST		7

static void
swap_mac_addr(u_char *swapped_addr, const u_char *orig_addr)
{
	int i;

	for (i = 0; i < 6; i++) {
		swapped_addr[i] = BIT_SWAP(orig_addr[i]);
	}
}


void
capture_fddi(const u_char *pd, packet_counts *ld)
{
  int        offset = 0, fc;

  if (!BYTES_ARE_IN_FRAME(0, FDDI_HEADER_SIZE)) {
    ld->other++;
    return;
  }
  offset = FDDI_HEADER_SIZE;

  fc = (int) pd[FDDI_P_FC];

  switch (fc) {

    /* From now, only 802.2 SNAP (Async. LCC frame) is supported */

    case FDDI_FC_LLC_ASYNC + 0  :
    case FDDI_FC_LLC_ASYNC + 1  :
    case FDDI_FC_LLC_ASYNC + 2  :
    case FDDI_FC_LLC_ASYNC + 3  :
    case FDDI_FC_LLC_ASYNC + 4  :
    case FDDI_FC_LLC_ASYNC + 5  :
    case FDDI_FC_LLC_ASYNC + 6  :
    case FDDI_FC_LLC_ASYNC + 7  :
    case FDDI_FC_LLC_ASYNC + 8  :
    case FDDI_FC_LLC_ASYNC + 9  :
    case FDDI_FC_LLC_ASYNC + 10 :
    case FDDI_FC_LLC_ASYNC + 11 :
    case FDDI_FC_LLC_ASYNC + 12 :
    case FDDI_FC_LLC_ASYNC + 13 :
    case FDDI_FC_LLC_ASYNC + 14 :
    case FDDI_FC_LLC_ASYNC + 15 :
      capture_llc(pd, offset, ld);
      return;
    default :
      ld->other++;
      return;

  } /* fc */

} /* capture_fddi */

static gchar *
fddifc_to_str(int fc)
{
  static gchar strbuf[128+1];

  switch (fc) {

  case FDDI_FC_VOID:			/* Void frame */
    return "Void frame";

  case FDDI_FC_NRT:			/* Nonrestricted token */
    return "Nonrestricted token";

  case FDDI_FC_RT:			/* Restricted token */
    return "Restricted token";

  case FDDI_FC_SMT_INFO:		/* SMT Info */
    return "SMT info";

  case FDDI_FC_SMT_NSA:			/* SMT Next station adrs */
    return "SMT Next station address";

  case FDDI_FC_MAC_BEACON:		/* MAC Beacon frame */
    return "MAC beacon";

  case FDDI_FC_MAC_CLAIM:		/* MAC Claim frame */
    return "MAC claim token";

  default:
    switch (fc & FDDI_FC_CLFF) {

    case FDDI_FC_MAC:
      sprintf(strbuf, "MAC frame, control %x", fc & FDDI_FC_ZZZZ);
      return strbuf;

    case FDDI_FC_SMT:
      sprintf(strbuf, "SMT frame, control %x", fc & FDDI_FC_ZZZZ);
      return strbuf;

    case FDDI_FC_LLC_ASYNC:
      if (fc & FDDI_FC_ASYNC_R)
        sprintf(strbuf, "Async LLC frame, control %x", fc & FDDI_FC_ZZZZ);
      else
        sprintf(strbuf, "Async LLC frame, priority %d",
			fc & FDDI_FC_ASYNC_PRI);
      return strbuf;

    case FDDI_FC_LLC_SYNC:
      if (fc & FDDI_FC_ZZZZ) {
        sprintf(strbuf, "Sync LLC frame, control %x", fc & FDDI_FC_ZZZZ);
        return strbuf;
      } else
        return "Sync LLC frame";

    case FDDI_FC_IMP_ASYNC:
      sprintf(strbuf, "Implementor async frame, control %x",
			fc & FDDI_FC_ZZZZ);
      return strbuf;

    case FDDI_FC_IMP_SYNC:
      sprintf(strbuf, "Implementor sync frame, control %x",
			fc & FDDI_FC_ZZZZ);
      return strbuf;
      break;

    default:
      return "Unknown frame type";
    }
  }
}

void
dissect_fddi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		gboolean bitswapped)
{
  int        fc;
  proto_tree *fh_tree = NULL;
  proto_item *ti;
  gchar      *fc_str;
  static u_char src[6], dst[6];
  u_char     src_swapped[6], dst_swapped[6];
  tvbuff_t   *next_tvb;

  CHECK_DISPLAY_AS_DATA(proto_fddi, tvb, pinfo, tree);

  pinfo->current_proto = "FDDI";
  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_add_str(pinfo->fd, COL_PROTOCOL, "FDDI");

  fc = (int) tvb_get_guint8(tvb, FDDI_P_FC);
  fc_str = fddifc_to_str(fc);

  if (check_col(pinfo->fd, COL_INFO))
    col_add_str(pinfo->fd, COL_INFO, fc_str);

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_fddi, tvb, 0, FDDI_HEADER_SIZE,
		"Fiber Distributed Data Interface, %s", fc_str);
    fh_tree = proto_item_add_subtree(ti, ett_fddi);
    proto_tree_add_uint(fh_tree, hf_fddi_fc, tvb, FDDI_P_FC, 1, fc);
  }

  /* Extract the destination address, possibly bit-swapping it. */
  if (bitswapped)
    swap_mac_addr(dst, (u_char *) tvb_get_ptr(tvb, FDDI_P_DHOST, 6));
  else
    memcpy(dst, (u_char *) tvb_get_ptr(tvb, FDDI_P_DHOST, 6), sizeof dst);
  swap_mac_addr(dst_swapped, (u_char*) tvb_get_ptr(tvb, FDDI_P_DHOST, 6));

  /* XXX - copy them to some buffer associated with "pi", rather than
     just making "dst" static? */
  SET_ADDRESS(&pi.dl_dst, AT_ETHER, 6, &dst[0]);
  SET_ADDRESS(&pi.dst, AT_ETHER, 6, &dst[0]);

  if (fh_tree) {
    proto_tree_add_ether(fh_tree, hf_fddi_dst, tvb, FDDI_P_DHOST, 6, dst);
    proto_tree_add_ether_hidden(fh_tree, hf_fddi_addr, tvb, FDDI_P_DHOST, 6, dst);

    /* hide some bit-swapped mac address fields in the proto_tree, just in case */
    proto_tree_add_ether_hidden(fh_tree, hf_fddi_dst, tvb, FDDI_P_DHOST, 6, dst_swapped);
    proto_tree_add_ether_hidden(fh_tree, hf_fddi_addr, tvb, FDDI_P_DHOST, 6, dst_swapped);
  }

  /* Extract the source address, possibly bit-swapping it. */
  if (bitswapped)
    swap_mac_addr(src, (u_char *) tvb_get_ptr(tvb, FDDI_P_SHOST, 6));
  else
    memcpy(src, (u_char *) tvb_get_ptr(tvb, FDDI_P_SHOST, 6), sizeof src);
  swap_mac_addr(src_swapped, (u_char*) tvb_get_ptr(tvb, FDDI_P_SHOST, 6));

  /* XXX - copy them to some buffer associated with "pi", rather than
     just making "src" static? */
  SET_ADDRESS(&pi.dl_src, AT_ETHER, 6, &src[0]);
  SET_ADDRESS(&pi.src, AT_ETHER, 6, &src[0]);

  if (fh_tree) {
      proto_tree_add_ether(fh_tree, hf_fddi_src, tvb, FDDI_P_SHOST, 6, src);
      proto_tree_add_ether_hidden(fh_tree, hf_fddi_addr, tvb, FDDI_P_SHOST, 6, src);

      /* hide some bit-swapped mac address fields in the proto_tree, just in case */
      proto_tree_add_ether_hidden(fh_tree, hf_fddi_src, tvb, FDDI_P_SHOST, 6, src_swapped);
      proto_tree_add_ether_hidden(fh_tree, hf_fddi_addr, tvb, FDDI_P_SHOST, 6, src_swapped);
  }

  next_tvb = tvb_new_subset(tvb, FDDI_HEADER_SIZE, -1, -1);

  switch (fc) {

    /* From now, only 802.2 SNAP (Async. LCC frame) is supported */

    case FDDI_FC_LLC_ASYNC + 0  :
    case FDDI_FC_LLC_ASYNC + 1  :
    case FDDI_FC_LLC_ASYNC + 2  :
    case FDDI_FC_LLC_ASYNC + 3  :
    case FDDI_FC_LLC_ASYNC + 4  :
    case FDDI_FC_LLC_ASYNC + 5  :
    case FDDI_FC_LLC_ASYNC + 6  :
    case FDDI_FC_LLC_ASYNC + 7  :
    case FDDI_FC_LLC_ASYNC + 8  :
    case FDDI_FC_LLC_ASYNC + 9  :
    case FDDI_FC_LLC_ASYNC + 10 :
    case FDDI_FC_LLC_ASYNC + 11 :
    case FDDI_FC_LLC_ASYNC + 12 :
    case FDDI_FC_LLC_ASYNC + 13 :
    case FDDI_FC_LLC_ASYNC + 14 :
    case FDDI_FC_LLC_ASYNC + 15 :
      dissect_llc(next_tvb, pinfo, tree);
      return;
      
    default :
      dissect_data(next_tvb, 0, pinfo, tree);
      return;

  } /* fc */
} /* dissect_fddi */

void
proto_register_fddi(void)
{
	static hf_register_info hf[] = {

		/*
		 * XXX - we want this guy to have his own private formatting
		 * routine, using "fc_to_str()"; if "fc_to_str()" returns
		 * NULL, just show the hex value, else show the string.
		 */
		{ &hf_fddi_fc,
		{ "Frame Control",	"fddi.fc", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_fddi_dst,
		{ "Destination",	"fddi.dst", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Destination Hardware Address" }},

		{ &hf_fddi_src,
		{ "Source",		"fddi.src", FT_ETHER, BASE_NONE, NULL, 0x0,
			"" }},

		{ &hf_fddi_addr,
		{ "Source or Destination Address", "fddi.addr", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Source or Destination Hardware Address" }},

	};
	static gint *ett[] = {
		&ett_fddi,
	};

	proto_fddi = proto_register_protocol ("Fiber Distributed Data Interface", "fddi" );
	proto_register_field_array(proto_fddi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
