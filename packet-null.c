/* packet-null.c
 * Routines for null packet disassembly
 *
 * $Id: packet-null.c,v 1.33 2000/11/19 02:00:02 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 *
 * This file created and by Mike Hall <mlh@io.com>
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <glib.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <string.h>
#include "packet.h"
#include "packet-null.h"
#include "packet-atalk.h"
#include "packet-ip.h"
#include "packet-ipv6.h"
#include "packet-ipx.h"
#include "packet-osi.h"
#include "packet-ppp.h"
#include "etypes.h"
#include "aftypes.h"

static dissector_table_t null_dissector_table;

extern const value_string etype_vals[];

/* protocols and header fields */
static int proto_null = -1;
static int hf_null_etype = -1;
static int hf_null_family = -1;

static gint ett_null = -1;

/* Null/loopback structs and definitions */

/* Family values. */
static const value_string family_vals[] = {
    {BSD_AF_INET,          "IP"             },
    {BSD_AF_ISO,           "OSI"            },
    {BSD_AF_APPLETALK,     "Appletalk"      },
    {BSD_AF_IPX,           "Netware IPX/SPX"},
    {BSD_AF_INET6_BSD,     "IPv6"           },
    {BSD_AF_INET6_FREEBSD, "IPv6"           },
    {0,                    NULL             }
};

static dissector_handle_t ppp_handle;

void
capture_null( const u_char *pd, packet_counts *ld )
{
  guint32 null_header;

  /*
   * BSD drivers that use DLT_NULL - including the FreeBSD 3.2 ISDN-for-BSD
   * drivers, as well as the 4.4-Lite and FreeBSD loopback drivers -
   * appear to stuff the AF_ value for the protocol, in *host* byte
   * order, in the first four bytes.
   *
   * However, according to Gerald Combs, a FreeBSD ISDN PPP dump that
   * Andreas Klemm sent to ethereal-dev has a packet type of DLT_NULL,
   * and the family bits look like PPP's protocol field.  (Was this an
   * older, or different, ISDN driver?)  Looking at what appears to be
   * that capture file, it appears that it's using PPP in HDLC framing,
   * RFC 1549, wherein the first two octets of the frame are 0xFF
   * (address) and 0x03 (control), so the header bytes are, in order:
   *
   *	0xFF
   *	0x03
   *	high-order byte of a PPP protocol field
   *	low-order byte of a PPP protocol field
   *
   * when reading it on a little-endian machine; that means it's
   * PPPP03FF, where PPPP is a byte-swapped PPP protocol field.
   *
   * "libpcap" for Linux uses DLT_NULL only for the loopback device.
   * The loopback driver in Linux 2.0.36, at least, puts an *Ethernet*
   * header at the beginning of loopback packets; however, "libpcap"
   * for Linux compensates for this by skipping the source and
   * destination MAC addresses, replacing them with 2 bytes of 0.
   * This means that if we're reading the capture on a little-endian
   * machine, the header, treated as a 32-bit integer, looks like
   *
   *	EEEEEEEEEEEEEEEE0000000000000000
   *
   * where "EEEEEEEEEEEEEEEE" is the Ethernet type, and if we're reading
   * it on a big-endian machine, it looks like
   *
   *	0000000000000000EEEEEEEEEEEEEEEE
   *
   * The Ethernet type might or might not be byte-swapped; I haven't
   * bothered thinking about that yet.
   *
   * AF_ values are (relatively) small integers, and shouldn't have their
   * upper 16 bits zero; Ethernet types have to fit in 16 bits and
   * thus must have their upper 16 bits zero.  Therefore, if the upper
   * 16 bits of the field aren't zero, it's in the wrong byte order.
   *
   * Ethernet types are bigger than 1536, and AF_ values are smaller
   * than 1536, so we needn't worry about one being mistaken for
   * the other.  (There may be a problem if the 16-bit Ethernet
   * type is byte-swapped as a 16-bit quantity, but if when treated
   * as a 32-bit quantity its upper 16 bits are zero, but I'll think
   * about that one later.)
   *
   * As for the PPP protocol field values:
   *
   * 0x0000 does not appear to be a valid PPP protocol field value,
   * so the upper 16 bits will be non-zero, and we'll byte swap it.
   * It'll then be
   *
   *	0xFF03PPPP
   *
   * where PPPP is a non-byte-swapped PPP protocol field; we'll
   * check for the upper 16 bits of the byte-swapped field being
   * non-zero and, if so, assume the lower 16 bits are a PPP
   * protocol field (AF_ and Ethernet protocol fields should leave
   * the upper 16 bits zero - unless somebody stuff something else
   * there; see below).
   *
   * So, to compensate for this mess, we:
   *
   *	check if the first two octets are 0xFF and 0x03 and, if so,
   *	treat it as a PPP frame;
   *
   *	otherwise, byte-swap the value if its upper 16 bits aren't zero,
   *	and compare the lower 16 bits of the value against Ethernet
   *	and AF_ types.
   *
   * If, as implied by an earlier version of the "e_nullhdr" structure,
   * the family is only 16 bits, and there are "next" and "len" fields
   * before it, that all goes completely to hell.  (Note that, for
   * the BSD header, we could byte-swap it if the capture was written
   * on a machine with the opposite byte-order to ours - the "libpcap"
   * header lets us determine that - but it's more of a mess for Linux,
   * given that the effect of inserting the two 0 bytes depends only
   * on the byte order of the machine reading the file.)
   */
  if (pd[0] == 0xFF && pd[1] == 0x03) {
    /*
     * Hand it to PPP.
     */
    capture_ppp(pd, 0, ld);
  } else {
    /*
     * Treat it as a normal DLT_NULL header.
     */
    memcpy((char *)&null_header, (char *)&pd[0], sizeof(null_header));

    if ((null_header & 0xFFFF0000) != 0) {
      /* Byte-swap it. */
      null_header = BSWAP32(null_header);
    }

    /*
     * The null header value must be greater than the IEEE 802.3 maximum
     * frame length to be a valid Ethernet type; if it is, hand it
     * to "ethertype()", otherwise treat it as a BSD AF_type (we wire
     * in the values of the BSD AF_ types, because the values
     * in the file will be BSD values, and the OS on which
     * we're building this might not have the same values or
     * might not have them defined at all; XXX - what if different
     * BSD derivatives have different values?).
     */
    if (null_header > IEEE_802_3_MAX_LEN)
      capture_ethertype(null_header, 4, pd, ld);
    else {
      switch (null_header) {

      case BSD_AF_INET:
        capture_ip(pd, 4, ld);
        break;

      default:
        ld->other++;
        break;
      }
    }
  }
}

void
dissect_null(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint32	null_header;
  proto_tree	*fh_tree;
  proto_item	*ti;
  tvbuff_t	*next_tvb;

  CHECK_DISPLAY_AS_DATA(proto_null, tvb, pinfo, tree);

  /*
   * See comment in "capture_null()" for an explanation of what we're
   * doing.
   */
  if (tvb_get_ntohs(tvb, 0) == 0xFF03) {
    /*
     * Hand it to PPP.
     */
    call_dissector(ppp_handle, tvb, pinfo, tree);
  } else {

    /* load the top pane info. This should be overwritten by
       the next protocol in the stack */
    if(check_col(pinfo->fd, COL_RES_DL_SRC))
      col_add_str(pinfo->fd, COL_RES_DL_SRC, "N/A" );
    if(check_col(pinfo->fd, COL_RES_DL_DST))
      col_add_str(pinfo->fd, COL_RES_DL_DST, "N/A" );
    if(check_col(pinfo->fd, COL_PROTOCOL))
      col_add_str(pinfo->fd, COL_PROTOCOL, "N/A" );
    if(check_col(pinfo->fd, COL_INFO))
      col_add_str(pinfo->fd, COL_INFO, "Null/Loopback" );

    /*
     * Treat it as a normal DLT_NULL header.
     */
    memcpy((char *)&null_header, (char *)tvb_get_ptr(tvb, 0, sizeof(null_header)), sizeof(null_header));

    if ((null_header & 0xFFFF0000) != 0) {
      /* Byte-swap it. */
      null_header = BSWAP32(null_header);
    }

    /*
     * The null header value must be greater than the IEEE 802.3 maximum
     * frame length to be a valid Ethernet type; if it is, hand it
     * to "ethertype()", otherwise treat it as a BSD AF_type (we wire
     * in the values of the BSD AF_ types, because the values
     * in the file will be BSD values, and the OS on which
     * we're building this might not have the same values or
     * might not have them defined at all; XXX - what if different
     * BSD derivatives have different values?).
     */
    if (null_header > IEEE_802_3_MAX_LEN) {
      if (tree) {
        ti = proto_tree_add_item(tree, proto_null, tvb, 0, 4, FALSE);
        fh_tree = proto_item_add_subtree(ti, ett_null);
      } else
      	fh_tree = NULL;
      ethertype(null_header, tvb, 4, pinfo, tree, fh_tree, hf_null_etype);
    } else {
      /* populate a tree in the second pane with the status of the link
         layer (ie none) */
      if (tree) {
        ti = proto_tree_add_item(tree, proto_null, tvb, 0, 4, FALSE);
        fh_tree = proto_item_add_subtree(ti, ett_null);
        proto_tree_add_uint(fh_tree, hf_null_family, tvb, 0, 4, null_header);
      }

      next_tvb = tvb_new_subset(tvb, 4, -1, -1);
      if (!dissector_try_port(null_dissector_table, null_header,
	    next_tvb, pinfo, tree)) {
        /* No sub-dissector found.  Label rest of packet as "Data" */
        dissect_data(next_tvb, 0, pinfo, tree);
      }
    }
  }
}

void
proto_register_null(void)
{
	static hf_register_info hf[] = {

		/* registered here but handled in ethertype.c */
		{ &hf_null_etype,
		{ "Type",		"null.type", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
			"" }},

		{ &hf_null_family,
		{ "Family",		"null.family",	FT_UINT32, BASE_HEX, VALS(family_vals), 0x0,
			"" }}
	};
	static gint *ett[] = {
		&ett_null,
	};

	proto_null = proto_register_protocol ("Null/Loopback", "null" );
	proto_register_field_array(proto_null, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	null_dissector_table = register_dissector_table("null.type");
}

void
proto_reg_handoff_null(void)
{
	/*
	 * Get a handle for the PPP dissector.
	 */
	ppp_handle = find_dissector("ppp");
}
