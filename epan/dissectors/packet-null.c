/* packet-null.c
 * Routines for null packet disassembly
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * This file created by Mike Hall <mlh@io.com>
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

#include <glib.h>

#include <string.h>
#include <epan/packet.h>
#include "packet-null.h"
#include <epan/atalk-utils.h>
#include <epan/prefs.h>
#include "packet-ip.h"
#include "packet-ipv6.h"
#include "packet-ipx.h"
#include "packet-osi.h"
#include "packet-ppp.h"
#include <epan/etypes.h>
#include <epan/aftypes.h>

static dissector_table_t null_dissector_table;
static dissector_table_t ethertype_dissector_table;

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
    {BSD_AF_INET6_DARWIN,  "IPv6"           },
    {0,                    NULL             }
};

static dissector_handle_t ppp_hdlc_handle;
static dissector_handle_t data_handle;
void
capture_null( const guchar *pd, int len, packet_counts *ld )
{
  guint32 null_header;

  /*
   * BSD drivers that use DLT_NULL - including the FreeBSD 3.2 ISDN-for-BSD
   * drivers, as well as the 4.4-Lite and FreeBSD loopback drivers -
   * stuff the AF_ value for the protocol, in *host* byte order, in the
   * first four bytes.  (BSD drivers that use DLT_LOOP, such as recent
   * OpenBSD loopback drivers, stuff it in *network* byte order in the
   * first four bytes.)
   *
   * However, the IRIX and UNICOS/mp snoop socket mechanism supplies,
   * on loopback devices, a 4-byte header that has a 2 byte (big-endian)
   * AF_ value and 2 bytes of 0, so it's
   *
   *	0000AAAA
   *
   * when read on a little-endian machine and
   *
   *	AAAA0000
   *
   * when read on a big-endian machine.  The current CVS version of libpcap
   * compensates for this by converting it to standard 4-byte format before
   * processing the packet, but snoop captures from IRIX or UNICOS/mp
   * have the 2-byte+2-byte header, as might tcpdump or libpcap captures
   * with older versions of libpcap.
   *
   * AF_ values are small integers, and probably fit in 8 bits (current
   * values on the BSDs do), and have their upper 24 bits zero.
   * This means that, in practice, if you look at the header as a 32-bit
   * integer in host byte order:
   *
   *	on a little-endian machine:
   *
   *		a little-endian DLT_NULL header looks like
   *
   *			000000AA
   *
   *		a big-endian DLT_NULL header, or a DLT_LOOP header, looks
   *		like
   *
   *			AA000000
   *
   *		an IRIX or UNICOS/mp DLT_NULL header looks like
   *
   *			0000AA00
   *
   *	on a big-endian machine:
   *
   *		a big-endian DLT_NULL header, or a DLT_LOOP header, looks
   *		like
   *
   *			000000AA
   *
   *		a little-endian DLT_NULL header looks like
   *
   *			AA000000
   *
   *		an IRIX or UNICOS/mp DLT_NULL header looks like
   *
   *			00AA0000
   *
   * However, according to Gerald Combs, a FreeBSD ISDN PPP dump that
   * Andreas Klemm sent to wireshark-dev has a packet type of DLT_NULL,
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
   * If we treat that as a 32-bit host-byte-order value, it looks like
   *
   *	PPPP03FF
   *
   * where PPPP is a byte-swapped PPP protocol type if we read it on
   * a little-endian machine and
   *
   *	FF03PPPP
   *
   * where PPPP is a PPP protocol type if we read it on a big-endian
   * machine.  0x0000 does not appear to be a valid PPP protocol type
   * value, so at least one of those hex digits is guaranteed not to
   * be 0.
   *
   * Old versions of libpcap for Linux used DLT_NULL for loopback devices,
   * but not any other devices.  (Current versions use DLT_EN10MB for it.)
   * The Linux loopback driver puts an *Ethernet* header at the beginning
   * of loopback packets, with fake source and destination addresses and
   * the appropriate Ethernet type value; however, those older versions of
   * libpcap for Linux compensated for this by skipping the source and
   * destination MAC addresses, replacing them with 2 bytes of 0.
   * This means that if we're reading the capture on a little-endian
   * machine, the header, treated as a 32-bit integer, looks like
   *
   *	EEEE0000
   *
   * where EEEE is a byte-swapped Ethernet type, and if we're reading it
   * on a big-endian machine, it looks like
   *
   *	0000EEEE
   *
   * where EEEE is an Ethernet type.
   *
   * If the first 2 bytes of the header are FF 03:
   *
   *	it can't be a big-endian BSD DLT_NULL header, or a DLT_LOOP
   *	header, as AF_ values are small so the first 2 bytes of the
   *	header would be 0;
   *
   *	it can't be a little-endian BSD DLT_NULL header, as the
   *	resulting AF_ value would be >= 0x03FF, which is too big
   *	for an AF_ value;
   *
   *	it can't be an IRIX or UNICOS/mp DLT_NULL header, as the
   *	resulting AF_ value with be 0x03FF.
   *
   * So the first thing we do is check the first two bytes of the
   * header; if it's FF 03, we treat the packet as a PPP frame.
   *
   * Otherwise, if the upper 16 bits are non-zero, either:
   *
   *	it's a BSD DLT_NULL or DLT_LOOP header whose AF_ value
   *	is not in our byte order;
   *
   *	it's an IRIX or UNICOS/mp DLT_NULL header being read on
   *	a big-endian machine;
   *
   *	it's a Linux DLT_NULL header being read on a little-endian
   *	machine.
   *
   * In all those cases except for the IRIX or UNICOS/mp DLT_NULL header,
   * we should byte-swap it (if it's a Linux DLT_NULL header, that'll
   * put the Ethernet type in the right byte order).  In the case
   * of the IRIX or UNICOS/mp DLT_NULL header, we should just get
   * the upper 16 bits as an AF_ value.
   *
   * If it's a BSD DLT_NULL or DLT_LOOP header whose AF_ value is not
   * in our byte order, then the upper 2 hex digits would be non-zero
   * and the next 2 hex digits down would be zero, as AF_ values fit in
   * 8 bits, and the upper 2 hex digits are the *lower* 8 bits of the value.
   *
   * If it's an IRIX or UNICOS/mp DLT_NULL header, the upper 2 hex digits
   * would be zero and the next 2 hex digits down would be non-zero, as
   * the upper 16 bits are a big-endian AF_ value.  Furthermore, the
   * next 2 hex digits down are likely to be < 0x60, as 0x60 is 96,
   * and, so far, we're far from requiring AF_ values that high.
   *
   * If it's a Linux DLT_NULL header, the third hex digit from the top
   * will be >= 6, as Ethernet types are >= 1536, or 0x0600, and
   * it's byte-swapped, so the second 2 hex digits from the top are
   * >= 0x60.
   *
   * So, if the upper 16 bits are non-zero:
   *
   *	if the upper 2 hex digits are 0 and the next 2 hex digits are
   *	in the range 0x00-0x5F, we treat it as a big-endian IRIX or
   *	UNICOS/mp DLT_NULL header;
   *
   *	otherwise, we byte-swap it and do the next stage.
   *
   * If the upper 16 bits are zero, either:
   *
   *	it's a BSD DLT_NULLor DLT_LOOP header whose AF_ value is in
   *	our byte order;
   *
   *	it's an IRIX or UNICOS/mp DLT_NULL header being read on
   *	a little-endian machine;
   *
   *	it's a Linux DLT_NULL header being read on a big-endian
   *	machine.
   *
   * In all of those cases except for the IRIX or UNICOS/mp DLT_NULL header,
   * we should *not* byte-swap it.  In the case of the IRIX or UNICOS/mp
   * DLT_NULL header, we should extract the AF_ value and byte-swap it.
   *
   * If it's a BSD DLT_NULL or DLT_LOOP header whose AF_ value is
   * in our byte order, the upper 6 hex digits would all be zero.
   *
   * If it's an IRIX or UNICOS/mp DLT_NULL header, the upper 4 hex
   * digits would be zero and the next 2 hex digits would not be zero.
   * Furthermore, the third hex digit from the bottom would be <
   */
  if (!BYTES_ARE_IN_FRAME(0, len, 2)) {
    ld->other++;
    return;
  }
  if (pd[0] == 0xFF && pd[1] == 0x03) {
    /*
     * Hand it to PPP.
     */
    capture_ppp_hdlc(pd, 0, len, ld);
  } else {
    /*
     * Treat it as a normal DLT_NULL header.
     */
    if (!BYTES_ARE_IN_FRAME(0, len, (int)sizeof(null_header))) {
      ld->other++;
      return;
    }
    memcpy((char *)&null_header, (const char *)&pd[0], sizeof(null_header));

    if ((null_header & 0xFFFF0000) != 0) {
      /*
       * It is possible that the AF_ type was only a 16 bit value.
       * IRIX and UNICOS/mp loopback snoop use a 4 byte header with
       * AF_ type in the first 2 bytes!
       * BSD AF_ types will always have the upper 8 bits as 0.
       */
      if ((null_header & 0xFF000000) == 0 &&
          (null_header & 0x00FF0000) < 0x00060000) {
        /*
         * Looks like a IRIX or UNICOS/mp loopback header, in the
         * correct byte order.  Set the null header value to the
         * AF_ type, which is in the upper 16 bits of "null_header".
         */
        null_header >>= 16;
      } else {
        /* Byte-swap it. */
        null_header = BSWAP32(null_header);
      }
    } else {
      /*
       * Check for an IRIX or UNICOS/mp snoop header.
       */
      if ((null_header & 0x000000FF) == 0 &&
          (null_header & 0x0000FF00) < 0x00000600) {
        /*
         * Looks like a IRIX or UNICOS/mp loopback header, in the
         * wrong byte order.  Set the null header value to the AF_
         * type; that's in the lower 16 bits of "null_header", but
         * is byte-swapped.
         */
        null_header = BSWAP16(null_header & 0xFFFF);
      }
    }

    /*
     * The null header value must be greater than the IEEE 802.3 maximum
     * frame length to be a valid Ethernet type; if it is, hand it
     * to "capture_ethertype()", otherwise treat it as a BSD AF_type (we
     * wire in the values of the BSD AF_ types, because the values
     * in the file will be BSD values, and the OS on which
     * we're building this might not have the same values or
     * might not have them defined at all; XXX - what if different
     * BSD derivatives have different values?).
     */
    if (null_header > IEEE_802_3_MAX_LEN)
      capture_ethertype((guint16) null_header, pd, 4, len, ld);
    else {

      switch (null_header) {

      case BSD_AF_INET:
        capture_ip(pd, 4, len, ld);
        break;

      case BSD_AF_INET6_BSD:
      case BSD_AF_INET6_FREEBSD:
      case BSD_AF_INET6_DARWIN:
        capture_ipv6(pd, 4, len, ld);
        break;

      default:
        ld->other++;
        break;
      }
    }
  }
}

static void
dissect_null(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint32	null_header;
  proto_tree	*fh_tree;
  proto_item	*ti;
  tvbuff_t	*next_tvb;

  /*
   * See comment in "capture_null()" for an explanation of what we're
   * doing.
   */
  if (tvb_get_ntohs(tvb, 0) == 0xFF03) {
    /*
     * Hand it to PPP.
     */
    call_dissector(ppp_hdlc_handle, tvb, pinfo, tree);
  } else {

    /* load the top pane info. This should be overwritten by
       the next protocol in the stack */
    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A");
    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "N/A");
    col_set_str(pinfo->cinfo, COL_INFO, "Null/Loopback");

    /*
     * Treat it as a normal DLT_NULL header.
     */
    tvb_memcpy(tvb, (guint8 *)&null_header, 0, sizeof(null_header));

    if ((null_header & 0xFFFF0000) != 0) {
      /*
       * It is possible that the AF_ type was only a 16 bit value.
       * IRIX and UNICOS/mp loopback snoop use a 4 byte header with
       * AF_ type in the first 2 bytes!
       * BSD AF_ types will always have the upper 8 bits as 0.
       */
      if ((null_header & 0xFF000000) == 0 &&
          (null_header & 0x00FF0000) < 0x00060000) {
        /*
         * Looks like a IRIX or UNICOS/mp loopback header, in the
         * correct byte order.  Set the null header value to the
         * AF_ type, which is in the upper 16 bits of "null_header".
         */
        null_header >>= 16;
      } else {
        /* Byte-swap it. */
        null_header = BSWAP32(null_header);
      }
    } else {
      /*
       * Check for an IRIX or UNICOS/mp snoop header.
       */
      if ((null_header & 0x000000FF) == 0 &&
          (null_header & 0x0000FF00) < 0x00000600) {
        /*
         * Looks like a IRIX or UNICOS/mp loopback header, in the
         * wrong byte order.  Set the null header value to the AF_
         * type; that's in the lower 16 bits of "null_header", but
         * is byte-swapped.
         */
        null_header = BSWAP16(null_header & 0xFFFF);
      }
    }

    /*
     * The null header value must be greater than the IEEE 802.3 maximum
     * frame length to be a valid Ethernet type; if it is, dissect it
     * as one, otherwise treat it as a BSD AF_type (we wire in the values
     * of the BSD AF_ types, because the values in the file will be BSD
     * values, and the OS on which we're building this might not have the
     * same values or might not have them defined at all; XXX - what if
     * different BSD derivatives have different values?).
     */
    if (null_header > IEEE_802_3_MAX_LEN) {
      if (tree) {
        ti = proto_tree_add_item(tree, proto_null, tvb, 0, 4, ENC_NA);
        fh_tree = proto_item_add_subtree(ti, ett_null);
        proto_tree_add_uint(fh_tree, hf_null_etype, tvb, 0, 4,
          (guint16) null_header);
      }

      next_tvb = tvb_new_subset_remaining(tvb, 4);
      if (!dissector_try_uint(ethertype_dissector_table,
            (guint16) null_header, next_tvb, pinfo, tree))
	call_dissector(data_handle, next_tvb, pinfo, tree);
    } else {
      /* populate a tree in the second pane with the status of the link
         layer (ie none) */
      if (tree) {
        ti = proto_tree_add_item(tree, proto_null, tvb, 0, 4, ENC_NA);
        fh_tree = proto_item_add_subtree(ti, ett_null);
        proto_tree_add_uint(fh_tree, hf_null_family, tvb, 0, 4, null_header);
      }

      next_tvb = tvb_new_subset_remaining(tvb, 4);
      if (!dissector_try_uint(null_dissector_table, null_header,
	    next_tvb, pinfo, tree)) {
        /* No sub-dissector found.  Label rest of packet as "Data" */
        call_dissector(data_handle,next_tvb, pinfo, tree);
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
			NULL, HFILL }},

		{ &hf_null_family,
		{ "Family",		"null.family",	FT_UINT32, BASE_DEC, VALS(family_vals), 0x0,
			NULL, HFILL }}
	};
	static gint *ett[] = {
		&ett_null,
	};

	proto_null = proto_register_protocol("Null/Loopback", "Null", "null");
	proto_register_field_array(proto_null, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	null_dissector_table = register_dissector_table("null.type",
	   "BSD AF_ type", FT_UINT32, BASE_DEC);
}

void
proto_reg_handoff_null(void)
{
	dissector_handle_t null_handle;

	/*
	 * Get a handle for the PPP-in-HDLC-like-framing dissector and
	 * the "I don't know what this is" dissector.
	 */
	ppp_hdlc_handle = find_dissector("ppp_hdlc");
	data_handle = find_dissector("data");

	ethertype_dissector_table = find_dissector_table("ethertype");

	null_handle = create_dissector_handle(dissect_null, proto_null);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NULL, null_handle);
}
