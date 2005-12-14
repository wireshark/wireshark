/* packet-udp.c
 * Routines for UDP packet disassembly
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Richard Sharpe, 13-Feb-1999, added dispatch table support and
 *                              support for tftp.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include <epan/prefs.h>

#include "packet-udp.h"

#include "packet-ip.h"
#include <epan/conversation.h>
#include <epan/tap.h>

static int udp_tap = -1;

static int proto_udp = -1;
static int proto_udplite = -1;
static int hf_udp_srcport = -1;
static int hf_udp_dstport = -1;
static int hf_udp_port = -1;
static int hf_udp_length = -1;
static int hf_udplite_checksum_coverage = -1;
static int hf_udplite_checksum_coverage_bad = -1;
static int hf_udp_checksum = -1;
static int hf_udp_checksum_bad = -1;

static gint ett_udp = -1;

/* Place UDP summary in proto tree */
static gboolean udp_summary_in_tree = TRUE;
/* Ignore an invalid checksum coverage field and continue dissection */
static gboolean udplite_ignore_checksum_coverage = TRUE;

static dissector_table_t udp_dissector_table;
static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t data_handle;

/* Determine if there is a sub-dissector and call it.  This has been */
/* separated into a stand alone routine so other protocol dissectors */
/* can call to it, ie. socks	*/

static gboolean try_heuristic_first = FALSE;

void
decode_udp_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, int uh_sport, int uh_dport, int uh_ulen)
{
  tvbuff_t *next_tvb;
  int low_port, high_port;
  gint len, reported_len;

  len = tvb_length_remaining(tvb, offset);
  reported_len = tvb_reported_length_remaining(tvb, offset);
  if (uh_ulen != -1) {
    /* This is the length from the UDP header; the payload should be cut
       off at that length.  (If our caller passed a value here, they
       are assumed to have checked that it's >= 8, and hence >= offset.)

       XXX - what if it's *greater* than the reported length? */
    if (uh_ulen - offset < reported_len)
      reported_len = uh_ulen - offset;
    if (len > reported_len)
      len = reported_len;
  }
  next_tvb = tvb_new_subset(tvb, offset, len, reported_len);

/* determine if this packet is part of a conversation and call dissector */
/* for the conversation if available */

  if (try_conversation_dissector(&pinfo->src, &pinfo->dst, PT_UDP,
		uh_sport, uh_dport, next_tvb, pinfo, tree)){
    return;
  }

  if (try_heuristic_first) {
    /* do lookup with the heuristic subdissector table */
    if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree))
      return;
  }

  /* Do lookups with the subdissector table.
     We try the port number with the lower value first, followed by the
     port number with the higher value.  This means that, for packets
     where a dissector is registered for *both* port numbers:

	1) we pick the same dissector for traffic going in both directions;

	2) we prefer the port number that's more likely to be the right
	   one (as that prefers well-known ports to reserved ports);

     although there is, of course, no guarantee that any such strategy
     will always pick the right port number.

     XXX - we ignore port numbers of 0, as some dissectors use a port
     number of 0 to disable the port, and as RFC 768 says that the source
     port in UDP datagrams is optional and is 0 if not used. */
  if (uh_sport > uh_dport) {
    low_port = uh_dport;
    high_port = uh_sport;
  } else {
    low_port = uh_sport;
    high_port = uh_dport;
  }
  if (low_port != 0 &&
      dissector_try_port(udp_dissector_table, low_port, next_tvb, pinfo, tree))
    return;
  if (high_port != 0 &&
      dissector_try_port(udp_dissector_table, high_port, next_tvb, pinfo, tree))
    return;

  if (!try_heuristic_first) {
    /* do lookup with the heuristic subdissector table */
    if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree))
      return;
  }

  call_dissector(data_handle,next_tvb, pinfo, tree);
}


static void
dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 ip_proto)
{
  proto_tree *udp_tree = NULL;
  proto_item *ti;
  guint      len;
  guint      reported_len;
  vec_t      cksum_vec[4];
  guint32    phdr[2];
  guint16    computed_cksum;
  int        offset = 0;
  static e_udphdr udphstruct[4], *udph;
  static int udph_count=0;

  udph_count++;
  if(udph_count>=4){
     udph_count=0;
  }
  udph=&udphstruct[udph_count];
  SET_ADDRESS(&udph->ip_src, pinfo->src.type, pinfo->src.len, pinfo->src.data);
  SET_ADDRESS(&udph->ip_dst, pinfo->dst.type, pinfo->dst.len, pinfo->dst.data);

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, (ip_proto == IP_PROTO_UDP) ? "UDP" : "UDPlite");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  udph->uh_sport=tvb_get_ntohs(tvb, offset);
  udph->uh_dport=tvb_get_ntohs(tvb, offset+2);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "Source port: %s  Destination port: %s",
	    get_udp_port(udph->uh_sport), get_udp_port(udph->uh_dport));

  if (tree) {
    if (udp_summary_in_tree) {
      if (ip_proto == IP_PROTO_UDP) {
        ti = proto_tree_add_protocol_format(tree, proto_udp, tvb, offset, 8, 
        "User Datagram Protocol, Src Port: %s (%u), Dst Port: %s (%u)",
        get_udp_port(udph->uh_sport), udph->uh_sport, get_udp_port(udph->uh_dport), udph->uh_dport);
      } else {
        ti = proto_tree_add_protocol_format(tree, proto_udplite, tvb, offset, 8, 
        "Lightweight User Datagram Protocol, Src Port: %s (%u), Dst Port: %s (%u)",
        get_udp_port(udph->uh_sport), udph->uh_sport, get_udp_port(udph->uh_dport), udph->uh_dport);
      }
    } else {
      ti = proto_tree_add_item(tree, proto_udp, tvb, offset, 8, FALSE);
    }
    udp_tree = proto_item_add_subtree(ti, ett_udp);

    proto_tree_add_uint_format(udp_tree, hf_udp_srcport, tvb, offset, 2, udph->uh_sport,
	"Source port: %s (%u)", get_udp_port(udph->uh_sport), udph->uh_sport);
    proto_tree_add_uint_format(udp_tree, hf_udp_dstport, tvb, offset + 2, 2, udph->uh_dport,
	"Destination port: %s (%u)", get_udp_port(udph->uh_dport), udph->uh_dport);

    proto_tree_add_uint_hidden(udp_tree, hf_udp_port, tvb, offset, 2, udph->uh_sport);
    proto_tree_add_uint_hidden(udp_tree, hf_udp_port, tvb, offset+2, 2, udph->uh_dport);
  }

  if (ip_proto == IP_PROTO_UDP) {
    udph->uh_ulen = udph->uh_sum_cov = tvb_get_ntohs(tvb, offset+4);
    if (udph->uh_ulen < 8) {
      /* Bogus length - it includes the header, so it must be >= 8. */
      if (tree) {
        proto_tree_add_uint_format(udp_tree, hf_udp_length, tvb, offset + 4, 2,
          udph->uh_ulen, "Length: %u (bogus, must be >= 8)", udph->uh_ulen);
      }
      return;
    }
    if (tree) {
      proto_tree_add_uint(udp_tree, hf_udp_length, tvb, offset + 4, 2, udph->uh_ulen);
      proto_tree_add_uint_hidden(udp_tree, hf_udplite_checksum_coverage, tvb, offset + 4, 0, udph->uh_sum_cov);
    }
  } else {
    udph->uh_ulen = pinfo->iplen - pinfo->iphdrlen;
    udph->uh_sum_cov = tvb_get_ntohs(tvb, offset+4);
    if (((udph->uh_sum_cov > 0) && (udph->uh_sum_cov < 8)) || (udph->uh_sum_cov > udph->uh_ulen)) {
      /* Bogus length - it includes the header, so it must be >= 8, and no larger then the IP payload size. */
      if (tree) {
        proto_tree_add_boolean_hidden(udp_tree, hf_udplite_checksum_coverage_bad, tvb, offset + 4, 2, TRUE);
        proto_tree_add_uint_hidden(udp_tree, hf_udp_length, tvb, offset + 4, 0, udph->uh_ulen);
        proto_tree_add_uint_format(udp_tree, hf_udplite_checksum_coverage, tvb, offset + 4, 2,
          udph->uh_sum_cov, "Checksum coverage: %u (bogus, must be >= 8 and <= %u (ip.len-ip.hdr_len))",
          udph->uh_sum_cov, udph->uh_ulen);
      }
      if (udplite_ignore_checksum_coverage == FALSE)
        return;
    } else if (tree) {
      proto_tree_add_uint_hidden(udp_tree, hf_udp_length, tvb, offset + 4, 0, udph->uh_ulen);
      proto_tree_add_uint(udp_tree, hf_udplite_checksum_coverage, tvb, offset + 4, 2, udph->uh_sum_cov);
    }
  }

  udph->uh_sum_cov = (udph->uh_sum_cov) ? udph->uh_sum_cov : udph->uh_ulen;
  udph->uh_sum = tvb_get_ntohs(tvb, offset+6);
  if (tree) {
    reported_len = tvb_reported_length(tvb);
    len = tvb_length(tvb);
    if (udph->uh_sum == 0) {
      /* No checksum supplied in the packet. */
      if (ip_proto == IP_PROTO_UDP) {
        proto_tree_add_uint_format(udp_tree, hf_udp_checksum, tvb, offset + 6, 2, 0, 
          "Checksum: 0x%04x (none)", 0);
      } else {
        proto_tree_add_uint_format(udp_tree, hf_udp_checksum, tvb, offset + 6, 2, 0, 
          "Checksum: 0x%04x (Illegal)", 0);
        proto_tree_add_boolean_hidden(udp_tree, hf_udp_checksum_bad, tvb,
	  offset + 6, 2, TRUE);
      }
    } else if (!pinfo->fragmented && len >= reported_len &&
               len >= udph->uh_sum_cov && reported_len >= udph->uh_sum_cov &&
               udph->uh_sum_cov >=8) {
      /* The packet isn't part of a fragmented datagram and isn't
         truncated, so we can checksum it.
	 XXX - make a bigger scatter-gather list once we do fragment
	 reassembly? */

      /* Set up the fields of the pseudo-header. */
      cksum_vec[0].ptr = pinfo->src.data;
      cksum_vec[0].len = pinfo->src.len;
      cksum_vec[1].ptr = pinfo->dst.data;
      cksum_vec[1].len = pinfo->dst.len;
      cksum_vec[2].ptr = (const guint8 *)&phdr;
      switch (pinfo->src.type) {

      case AT_IPv4:
	phdr[0] = g_htonl((ip_proto<<16) + udph->uh_ulen);
	cksum_vec[2].len = 4;
	break;

      case AT_IPv6:
        phdr[0] = g_htonl(udph->uh_ulen);
        phdr[1] = g_htonl(ip_proto);
        cksum_vec[2].len = 8;
        break;

      default:
        /* UDP runs only atop IPv4 and IPv6.... */
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
      }
      cksum_vec[3].ptr = tvb_get_ptr(tvb, offset, udph->uh_sum_cov);
      cksum_vec[3].len = udph->uh_sum_cov;
      computed_cksum = in_cksum(&cksum_vec[0], 4);
      if (computed_cksum == 0) {
        proto_tree_add_uint_format(udp_tree, hf_udp_checksum, tvb,
          offset + 6, 2, udph->uh_sum, "Checksum: 0x%04x [correct]", udph->uh_sum);
      } else {
	proto_tree_add_boolean_hidden(udp_tree, hf_udp_checksum_bad, tvb,
	   offset + 6, 2, TRUE);
        proto_tree_add_uint_format(udp_tree, hf_udp_checksum, tvb,
          offset + 6, 2, udph->uh_sum,
	  "Checksum: 0x%04x [incorrect, should be 0x%04x]", udph->uh_sum,
	   in_cksum_shouldbe(udph->uh_sum, computed_cksum));
      }
    } else {
      proto_tree_add_uint_format(udp_tree, hf_udp_checksum, tvb,
        offset + 6, 2, udph->uh_sum, "Checksum: 0x%04x", udph->uh_sum);
    }
  }

  /* Skip over header */
  offset += 8;

  pinfo->ptype = PT_UDP;
  pinfo->srcport = udph->uh_sport;
  pinfo->destport = udph->uh_dport;

  tap_queue_packet(udp_tap, pinfo, udph);
  /*
   * Call sub-dissectors.
   *
   * XXX - should we do this if this is included in an error packet?
   * It might be nice to see the details of the packet that caused the
   * ICMP error, but it might not be nice to have the dissector update
   * state based on it.
   * Also, we probably don't want to run UDP taps on those packets.
   *
   * We definitely don't want to do it for an error packet if there's
   * nothing left in the packet.
   */
  if (!pinfo->in_error_pkt || tvb_length_remaining(tvb, offset) > 0)
    decode_udp_ports(tvb, offset, pinfo, tree, udph->uh_sport, udph->uh_dport,
                     udph->uh_ulen);
}

static void
dissect_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect(tvb, pinfo, tree, IP_PROTO_UDP);
}

static void
dissect_udplite(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect(tvb, pinfo, tree, IP_PROTO_UDPLITE);
}

void
proto_register_udp(void)
{
	module_t *udp_module;
	module_t *udplite_module;

	static hf_register_info hf[] = {
		{ &hf_udp_srcport,
		{ "Source Port",	"udp.srcport", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_udp_dstport,
		{ "Destination Port",	"udp.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_udp_port,
		{ "Source or Destination Port",	"udp.port", FT_UINT16, BASE_DEC,  NULL, 0x0,
			"", HFILL }},

		{ &hf_udp_length,
		{ "Length",		"udp.length", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_udp_checksum_bad,
		{ "Bad Checksum",	"udp.checksum_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_udp_checksum,
		{ "Checksum",		"udp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			"", HFILL }},
	};

	static hf_register_info hf_lite[] = {
		{ &hf_udplite_checksum_coverage_bad,
		{ "Bad Checksum coverage",	"udp.checksum_coverage_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_udplite_checksum_coverage,
		{ "Checksum coverage",	"udp.checksum_coverage", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},
	};

	static gint *ett[] = {
		&ett_udp,
	};

	proto_udp = proto_register_protocol("User Datagram Protocol",
	    "UDP", "udp");
	proto_udplite = proto_register_protocol("Lightweight User Datagram Protocol",
	    "UDPlite", "udplite");
	proto_register_field_array(proto_udp, hf, array_length(hf));
	proto_register_field_array(proto_udplite, hf_lite, array_length(hf_lite));
	proto_register_subtree_array(ett, array_length(ett));

/* subdissector code */
	udp_dissector_table = register_dissector_table("udp.port",
	    "UDP port", FT_UINT16, BASE_DEC);
	register_heur_dissector_list("udp", &heur_subdissector_list);
	register_heur_dissector_list("udplite", &heur_subdissector_list);

	/* Register configuration preferences */
	udp_module = prefs_register_protocol(proto_udp, NULL);
	prefs_register_bool_preference(udp_module, "summary_in_tree",
	    "Show UDP summary in protocol tree",
	    "Whether the UDP summary line should be shown in the protocol tree",
	    &udp_summary_in_tree);
	prefs_register_bool_preference(udp_module, "try_heuristic_first",
	    "Try heuristic sub-dissectors first",
	    "Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port",
	    &try_heuristic_first);

	udplite_module = prefs_register_protocol(proto_udplite, NULL);
	prefs_register_bool_preference(udplite_module, "ignore_checksum_coverage",
	    "Ignore UDPlite checksum coverage",
	    "Ignore an invalid checksum coverage field and continue dissection",
	    &udplite_ignore_checksum_coverage);
}

void
proto_reg_handoff_udp(void)
{
	dissector_handle_t udp_handle;
	dissector_handle_t udplite_handle;

	udp_handle = create_dissector_handle(dissect_udp, proto_udp);
	dissector_add("ip.proto", IP_PROTO_UDP, udp_handle);
	udplite_handle = create_dissector_handle(dissect_udplite, proto_udplite);
	dissector_add("ip.proto", IP_PROTO_UDPLITE, udplite_handle);
	data_handle = find_dissector("data");
	udp_tap = register_tap("udp");
}
