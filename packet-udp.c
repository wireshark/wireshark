/* packet-udp.c
 * Routines for UDP packet disassembly
 *
 * $Id: packet-udp.c,v 1.78 2000/11/18 10:38:25 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include "globals.h"
#include "resolv.h"

#include "plugins.h"
#include "packet-udp.h"

#include "packet-ip.h"
#include "conversation.h"
#include "packet-vines.h"

static int proto_udp = -1;		
static int hf_udp_srcport = -1;
static int hf_udp_dstport = -1;
static int hf_udp_port = -1;
static int hf_udp_length = -1;
static int hf_udp_checksum = -1;

static gint ett_udp = -1;

/* UDP structs and definitions */

typedef struct _e_udphdr {
  guint16 uh_sport;
  guint16 uh_dport;
  guint16 uh_ulen;
  guint16 uh_sum;
} e_udphdr;

/* UDP Ports -> should go in packet-udp.h */

#define UDP_PORT_VINES	573

static dissector_table_t udp_dissector_table;
static heur_dissector_list_t heur_subdissector_list;

/* Determine if there is a sub-dissector and call it.  This has been */
/* separated into a stand alone routine to other protocol dissectors */
/* can call to it, ie. socks	*/

void
decode_udp_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, int uh_sport, int uh_dport)
{
  tvbuff_t *next_tvb;
  const u_char *next_pd;
  int next_offset;

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);

/* determine if this packet is part of a conversation and call dissector */
/* for the conversation if available */

  if (try_conversation_dissector(&pinfo->src, &pinfo->dst, PT_UDP,
		uh_sport, uh_dport, next_tvb, pinfo, tree))
	return;

  /* try to apply the plugins */
#ifdef HAVE_PLUGINS
  {
      plugin *pt_plug = plugin_list;

      if (enabled_plugins_number > 0) {
	  tvb_compat(next_tvb, &next_pd, &next_offset);
	  while (pt_plug) {
	      if (pt_plug->enabled && strstr(pt_plug->protocol, "udp") &&
		  tree && dfilter_apply(pt_plug->filter, tree, next_pd, pinfo->fd->cap_len)) {
		  pt_plug->dissector(next_pd, next_offset, pinfo->fd, tree);
		  return;
	      }
	      pt_plug = pt_plug->next;
	  }
      }
  }
#endif

  /* do lookup with the subdissector table */
  if (dissector_try_port(udp_dissector_table, uh_sport, next_tvb, pinfo, tree) ||
      dissector_try_port(udp_dissector_table, uh_dport, next_tvb, pinfo, tree))
    return;

  /* do lookup with the heuristic subdissector table */
  if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree))
    return;

  /* XXX - we should do these with the subdissector table as well. */
#define PORT_IS(port)	(uh_sport == port || uh_dport == port)
  if (PORT_IS(UDP_PORT_VINES)) {
    /* FIXME: AFAIK, src and dst port must be the same */
    tvb_compat(next_tvb, &next_pd, &next_offset);
    dissect_vines_frp(next_pd, next_offset, pinfo->fd, tree);
  } else
    dissect_data(next_tvb, 0, pinfo, tree);
}


static void
dissect_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  e_udphdr  uh;
  guint16    uh_sport, uh_dport, uh_ulen, uh_sum;
  proto_tree *udp_tree;
  proto_item *ti;
  int        offset = 0;

  CHECK_DISPLAY_AS_DATA(proto_udp, tvb, pinfo, tree);

  pinfo->current_proto = "UDP";

  /* Avoids alignment problems on many architectures. */
  tvb_memcpy(tvb, (guint8 *)&uh, offset, sizeof(e_udphdr));
  uh_sport = ntohs(uh.uh_sport);
  uh_dport = ntohs(uh.uh_dport);
  uh_ulen  = ntohs(uh.uh_ulen);
  uh_sum   = ntohs(uh.uh_sum);
  
  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_add_str(pinfo->fd, COL_PROTOCOL, "UDP");
  if (check_col(pinfo->fd, COL_INFO))
    col_add_fstr(pinfo->fd, COL_INFO, "Source port: %s  Destination port: %s",
	    get_udp_port(uh_sport), get_udp_port(uh_dport));
    
  if (tree) {
    ti = proto_tree_add_item(tree, proto_udp, tvb, offset, 8, FALSE);
    udp_tree = proto_item_add_subtree(ti, ett_udp);

    proto_tree_add_uint_format(udp_tree, hf_udp_srcport, tvb, offset, 2, uh_sport,
	"Source port: %s (%u)", get_udp_port(uh_sport), uh_sport);
    proto_tree_add_uint_format(udp_tree, hf_udp_dstport, tvb, offset + 2, 2, uh_dport,
	"Destination port: %s (%u)", get_udp_port(uh_dport), uh_dport);

    proto_tree_add_uint_hidden(udp_tree, hf_udp_port, tvb, offset, 2, uh_sport);
    proto_tree_add_uint_hidden(udp_tree, hf_udp_port, tvb, offset+2, 2, uh_dport);

    proto_tree_add_uint(udp_tree, hf_udp_length, tvb, offset + 4, 2,  uh_ulen);
    proto_tree_add_uint_format(udp_tree, hf_udp_checksum, tvb, offset + 6, 2, uh_sum,
	"Checksum: 0x%04x", uh_sum);
  }

  /* Skip over header */
  offset += 8;

  pinfo->ptype = PT_UDP;
  pinfo->srcport = uh_sport;
  pinfo->destport = uh_dport;

/* call sub-dissectors */
  decode_udp_ports( tvb, offset, pinfo, tree, uh_sport, uh_dport);

}

void
proto_register_udp(void)
{
	static hf_register_info hf[] = {
		{ &hf_udp_srcport,
		{ "Source Port",	"udp.srcport", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_udp_dstport,
		{ "Destination Port",	"udp.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_udp_port,
		{ "Source or Destination Port",	"udp.port", FT_UINT16, BASE_DEC,  NULL, 0x0,
			"" }},

		{ &hf_udp_length,
		{ "Length",		"udp.length", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_udp_checksum,
		{ "Checksum",		"udp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},
	};
	static gint *ett[] = {
		&ett_udp,
	};

	proto_udp = proto_register_protocol("User Datagram Protocol", "udp");
	proto_register_field_array(proto_udp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

/* subdissector code */
	udp_dissector_table = register_dissector_table("udp.port");
	register_heur_dissector_list("udp", &heur_subdissector_list);
}

void
proto_reg_handoff_udp(void)
{
	dissector_add("ip.proto", IP_PROTO_UDP, dissect_udp);
}
