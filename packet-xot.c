/* packet-xot.c
 * Routines for X25 over TCP dissection (RFC 1613)
 *
 * Copyright 2000, Paul Ionescu	<paul@acorp.ro>
 *
 * $Id: packet-xot.c,v 1.6 2001/09/13 08:05:26 guy Exp $
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <string.h>
#include <glib.h>
#include "packet.h"

#define TCP_PORT_XOT 1998

static gint proto_xot = -1;
static gint hf_xot_version = -1;
static gint hf_xot_length = -1;

static gint ett_xot = -1;

static dissector_handle_t x25_handle;

static void dissect_xot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *xot_tree;
  guint16 version,len;
  tvbuff_t   *next_tvb; 
    
  if (check_col(pinfo->fd, COL_PROTOCOL))
      col_set_str(pinfo->fd, COL_PROTOCOL, "XOT");
  if (check_col(pinfo->fd, COL_INFO))
      col_clear(pinfo->fd, COL_INFO);

  version = tvb_get_ntohs(tvb,0);
  len     = tvb_get_ntohs(tvb,2);

  if (check_col(pinfo->fd, COL_INFO)) 
     col_add_fstr(pinfo->fd, COL_INFO, "XOT Version = %u, size = %u",version,len );

  if (tree) {
	
      ti = proto_tree_add_protocol_format(tree, proto_xot, tvb, 0, 4, "X.25 over TCP");
      xot_tree = proto_item_add_subtree(ti, ett_xot);
     
      proto_tree_add_uint(xot_tree, hf_xot_version, tvb, 0, 2, version);
      proto_tree_add_uint(xot_tree, hf_xot_length, tvb, 2, 2, len);

  }
  next_tvb =  tvb_new_subset(tvb,4, -1 , -1);
  call_dissector(x25_handle,next_tvb,pinfo,tree);
}
 
/* Register the protocol with Ethereal */
void 
proto_register_xot(void)
{
	static hf_register_info hf[] = {
		{ &hf_xot_version,
			{ "Version", "xot.version", FT_UINT16, BASE_DEC,
			NULL, 0, "Version of X.25 over TCP protocol", HFILL }},

		{ &hf_xot_length,
			{ "Length", "xot.length", FT_UINT16, BASE_DEC,
			NULL, 0, "Length of X.25 over TCP packet", HFILL }}

	};

	static gint *ett[] = {
		&ett_xot,
	};

	proto_xot = proto_register_protocol("X.25 over TCP", "XOT", "xot");
	proto_register_field_array(proto_xot, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
};

void
proto_reg_handoff_xot(void)
{
	/*
	 * Get a handle for the X.25 dissector.
	 */
	x25_handle = find_dissector("x.25");

	dissector_add("tcp.port", TCP_PORT_XOT, dissect_xot, proto_xot);
}
