/* packet-xot.c
 * Routines for X25 over TCP dissection (RFC 1613)
 *
 * Copyright 2000, Paul Ionescu	<paul@acorp.ro>
 *
 * $Id: packet-xot.c,v 1.3 2001/01/09 06:31:45 guy Exp $
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
#include "packet-x25.h"

#define TCP_PORT_XOT 1998

static gint proto_xot = -1;
static gint ett_xot = -1;

static void dissect_xot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *xot_tree;
  guint16 version,len;
  tvbuff_t   *next_tvb; 
    
  CHECK_DISPLAY_AS_DATA(proto_xot, tvb, pinfo, tree);

  pinfo->current_proto = "XOT";
  if (check_col(pinfo->fd, COL_PROTOCOL)) 
      col_set_str(pinfo->fd, COL_PROTOCOL, "XOT");

  version = tvb_get_ntohs(tvb,0);
  len     = tvb_get_ntohs(tvb,2);

  if (check_col(pinfo->fd, COL_INFO)) 
     col_add_fstr(pinfo->fd, COL_INFO, "XOT Version = %u, size = %u",version,len );

  if (tree) {
	
      ti = proto_tree_add_protocol_format(tree, proto_xot, tvb, 0, 4, "X.25 over TCP");
      xot_tree = proto_item_add_subtree(ti, ett_xot);
      
      ti = proto_tree_add_text(xot_tree, tvb, 0,2,"XOT Version : %u %s",version,(version==0?"":" - Unknown version")) ;
      ti = proto_tree_add_text(xot_tree, tvb, 2,2,"XOT length : %u",len) ;
  }
  next_tvb =  tvb_new_subset(tvb,4, -1 , -1);
  dissect_x25(next_tvb,pinfo,tree);
}
 
/* Register the protocol with Ethereal */
void proto_register_xot(void)
{                 


  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_xot,
  };

  /* Register the protocol name and description */
  proto_xot = proto_register_protocol("X.25 over TCP", "XOT", "xot");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_subtree_array(ett, array_length(ett));
};

void
proto_reg_handoff_xot(void)
{
  dissector_add("tcp.port", TCP_PORT_XOT, dissect_xot, proto_xot);
}
