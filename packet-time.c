/* packet-time.c
 * Routines for time packet dissection
 *
 * Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-time.c,v 1.16 2001/12/10 00:25:40 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#include "packet.h"

static int proto_time = -1;
static int hf_time_time = -1;

static gint ett_time = -1;

#define UDP_PORT_TIME    37

static void
dissect_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree	*time_tree;
  proto_item	*ti;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TIME");
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "TIME %s",
		 pinfo->srcport == pinfo->match_port ? "Response":"Request");
  }
  
  if (tree) {
    
    ti = proto_tree_add_item(tree, proto_time, tvb, 0,
			     tvb_length(tvb), FALSE);
    time_tree = proto_item_add_subtree(ti, ett_time);
    
    proto_tree_add_text(time_tree, tvb, 0, 0,
			pinfo->srcport==UDP_PORT_TIME? "Type: Response":"Type: Request");
    if (pinfo->srcport == UDP_PORT_TIME) { 
      guint32 delta_seconds = tvb_get_ntohl(tvb, 0);
      proto_tree_add_text(time_tree, tvb, 0, 4,
			  "%u seconds since midnight 1 January 1900 GMT",
			  delta_seconds);
    }
  }
}

void
proto_register_time(void)
{

  static hf_register_info hf[] = {
    { &hf_time_time,
      { "Time", "time.time",
	FT_UINT32, BASE_DEC, NULL, 0x0,
      	"Seconds since 00:00 (midnight) 1 January 1900 GMT", HFILL }}
  };
  static gint *ett[] = {
    &ett_time,
  };

  proto_time = proto_register_protocol("Time Protocol", "TIME", "time");
  proto_register_field_array(proto_time, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_time(void)
{
  dissector_handle_t time_handle;

  time_handle = create_dissector_handle(dissect_time, proto_time);
  dissector_add("udp.port", UDP_PORT_TIME, time_handle);
}
