/* packet-time.c
 * Routines for time packet dissection
 *
 * Richard Sharpe <rsharpe@ns.aus.com>
 * Craig Newell <CraigN@cheque.uq.edu.au>
 *	RFC2347 TIME Option Extension
 *
 * $Id: packet-time.c,v 1.10 2001/01/03 06:55:34 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
dissect_time(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
  proto_tree	*time_tree;
  proto_item	*ti;

  OLD_CHECK_DISPLAY_AS_DATA(proto_time, pd, offset, fd, tree);
  
  if (check_col(fd, COL_PROTOCOL))
    col_set_str(fd, COL_PROTOCOL, "TIME");
  
  if (check_col(fd, COL_INFO)) {
    col_add_fstr(fd, COL_INFO, "TIME %s", pi.srcport == UDP_PORT_TIME? "Response":"Request");
  }
  
  if (tree) {
    
    ti = proto_tree_add_item(tree, proto_time, NullTVB, offset, END_OF_FRAME, FALSE);
    time_tree = proto_item_add_subtree(ti, ett_time);
    
    proto_tree_add_text(time_tree, NullTVB, offset, 0,
			pi.srcport==37? "Type: Response":"Type: Request");
    if (pi.srcport == 37) { 
      guint32 delta_seconds = pntohl(pd+offset);
      proto_tree_add_text(time_tree, NullTVB, offset, 4,
			  " %u seconds since midnight 1 January 1900 GMT",
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
      	"Seconds since 00:00 (midnight) 1 January 1900 GMT" }}
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
  old_dissector_add("udp.port", UDP_PORT_TIME, dissect_time);
}
