/* packet-imap.c
 * Routines for imap packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-imap.c,v 1.1 1999/11/10 14:44:57 nneul Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"

static int proto_imap = -1;

void
dissect_imap(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
        proto_tree      *imap_tree, *ti;
	gchar          rr[50], rd[1500];
	int i1 = (u_char *)strchr(pd + offset, ' ') - (pd + offset); /* Where is that space */
	int i2;
	int max_data = pi.captured_len - offset;

	memset(rr, '\0', sizeof(rr));
	memset(rd, '\0', sizeof(rd));

	if ((i1 > max_data) || (i1 <= 0)) {
	  
	  i1 = max_data;
	  strncpy(rr, pd + offset, MIN(max_data - 2, sizeof(rr) - 1));

	}
	else {

	  strncpy(rr, pd + offset, MIN(i1, sizeof(rr) - 1));
	  i2 = ((u_char *)strchr(pd + offset + i1 + 1, '\r') - (pd + offset)) - i1 - 1;
	  if (i2 > max_data - i1 - 1 || i2 <= 0) {
	    i2 = ((u_char *)strchr(pd + offset + i1 + 1, '\n') - (pd + offset)) - i1 - 1;
	    if (i2 > max_data - i1 - 1 || i2 <= 0)
	      i2 = max_data - i1 - 1;
	  }
	  strncpy(rd, pd + offset + i1 + 1, MIN(i2, sizeof(rd) - 1));
	}

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "IMAP");

	if (check_col(fd, COL_INFO)) {

	  col_add_fstr(fd, COL_INFO, "%s: %s %s", (pi.match_port == pi.destport)? "Request" : "Response", rr, rd);	  
	}

	if (tree) {

	  ti = proto_tree_add_item(tree, proto_imap, offset, END_OF_FRAME, NULL);
	  imap_tree = proto_item_add_subtree(ti, ETT_IMAP);

	  if (pi.match_port == pi.destport) { /* Request */

	    proto_tree_add_text(imap_tree, offset, i1, "Request Tag: %s", rr);

	    proto_tree_add_text(imap_tree, offset + i1 + 1, END_OF_FRAME, "Request: %s", rd);

	  }
	  else {

	    proto_tree_add_text(imap_tree, offset, i1, "Response Tag: %s", rr);

	    proto_tree_add_text(imap_tree, offset + i1 + 1, END_OF_FRAME, "Response: %s", rd);
	  }

	}
}

void
proto_register_imap(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "imap.abbreviation", TYPE, VALS_POINTER }},
        };*/

	proto_imap = proto_register_protocol("IMAP", "imap");
 /*       proto_register_field_array(proto_imap, hf, array_length(hf));*/
}
