/* packet-yhoo.c
 * Routines for yahoo messenger packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 *
 * $Id: packet-yhoo.c,v 1.1 1999/10/14 01:28:25 guy Exp $
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
#include "packet-yhoo.h"

static int proto_yhoo = -1;

static unsigned int yahoo_makeint(unsigned char *data)
{
    if (data)
    {
        return ((data[3] << 24) + (data[2] << 16) + (data[1] << 8) + (data[0]));
    }
    return 0;
}

void
dissect_yhoo(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree      *yhoo_tree, *ti;
	struct yahoo_rawpacket *pkt;
	int max_data = pi.captured_len - offset;

	/* get at least a full packet structure */
	pkt = (struct yahoo_rawpacket *) &pd[offset];

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "YHOO");

	if (check_col(fd, COL_INFO)) {
		if ( max_data > sizeof(struct yahoo_rawpacket) )
		{
			col_add_fstr(fd, COL_INFO, "%s: Service #%u", (pi.match_port == pi.destport)?"Request" : "Response", 
				yahoo_makeint(pkt->service));
		}
		else
		{
			col_add_fstr(fd, COL_INFO, "%s: too short", (pi.match_port == pi.destport)? "Request" : "Response");
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_yhoo, offset, END_OF_FRAME, NULL);
		yhoo_tree = proto_item_add_subtree(ti, ETT_YHOO);

		if ( max_data > sizeof(struct yahoo_rawpacket) )
		{
			int fieldoff;

			fieldoff = offset;
			proto_tree_add_text(yhoo_tree, 
				fieldoff, 8, "Protocol Version: %s", pkt->version);

			fieldoff += 8;
			proto_tree_add_text(yhoo_tree, 
				fieldoff, 4, "Packet Length: %u", yahoo_makeint(pkt->len));

			fieldoff += 4;
			proto_tree_add_text(yhoo_tree, 
				fieldoff, 4, "Service Type: %u", yahoo_makeint(pkt->service));

			fieldoff += 4;
			proto_tree_add_text(yhoo_tree, 
				fieldoff, 4, "Connection ID: %X", yahoo_makeint(pkt->connection_id));

			fieldoff += 4;
			proto_tree_add_text(yhoo_tree, 
				fieldoff, 4, "Magic ID: %X", yahoo_makeint(pkt->magic_id));

			fieldoff += 4;
			proto_tree_add_text(yhoo_tree, 
				fieldoff, 4, "Unknown 1: %X", yahoo_makeint(pkt->unknown1));
		
			fieldoff += 4;
			proto_tree_add_text(yhoo_tree, 
				fieldoff, 4, "Message Type: %d", yahoo_makeint(pkt->msgtype));
		
			fieldoff += 4;
			proto_tree_add_text(yhoo_tree, 
				fieldoff, 36, "Nick 1: %s", pkt->nick1);
		
			fieldoff += 36;
			proto_tree_add_text(yhoo_tree, 
				fieldoff, 36, "Nick 2: %s", pkt->nick2);
		
			fieldoff += 36;
			proto_tree_add_text(yhoo_tree, fieldoff, END_OF_FRAME, 
				"Content: %s", pkt->content);
		}
	}
}

void
proto_register_yhoo(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "yhoo.abbreviation", TYPE, VALS_POINTER }},
        };*/

        proto_yhoo = proto_register_protocol("Yahoo Messenger Protocol", "yhoo");

	/* the following is for filtering - see packet-tcp.c */
 /*       proto_register_field_array(proto_yhoo, hf, array_length(hf));*/
}
