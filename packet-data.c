/* packet-data.c
 * Routines for raw data (default case)
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-data.c,v 1.18 2000/05/12 06:23:33 gram Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>
#include "packet.h"

/* proto_data cannot be static because it's referenced in the
 * print routines
 */
int proto_data = -1;

void
dissect_data(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	if (IS_DATA_IN_FRAME(offset) && tree) {
		proto_tree_add_protocol_format(tree, proto_data, NullTVB, offset,
			END_OF_FRAME, "Data (%d byte%s)", END_OF_FRAME,
			plurality(END_OF_FRAME, "", "s"));
	}
}

/* This will become dissect_data() once all dissectors are converted to use tvbuffs */
void
dissect_data_tvb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int bytes;

	if (tree) {
		bytes = tvb_length(tvb);
		if (bytes > 0) {
			proto_tree_add_protocol_format(tree, proto_data, tvb, 0,
				bytes, "Data (%d byte%s)", bytes,
				plurality(bytes, "", "s"));
		}
	}
}

void
proto_register_data(void)
{
	proto_data = proto_register_protocol (
		/* name */	"Data",
		/* abbrev */	"data" );
}
