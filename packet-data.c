/* packet-data.c
 * Routines for raw data (default case)
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-data.c,v 1.13 2000/01/22 06:22:13 guy Exp $
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
dissect_data(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	if (fd->cap_len > offset && tree) {
		proto_tree_add_item_format(tree, proto_data, offset,
			END_OF_FRAME, NULL, "Data (%d byte%s)", END_OF_FRAME,
			plurality(END_OF_FRAME, "", "s"));
	}
}

void
proto_register_data(void)
{
	proto_data = proto_register_protocol (
		/* name */	"Data",
		/* abbrev */	"data" );
}
