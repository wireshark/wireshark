/* packet-data.c
 * Routines for raw data (default case)
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-data.c,v 1.22 2001/10/31 05:59:18 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
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
dissect_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	int bytes;

	if (tree) {
		bytes = tvb_length_remaining(tvb, offset);
		if (bytes > 0) {
			proto_tree_add_protocol_format(tree, proto_data, tvb,
				offset,
				bytes, "Data (%d byte%s)", bytes,
				plurality(bytes, "", "s"));
		}
	}
}

void
proto_register_data(void)
{
	proto_data = proto_register_protocol (
		"Data",		/* name */
		"Data",		/* short name */
		"data"		/* abbrev */
		);

	/*
	 * "Data" is used to dissect something whose normal dissector
	 * is disabled, so it cannot itself be disabled.
	 */
	proto_set_cant_disable(proto_data);

}
