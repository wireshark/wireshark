/* packet-sdp.c
 * Routines for SDP packet disassembly
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@netapp.com>
 *
 * $Id: packet-sdp.c,v 1.2 1999/07/07 22:51:53 gram Exp $
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
 *
 *
 */

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include "packet.h"

void dissect_sdp(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	proto_tree	*sdp_tree;
	proto_item	*ti;
	const u_char	*data, *dataend;
	const u_char	*lineend, *eol;
	int		linelen;
	u_char		section;
	u_char		type;
	const u_char	*value;
	int		valuelen;
	const char	*typename;

	data = &pd[offset];
	dataend = data + END_OF_FRAME;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "SDP");

	if (check_col(fd, COL_INFO)) {
		/* XXX: Needs description. */
		col_add_str(fd, COL_INFO, "Session Description");
	}

	if (!tree)
		return;

	ti = proto_tree_add_text(tree, offset, END_OF_FRAME,
		"Session Description Protocol");
	sdp_tree = proto_item_add_subtree(ti, ETT_SDP);

	section = 0;
	for (; data < dataend; offset += linelen, data = lineend) {
		/*
		 * Find the end of the line.
		 */
		lineend = find_line_end(data, dataend, &eol);
		linelen = lineend - data;

		/*
		 * Line must contain at least e.g. "v=".
		 */
		if (linelen < 2)
			break;

		type = data[0];
		if (data[1] != '=') {
			proto_tree_add_text(sdp_tree, offset, linelen,
				"Invalid line: %s",
				format_text(data, linelen));
			continue;
		}
		value = data + 2;
		valuelen = linelen - 2;

		/*
		 * Attributes.
		 */
		switch (type) {
		case 'v':
			section = 'v';
			typename = "Session Description, version";
			break;
		case 'o':
			typename = "Owner/Creator, Session Id";
			break;
		case 's':
			typename = "Session Name";
			break;
		case 'i':
			if (section == 'v')
				typename = "Session Information";
			else if (section == 'm')
				typename = "Media Title";
			else
				typename = "Misplaced";
			break;
		case 'u':
			typename = "URI of Description";
			break;
		case 'e':
			typename = "E-mail Address";
			break;
		case 'p':
			typename = "Phone Number";
			break;
		case 'c':
			typename = "Connection Information";
			break;
		case 'b':
			typename = "Bandwidth Information";
			break;
		case 't':
			section = 't';
			typename = "Time Description, active time";
			break;
		case 'r':
			typename = "Repeat Time";
			break;
		case 'm':
			section = 'm';
			typename = "Media Description, name and address";
			break;
		case 'k':
			typename = "Encryption Key";
			break;
		case 'a':
			if (section == 'v')
				typename = "Session Attribute";
			else if (section == 'm')
				typename = "Media Attribute";
			else
				typename = "Misplaced";
			break;
		case 'z':
			typename = "Time Zone Adjustment";
			break;
		default:
			typename = "Unknown";
			break;
		}

		proto_tree_add_text(sdp_tree, offset, linelen,
			"%s (%c): %s", typename, type,
			format_text(value, valuelen));
	}

	if (data < dataend) {
		proto_tree_add_text(sdp_tree, offset, END_OF_FRAME,
		    "Data (%d bytes)", END_OF_FRAME);
	}
}
