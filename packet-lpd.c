/* packet-lpr.c
 * Routines for LPR and LPRng packet disassembly
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-lpd.c,v 1.7 1999/03/23 03:14:39 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

#include <string.h>

#include <glib.h>
#include "packet.h"

enum lpr_type { request, response };

void
dissect_lpd(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree	*lpd_tree;
	proto_item	*ti;
	enum lpr_type	lpr_packet_type;
	char		*newline, *printer, *line_pos;
	int			substr_len, curr_offset;

	/* This information comes from the LPRng HOWTO, which also describes
		RFC 1179. http://www.astart.com/lprng/LPRng-HOWTO.html */
	char		*lpd_client_code[] = {
		"Unknown command",
		"LPC: start print",
		"LPR: transfer a printer job",
		"LPQ: print short form of queue status",
		"LPQ: print long form of queue status",
		"LPRM: remove jobs",
		"LPRng lpc: do control operation",
		"LPRng lpr: transfer a block format print job",
		"LPRng lpc: secure command transfer",
		"LPRng lpq: verbose status information"
	};
	char		*lpd_server_code[] = {
		"Success: accepted, proceed",
		"Queue not accepting jobs",
		"Queue temporarily full, retry later",
		"Bad job format, do not retry"
	};


	if (pd[offset+1] == '\n') {
		lpr_packet_type = response;
	}
	else if (pd[offset] <= 9) {
		lpr_packet_type = request;
	}
	else {
		lpr_packet_type = response;
	}


	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "LPD");
	if (check_col(fd, COL_INFO)) {
		if (lpr_packet_type == request) {
			col_add_str(fd, COL_INFO, lpd_client_code[pd[offset]]);
		}
		else {
			col_add_str(fd, COL_INFO, "LPD response");
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, offset, fd->cap_len - offset,
		  "Line Printer Daemon Protocol");
		lpd_tree = proto_tree_new();
		proto_item_add_subtree(ti, lpd_tree, ETT_LPD);

		if (lpr_packet_type == request) {
			if (pd[offset] <= 9) {
				proto_tree_add_item(lpd_tree, offset,		1,
					lpd_client_code[pd[offset]]);
			}
			else {
				proto_tree_add_item(lpd_tree, offset,		1,
					lpd_client_code[0]);
			}
			printer = g_strdup(&pd[offset+1]);

			/* get rid of the new-line so that the tree prints out nicely */
			if (printer[fd->cap_len - offset - 2] == 0x0a) {
				printer[fd->cap_len - offset - 2] = 0;
			}
			proto_tree_add_item(lpd_tree, offset+1, fd->cap_len - (offset+1),
					/*"Printer/options: %s", &pd[offset+1]);*/
					"Printer/options: %s", printer);
			g_free(printer);
		}
		else {
			if (pd[offset] <= 3) {
				proto_tree_add_item(lpd_tree, offset, 2, "Response: %s",
					lpd_server_code[pd[offset]]);
			}
			else {
				printer = strdup(&pd[offset]);
				line_pos = printer;
				curr_offset = offset;
				while (fd->cap_len > curr_offset) {
					newline = strchr(line_pos, '\n');
					if (!newline) {
						proto_tree_add_item(lpd_tree, curr_offset,
							fd->cap_len - offset, "Text: %s", line_pos);
						break;
					}
					*newline = 0;
					substr_len = strlen(line_pos);
					proto_tree_add_item(lpd_tree, curr_offset, substr_len + 1,
						"Text: %s", line_pos);
					curr_offset += substr_len + 1;
					line_pos = newline + 1;
				}
			}
		}
	}
}

