/* packet-lpr.c
 * Routines for LPR and LPRng packet disassembly
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-lpd.c,v 1.4 1998/11/12 00:06:31 gram Exp $
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

#include <gtk/gtk.h>

#include <stdio.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif


#include "ethereal.h"
#include "packet.h"
#include "etypes.h"

enum lpr_type { request, response };

void
dissect_lpd(const u_char *pd, int offset, frame_data *fd, GtkTree *tree)
{
	GtkWidget	*lpd_tree, *ti;
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


	if (fd->win_info[COL_NUM]) {
		strcpy(fd->win_info[COL_PROTOCOL], "LPD");
		if (lpr_packet_type == request) {
			strcpy(fd->win_info[COL_INFO], lpd_client_code[pd[offset]]);
		}
		else {
			strcpy(fd->win_info[COL_INFO], "LPD response");
		}
	}

	if (tree) {
		ti = add_item_to_tree(GTK_WIDGET(tree), offset, fd->cap_len - offset,
		  "Line Printer Daemon Protocol");
		lpd_tree = gtk_tree_new();
		add_subtree(ti, lpd_tree, ETT_LPD);

		if (lpr_packet_type == request) {
			if (pd[offset] <= 9) {
				add_item_to_tree(lpd_tree, offset,		1,
					lpd_client_code[pd[offset]]);
			}
			else {
				add_item_to_tree(lpd_tree, offset,		1,
					lpd_client_code[0]);
			}
			printer = strdup(&pd[offset+1]);

			/* get rid of the new-line so that the tree prints out nicely */
			if (printer[fd->cap_len - offset - 2] == 0x0a) {
				printer[fd->cap_len - offset - 2] = 0;
			}
			add_item_to_tree(lpd_tree, offset+1, fd->cap_len - (offset+1),
					/*"Printer/options: %s", &pd[offset+1]);*/
					"Printer/options: %s", printer);
			free(printer);
		}
		else {
			if (pd[offset] <= 3) {
				add_item_to_tree(lpd_tree, offset, 2, "Response: %s",
					lpd_server_code[pd[offset]]);
			}
			else {
				printer = strdup(&pd[offset]);
				line_pos = printer;
				curr_offset = offset;
				while (fd->cap_len > curr_offset) {
					newline = strchr(line_pos, '\n');
					if (!newline) {
						add_item_to_tree(lpd_tree, curr_offset,
							fd->cap_len - offset, "Text: %s", line_pos);
						break;
					}
					*newline = 0;
					substr_len = strlen(line_pos);
					add_item_to_tree(lpd_tree, curr_offset, substr_len + 1,
						"Text: %s", line_pos);
					curr_offset += substr_len + 1;
					line_pos = newline + 1;
				}
			}
		}
	}
}

