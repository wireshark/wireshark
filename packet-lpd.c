/* packet-lpd.c
 * Routines for LPR and LPRng packet disassembly
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-lpd.c,v 1.15 2000/01/07 22:05:32 guy Exp $
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

#include <string.h>

#include <glib.h>
#include "packet.h"

static int proto_lpd = -1;
static int hf_lpd_response = -1;
static int hf_lpd_request = -1;

static gint ett_lpd = -1;

enum lpr_type { request, response, unknown };

static char* find_printer_string(const u_char *pd, int offset, int frame_length);

void
dissect_lpd(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree	*lpd_tree;
	proto_item	*ti;
	enum lpr_type	lpr_packet_type;
	char		*printer;

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
		lpr_packet_type = unknown;
	}

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "LPD");
	if (check_col(fd, COL_INFO)) {
		if (lpr_packet_type == request) {
			col_add_str(fd, COL_INFO, lpd_client_code[pd[offset]]);
		}
		else if (lpr_packet_type == response) {
			col_add_str(fd, COL_INFO, "LPD response");
		}
		else {
			col_add_str(fd, COL_INFO, "LPD continuation");
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_lpd, offset, 
					 END_OF_FRAME, NULL);
		lpd_tree = proto_item_add_subtree(ti, ett_lpd);

		if (lpr_packet_type == response) {
		  proto_tree_add_item_hidden(lpd_tree, hf_lpd_response, 0, 0, TRUE);
		} else {
		  proto_tree_add_item_hidden(lpd_tree, hf_lpd_request, 0, 0, TRUE);
		}

		if (lpr_packet_type == request) {
			printer = find_printer_string(pd, offset+1, END_OF_FRAME);

			if (pd[offset] <= 9 && printer) {
				proto_tree_add_text(lpd_tree, offset,		1,
					lpd_client_code[pd[offset]]);
				proto_tree_add_text(lpd_tree, offset+1,
					strlen(printer), "Printer/options: %s", printer);
			}
			else {
				dissect_data(pd, offset, fd, tree);
			}

			if (printer) 
				g_free(printer);
		}
		else if (lpr_packet_type == response) {
			int response = pd[offset];

			if (response <= 3) {
				proto_tree_add_text(lpd_tree, offset, 2, "Response: %s",
					lpd_server_code[response]);
			}
			else {
				dissect_data(pd, offset, fd, tree);
			}
		}
		else {
				dissect_data(pd, offset, fd, tree);
		}
	}
}


static char*
find_printer_string(const u_char *pd, int offset, int frame_length)
{
	int	i, final_offset;
	char	c;
	char	*string;
	int	bytes;

	final_offset = offset + frame_length;

	/* try to find end of string, either 0x0a or 0x00 */
	for (i = offset; i < final_offset; i++) {
		c = pd[i];
		if (c == '\x00' || c == '\x0a') {
			bytes = i - offset;
			string = g_malloc(bytes+1);
			memcpy(string, &pd[offset], bytes);
			string[bytes] = 0;
			return string;
		}
	}

	return NULL;
}


void
proto_register_lpd(void)
{
  static hf_register_info hf[] = {
    { &hf_lpd_response,
      { "Response",           "lpd.response",		
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if LPD response" }},

    { &hf_lpd_request,
      { "Request",            "lpd.request",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if LPD request" }}
  };
  static gint *ett[] = {
    &ett_lpd,
  };

  proto_lpd = proto_register_protocol("Line Printer Daemon Protocol", "lpd");
  proto_register_field_array(proto_lpd, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

