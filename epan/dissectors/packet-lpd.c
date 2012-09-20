/* packet-lpd.c
 * Routines for LPR and LPRng packet disassembly
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#define TCP_PORT_PRINTER		515

static int proto_lpd = -1;
static int hf_lpd_response = -1;
static int hf_lpd_request = -1;

static gint ett_lpd = -1;

enum lpr_type { request, response, unknown };

static gint find_printer_string(tvbuff_t *tvb, int offset);

static dissector_handle_t data_handle;

static void
dissect_lpd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*lpd_tree;
	proto_item	*ti, *hidden_item;
	enum lpr_type	lpr_packet_type;
	guint8		code;
	gint		printer_len;

	/* This information comes from the LPRng HOWTO, which also describes
		RFC 1179. http://www.astart.com/lprng/LPRng-HOWTO.html */
	static const value_string lpd_client_code[] = {
		{ 1, "LPC: start print / jobcmd: abort" },
		{ 2, "LPR: transfer a printer job / jobcmd: receive control file" },
		{ 3, "LPQ: print short form of queue status / jobcmd: receive data file" },
		{ 4, "LPQ: print long form of queue status" },
		{ 5, "LPRM: remove jobs" },
		{ 6, "LPRng lpc: do control operation" },
		{ 7, "LPRng lpr: transfer a block format print job" },
		{ 8, "LPRng lpc: secure command transfer" },
		{ 9, "LPRng lpq: verbose status information" },
		{ 0, NULL }
	};
	static const value_string lpd_server_code[] = {
		{ 0, "Success: accepted, proceed" },
		{ 1, "Queue not accepting jobs" },
		{ 2, "Queue temporarily full, retry later" },
		{ 3, "Bad job format, do not retry" },
		{ 0, NULL }
	};

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LPD");
	col_clear(pinfo->cinfo, COL_INFO);

	/* rfc1179 states that all responses are 1 byte long */
	code = tvb_get_guint8(tvb, 0);
	if (tvb_reported_length(tvb) == 1) {
		lpr_packet_type = response;
	}
	else if (code <= 9) {
		lpr_packet_type = request;
	}
	else {
		lpr_packet_type = unknown;
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
		if (lpr_packet_type == request && code !=0) {
			col_add_str(pinfo->cinfo, COL_INFO, val_to_str(code, lpd_client_code, "Unknown client code: %u"));
		}
		else if (lpr_packet_type == response) {
			col_set_str(pinfo->cinfo, COL_INFO, "LPD response");
		}
		else {
			col_set_str(pinfo->cinfo, COL_INFO, "LPD continuation");
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_lpd, tvb, 0, -1, ENC_NA);
		lpd_tree = proto_item_add_subtree(ti, ett_lpd);

		if (lpr_packet_type == response) {
		  hidden_item = proto_tree_add_boolean(lpd_tree, hf_lpd_response,
		  				tvb, 0, 0, TRUE);
		} else {
		  hidden_item = proto_tree_add_boolean(lpd_tree, hf_lpd_request,
		  				tvb, 0, 0, TRUE);
		}
		PROTO_ITEM_SET_HIDDEN(hidden_item);

		if (lpr_packet_type == request) {
			printer_len = find_printer_string(tvb, 1);

			if (code <= 9 && printer_len != -1) {
				proto_tree_add_text(lpd_tree, tvb, 0, 1, "%s",
					val_to_str(code, lpd_client_code, "Unknown client code: %u"));
				proto_tree_add_text(lpd_tree, tvb, 1, printer_len,
					 "Printer/options: %s",
					 tvb_format_text(tvb, 1, printer_len));
			}
			else {
				call_dissector(data_handle,tvb, pinfo, lpd_tree);
			}
		}
		else if (lpr_packet_type == response) {
			if (code <= 3) {
				proto_tree_add_text(lpd_tree, tvb, 0, 1,
					"Response: %s", val_to_str(code, lpd_server_code, "Unknown server code: %u"));
			}
			else {
				call_dissector(data_handle,tvb, pinfo, lpd_tree);
			}
		}
		else {
			call_dissector(data_handle,tvb, pinfo, lpd_tree);
		}
	}
}


static gint
find_printer_string(tvbuff_t *tvb, int offset)
{
	int	i;

	/* try to find end of string, either '\n' or '\0' */
	i = tvb_find_guint8(tvb, offset, -1, '\0');
	if (i == -1)
		i = tvb_find_guint8(tvb, offset, -1, '\n');
	if (i == -1)
		return -1;
	return i - offset;	/* length of string */
}


void
proto_register_lpd(void)
{
  static hf_register_info hf[] = {
    { &hf_lpd_response,
      { "Response",           "lpd.response",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if LPD response", HFILL }},

    { &hf_lpd_request,
      { "Request",            "lpd.request",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if LPD request", HFILL }}
  };
  static gint *ett[] = {
    &ett_lpd,
  };

  proto_lpd = proto_register_protocol("Line Printer Daemon Protocol", "LPD", "lpd");
  proto_register_field_array(proto_lpd, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_lpd(void)
{
  dissector_handle_t lpd_handle;

  lpd_handle = create_dissector_handle(dissect_lpd, proto_lpd);
  dissector_add_uint("tcp.port", TCP_PORT_PRINTER, lpd_handle);
  data_handle = find_dissector("data");
}
