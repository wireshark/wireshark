/* packet-kismet.c
 * Routines for kismet packet dissection
 * Copyright 2006, Krzysztof Burghardt <krzysztof@burghardt.pl>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/prefs.h>

static int proto_kismet = -1;
static int hf_kismet_response = -1;
static int hf_kismet_request = -1;

static gint ett_kismet = -1;
static gint ett_kismet_reqresp = -1;

static dissector_handle_t data_handle;

#define TCP_PORT_KISMET	2501

static guint global_kismet_tcp_port = TCP_PORT_KISMET;

static gboolean response_is_continuation(const guchar * data);
void proto_reg_handoff_kismet(void);
void proto_register_kismet(void);

static gboolean
dissect_kismet(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data _U_)
{
	gboolean is_request;
	gboolean is_continuation;
	proto_tree *kismet_tree=NULL, *reqresp_tree=NULL;
	proto_item *ti;
	proto_item *tmp_item;
	gint offset = 0;
	const guchar *line;
	gint next_offset;
	int linelen;
	int tokenlen;
	int i;
	const guchar *next_token;

	/*
	 * Find the end of the first line.
	 *
	 * Note that "tvb_find_line_end()" will return a value that is
	 * not longer than what's in the buffer, so the "tvb_get_ptr()"
	 * call won't throw an exception.
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
	line = tvb_get_ptr(tvb, offset, linelen);

	/*
	 * Check if it is an ASCII based protocol with reasonable length
	 * packets, if not return, and try annother dissector.
	 */
	if (linelen < 8) {
		/*
		 * Packet is too short
		 */
		return FALSE;
	} else {
		for (i = 0; i < 8; ++i) {
			/*
			 * Packet contains non-ASCII data
			 */
			if (line[i] < 32 || line[i] > 128)
				return FALSE;
		}
	}

	/*
	 * If it is Kismet traffic set COL_PROTOCOL.
	 */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "kismet");

	/*
	 * Check if it is request, reply or continuation.
	 */
	if (pinfo->match_uint == pinfo->destport) {
		is_request = TRUE;
		is_continuation = FALSE;
	} else {
		is_request = FALSE;
		is_continuation = response_is_continuation (line);
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
		 * if it's a kismet request or reply (but leave out the
		 * line terminator).
		 * Otherwise, just call it a continuation.
		 */
		if (is_continuation)
			col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
				is_request ? "Request" : "Response",
				format_text(line, linelen));
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_kismet, tvb, offset, -1, ENC_NA);
		kismet_tree = proto_item_add_subtree(ti, ett_kismet);
	}

	if (is_continuation) {
		/*
		 * Put the whole packet into the tree as data.
		 */
		call_dissector(data_handle, tvb, pinfo, kismet_tree);
		return TRUE;
	}

	if (is_request) {
		tmp_item = proto_tree_add_boolean(kismet_tree,
				hf_kismet_request, tvb, 0, 0, TRUE);
	} else {
		tmp_item = proto_tree_add_boolean(kismet_tree,
				hf_kismet_response, tvb, 0, 0, TRUE);
	}
	PROTO_ITEM_SET_GENERATED (tmp_item);

	while (tvb_offset_exists(tvb, offset)) {
		/*
		 * Find the end of the line.
		 */
		linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);

		if (linelen) {
			/*
			 * Put this line.
			 */
			ti = proto_tree_add_text(kismet_tree, tvb, offset,
					next_offset - offset, "%s",
					tvb_format_text(tvb, offset,
					next_offset - offset - 1));
			reqresp_tree = proto_item_add_subtree(ti, ett_kismet_reqresp);
			tokenlen = get_token_len(line, line + linelen, &next_token);
			if (tokenlen != 0) {
				guint8 *reqresp;
				reqresp = tvb_get_ephemeral_string(tvb, offset, tokenlen);
				if (is_request) {
					/*
					 * No request dissection
					 */
				} else {
					/*
					 * *KISMET: {Version} {Start time} \001{Server name}\001 {Build Revision}
					 * two fields left undocumented: {???} {?ExtendedVersion?}
					 */
					if (!strncmp(reqresp, "*KISMET", 7)) {
						offset += (gint) (next_token - line);
						linelen -= (int) (next_token - line);
						line = next_token;
						tokenlen = get_token_len(line, line + linelen, &next_token);
						proto_tree_add_text(reqresp_tree, tvb, offset,
							tokenlen, "Kismet version: %s",
							format_text(line, tokenlen));

						offset += (gint) (next_token - line);
						linelen -= (int) (next_token - line);
						line = next_token;
						tokenlen = get_token_len(line, line + linelen, &next_token);
						proto_tree_add_text(reqresp_tree, tvb, offset,
							tokenlen, "Start time: %s",
							format_text(line, tokenlen));

						offset += (gint) (next_token - line);
						linelen -= (int) (next_token - line);
						line = next_token;
						tokenlen = get_token_len(line, line + linelen, &next_token);
						proto_tree_add_text(reqresp_tree, tvb, offset,
							tokenlen, "Server name: %s",
							format_text(line + 1, tokenlen - 2));

						offset += (gint) (next_token - line);
						linelen -= (int) (next_token - line);
						line = next_token;
						tokenlen = get_token_len(line, line + linelen, &next_token);
						proto_tree_add_text(reqresp_tree, tvb, offset,
							tokenlen, "Build revision: %s",
							format_text(line, tokenlen));

						offset += (gint) (next_token - line);
						linelen -= (int) (next_token - line);
						line = next_token;
						tokenlen = get_token_len(line, line + linelen, &next_token);
						proto_tree_add_text(reqresp_tree, tvb, offset,
							tokenlen, "Unknown field: %s",
							format_text(line, tokenlen));

						offset += (gint) (next_token - line);
						linelen -= (int) (next_token - line);
						line = next_token;
						tokenlen = get_token_len(line, line + linelen, &next_token);
						proto_tree_add_text(reqresp_tree, tvb, offset,
							tokenlen,
							"Extended version string: %s",
							format_text(line, tokenlen));
					}
					/*
					 * *TIME: {Time}
					 */
					if (!strncmp(reqresp, "*TIME", 5)) {
						time_t t;
						char *ptr;

						offset += (gint) (next_token - line);
						linelen -= (int) (next_token - line);
						line = next_token;
						tokenlen = get_token_len(line, line + linelen, &next_token);

						/*
						 * Convert form ascii to time_t
						 */
						t = atoi(format_text (line, tokenlen));

						/*
						 * Format ascii representaion of time
						 */
						ptr = abs_time_secs_to_str(t, ABSOLUTE_TIME_LOCAL, TRUE);
						proto_tree_add_text(reqresp_tree, tvb, offset,
							tokenlen, "Time: %s", ptr);
					}
				}

				offset += (gint) (next_token - line);
				linelen -= (int) (next_token - line);
				line = next_token;
			}
		}
		offset = next_offset;
	}

	return TRUE;
}

static gboolean
response_is_continuation(const guchar * data)
{
	if (!strncmp(data, "*", 1))
		return FALSE;

	if (!strncmp(data, "!", 1))
		return FALSE;

	return TRUE;
}

void
proto_register_kismet(void)
{
	static hf_register_info hf[] = {
		{&hf_kismet_response,
		{"Response", "kismet.response", FT_BOOLEAN, BASE_NONE,
		NULL, 0x0, "TRUE if kismet response", HFILL}},

		{&hf_kismet_request,
		{"Request", "kismet.request", FT_BOOLEAN, BASE_NONE,
		NULL, 0x0, "TRUE if kismet request", HFILL}}
	};

	static gint *ett[] = {
		&ett_kismet,
		&ett_kismet_reqresp,
	};
	module_t *kismet_module;

	proto_kismet = proto_register_protocol("Kismet Client/Server Protocol", "Kismet", "kismet");
	proto_register_field_array(proto_kismet, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length (ett));

	/* Register our configuration options for Kismet, particularly our port */

	kismet_module = prefs_register_protocol(proto_kismet, proto_reg_handoff_kismet);

	prefs_register_uint_preference(kismet_module, "tcp.port",
			  "Kismet Server TCP Port",
			  "Set the port for Kismet Client/Server messages (if other"
			  " than the default of 2501)", 10,
			  &global_kismet_tcp_port);
}

void
proto_reg_handoff_kismet(void)
{
	static gboolean kismet_prefs_initialized = FALSE;
	static dissector_handle_t kismet_handle;
	static guint tcp_port;

	if (!kismet_prefs_initialized) {
		kismet_handle = new_create_dissector_handle(dissect_kismet, proto_kismet);
		data_handle = find_dissector("data");
		kismet_prefs_initialized = TRUE;
	} else {
		dissector_delete_uint("tcp.port", tcp_port, kismet_handle);
	}

	/* Set our port number for future use */
	tcp_port = global_kismet_tcp_port;

	dissector_add_uint("tcp.port", global_kismet_tcp_port, kismet_handle);
}
