/* packet-icap.c
 * Routines for ICAP packet disassembly
 * RFC 3507
 *
 * Srishylam Simharajan simha@netapp.com
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

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>

typedef enum _icap_type {
	ICAP_OPTIONS,
	ICAP_REQMOD,
	ICAP_RESPMOD,
	ICAP_RESPONSE,
	ICAP_OTHER
} icap_type_t;

static int proto_icap = -1;
static int hf_icap_response = -1;
static int hf_icap_reqmod = -1;
static int hf_icap_respmod = -1;
static int hf_icap_options = -1;
static int hf_icap_other = -1;

static gint ett_icap = -1;

static dissector_handle_t data_handle;

#define TCP_PORT_ICAP			1344
static int is_icap_message(const guchar *data, int linelen, icap_type_t *type);
static void
dissect_icap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*icap_tree = NULL;
	proto_item	*ti = NULL;
	proto_item	*hidden_item;
	gint		offset = 0;
	const guchar	*line;
	gint		next_offset;
	const guchar	*linep, *lineend;
	int		linelen;
	guchar		c;
	icap_type_t     icap_type;
	int		datalen;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ICAP");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
		 * if it's an ICAP header (but leave out the
		 * line terminator).
		 * Otherwise, just call it a continuation.
		 *
		 * Note that "tvb_find_line_end()" will return a value that
		 * is not longer than what's in the buffer, so the
		 * "tvb_get_ptr()" call won't throw an exception.
		 */
		linelen = tvb_find_line_end(tvb, offset, -1, &next_offset,
		    FALSE);
		line = tvb_get_ptr(tvb, offset, linelen);
		icap_type = ICAP_OTHER;	/* type not known yet */
		if (is_icap_message(line, linelen, &icap_type))
			col_add_str(pinfo->cinfo, COL_INFO,
			    format_text(line, linelen));
		else
			col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_icap, tvb, offset, -1,
		    ENC_NA);
		icap_tree = proto_item_add_subtree(ti, ett_icap);
	}

	/*
	 * Process the packet data, a line at a time.
	 */
	icap_type = ICAP_OTHER;	/* type not known yet */
	while (tvb_offset_exists(tvb, offset)) {
		gboolean is_icap = FALSE;
		gboolean loop_done = FALSE;
		/*
		 * Find the end of the line.
		 */
		linelen = tvb_find_line_end(tvb, offset, -1, &next_offset,
		    FALSE);

		/*
		 * Get a buffer that refers to the line.
		 */
		line = tvb_get_ptr(tvb, offset, linelen);
		lineend = line + linelen;

		/*
		 * find header format
		 */
		if (is_icap_message(line, linelen, &icap_type)) {
			is_icap = TRUE;
			goto is_icap_header;
		}

		/*
		 * if it looks like a blank line, end of header perhaps?
		 */
		if (linelen == 0) {
			is_icap = TRUE;
			goto is_icap_header;
		}

		/*
		 * No.  Does it look like a header?
		 */
		linep = line;
		loop_done = FALSE;
		while (linep < lineend && (!loop_done)) {
			c = *linep++;

			/*
			 * This must be a CHAR to be part of a token; that
			 * means it must be ASCII.
			 */
			if (!isascii(c)) {
				is_icap = FALSE;
				break;	/* not ASCII, thus not a CHAR */
			}

			/*
			 * This mustn't be a CTL to be part of a token.
			 *
			 * XXX - what about leading LWS on continuation
			 * lines of a header?
			 */
			if (iscntrl(c)) {
				is_icap = FALSE;
				break;	/* CTL, not part of a header */
			}

			switch (c) {

			case '(':
			case ')':
			case '<':
			case '>':
			case '@':
			case ',':
			case ';':
			case '\\':
			case '"':
			case '/':
			case '[':
			case ']':
			case '?':
			case '=':
			case '{':
			case '}':
				/*
				 * It's a separator, so it's not part of a
				 * token, so it's not a field name for the
				 * beginning of a header.
				 *
				 * (We don't have to check for HT; that's
				 * already been ruled out by "iscntrl()".)
				 *
				 * XXX - what about ' '?  HTTP's checks
				 * check for that.
				 */
				is_icap = FALSE;
				loop_done = TRUE;
				break;

			case ':':
				/*
				 * This ends the token; we consider this
				 * to be a header.
				 */
				is_icap = TRUE;
				goto is_icap_header;
			}
		}

		/*
		 * We don't consider this part of an ICAP message,
		 * so we don't display it.
		 * (Yeah, that means we don't display, say, a text/icap
		 * page, but you can get that from the data pane.)
		 */
		if (!is_icap)
			break;
is_icap_header:
		if (tree) {
			proto_tree_add_text(icap_tree, tvb, offset,
				next_offset - offset, "%s",
				tvb_format_text(tvb, offset,
						next_offset - offset)
				);
		}
		offset = next_offset;
	}

	if (tree) {
		switch (icap_type) {

		case ICAP_OPTIONS:
			hidden_item = proto_tree_add_boolean(icap_tree,
					    hf_icap_options, tvb, 0, 0, 1);
                        PROTO_ITEM_SET_HIDDEN(hidden_item);
			break;

		case ICAP_REQMOD:
			hidden_item = proto_tree_add_boolean(icap_tree,
					    hf_icap_reqmod, tvb, 0, 0, 1);
                        PROTO_ITEM_SET_HIDDEN(hidden_item);
			break;

		case ICAP_RESPMOD:
			hidden_item = proto_tree_add_boolean(icap_tree,
					    hf_icap_respmod, tvb, 0, 0, 1);
                        PROTO_ITEM_SET_HIDDEN(hidden_item);
			break;

		case ICAP_RESPONSE:
			hidden_item = proto_tree_add_boolean(icap_tree,
					    hf_icap_response, tvb, 0, 0, 1);
                        PROTO_ITEM_SET_HIDDEN(hidden_item);
			break;

		case ICAP_OTHER:
		default:
			break;
		}
	}

	datalen = tvb_length_remaining(tvb, offset);
	if (datalen > 0) {
		call_dissector(data_handle,
		    tvb_new_subset_remaining(tvb, offset), pinfo, icap_tree);
	}
}


static int
is_icap_message(const guchar *data, int linelen, icap_type_t *type)
{
#define ICAP_COMPARE(string, length, msgtype) {		\
	if (strncmp(data, string, length) == 0) {	\
		if (*type == ICAP_OTHER)		\
			*type = msgtype;		\
		return TRUE;				\
	}						\
}
	/*
	 * From draft-elson-opes-icap-01(72).txt
	 */
	if (linelen >= 5) {
		ICAP_COMPARE("ICAP/", 5, ICAP_RESPONSE); /* response */
	}
	if (linelen >= 7) {
		ICAP_COMPARE("REQMOD ", 7, ICAP_REQMOD); /* request mod */
	}
	if (linelen >= 8) {
		ICAP_COMPARE("OPTIONS ", 8, ICAP_OPTIONS); /* options */
		ICAP_COMPARE("RESPMOD ", 8, ICAP_RESPMOD); /* response mod */
	}
	return FALSE;
#undef ICAP_COMPARE
}

void
proto_register_icap(void)
{
	static hf_register_info hf[] = {
	    { &hf_icap_response,
	      { "Response",		"icap.response",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if ICAP response", HFILL }},
	    { &hf_icap_reqmod,
	      { "Reqmod",		"icap.reqmod",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if ICAP reqmod", HFILL }},
	    { &hf_icap_respmod,
	      { "Respmod",		"icap.respmod",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if ICAP respmod", HFILL }},
	    { &hf_icap_options,
	      { "Options",		"icap.options",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if ICAP options", HFILL }},
	    { &hf_icap_other,
	      { "Other",		"icap.other",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if ICAP other", HFILL }},
	};
	static gint *ett[] = {
		&ett_icap,
	};

	proto_icap = proto_register_protocol(
			"Internet Content Adaptation Protocol",
			"ICAP", "icap");
	proto_register_field_array(proto_icap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_icap(void)
{
	dissector_handle_t icap_handle;

        data_handle = find_dissector("data");
	icap_handle = create_dissector_handle(dissect_icap, proto_icap);
	dissector_add_uint("tcp.port", TCP_PORT_ICAP, icap_handle);
}
