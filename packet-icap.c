/* packet-icap.c
 * Routines for ICAP packet disassembly
 *
 * Srishylam Simharajan simha@netapp.com
 *
 * packet-icap.c Mon Aug 13 17:50:19 PDT 2001 simha 
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
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include "packet.h"
#include "strutil.h"

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

#define TCP_PORT_ICAP			1344
static int is_icap_message(const u_char *data, int linelen, icap_type_t *type);
static void
dissect_icap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*icap_tree = NULL;
	proto_item	*ti = NULL;
	gint		offset = 0;
	const u_char	*line;
	gint		next_offset;
	const u_char	*linep, *lineend;
	int		linelen;
	u_char		c;
	icap_type_t     icap_type;
	int		datalen;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "ICAP");

	if (check_col(pinfo->fd, COL_INFO)) {
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
		linelen = tvb_find_line_end(tvb, offset, -1, &next_offset);
		line = tvb_get_ptr(tvb, offset, linelen);
		icap_type = ICAP_OTHER;	/* type not known yet */
		if (is_icap_message(line, linelen, &icap_type))
			col_add_str(pinfo->fd, COL_INFO,
			    format_text(line, linelen));
		else
			col_set_str(pinfo->fd, COL_INFO, "Continuation");
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_icap, tvb, offset,
		    tvb_length_remaining(tvb, offset), FALSE);
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
		linelen = tvb_find_line_end(tvb, offset, -1, &next_offset);

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
		 * No.  Does it look like a MIME header?
		 */
		linep = line;
		loop_done = FALSE;
		while (linep < lineend && (!loop_done)) {
			c = *linep++;
			if (!isprint(c)) {
				is_icap = FALSE;
				break;	/* not printable, not a MIME header */
			}
			switch (c) {
			case ':':
				is_icap = TRUE;
				goto is_icap_header;
				break;
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
				is_icap = FALSE;
				loop_done = TRUE;
				break;
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
			proto_tree_add_boolean_hidden(icap_tree,
			    hf_icap_options, tvb, 0, 0, 1);
			break;

		case ICAP_REQMOD:
			proto_tree_add_boolean_hidden(icap_tree,
			    hf_icap_reqmod, tvb, 0, 0, 1);
			break;

		case ICAP_RESPMOD:
			proto_tree_add_boolean_hidden(icap_tree,
			    hf_icap_respmod, tvb, 0, 0, 1);
			break;

		case ICAP_RESPONSE:
			proto_tree_add_boolean_hidden(icap_tree,
			    hf_icap_response, tvb, 0, 0, 1);
			break;

		case ICAP_OTHER:
		default:
			break;
		}
	}

	datalen = tvb_length_remaining(tvb, offset);
	if (datalen > 0) {
		tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, -1, -1);
		dissect_data(tvb, offset, pinfo, icap_tree);
	}
}

	
static int
is_icap_message(const u_char *data, int linelen, icap_type_t *type)
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
	dissector_add("tcp.port", TCP_PORT_ICAP, dissect_icap, proto_icap);
}
