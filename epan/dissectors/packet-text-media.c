/* packet-text-media.c
 * Routines for text-based media dissection.
 *
 * NOTE - The media type is either found in pinfo->match_string
 *        or in pinfo->private_data.
 *
 * (C) Olivier Biot, 2004.
 *
 * $Id$
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Edit this file with 4-space tabs */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>


/*
 * Media dissector for line-based text media like text/plain, message/http.
 *
 * TODO - character set and chunked transfer-coding
 */

/* Filterable header fields */
static gint proto_text_lines = -1;

/* Subtrees */
static gint ett_text_lines = -1;

/* Dissector handles */
static dissector_handle_t text_lines_handle;

static void
dissect_text_lines(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*subtree;
	proto_item	*ti;
	gint		offset = 0, next_offset;
	gint		len;
	const char	*data_name;

	data_name = pinfo->match_string;
	if (! (data_name && data_name[0])) {
		/*
		 * No information from "match_string"
		 */
		data_name = (char *)(pinfo->private_data);
		if (! (data_name && data_name[0])) {
			/*
			 * No information from "private_data"
			 */
			data_name = NULL;
		}
	}

	if (data_name && check_col(pinfo->cinfo, COL_INFO))
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "(%s)",
				data_name);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_text_lines,
				tvb, 0, -1, FALSE);
		if (data_name)
			proto_item_append_text(ti, ": %s", data_name);
		subtree = proto_item_add_subtree(ti, ett_text_lines);
		/* Read the media line by line */
		while (tvb_reported_length_remaining(tvb, offset) != 0) {
			/*
			 * XXX - we need to be passed the parameters
			 * of the content type via "pinfo->private_data",
			 * so that we know the character set.  We'd
			 * have to handle that character set, which
			 * might be a multibyte character set such
			 * as "iso-10646-ucs-2", or might require other
			 * special processing.
			 */
			len = tvb_find_line_end(tvb, offset,
					tvb_ensure_length_remaining(tvb, offset),
					&next_offset, FALSE);
			if (len == -1)
				break;
			proto_tree_add_text(subtree, tvb, offset, next_offset - offset,
					"%s", tvb_format_text(tvb, offset, len));
			offset = next_offset;
		}
	}
}

void
proto_register_text_lines(void)
{
	static gint *ett[] = {
		&ett_text_lines,
	};

	proto_register_subtree_array(ett, array_length(ett));

	proto_text_lines = proto_register_protocol(
			"Line-based text data",	/* Long name */
			"Line-based text data",	/* Short name */
			"data-text-lines");		/* Filter name */
	register_dissector("data-text-lines", dissect_text_lines, proto_text_lines);
}

void
proto_reg_handoff_text_lines(void)
{
	text_lines_handle = create_dissector_handle(
					dissect_text_lines, proto_text_lines);

	dissector_add_string("media_type", "text/plain", text_lines_handle); /* RFC 2046 */
	dissector_add_string("media_type", "text/richtext", text_lines_handle);  /* RFC 1341 */
	dissector_add_string("media_type", "text/enriched", text_lines_handle);  /* RFC 1896 */
	/* W3C line-based textual media */
	dissector_add_string("media_type", "text/html", text_lines_handle);
	dissector_add_string("media_type", "text/xml-external-parsed-entity", text_lines_handle);
	dissector_add_string("media_type", "text/css", text_lines_handle);
	dissector_add_string("media_type", "application/xml-external-parsed-entity", text_lines_handle);
	dissector_add_string("media_type", "application/x-javascript", text_lines_handle);
	dissector_add_string("media_type", "application/x-www-form-urlencoded", text_lines_handle);
	dissector_add_string("media_type", "application/x-ns-proxy-autoconfig", text_lines_handle);

	dissector_add_string("media_type", "text/vnd.sun.j2me.app-descriptor", text_lines_handle);
	dissector_add_string("media_type", "application/vnd.poc.refer-to", text_lines_handle);
}
