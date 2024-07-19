/* packet-text-media.c
 * Routines for text-based media dissection.
 *
 * NOTE - The media type is either found in pinfo->match_string,
 *        or passed into the dissector
 *
 * (C) Olivier Biot, 2004.
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Edit this file with 4-space tabs */

#include "config.h"

#include <epan/packet.h>

#include "packet-media-type.h"

/*
 * Media dissector for line-based text media like text/plain, message/http.
 *
 * TODO - character set and chunked transfer-coding
 */
void proto_register_text_lines(void);
void proto_reg_handoff_text_lines(void);

/* Filterable header fields */
static int proto_text_lines;

/* Subtrees */
static int ett_text_lines;

/* Dissector handles */
static dissector_handle_t xml_handle;

static int
dissect_text_lines(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	proto_tree	*subtree;
	proto_item	*ti;
	int		offset = 0, next_offset;
	int		len;
	media_content_info_t *content_info;
	const char	*data_name;
	int length = tvb_captured_length(tvb);

	/* Check if this is actually xml
	 * If there is less than 38 characters this is not XML
	 * <?xml version="1.0" encoding="UTF-8"?>
	 */
	if(length > 38){
		if (tvb_strncaseeql(tvb, 0, "<?xml", 5) == 0){
			call_dissector(xml_handle, tvb, pinfo, tree);
			return length;
		}
	}

	data_name = pinfo->match_string;
	if (! (data_name && data_name[0])) {
		/*
		 * No information from "match_string"
		 */
		content_info = (media_content_info_t *)data;
		if (content_info == NULL) {
			/*
			 * No information from dissector data
			 */
			data_name = NULL;
		} else {
			data_name = content_info->media_str;
			if (! (data_name && data_name[0])) {
				/*
				 * No information from dissector data
				 */
				data_name = NULL;
			}
		}
	}

	if (data_name)
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "(%s)",
				data_name);

	if (tree) {
		unsigned lines_read = 0;
		ti = proto_tree_add_item(tree, proto_text_lines,
				tvb, 0, -1, ENC_NA);
		if (data_name)
			proto_item_append_text(ti, ": %s", data_name);
		subtree = proto_item_add_subtree(ti, ett_text_lines);
		/* Read the media line by line */
		while (tvb_offset_exists(tvb, offset)) {
			/*
			 * XXX - we need to be passed the parameters
			 * of the content type via data parameter,
			 * so that we know the character set.  We'd
			 * have to handle that character set, which
			 * might be a multibyte character set such
			 * as "iso-10646-ucs-2", or might require other
			 * special processing.
			 */
			len = tvb_find_line_end(tvb, offset, -1, &next_offset, false);
			if (len == -1)
				break;

			/* We use next_offset - offset instead of len in the
			 * call to proto_tree_add_format_text() so it will include the
			 * line terminator(s) (\r and/or \n) in the display.
			 */
			proto_tree_add_format_text(subtree, tvb, offset, next_offset - offset);
			lines_read++;
			offset = next_offset;
		}
		proto_item_append_text(subtree, " (%u lines)", lines_read);
	}

	return length;
}

void
proto_register_text_lines(void)
{
	static int *ett[] = {
		&ett_text_lines,
	};

	proto_register_subtree_array(ett, array_length(ett));

	proto_text_lines = proto_register_protocol("Line-based text data", "Line-based text data", "data-text-lines");
	register_dissector("data-text-lines", dissect_text_lines, proto_text_lines);
}

void
proto_reg_handoff_text_lines(void)
{
	dissector_handle_t text_lines_handle;

	text_lines_handle = find_dissector("data-text-lines");

	dissector_add_string("media_type", "text/plain", text_lines_handle); /* RFC 2046 */
	dissector_add_string("media_type", "text/richtext", text_lines_handle);  /* RFC 1341 */
	dissector_add_string("media_type", "text/enriched", text_lines_handle);  /* RFC 1896 */
	dissector_add_string("media_type", "text/parameters", text_lines_handle);
	/* W3C line-based textual media */
	dissector_add_string("media_type", "text/html", text_lines_handle);
	dissector_add_string("media_type", "text/xml-external-parsed-entity", text_lines_handle);
	dissector_add_string("media_type", "text/css", text_lines_handle);
	dissector_add_string("media_type", "application/xml-external-parsed-entity", text_lines_handle);
	dissector_add_string("media_type", "text/javascript", text_lines_handle);
	dissector_add_string("media_type", "application/x-javascript", text_lines_handle);
	dissector_add_string("media_type", "application/x-tia-p25-issi", text_lines_handle);
	dissector_add_string("media_type", "application/x-tia-p25-sndcp", text_lines_handle);
	dissector_add_string("media_type", "application/x-ns-proxy-autoconfig", text_lines_handle);

	dissector_add_string("media_type", "text/vnd.sun.j2me.app-descriptor", text_lines_handle);
	dissector_add_string("media_type", "application/vnd.poc.refer-to", text_lines_handle);
	dissector_add_string("media_type", "application/vnd.drm.message", text_lines_handle);

	dissector_add_string("media_type", "application/x-wms-logplaystats", text_lines_handle);
	dissector_add_string("media_type", "application/x-rtsp-udp-packetpair", text_lines_handle);
	xml_handle = find_dissector_add_dependency("xml", proto_text_lines);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
