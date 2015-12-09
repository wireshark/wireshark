/* packet-l1-events.c
 * Routines for text-based layer 1 messages in EyeSDN trace files
 *
 * (C) Rolf Fiedler 2008, based on packet-text-media.c by Olivier Biot, 2004.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Edit this file with 4-space tabs */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>

void proto_register_l1_events(void);
void proto_reg_handoff_l1_events(void);

/*
 * dissector for line-based text messages from layer 1
 */

/* Filterable header fields */
static gint proto_l1_events = -1;

/* Subtrees */
static gint ett_l1_events = -1;

static int
dissect_l1_events(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree	*subtree;
	proto_item	*ti;
	gint		offset = 0, next_offset;
	gint		len;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Layer1");
	col_set_str(pinfo->cinfo, COL_DEF_SRC,
			    pinfo->pseudo_header->l1event.uton? "TE" : "NT");
	len = tvb_find_line_end(tvb, 0, -1, &next_offset, FALSE);
	if(len>0)
		col_add_str(pinfo->cinfo, COL_INFO, tvb_format_text(tvb, 0, len));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_l1_events,
				tvb, 0, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, ett_l1_events);
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
			len = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
			if (len == -1)
				break;

			/* We use next_offset - offset instead of len in the
			 * call to proto_tree_add_format_text() so it will include the
			 * line terminator(s) (\r and/or \n) in the display.
			 */
			proto_tree_add_format_text(subtree, tvb, offset, next_offset - offset);
			offset = next_offset;
		}
	}

	return tvb_captured_length(tvb);
}

void
proto_register_l1_events(void)
{
	static gint *ett[] = {
		&ett_l1_events,
	};

	proto_register_subtree_array(ett, array_length(ett));

	proto_l1_events = proto_register_protocol(
			"Layer 1 Event Messages", /* Long name */
			"Layer 1 Events",	  /* Short name */
			"data-l1-events");		/* Filter name */
}

void
proto_reg_handoff_l1_events(void)
{
	dissector_handle_t l1_events_handle = create_dissector_handle(dissect_l1_events, proto_l1_events);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_LAYER1_EVENT, l1_events_handle); /* for text msgs from trace files */
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
