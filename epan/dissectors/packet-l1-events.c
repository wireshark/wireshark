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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Edit this file with 4-space tabs */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>

void proto_register_l1_events(void);
void proto_reg_handoff_l1_events(void);

static dissector_handle_t l1_events_handle;
/*
 * dissector for line-based text messages from layer 1
 */

/* Filterable header fields */
static int proto_l1_events;

/* Subtrees */
static int ett_l1_events;

static int
dissect_l1_events(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree	*subtree;
	proto_item	*ti;
	int		offset = 0, next_offset;
	int		len;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Layer1");
	col_set_str(pinfo->cinfo, COL_DEF_SRC,
			    pinfo->pseudo_header->l1event.uton? "TE" : "NT");
	len = tvb_find_line_end(tvb, 0, -1, &next_offset, false);
	if(len>0)
		col_add_str(pinfo->cinfo, COL_INFO, tvb_format_text(pinfo->pool, tvb, 0, len));

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
			len = tvb_find_line_end(tvb, offset, -1, &next_offset, false);
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
	static int *ett[] = {
		&ett_l1_events,
	};

	proto_register_subtree_array(ett, array_length(ett));

	proto_l1_events = proto_register_protocol("Layer 1 Event Messages", "Layer 1 Events", "data-l1-events");

	l1_events_handle = register_dissector("data-l1-events", dissect_l1_events, proto_l1_events);
}

void
proto_reg_handoff_l1_events(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_LAYER1_EVENT, l1_events_handle); /* for text msgs from trace files */
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
