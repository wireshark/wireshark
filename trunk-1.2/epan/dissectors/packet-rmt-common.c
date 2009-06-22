/* packet-rmt-common.c
 * Reliable Multicast Transport (RMT)
 * Common RMT functions
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-rmt-common.h"

/* Boolean string tables */
const true_false_string boolean_set_notset = { "Set", "Not set" };
const true_false_string boolean_yes_no = { "Yes", "No" };

/* Common RMT exported functions */
/* ============================= */

/* Scan the tvb and put extensions found in an array */
void rmt_ext_parse(GArray *a, tvbuff_t *tvb, guint *offset, guint offset_max)
{
	struct _ext e;
	
	while (*offset < offset_max)
	{
		/* Clear the temporary extension */
		memset(&e, 0, sizeof(struct _ext));
		
		/* Dissect the extension */
		e.offset = *offset;
		e.het = tvb_get_guint8(tvb, *offset);
		
		if (e.het <= 127) {
			/* If HET <= 127, we have a variable-size extention */
			e.hel = tvb_get_guint8(tvb, *offset+1);
			e.hec_offset = *offset + 2;
			e.hec_size = e.hel * 4 - 2;
			e.length = e.hel * 4;
		} else {
			/* If HET > 127, we have a short 32-bit extention */
			e.hel = 1;	/* even if HEL field is not defined for HET > 127 */
			e.hec_offset = *offset + 1;
			e.hec_size = 3;
			e.length = 4;
		}
			
		/* Prevents infinite loops */
		if (e.length == 0)
			break;
			
		g_array_append_val(a, e);
		*offset += e.length;
	}
}

/* Add default items to a subtree */
void rmt_ext_decode_default_header(struct _ext *e, tvbuff_t *tvb, proto_tree *tree)
{
	if (tree)
	{
		proto_tree_add_text(tree, tvb, e->offset, 1, "Header Extension Type (HET): %u", e->het);
		if (e->het <= 127)
			proto_tree_add_text(tree, tvb, e->offset+1, 1, "Header Extension Length (HEL): %u", e->hel);
	}
}

/* Add a default subtree to a tree item */
void rmt_ext_decode_default_subtree(struct _ext *e, tvbuff_t *tvb, proto_item *ti, gint ett)
{
	proto_tree *ext_tree;
	
	ext_tree = proto_item_add_subtree(ti, ett);
	rmt_ext_decode_default_header(e, tvb, ext_tree);
		
	if (ext_tree)
		proto_tree_add_text(ext_tree, tvb, e->hec_offset, e->hec_size,
			"Header Extension Content (HEC): %s", tvb_bytes_to_str(tvb, e->hec_offset, e->hec_size));
}

/* Add a default subtree for unknown extensions */
void rmt_ext_decode_default(struct _ext *e, tvbuff_t *tvb, proto_tree *tree, gint ett)
{
	proto_item *ti;
	
	if (tree)
	{
		ti = proto_tree_add_text(tree, tvb, e->offset, e->length,
			"Unknown extension (%u)", e->het);
		
		rmt_ext_decode_default_subtree(e, tvb, ti, ett);
	}
}
