/* packet-wbxml.c
 * Routines for wbxml dissection
 * Copyright 2003, Olivier Biot <olivier.biot (ad) siemens.com>
 *
 * $Id: packet-wbxml.c,v 1.1 2003/02/06 01:23:32 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Wap Binary XML decoding functionality provided by Olivier Biot.
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

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include "packet-wap.h"
#include "packet-wbxml.h"

/* Initialize the protocol and registered fields */
static int proto_wbxml = -1;
static int hf_wbxml_version = -1;
static int hf_wbxml_public_id_known = -1;
static int hf_wbxml_public_id_literal = -1;
static int hf_wbxml_charset = -1;

/* Initialize the subtree pointers */
static gint ett_wbxml = -1;

/*
 * Function prototypes
 */

static void
dissect_wbxml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void
proto_register_wbxml(void);

void
add_wml_10 (proto_tree *tree, tvbuff_t *tvb, guint32 offset, guint8 version);


/* WBXML format
 * Version 1.0: version publicid         strtbl BODY
 * Version 1.x: version publicid charset strtbl BODY
 */

/* Code to actually dissect the packets */
static void
dissect_wbxml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *wbxml_tree;
	guint8 peek, version;
	guint offset = 0;
	const char *token;
	int token_size;
	guint32 index, len, type=0;

	switch ( peek = tvb_get_guint8(tvb, 0) ) {
		case 0x00: /* WBXML/1.0 */
			break;

		case 0x01: /* WBXML/1.1 */
		case 0x02: /* WBXML/1.2 */
		case 0x03: /* WBXML/1.3 */
			break;

		default:
			break;
	}

	/* In the interest of speed, if "tree" is NULL, don't do any work not
	   necessary to generate protocol tree items. */
	if (tree) {

		/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_wbxml, tvb, 0, -1, FALSE);
		wbxml_tree = proto_item_add_subtree(ti, ett_wbxml);

		/* WBXML Version */
		version = tvb_get_guint8(tvb, offset++);
		proto_tree_add_uint(wbxml_tree, hf_wbxml_version,
				tvb, 0, 1, version);

		/* Public ID */
		peek = tvb_get_guint8(tvb, offset++);
		if (peek == 0) { /* Public identifier in string table */
			/* TODO
			 * Check the value of index as String Table not yet parsed */
			index = tvb_get_guintvar (tvb, offset, &len);
			token_size = tvb_strsize(tvb, offset + len + index);
			token = tvb_get_ptr(tvb, offset + len + index, token_size);
			proto_tree_add_string(wbxml_tree, hf_wbxml_public_id_literal,
					tvb, 1, len, token);
		} else { /* Known public identifier */
			if (peek < 0x80) {
				type = peek;
				proto_tree_add_uint(wbxml_tree, hf_wbxml_public_id_known,
						tvb, 1, 1, type);
			} else {
				type = tvb_get_guintvar (tvb, offset, &len);
				proto_tree_add_uint(wbxml_tree, hf_wbxml_public_id_known,
						tvb, 1, len, type);
				offset += len;
			}
		}
		
		/* Version-specific handling of header */
		switch ( version ) {
			case 0x00: /* WBXML/1.0 */
				break;

			case 0x01: /* WBXML/1.1 */
			case 0x02: /* WBXML/1.2 */
			case 0x03: /* WBXML/1.3 */
				/* Get charset */
				index = tvb_get_guintvar (tvb, offset, &len);
				proto_tree_add_uint(wbxml_tree, hf_wbxml_charset,
						tvb, offset, len, index);
				offset += len;
				break;

			default:
				return;
		}

		/* String table */
		index = tvb_get_guintvar (tvb, offset, &len);
		proto_tree_add_text(wbxml_tree,
				tvb, offset, 1+index, "String table: %u bytes", index);
		offset += 1 + index;

		/* The WBXML BODY starts here */
		switch (type) {
			case WBXML_WML_10:
				add_wml_10 (wbxml_tree, tvb, offset, version);
				break;
			default:
				break;
		}
	}
}

void
add_wml_10 (proto_tree *tree, tvbuff_t *tvb, guint32 offset, guint8 version)
{
	guint32 size = tvb_reported_length(tvb) - offset;

	if (version) { /* Not WBXML 1.0 */
		;
	} else { /* WBXML 1.0 */
		;
	}

	/* TODO */
}



/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_wbxml(void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_wbxml_version,
			{ "Version",
			  "wbxml.version",
			  FT_UINT8, BASE_HEX,
			  VALS ( vals_wbxml_versions ), 0x00,
			  "WBXML version", HFILL }
		},

		{ &hf_wbxml_public_id_known,
			{ "Public Identifier (known)",
			  "wbxml.public_id",
			  FT_UINT32, BASE_HEX,
			  VALS ( vals_wbxml_public_ids ), 0x00,
			  "WBXML Public Identifier (known)", HFILL }
		},

		{ &hf_wbxml_public_id_literal,
			{ "Public Identifier (literal)",
			  "wbxml.public_id",
			  FT_STRING, BASE_NONE,
			  NULL, 0x00,
			  "WBXML Public Identifier (literal)", HFILL }
		},

		{ &hf_wbxml_charset,
			{ "Character Set",
			  "wbxml.charset",
			  FT_UINT32, BASE_HEX,
			  VALS ( vals_character_sets ), 0x00,
			  "WBXML Character Set", HFILL }
		},

	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_wbxml,
	};

/* Register the protocol name and description */
	proto_wbxml = proto_register_protocol(
			"WAP Binary XML",
			"WBXML",
			"wbxml"
	);

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_wbxml, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("wbxml", dissect_wbxml, proto_wbxml);
/*	register_init_routine(dissect_wbxml); */
	/* wbxml_handle = find_dissector("wsp-co"); */
};


void
proto_reg_handoff_wbxml(void)
{
	dissector_handle_t wbxml_handle;

	/* heur_dissector_add("wsp", dissect_wbxml_heur, proto_wbxml); */
	wbxml_handle = create_dissector_handle(dissect_wbxml, proto_wbxml);

	dissector_add("wsp.content_type.type", 0x14, wbxml_handle); /* wmlc */
	dissector_add("wsp.content_type.type", 0x16, wbxml_handle); /* channelc */
	dissector_add("wsp.content_type.type", 0x2E, wbxml_handle); /* sic */
	dissector_add("wsp.content_type.type", 0x30, wbxml_handle); /* slc */
	dissector_add("wsp.content_type.type", 0x32, wbxml_handle); /* coc */
}
