/* packet-wbxml.c
 * Routines for wbxml dissection
 * Copyright 2003, Olivier Biot <olivier.biot (ad) siemens.com>
 *
 * $Id: packet-wbxml.c,v 1.3 2003/02/12 21:46:15 guy Exp $
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

/* Edit this file with 4-space tabulation */

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

/* The code in this source file dissects the WAP Binary XML content,
 * and if possible renders it. WBXML mappings are defined in a struct
 * located at the very end of "packet-wbxml.h".
 *
 * NOTES:
 *
 *  - Although Code Page processing is already foreseen in the tag and
 *    attribute parsing code, there is no mechanism available yet to
 *    properly deal with multiple code pages (see, e.g., the wbxml_map[]
 *    array). As a consequence, the same token rendering will occur,
 *    irrespective of the code pages in use.
 *    As there currently is no registered WBXML type with support of more
 *    than one tag or attribute code page, this is a safe assumption.
 *
 *  - In order to render the XML content, recursion is inevitable at some
 *    point (when a tag with content occurs in the content of a tag with
 *    content). The code will however not recurse if this is not strictly
 *    required (e.g., tag without content in the content of a tag with
 *    content).
 *
 *  - I found it useful to display the XML nesting level as a first "column",
 *    followed by the abbreviated WBXML token interpretation. When a mapping
 *    is defined for the parsed WBXML content, then the XML rendering is
 *    displayed with appropriate indentation (maximum nesting level = 255,
 *    after which the nesting and level will safely roll-over to 0).
 */

/* Initialize the protocol and registered fields */
static int proto_wbxml = -1;
static int hf_wbxml_version = -1;
static int hf_wbxml_public_id_known = -1;
static int hf_wbxml_public_id_literal = -1;
static int hf_wbxml_charset = -1;

/* Initialize the subtree pointers */
static gint ett_wbxml = -1;
static gint ett_wbxml_str_tbl = -1;
static gint ett_wbxml_content = -1;



/************************** Function prototypes **************************/



static void
dissect_wbxml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


void
proto_register_wbxml(void);


/* Parse and display the WBXML string table
 */
static void
show_wbxml_string_table (proto_tree *tree, tvbuff_t *tvb, guint32 str_tbl,
		guint32 str_tbl_len);


/* Return a pointer to the string in the string table.
 * Can also be hacked for inline string retrieval.
 */
static const char*
strtbl_lookup (tvbuff_t *tvb, guint32 str_tbl, guint32 offset, guint32 *len);


/* Parse data while in STAG state
 */
static void
parse_wbxml_tag (proto_tree *tree, tvbuff_t *tvb, guint32 offset,
		guint32 str_tbl, guint8 *level,
		guint8 *codepage_stag, guint8 *codepage_attr, guint32 *parsed_length);


/* Parse data while in STAG state;
 * interpret tokens as defined by content type
 */
static void
parse_wbxml_tag_defined (proto_tree *tree, tvbuff_t *tvb, guint32 offset,
		guint32 str_tbl, guint8 *level,
		guint8 *codepage_stag, guint8 *codepage_attr, guint32 *parsed_length,
		const wbxml_mapping_table *map);


/* Parse data while in ATTR state
 */
static void
parse_wbxml_attribute_list (proto_tree *tree, tvbuff_t *tvb,
		guint32 offset, guint32 str_tbl, guint8 level,
		guint8 *codepage_attr, guint32 *parsed_length);


/* Parse data while in ATTR state;
 * interpret tokens as defined by content type
 */
static void
parse_wbxml_attribute_list_defined (proto_tree *tree, tvbuff_t *tvb,
		guint32 offset, guint32 str_tbl, guint8 level,
		guint8 *codepage_attr, guint32 *parsed_length,
		const wbxml_mapping_table *map);




/****************** WBXML protocol dissection functions ******************/




/* Code to actually dissect the packets */
static void
dissect_wbxml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *wbxml_tree; /* Main WBXML tree */
	proto_tree *wbxml_str_tbl_tree; /* String table subtree */
	proto_tree *wbxml_content_tree; /* Content subtree */
	guint8 version;
	guint offset = 0;
	const char *token;
	guint32 len;
	guint32 charset=0;
	guint32 charset_len;
	guint32 publicid;
	guint32 publicid_index = 0;
	guint32 publicid_len;
	guint32 str_tbl;
	guint32 str_tbl_len;
	guint8 level = 0; /* WBXML recursion level */
	guint8 codepage_stag = 0; /* Initial codepage in state = STAG */
	guint8 codepage_attr = 0; /* Initial codepage in state = ATTR */

	/* WBXML format
	 * 
	 * Version 1.0: version publicid         strtbl BODY
	 * Version 1.x: version publicid charset strtbl BODY
	 *
	 * Last valid format: WBXML 1.3
	 */
	switch ( version = tvb_get_guint8 (tvb, 0) ) {
		case 0x00: /* WBXML/1.0 */
			break;

		case 0x01: /* WBXML/1.1 */
		case 0x02: /* WBXML/1.2 */
		case 0x03: /* WBXML/1.3 */
			break;

		default:
			return;
	}

	/* In the interest of speed, if "tree" is NULL, don't do any work not
	   necessary to generate protocol tree items. */
	if ( tree ) {
		/* create display subtree for the protocol */
		ti = proto_tree_add_item (tree, proto_wbxml, tvb, 0, -1, FALSE);
		wbxml_tree = proto_item_add_subtree(ti, ett_wbxml);

		/* WBXML Version */
		proto_tree_add_uint (wbxml_tree, hf_wbxml_version,
				tvb, 0, 1, version);

		/* Public ID */
		publicid = tvb_get_guintvar(tvb, 1, &publicid_len);
		if (publicid) { /* Known Public ID */
			proto_tree_add_uint(wbxml_tree, hf_wbxml_public_id_known,
					tvb, 1, publicid_len, publicid);
		} else { /* Public identifier in string table */
			publicid_index = tvb_get_guintvar (tvb, 1+publicid_len, &len);
			publicid_len += len;
		}
		offset = 1 + publicid_len;

		/* Version-specific handling of Charset */
		switch ( version ) {
			case 0x00: /* WBXML/1.0 */
				/* No charset */
				break;

			case 0x01: /* WBXML/1.1 */
			case 0x02: /* WBXML/1.2 */
			case 0x03: /* WBXML/1.3 */
				/* Get charset */
				charset = tvb_get_guintvar (tvb, offset, &charset_len);
				offset += charset_len;
				break;

			default: /* Impossible since return already earlier */
				break;
		}

		/* String table: read string table length in bytes */
		str_tbl_len = tvb_get_guintvar (tvb, offset, &len);
		str_tbl = offset + len; /* Start of 1st string in string table */


		/* Now we can add public ID, charset (if available),
		 * and string table */
		if ( ! publicid ) { /* Read Public ID from string table */
			token = strtbl_lookup (tvb, str_tbl, publicid_index, NULL);
			proto_tree_add_string (wbxml_tree, hf_wbxml_public_id_literal,
					tvb, 1, publicid_len, token?token:"[NULL STRING]");
		}
		if ( version ) { /* Charset */
			proto_tree_add_uint (wbxml_tree, hf_wbxml_charset,
					tvb, 1+publicid_len, charset_len, charset);
		}
		/* String Table */
		ti = proto_tree_add_text(wbxml_tree,
				tvb, offset, len + str_tbl_len, "String table: %u bytes",
				str_tbl_len);

		if (wbxml_tree && str_tbl_len) { /* Display string table as subtree */
			wbxml_str_tbl_tree = proto_item_add_subtree (ti,
					ett_wbxml_str_tbl);
			show_wbxml_string_table (wbxml_str_tbl_tree, tvb,
					str_tbl, str_tbl_len);
		}

		/* Data starts HERE */
		offset += len + str_tbl_len;

		/* The WBXML BODY starts here */
		ti = proto_tree_add_text (wbxml_tree, tvb, offset, -1,
				"Data representation");
		wbxml_content_tree = proto_item_add_subtree (ti, ett_wbxml_content);

		/* The parse_wbxml_X() functions will process the content correctly,
		 * irrespective of the WBXML version used. For the WBXML body, this
		 * means that there is a different processing for the global token
		 * RESERVED_2 (WBXML 1.0) or OPAQUE (WBXML 1.x with x > 0).
		 */
		if (wbxml_tree) { /* Show only if visible */
			if (publicid) {
#ifdef DEBUG
				printf ("WBXML - Content Type : \"%s\"\n",
						match_strval (publicid, vals_wbxml_public_ids));
#endif
				/* Look in wbxml_map[] table for defined mapping */
				if (publicid < WBXML_MAP_MAX_ID) {
					if (wbxml_map[publicid].defined) {
						proto_tree_add_text (wbxml_content_tree, tvb,
								offset, -1,
								"Level | State "
								"| WBXML Token Description         "
								"| Rendering");
						parse_wbxml_tag_defined (wbxml_content_tree,
								tvb, offset, str_tbl, &level,
								&codepage_stag, &codepage_attr, &len,
								wbxml_map + publicid);
						return;
					}
					proto_tree_add_text (wbxml_content_tree, tvb,
							offset, -1,
							"Rendering of this content type"
							" not (yet) supported");
				}
			}
			/* Default: WBXML only, no interpretation of the content */
			proto_tree_add_text (wbxml_content_tree, tvb, offset, -1,
					"Level | State | WBXML Token Description         "
					"| Rendering");
			parse_wbxml_tag (wbxml_content_tree, tvb, offset,
					str_tbl, &level,
					&codepage_stag, &codepage_attr, &len);
			return;
		} else {
			proto_tree_add_text (wbxml_content_tree, tvb, offset, -1,
					"WBXML 1.0 decoding not yet supported");
		}
		return;
	}
}




/* Return a pointer to the string in the string table.
 * Can also be hacked for inline string retrieval.
 */
static const char*
strtbl_lookup (tvbuff_t *tvb, guint32 str_tbl, guint32 offset, guint32 *len)
{
	if (len) { /* The "hack" call for inline string reading */
		*len = tvb_strsize (tvb, str_tbl+offset);
		return tvb_get_ptr (tvb, str_tbl+offset, *len);
	} else { /* Normal string table reading */
		return tvb_get_ptr (tvb, str_tbl+offset,
				tvb_strsize (tvb, str_tbl+offset));
	}
}




/* Parse and display the WBXML string table (in a 3-column table format).
 * This function displays:
 *  - the offset in the string table,
 *  - the length of the string
 *  - the string.
 */
static void
show_wbxml_string_table (proto_tree *tree, tvbuff_t *tvb, guint32 str_tbl,
		guint32 str_tbl_len)
{
	guint32 off = str_tbl;
	guint32 len = 0;
	guint32 end = str_tbl + str_tbl_len;
	const char *str;

	proto_tree_add_text (tree, tvb, off, end,
			"Start  | Length | String");
	while (off < end) {
		/* Hack the string table lookup function */
		str = strtbl_lookup (tvb, off, 0, &len);
		proto_tree_add_text (tree, tvb, off, len,
				"%6d | %6d | '%s'",
				off - str_tbl, len, str);
		off += len;
	}
}




/* Indentation code is based on a static const array of space characters.
 * At least one single space is returned */
static const char indent_buffer[514] = " "
	"                                                                "
	"                                                                "
	"                                                                "
	"                                                                "
	"                                                                "
	"                                                                "
	"                                                                "
	"                                                                "
	; /* Generate XML indentation (length = 1 + 2 * 256 + 1 for '\0') */

static const char * Indent (guint8 level) {
	return indent_buffer + (512 - 2 * (level));
}




/********************
 * WBXML tag tokens *
 ********************
 * 
 * Bit Mask  : Example
 * -------------------
 * 00.. .... : <tag />
 *
 * 01.. .... : <tag>
 *               CONTENT
 *             </tag>
 *
 * 10.. .... : <tag
 *               atrtribute1="value1"
 *               atrtribute2="value2"
 *             />
 * 
 * 11.. .... : <tag
 *               atrtribute1="value1"
 *               atrtribute2="value2"
 *             >
 *               CONTENT
 *             </tag>
 *
 * NOTE: an XML PI is parsed as an attribute list (same syntax).
 */




/* This function parses the WBXML and maps known token interpretations
 * to the WBXML tokens. As a result, the original XML document can be
 * recreated. Indentation is generated in order to ease reading.
 *
 * Attribute parsing is done in parse_wbxml_attribute_list_defined().
 *
 * The wbxml_mapping_table entry *map contains the actual token mapping.
 *
 * NOTE: In order to parse the content, some recursion is required.
 *       However, for performance reasons, recursion has been avoided
 *       where possible (tags without content within tags with content).
 *       This is achieved by means of the parsing_tag_content and tag_save*
 *       variables.
 *
 * NOTE: Code page switches not yet processed in the code!
 *
 * NOTE: See packet-wbxml.h for known token mappings.
 */
static void
parse_wbxml_tag_defined (proto_tree *tree, tvbuff_t *tvb, guint32 offset,
		guint32 str_tbl, guint8 *level,
		guint8 *codepage_stag, guint8 *codepage_attr, guint32 *parsed_length,
		const wbxml_mapping_table *map)
{
	guint32 tvb_len = tvb_reported_length (tvb);
	guint32 off = offset;
	guint32 len;
	guint32 ent;
	guint32 index;
	const char* str;
	guint8 peek;
	guint32 tag_len; /* Length of the index (uintvar) from a LITERAL tag */
	guint8 tag_save_known = 0; /* Will contain peek & 0x3F (tag identity) */
	guint8 tag_new_known = 0; /* Will contain peek & 0x3F (tag identity) */
	const char *tag_save_literal; /* Will contain the LITERAL tag identity */
	const char *tag_new_literal; /* Will contain the LITERAL tag identity */
	guint8 parsing_tag_content = FALSE; /* Are we parsing content from a
										   tag with content: <x>Content</x>
										   
										   The initial state is FALSE.
										   This state will trigger recursion. */
	tag_save_literal = NULL; /* Prevents compiler warning */

#ifdef DEBUG
	printf ("WBXML - parse_wbxml_tag_defined (level = %d, offset = %d)\n",
			*level, offset);
#endif
	while (off < tvb_len) {
		peek = tvb_get_guint8 (tvb, off);
#ifdef DEBUG
		printf("WBXML - STAG: level = %3d, peek = 0x%02X, off = %d, "
				"tvb_len = %d\n",
				*level, peek, off, tvb_len);
#endif
		if ((peek & 0x3F) < 4) switch (peek) { /* Global tokens in state = STAG
												  but not the LITERAL tokens */
			case 0x00: /* SWITCH_PAGE */
				peek = tvb_get_guint8 (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 2,
						"        Tag   | SWITCH_PAGE (Tag code page)     "
						"| Code page switch (was: %d, is: %d)",
						*codepage_stag, peek);
				*codepage_stag = peek;
				off += 2;
				break;
			case 0x01: /* END: only possible for Tag with Content */
				if (tag_save_known) {
					proto_tree_add_text (tree, tvb, off, 1,
							"  %3d | Tag   | END (Known Tag 0x%02X)            "
							"| %s</%s>",
							*level, tag_save_known, Indent (*level),
							match_strval (tag_save_known, map->tags));
				} else { /* Literal TAG */
					proto_tree_add_text (tree, tvb, off, 1,
							"  %3d | Tag   | END (Literal Tag)               "
							"| %s</%s>",
							*level, Indent (*level), tag_save_literal);
				}
				(*level)--;
				off++;
				*parsed_length = off - offset;
				return;
				break;
			case 0x02: /* ENTITY */
				ent = tvb_get_guintvar (tvb, off+1, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | ENTITY                          "
						"| %s'&#%u;'",
						*level, Indent (*level), ent);
				off += 1+len;
				break;
			case 0x03: /* STR_I */
				/* Hack the string table lookup function */
				str = strtbl_lookup (tvb, off+1, 0, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | STR_I (Inline string)           "
						"| %s\'%s\'",
						*level, Indent(*level), str);
				off += 1+len;
				break;
			case 0x40: /* EXT_I_0 */
			case 0x41: /* EXT_I_1 */
			case 0x42: /* EXT_I_2 */
				/* Extension tokens */
				/* Hack the string table lookup function */
				str = strtbl_lookup (tvb, off+1, 0, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | EXT_I_%1x    (Extension Token)    "
						"| %s(%s: \'%s\')",
						*level, peek & 0x0f, Indent (*level),
						match_strval (peek, map->global), str);
				off += 1+len;
				break;
			case 0x43: /* PI */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d | Tag   | PI (XML Processing Instruction) "
						"| %s<?xml",
						*level, Indent (*level));
				parse_wbxml_attribute_list (tree, tvb, off, str_tbl,
						*level, codepage_attr, &len);
				off += len;
				proto_tree_add_text (tree, tvb, off-1, 1,
						"  %3d | Tag   | END (PI)                        "
						"| %s?>",
						*level, Indent (*level));
				break;
			case 0x80: /* EXT_T_0 */
			case 0x81: /* EXT_T_1 */
			case 0x82: /* EXT_T_2 */
				/* Extension tokens */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str = strtbl_lookup (tvb, str_tbl, index, NULL);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | EXT_T_%1x    (Extension Token)    "
						"| %s(%s: \'%s\')",
						*level, peek & 0x0f, Indent (*level),
						match_strval (peek, map->global), str);
				off += 1+len;
				break;
			case 0x83: /* STR_T */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str = strtbl_lookup (tvb, str_tbl, index, NULL);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | STR_T (Tableref string)         "
						"| %s\'%s\'",
						*level, Indent (*level), str);
				off += 1+len;
				break;
			case 0xC0: /* EXT_0 */
			case 0xC1: /* EXT_1 */
			case 0xC2: /* EXT_2 */
				/* Extension tokens */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d | Tag   | EXT_%1x      (Extension Token)    "
						"| %s(%s)",
						*level, peek & 0x0f, Indent (*level),
						match_strval (peek, map->global));
				off++;
				break;
			case 0xC3: /* OPAQUE - WBXML 1.1 and newer */
				if (tvb_get_guint8 (tvb, 0)) { /* WBXML 1.x (x > 0) */
					index = tvb_get_guintvar (tvb, off+1, &len);
					proto_tree_add_text (tree, tvb, off, 1 + len + index,
							"  %3d | Tag   | OPAQUE (Opaque data)            "
							"| %s(%d bytes of opaque data)",
							*level, Indent (*level), index);
					off += 1+len+index;
				} else { /* WBXML 1.0 - RESERVED_2 token (invalid) */
					proto_tree_add_text (tree, tvb, off, 1,
							"        Tag   | RESERVED_2     (Invalid Token!) "
							"| WBXML 1.0 parsing stops here.");
					/* Stop processing as it is impossible to parse now */
					off = tvb_len;
					*parsed_length = off - offset;
					return;
				}
				break;

				/* No default clause, as all cases have been treated */
		} else { /* LITERAL or Known TAG */
			/*
			 * We must store the initial tag, and also retrieve the new tag.
			 * 
			 * There are 4 possibilities:
			 *
			 *  1. Known tag followed by a known tag
			 *  2. Known tag followed by a LITERAL tag
			 *  3. LITERAL tag followed by Known tag
			 *  4. LITERAL tag followed by LITERAL tag
			 */

			/* Store the new tag */
			tag_len = 0;
			if ((peek & 0x3F) == 4) { /* LITERAL */
				index = tvb_get_guintvar (tvb, off+1, &tag_len);
				tag_new_literal = strtbl_lookup (tvb, str_tbl, index, NULL);
				tag_new_known = 0; /* invalidate known tag_new */
			} else {
				tag_new_known = peek & 0x3F;
				tag_new_literal = NULL; /* invalidate LITERAL tag_new */
			}

			/*
			 * Parsing of TAG starts HERE
			 */
			if (peek & 0x40) { /* Content present */
				/* Content follows
				 * [!] An explicit END token is expected in these cases!
				 * ==> Recursion possible if we encounter a tag with content;
				 *     recursion will return at the explicit END token.
				 */
				if (parsing_tag_content) { /* Recurse */
#ifdef DEBUG
					printf ("WBXML: Tag in Tag - RECURSE! (off = %d)\n",off);
#endif
					/* Do not process the attribute list:
					 * recursion will take care of it */
					(*level)++;
					parse_wbxml_tag_defined (tree, tvb, off, str_tbl, level,
							codepage_stag, codepage_attr, &len, map);
					off += len;
				} else { /* Now we will have content to parse */
					/* Save the start tag so we can properly close it later. */
					if ((peek & 0x3F) == 4) {
						tag_save_literal = tag_new_literal;
						tag_save_known = 0;
					} else {
						tag_save_known = tag_new_known;
						tag_save_literal = NULL;
					}
					/* Process the attribute list if present */
					if (peek & 0x80) { /* Content and Attribute list present */
						if (tag_new_known) { /* Known tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   "
									"|   Known Tag 0x%02X           (AC) "
									"| %s<%s",
									*level, tag_new_known, Indent (*level),
									match_strval (tag_new_known, map->tags));
							off++;
						} else { /* LITERAL tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   "
									"| LITERAL_AC (Literal tag)   (AC) "
									"| %s<%s",
									*level, Indent (*level), tag_new_literal);
							off += 1 + tag_len;
						}
						parse_wbxml_attribute_list_defined (tree, tvb,
								off, str_tbl,
								*level, codepage_attr, &len, map);
						off += len;
						proto_tree_add_text (tree, tvb, off-1, 1,
								"  %3d | Tag   "
								"| END (attribute list)            "
								"| %s>",
								*level, Indent (*level));
					} else { /* Content, no Attribute list */
						if (tag_new_known) { /* Known tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   "
									"|   Known Tag 0x%02X           (.C) "
									"| %s<%s>",
									*level, tag_new_known, Indent (*level),
									match_strval (tag_new_known, map->tags));
							off++;
						} else { /* LITERAL tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   "
									"| LITERAL_C  (Literal Tag)   (.C) "
									"| %s<%s>",
									*level, Indent (*level), tag_new_literal);
							off += 1 + tag_len;
						}
					}
					/* The data that follows in the parsing process
					 * represents content for the opening tag
					 * we've just processed in the lines above.
					 * Next time we encounter a tag with content: recurse
					 */
					parsing_tag_content = TRUE;
#ifdef DEBUG
					printf ("WBXML: Tag in Tag - No recursion this time! "
							"(off = %d)\n", off);
#endif
				}
			} else { /* No Content */
#ifdef DEBUG
				printf ("WBXML: <Tag/> in Tag - No recursion! "
						"(off = %d)\n", off);
#endif
				(*level)++;
				if (peek & 0x80) { /* No Content, Attribute list present */
					if (tag_new_known) { /* Known tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   "
								"|   Known Tag 0x%02X           (A.) "
								"| %s<%s",
								*level, tag_new_known, Indent (*level),
								match_strval (tag_new_known, map->tags));
						off++;
						parse_wbxml_attribute_list_defined (tree, tvb,
								off, str_tbl,
								*level, codepage_attr, &len, map);
						off += len;
						proto_tree_add_text (tree, tvb, off-1, 1,
								"  %3d | Tag   "
								"| END (Known Tag)                 "
								"| %s/>",
								*level, Indent (*level));
					} else { /* LITERAL tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   "
								"| LITERAL_A  (Literal Tag)   (A.) "
								"| %s<%s",
								*level, Indent (*level), tag_new_literal);
						off += 1 + tag_len;
						parse_wbxml_attribute_list_defined (tree, tvb,
								off, str_tbl,
								*level, codepage_attr, &len, map);
						off += len;
						proto_tree_add_text (tree, tvb, off-1, 1,
								"  %3d | Tag   "
								"| END (Literal Tag)               "
								"| %s/>",
								*level, Indent (*level));
					}
				} else { /* No Content, No Attribute list */
					if (tag_new_known) { /* Known tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   "
								"|   Known Tag 0x%02x           (..) "
								"| %s<%s />",
								*level, tag_new_known, Indent (*level),
								match_strval (tag_new_known, map->tags));
						off++;
					} else { /* LITERAL tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   "
								"| LITERAL    (Literal Tag)   (..) "
								"| %s<%s />",
								*level, Indent (*level), tag_new_literal);
						off += 1 + tag_len;
					}
				}
				(*level)--;
			}
		} /* if (tag & 0x3F) >= 5 */
	} /* while */
}




/* This function performs the WBXML decoding as in parse_wbxml_tag_defined()
 * but this time no WBXML mapping is performed.
 *
 * Attribute parsing is done in parse_wbxml_attribute_list().
 *
 * NOTE: Code page switches not yet processed in the code!
 */
static void
parse_wbxml_tag (proto_tree *tree, tvbuff_t *tvb, guint32 offset,
		guint32 str_tbl, guint8 *level,
		guint8 *codepage_stag, guint8 *codepage_attr, guint32 *parsed_length)
{
	guint32 tvb_len = tvb_reported_length (tvb);
	guint32 off = offset;
	guint32 len;
	guint32 ent;
	guint32 index;
	const char* str;
	guint8 peek;
	guint32 tag_len; /* Length of the index (uintvar) from a LITERAL tag */
	guint8 tag_save_known = 0; /* Will contain peek & 0x3F (tag identity) */
	guint8 tag_new_known = 0; /* Will contain peek & 0x3F (tag identity) */
	const char *tag_save_literal; /* Will contain the LITERAL tag identity */
	const char *tag_new_literal; /* Will contain the LITERAL tag identity */
	guint8 parsing_tag_content = FALSE; /* Are we parsing content from a
										   tag with content: <x>Content</x>
										   
										   The initial state is FALSE.
										   This state will trigger recursion. */
	tag_save_literal = NULL; /* Prevents compiler warning */

#ifdef DEBUG
	printf ("WBXML - parse_wbxml_tag (level = %d, offset = %d)\n",
			*level, offset);
#endif
	while (off < tvb_len) {
		peek = tvb_get_guint8 (tvb, off);
#ifdef DEBUG
		printf("WBXML - STAG: level = %3d, peek = 0x%02X, off = %d, "
				"tvb_len = %d\n",
				*level, peek, off, tvb_len);
#endif
		if ((peek & 0x3F) < 4) switch (peek) { /* Global tokens in state = STAG
												  but not the LITERAL tokens */
			case 0x00: /* SWITCH_PAGE */
				peek = tvb_get_guint8 (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 2,
						"        Tag   | SWITCH_PAGE (Tag code page)     "
						"| Code page switch (was: %d, is: %d)",
						*codepage_stag, peek);
				*codepage_stag = peek;
				off += 2;
				break;
			case 0x01: /* END: only possible for Tag with Content */
				if (tag_save_known) {
					proto_tree_add_text (tree, tvb, off, 1,
							"  %3d | Tag   | END (Known Tag 0x%02X)            "
							"| %s</Tag_0x%02X>",
							*level, tag_save_known, Indent (*level),
							tag_save_known);
				} else { /* Literal TAG */
					proto_tree_add_text (tree, tvb, off, 1,
							"  %3d | Tag   | END (Literal Tag)               "
							"| %s</%s>",
							*level, Indent (*level), tag_save_literal);
				}
				(*level)--;
				off++;
				*parsed_length = off - offset;
				return;
				break;
			case 0x02: /* ENTITY */
				ent = tvb_get_guintvar (tvb, off+1, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | ENTITY                          "
						"| %s'&#%u;'",
						*level, Indent (*level), ent);
				off += 1+len;
				break;
			case 0x03: /* STR_I */
				/* Hack the string table lookup function */
				str = strtbl_lookup (tvb, off+1, 0, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | STR_I (Inline string)           "
						"| %s\'%s\'",
						*level, Indent(*level), str);
				off += 1+len;
				break;
			case 0x40: /* EXT_I_0 */
			case 0x41: /* EXT_I_1 */
			case 0x42: /* EXT_I_2 */
				/* Extension tokens */
				/* Hack the string table lookup function */
				str = strtbl_lookup (tvb, off+1, 0, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | EXT_I_%1x    (Extension Token)    "
						"| %s(Inline string extension: \'%s\')",
						*level, peek & 0x0f, Indent (*level), str);
				off += 1+len;
				break;
			case 0x43: /* PI */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d | Tag   | PI (XML Processing Instruction) "
						"| %s<?xml",
						*level, Indent (*level));
				parse_wbxml_attribute_list (tree, tvb, off, str_tbl,
						*level, codepage_attr, &len);
				off += len;
				proto_tree_add_text (tree, tvb, off-1, 1,
						"  %3d | Tag   | END (PI)                        "
						"| %s?>",
						*level, Indent (*level));
				break;
			case 0x80: /* EXT_T_0 */
			case 0x81: /* EXT_T_1 */
			case 0x82: /* EXT_T_2 */
				/* Extension tokens */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str = strtbl_lookup (tvb, str_tbl, index, NULL);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | EXT_T_%1x    (Extension Token)    "
						"| %s(Tableref string extension: \'%s\')",
						*level, peek & 0x0f, Indent (*level), str);
				off += 1+len;
				break;
			case 0x83: /* STR_T */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str = strtbl_lookup (tvb, str_tbl, index, NULL);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | STR_T (Tableref string)         "
						"| %s\'%s\'",
						*level, Indent (*level), str);
				off += 1+len;
				break;
			case 0xC0: /* EXT_0 */
			case 0xC1: /* EXT_1 */
			case 0xC2: /* EXT_2 */
				/* Extension tokens */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d | Tag   | EXT_%1x      (Extension Token)    "
						"| %s(Single-byte extension)",
						*level, peek & 0x0f, Indent (*level));
				off++;
				break;
			case 0xC3: /* OPAQUE - WBXML 1.1 and newer */
				if (tvb_get_guint8 (tvb, 0)) { /* WBXML 1.x (x > 0) */
					index = tvb_get_guintvar (tvb, off+1, &len);
					proto_tree_add_text (tree, tvb, off, 1 + len + index,
							"  %3d | Tag   | OPAQUE (Opaque data)            "
							"| %s(%d bytes of opaque data)",
							*level, Indent (*level), index);
					off += 1+len+index;
				} else { /* WBXML 1.0 - RESERVED_2 token (invalid) */
					proto_tree_add_text (tree, tvb, off, 1,
							"        Tag   | RESERVED_2     (Invalid Token!) "
							"| WBXML 1.0 parsing stops here.");
					/* Stop processing as it is impossible to parse now */
					off = tvb_len;
					*parsed_length = off - offset;
					return;
				}
				break;

				/* No default clause, as all cases have been treated */
		} else { /* LITERAL or Known TAG */
			/*
			 * We must store the initial tag, and also retrieve the new tag.
			 * 
			 * There are 4 possibilities:
			 *
			 *  1. Known tag followed by a known tag
			 *  2. Known tag followed by a LITERAL tag
			 *  3. LITERAL tag followed by Known tag
			 *  4. LITERAL tag followed by LITERAL tag
			 */

			/* Store the new tag */
			tag_len = 0;
			if ((peek & 0x3F) == 4) { /* LITERAL */
				index = tvb_get_guintvar (tvb, off+1, &tag_len);
				tag_new_literal = strtbl_lookup (tvb, str_tbl, index, NULL);
				tag_new_known = 0; /* invalidate known tag_new */
			} else {
				tag_new_known = peek & 0x3F;
				tag_new_literal = NULL; /* invalidate LITERAL tag_new */
			}

			/*
			 * Parsing of TAG starts HERE
			 */
			if (peek & 0x40) { /* Content present */
				/* Content follows
				 * [!] An explicit END token is expected in these cases!
				 * ==> Recursion possible if we encounter a tag with content;
				 *     recursion will return at the explicit END token.
				 */
				if (parsing_tag_content) { /* Recurse */
#ifdef DEBUG
					printf ("WBXML: Tag in Tag - RECURSE! (off = %d)\n",off);
#endif
					/* Do not process the attribute list:
					 * recursion will take care of it */
					(*level)++;
					parse_wbxml_tag (tree, tvb, off, str_tbl, level,
							codepage_stag, codepage_attr, &len);
					off += len;
				} else { /* Now we will have content to parse */
					/* Save the start tag so we can properly close it later. */
					if ((peek & 0x3F) == 4) {
						tag_save_literal = tag_new_literal;
						tag_save_known = 0;
					} else {
						tag_save_known = tag_new_known;
						tag_save_literal = NULL;
					}
					/* Process the attribute list if present */
					if (peek & 0x80) { /* Content and Attribute list present */
						if (tag_new_known) { /* Known tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   "
									"|   Known Tag 0x%02X           (AC) "
									"| %s<Tag_0x%02X",
									*level, tag_new_known, Indent (*level),
									tag_new_known);
							off++;
						} else { /* LITERAL tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   "
									"| LITERAL_AC (Literal tag)   (AC) "
									"| %s<%s",
									*level, Indent (*level), tag_new_literal);
							off += 1 + tag_len;
						}
						parse_wbxml_attribute_list (tree, tvb, off, str_tbl,
								*level, codepage_attr, &len);
						off += len;
						proto_tree_add_text (tree, tvb, off-1, 1,
								"  %3d | Tag   "
								"| END (attribute list)            "
								"| %s>",
								*level, Indent (*level));
					} else { /* Content, no Attribute list */
						if (tag_new_known) { /* Known tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   "
									"|   Known Tag 0x%02X           (.C) "
									"| %s<Tag_0x%02X>",
									*level, tag_new_known, Indent (*level),
									tag_new_known);
							off++;
						} else { /* LITERAL tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   "
									"| LITERAL_C  (Literal Tag)   (.C) "
									"| %s<%s>",
									*level, Indent (*level), tag_new_literal);
							off += 1 + tag_len;
						}
					}
					/* The data that follows in the parsing process
					 * represents content for the opening tag
					 * we've just processed in the lines above.
					 * Next time we encounter a tag with content: recurse
					 */
					parsing_tag_content = TRUE;
#ifdef DEBUG
					printf ("WBXML: Tag in Tag - No recursion this time! "
							"(off = %d)\n", off);
#endif
				}
			} else { /* No Content */
#ifdef DEBUG
				printf ("WBXML: <Tag/> in Tag - No recursion! "
						"(off = %d)\n", off);
#endif
				(*level)++;
				if (peek & 0x80) { /* No Content, Attribute list present */
					if (tag_new_known) { /* Known tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   "
								"|   Known Tag 0x%02X           (A.) "
								"| %s<Tag 0x%02X",
								*level, tag_new_known, Indent (*level),
								tag_new_known);
						off++;
						parse_wbxml_attribute_list (tree, tvb, off, str_tbl,
								*level, codepage_attr, &len);
						off += len;
						proto_tree_add_text (tree, tvb, off-1, 1,
								"  %3d | Tag   "
								"| END (Known Tag)                 "
								"| %s/>",
								*level, Indent (*level));
					} else { /* LITERAL tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   "
								"| LITERAL_A  (Literal Tag)   (A.) "
								"| %s<%s",
								*level, Indent (*level), tag_new_literal);
						off += 1 + tag_len;
						parse_wbxml_attribute_list (tree, tvb, off, str_tbl,
								*level, codepage_attr, &len);
						off += len;
						proto_tree_add_text (tree, tvb, off-1, 1,
								"  %3d | Tag   "
								"| END (Literal Tag)               "
								"| %s/>",
								*level, Indent (*level));
					}
				} else { /* No Content, No Attribute list */
					if (tag_new_known) { /* Known tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   "
								"|   Known Tag 0x%02x           (..) "
								"| %s<Tag_0x%02X />",
								*level, tag_new_known, Indent (*level),
								tag_new_known);
						off++;
					} else { /* LITERAL tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   "
								"| LITERAL    (Literal Tag)   (..) "
								"| %s<%s />",
								*level, Indent (*level), tag_new_literal);
						off += 1 + tag_len;
					}
				}
				(*level)--;
			}
		} /* if (tag & 0x3F) >= 5 */
	} /* while */
}




/**************************
 * WBXML Attribute tokens *
 **************************
 * Bit Mask  : Example
 * -------------------
 * 0... .... : attr=             (attribute name)
 *             href="http://"    (attribute name with start of attribute value)
 * 1... .... : "www."            (attribute value, or part of it)
 * 
 */




/* This function parses the WBXML and maps known token interpretations
 * to the WBXML tokens. As a result, the original XML document can be
 * recreated. Indentation is generated in order to ease reading.
 *
 * This function performs attribute list parsing.
 * 
 * The wbxml_mapping_table entry *map contains the actual token mapping.
 *
 * NOTE: See packet-wbxml.h for known token mappings.
 *
 * NOTE: Code page switches not yet processed in the code!
 */
static void
parse_wbxml_attribute_list_defined (proto_tree *tree, tvbuff_t *tvb,
		guint32 offset, guint32 str_tbl, guint8 level,
		guint8 *codepage_attr, guint32 *parsed_length,
		const wbxml_mapping_table *map)
{
	guint32 tvb_len = tvb_reported_length (tvb);
	guint32 off = offset;
	guint32 len;
	guint32 ent;
	guint32 index;
	const char* str;
	guint8 peek;

#ifdef DEBUG
	printf ("WBXML - parse_wbxml_attr_defined (level = %d, offset = %d)\n",
			level, offset);
#endif
	/* Parse attributes */
	while (off < tvb_len) {
		peek = tvb_get_guint8 (tvb, off);
#ifdef DEBUG
		printf("WBXML - ATTR: level = %3d, peek = 0x%02X, off = %d, "
				"tvb_len = %d\n",
				level, peek, off, tvb_len);
#endif
		if ((peek & 0x3F) < 5) switch (peek) { /* Global tokens
												  in state = ATTR */
			case 0x00: /* SWITCH_PAGE */
				peek = tvb_get_guint8 (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 2,
						"         Attr | SWITCH_PAGE (Attr code page)    "
						"| Code page switch (was: %d, is: %d)",
						*codepage_attr, peek);
				*codepage_attr = peek;
				off += 2;
				break;
			case 0x01: /* END */
				/* BEWARE
				 *   The Attribute END token means either ">" or "/>"
				 *   and as a consequence both must be trated separately.
				 *   This is done in the TAG state parser.
				 */
				off++;
				*parsed_length = off - offset;
				return;
			case 0x02: /* ENTITY */
				ent = tvb_get_guintvar (tvb, off+1, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | ENTITY                          "
						"|     %s'&#%u;'",
						level, Indent (level), ent);
				off += 1+len;
				break;
			case 0x03: /* STR_I */
				/* Hack the string table lookup function */
				str = strtbl_lookup (tvb, off+1, 0, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | STR_I (Inline string)           "
						"|     %s\'%s\'",
						level, Indent (level), str);
				off += 1+len;
				break;
			case 0x04: /* LITERAL */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str = strtbl_lookup (tvb, str_tbl, index, NULL);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | LITERAL (Literal Attribute)     "
						"|   %s<%s />",
						level, Indent (level), str);
				off += 1+len;
				break;
			case 0x40: /* EXT_I_0 */
			case 0x41: /* EXT_I_1 */
			case 0x42: /* EXT_I_2 */
				/* Extension tokens */
				/* Hack the string table lookup function */
				str = strtbl_lookup (tvb, off+1, 0, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | EXT_I_%1x    (Extension Token)    "
						"|     %s(%s: \'%s\')",
						level, peek & 0x0f, Indent (level),
						match_strval (peek, map->global), str);
				off += 1+len;
				break;
			/* 0x43 impossible in ATTR state */
			/* 0x44 impossible in ATTR state */
			case 0x80: /* EXT_T_0 */
			case 0x81: /* EXT_T_1 */
			case 0x82: /* EXT_T_2 */
				/* Extension tokens */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str = strtbl_lookup (tvb, str_tbl, index, NULL);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | EXT_T_%1x    (Extension Token)    "
						"|     %s(%s: \'%s\')",
						level, peek & 0x0f, Indent (level),
						match_strval (peek, map->global), str);
				off += 1+len;
				break;
			case 0x83: /* EXT_T */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str = strtbl_lookup (tvb, str_tbl, index, NULL);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | STR_T (Tableref string)         "
						"|     %s\'%s\'",
						level, Indent (level), str);
				off += 1+len;
				break;
			/* 0x84 impossible in ATTR state */
			case 0xC0: /* EXT_0 */
			case 0xC1: /* EXT_1 */
			case 0xC2: /* EXT_2 */
				/* Extension tokens */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr | EXT_%1x      (Extension Token)    "
						"|     %s(%s)",
						level, peek & 0x0f, Indent (level),
						match_strval (peek, map->global));
				off++;
				break;
			case 0xC3: /* OPAQUE - WBXML 1.1 and newer */
				if (tvb_get_guint8 (tvb, 0)) { /* WBXML 1.x (x > 0) */
					index = tvb_get_guintvar (tvb, off+1, &len);
					proto_tree_add_text (tree, tvb, off, 1 + len + index,
							"  %3d |  Attr | OPAQUE (Opaque data)            "
							"|       %s(%d bytes of opaque data)",
							level, Indent (level), index);
					off += 1+len+index;
				} else { /* WBXML 1.0 - RESERVED_2 token (invalid) */
					proto_tree_add_text (tree, tvb, off, 1,
							"         Attr | RESERVED_2     (Invalid Token!) "
							"| WBXML 1.0 parsing stops here.");
					/* Stop processing as it is impossible to parse now */
					off = tvb_len;
					*parsed_length = off - offset;
					return;
				}
				break;
			/* 0xC4 impossible in ATTR state */
			default:
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr | %-10s     (Invalid Token!) "
						"| WBXML parsing stops here.",
						level, match_strval (peek, vals_wbxml1x_global_tokens));
				/* Move to end of buffer */
				off = tvb_len;
				break;
		} else { /* Known atribute token */
			if (peek & 0x80) { /* attrValue */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr |   Known attrValue 0x%02X          "
						"|       %s%s",
						level, peek & 0x7f, Indent (level),
						match_strval (peek, map->attrValue));
				off++;
			} else { /* attrStart */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr |   Known attrStart 0x%02X          "
						"|   %s%s",
						level, peek & 0x7f, Indent (level),
						match_strval (peek, map->attrStart));
				off++;
			}
		}
	} /* End WHILE */
}




/* This function performs the WBXML attribute decoding as in
 * parse_wbxml_attribute_list_defined() but this time no WBXML mapping
 * is performed.
 *
 * This function performs attribute list parsing.
 * 
 * NOTE: Code page switches not yet processed in the code!
 */
static void
parse_wbxml_attribute_list (proto_tree *tree, tvbuff_t *tvb,
		guint32 offset, guint32 str_tbl, guint8 level,
		guint8 *codepage_attr, guint32 *parsed_length)
{
	guint32 tvb_len = tvb_reported_length (tvb);
	guint32 off = offset;
	guint32 len;
	guint32 ent;
	guint32 index;
	const char* str;
	guint8 peek;

#ifdef DEBUG
	printf ("WBXML - parse_wbxml_attr_defined (level = %d, offset = %d)\n",
			level, offset);
#endif
	/* Parse attributes */
	while (off < tvb_len) {
		peek = tvb_get_guint8 (tvb, off);
#ifdef DEBUG
		printf("WBXML - ATTR: level = %3d, peek = 0x%02X, off = %d, "
				"tvb_len = %d\n",
				level, peek, off, tvb_len);
#endif
		if ((peek & 0x3F) < 5) switch (peek) { /* Global tokens
												  in state = ATTR */
			case 0x00: /* SWITCH_PAGE */
				peek = tvb_get_guint8 (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 2,
						"         Attr | SWITCH_PAGE (Attr code page)    "
						"| Code page switch (was: %d, is: %d)",
						*codepage_attr, peek);
				*codepage_attr = peek;
				off += 2;
				break;
			case 0x01: /* END */
				/* BEWARE
				 *   The Attribute END token means either ">" or "/>"
				 *   and as a consequence both must be trated separately.
				 *   This is done in the TAG state parser.
				 */
				off++;
				*parsed_length = off - offset;
				return;
			case 0x02: /* ENTITY */
				ent = tvb_get_guintvar (tvb, off+1, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | ENTITY                          "
						"|     %s'&#%u;'",
						level, Indent (level), ent);
				off += 1+len;
				break;
			case 0x03: /* STR_I */
				/* Hack the string table lookup function */
				str = strtbl_lookup (tvb, off+1, 0, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | STR_I (Inline string)           "
						"|     %s\'%s\'",
						level, Indent (level), str);
				off += 1+len;
				break;
			case 0x04: /* LITERAL */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str = strtbl_lookup (tvb, str_tbl, index, NULL);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | LITERAL (Literal Attribute)     "
						"|   %s<%s />",
						level, Indent (level), str);
				off += 1+len;
				break;
			case 0x40: /* EXT_I_0 */
			case 0x41: /* EXT_I_1 */
			case 0x42: /* EXT_I_2 */
				/* Extension tokens */
				/* Hack the string table lookup function */
				str = strtbl_lookup (tvb, off+1, 0, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | EXT_I_%1x    (Extension Token)    "
						"|     %s(Inline string extension: \'%s\')",
						level, peek & 0x0f, Indent (level), str);
				off += 1+len;
				break;
			/* 0x43 impossible in ATTR state */
			/* 0x44 impossible in ATTR state */
			case 0x80: /* EXT_T_0 */
			case 0x81: /* EXT_T_1 */
			case 0x82: /* EXT_T_2 */
				/* Extension tokens */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str = strtbl_lookup (tvb, str_tbl, index, NULL);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | EXT_T_%1x    (Extension Token)    "
						"|     %s(Tableref string extension: \'%s\')",
						level, peek & 0x0f, Indent (level), str);
				off += 1+len;
				break;
			case 0x83: /* EXT_T */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str = strtbl_lookup (tvb, str_tbl, index, NULL);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | STR_T (Tableref string)         "
						"|     %s\'%s\'",
						level, Indent (level), str);
				off += 1+len;
				break;
			/* 0x84 impossible in ATTR state */
			case 0xC0: /* EXT_0 */
			case 0xC1: /* EXT_1 */
			case 0xC2: /* EXT_2 */
				/* Extension tokens */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr | EXT_%1x      (Extension Token)    "
						"|     %s(Single-byte extension)",
						level, peek & 0x0f, Indent (level));
				off++;
				break;
			case 0xC3: /* OPAQUE - WBXML 1.1 and newer */
				if (tvb_get_guint8 (tvb, 0)) { /* WBXML 1.x (x > 0) */
					index = tvb_get_guintvar (tvb, off+1, &len);
					proto_tree_add_text (tree, tvb, off, 1 + len + index,
							"  %3d |  Attr | OPAQUE (Opaque data)            "
							"|       %s(%d bytes of opaque data)",
							level, Indent (level), index);
					off += 1+len+index;
				} else { /* WBXML 1.0 - RESERVED_2 token (invalid) */
					proto_tree_add_text (tree, tvb, off, 1,
							"         Attr | RESERVED_2     (Invalid Token!) "
							"| WBXML 1.0 parsing stops here.");
					/* Stop processing as it is impossible to parse now */
					off = tvb_len;
					*parsed_length = off - offset;
					return;
				}
				break;
			/* 0xC4 impossible in ATTR state */
			default:
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr | %-10s     (Invalid Token!) "
						"| WBXML parsing stops here.",
						level, match_strval (peek, vals_wbxml1x_global_tokens));
				/* Move to end of buffer */
				off = tvb_len;
				break;
		} else { /* Known atribute token */
			if (peek & 0x80) { /* attrValue */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr |   Known attrValue 0x%02X          "
						"|       %sattrValue_0x%02X",
						level, peek & 0x7f, Indent (level), peek);
				off++;
			} else { /* attrStart */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr |   Known attrStart 0x%02X          "
						"|   %sattrStart_0x%02X",
						level, peek & 0x7f, Indent (level), peek);
				off++;
			}
		}
	} /* End WHILE */
}




/****************** Register the protocol with Ethereal ******************/

/* This format is required because a script is used to build the C function
 * that calls the protocol registration.
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
		&ett_wbxml_str_tbl,
		&ett_wbxml_content,
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

	/* Heuristic dissectors would be declared by means of:
	 * heur_dissector_add("wsp", dissect_wbxml_heur, proto_wbxml);
	 */

	wbxml_handle = create_dissector_handle(dissect_wbxml, proto_wbxml);

	/* Register the WSP content types (defined as protocol port)
	 * for WBXML dissection.
	 * 
	 * See http://www.wapforum.org/wina/wsp-content-type.htm
	 */

	/**** Well-known WBXML WSP Content-Type values ****/
	
	/* application/vnd.wap.wmlc */
	dissector_add("wsp.content_type.type", 0x14, wbxml_handle);
	
	/* application/vnd.wap.wta-eventc */
	dissector_add("wsp.content_type.type", 0x16, wbxml_handle);
	
	/* application/vnd.wap.wbxml */
	dissector_add("wsp.content_type.type", 0x29, wbxml_handle);
	
	/* application/vnd.wap.sic */
	dissector_add("wsp.content_type.type", 0x2E, wbxml_handle);
	
	/* application/vnd.wap.slc */
	dissector_add("wsp.content_type.type", 0x30, wbxml_handle);
	
	/* application/vnd.wap.coc */
	dissector_add("wsp.content_type.type", 0x32, wbxml_handle);
	
	/* application/vnd.wap.connectivity-wbxml */
	dissector_add("wsp.content_type.type", 0x36, wbxml_handle);
	
	/* application/vnd.wap.locc+wbxml */
	dissector_add("wsp.content_type.type", 0x40, wbxml_handle);
	
	/* application/vnd.syncml.dm+wbxml */
	dissector_add("wsp.content_type.type", 0x42, wbxml_handle);
	
	/* application/vnd.oma.drm.rights+wbxml */
	dissector_add("wsp.content_type.type", 0x4B, wbxml_handle);

#ifdef WSP_DISSECTOR_REGISTERS_ContentType_AS_FourByteGuint	
	
	/**** Registered WBXML WSP Content-Type values ****/

	/* application/vnd.uplanet.cacheop-wbxml */
	dissector_add("wsp.content_type.type", 0x0201, wbxml_handle);
	
	/* application/vnd.uplanet.alert-wbxml */
	dissector_add("wsp.content_type.type", 0x0203, wbxml_handle);
	
	/* application/vnd.uplanet.list-wbxml */
	dissector_add("wsp.content_type.type", 0x0204, wbxml_handle);
	
	/* application/vnd.uplanet.listcmd-wbxml */
	dissector_add("wsp.content_type.type", 0x0205, wbxml_handle);
	
	/* application/vnd.uplanet.channel-wbxml */
	dissector_add("wsp.content_type.type", 0x0206, wbxml_handle);
	
	/* application/vnd.uplanet.bearer-choice-wbxml */
	dissector_add("wsp.content_type.type", 0x0209, wbxml_handle);
	
	/* application/vnd.phonecom.mmc-wbxml */
	dissector_add("wsp.content_type.type", 0x020A, wbxml_handle);
	
	/* application/vnd.nokia.syncset+wbxml */
	dissector_add("wsp.content_type.type", 0x020B, wbxml_handle);
#endif
}
