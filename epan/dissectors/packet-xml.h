/* packet-xml.h
 * wireshark's xml dissector .
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#ifndef __PACKET_XML_H__
#define __PACKET_XML_H__

#include "ws_symbol_export.h"

typedef struct _xml_ns_t {
    /* the name of this namespace */
	gchar* name;

    /* its fully qualified name */
	const gchar* fqn;

	/* the contents of the whole element from <> to </> */
	int hf_tag;

	/* chunks of cdata from <> to </> excluding sub tags */
	int hf_cdata;

    /* the subtree for its sub items  */
	gint ett;

	GHashTable* attributes;
    /*  key:   the attribute name
        value: hf_id of what's between quotes */

    /* the namespace's namespaces */
    GHashTable* elements;
    /*  key:   the element name
        value: the child namespace */

	GPtrArray* element_names;
    /* imported directly from the parser and used while building the namespace */

} xml_ns_t;

#define XML_FRAME_ROOT  0
#define XML_FRAME_TAG   1
#define XML_FRAME_XMPLI 2
#define XML_FRAME_DTD_DOCTYPE 3
#define XML_FRAME_ATTRIB 4
#define XML_FRAME_CDATA 5

typedef struct _xml_frame_t {
	int type;
	struct _xml_frame_t* parent;
	struct _xml_frame_t* first_child;
	struct _xml_frame_t* last_child;
	struct _xml_frame_t* prev_sibling;
	struct _xml_frame_t* next_sibling;
	const gchar *name;
	const gchar *name_orig_case;
	tvbuff_t *value;
	proto_tree* tree;
	proto_item* item;
	proto_item* last_item;
	xml_ns_t* ns;
	int start_offset;
} xml_frame_t;

WS_DLL_PUBLIC
xml_frame_t *xml_get_tag(xml_frame_t *frame, const gchar *name);
WS_DLL_PUBLIC
xml_frame_t *xml_get_attrib(xml_frame_t *frame, const gchar *name);
WS_DLL_PUBLIC
xml_frame_t *xml_get_cdata(xml_frame_t *frame);

#endif /* __PACKET_XML_H__ */
