/*
 * packet-radius.h
 *
 * Definitions for RADIUS packet disassembly
 * $Id$
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

typedef struct _radius_vendor_info_t {
	gchar *name;
	guint code;
	GHashTable* attrs_by_id;
    gint ett;
} radius_vendor_info_t;

typedef struct _radius_attr_info_t radius_attr_info_t;
typedef void (radius_attr_dissector_t)(radius_attr_info_t*, proto_tree*, packet_info*, tvbuff_t*, int, int, proto_item* );

typedef const gchar* (radius_avp_dissector_t)(proto_tree*,tvbuff_t*);

struct _radius_attr_info_t {
	const gchar *name;
	guint code;
	gboolean encrypt;
	gboolean tagged;
	radius_attr_dissector_t* type;
	radius_avp_dissector_t* dissector;
	const value_string *vs;
	gint ett;
	int hf;
	int hf64;
	int hf_tag;
	int hf_len;
};

typedef struct _radius_dictionary_t {
	GHashTable* attrs_by_id;
	GHashTable* attrs_by_name;
	GHashTable* vendors_by_id;
	GHashTable* vendors_by_name;
} radius_dictionary_t;

radius_attr_dissector_t radius_integer;
radius_attr_dissector_t radius_string;
radius_attr_dissector_t radius_octets;
radius_attr_dissector_t radius_ipaddr;
radius_attr_dissector_t radius_ipv6addr;
radius_attr_dissector_t radius_date;
radius_attr_dissector_t radius_abinary;
radius_attr_dissector_t radius_ifid;

extern void radius_register_avp_dissector(guint32 vendor_id, guint32 attribute_id, radius_avp_dissector_t dissector);

/* from radius_dict.l */
radius_dictionary_t* radius_load_dictionary (gchar* directory, const gchar* filename, gchar** err_str);
