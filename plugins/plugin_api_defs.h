/* plugin_api_defs.h
 * Define the variables that hold pointers to plugin API functions
 *
 * $Id: plugin_api_defs.h,v 1.2 2001/11/01 09:53:13 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * Copyright 2000 by Gilbert Ramirez <gram@xiexie.org>
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

#ifdef PLUGINS_NEED_ADDRESS_TABLE

gint (*p_check_col)(frame_data*, gint);
void (*p_col_clear)(frame_data*, gint);
void (*p_col_add_fstr)(frame_data*, gint, gchar*, ...);
void (*p_col_append_fstr)(frame_data*, gint, gchar*, ...);
void (*p_col_add_str)(frame_data*, gint, const gchar*);
void (*p_col_append_str)(frame_data*, gint, gchar*);
void (*p_col_set_str)(frame_data*, gint, gchar*);

int (*p_proto_register_protocol)(char*, char*, char*);
void (*p_proto_register_field_array)(int, hf_register_info*, int);
void (*p_proto_register_subtree_array)(int**, int);

void (*p_dissector_add)(const char *, guint32, dissector_t, int);
void (*p_dissector_delete)(const char *, guint32, dissector_t);

void (*p_heur_dissector_add)(const char *, heur_dissector_t, int);

void (*p_register_dissector)(const char *, dissector_t, int);
dissector_handle_t (*p_find_dissector)(const char *);
void (*p_call_dissector)(dissector_handle_t, tvbuff_t *,
    packet_info *, proto_tree *);

void (*p_dissect_data)(tvbuff_t *, int, packet_info *, proto_tree *);

gboolean (*p_proto_is_protocol_enabled)(int);

int (*p_proto_item_get_len)(proto_item*);
void (*p_proto_item_set_len)(proto_item*, gint);
void (*p_proto_item_set_text)(proto_item*, const char*, ...);
void (*p_proto_item_append_text)(proto_item*, const char*, ...);
proto_tree* (*p_proto_item_add_subtree)(proto_item*, gint);
proto_item* (*p_proto_tree_add_item)(proto_tree*, int, tvbuff_t*, gint, gint, gboolean);
proto_item* (*p_proto_tree_add_item_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, gboolean);
proto_item* (*p_proto_tree_add_protocol_format)(proto_tree*, int, tvbuff_t*, gint, gint, const char*, ...);

proto_item* (*p_proto_tree_add_bytes)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
proto_item* (*p_proto_tree_add_bytes_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
proto_item* (*p_proto_tree_add_bytes_format)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*, const char*, ...);

proto_item* (*p_proto_tree_add_time)(proto_tree*, int, tvbuff_t*, gint, gint, nstime_t*);
proto_item* (*p_proto_tree_add_time_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, nstime_t*);
proto_item* (*p_proto_tree_add_time_format)(proto_tree*, int, tvbuff_t*, gint, gint, nstime_t*, const char*, ...);

proto_item* (*p_proto_tree_add_ipxnet)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
proto_item* (*p_proto_tree_add_ipxnet_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
proto_item* (*p_proto_tree_add_ipxnet_format)(proto_tree*, int, tvbuff_t*, gint, gint, guint32, const char*, ...);

proto_item* (*p_proto_tree_add_ipv4)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
proto_item* (*p_proto_tree_add_ipv4_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
proto_item* (*p_proto_tree_add_ipv4_format)(proto_tree*, int, tvbuff_t*, gint, gint, guint32, const char*, ...);

proto_item* (*p_proto_tree_add_ipv6)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
proto_item* (*p_proto_tree_add_ipv6_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
proto_item* (*p_proto_tree_add_ipv6_format)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*, const char*, ...);

proto_item* (*p_proto_tree_add_ether)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
proto_item* (*p_proto_tree_add_ether_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
proto_item* (*p_proto_tree_add_ether_format)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*, const char*, ...);

proto_item* (*p_proto_tree_add_string)(proto_tree*, int, tvbuff_t*, gint, gint, const char*);
proto_item* (*p_proto_tree_add_string_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, const char*);
proto_item* (*p_proto_tree_add_string_format)(proto_tree*, int, tvbuff_t*, gint, gint, const char*, const char*, ...);

proto_item* (*p_proto_tree_add_boolean)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
proto_item* (*p_proto_tree_add_boolean_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
proto_item* (*p_proto_tree_add_boolean_format)(proto_tree*, int, tvbuff_t*, gint, gint, guint32, const char*, ...);

proto_item* (*p_proto_tree_add_double)(proto_tree*, int, tvbuff_t*, gint, gint, double);
proto_item* (*p_proto_tree_add_double_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, double);
proto_item* (*p_proto_tree_add_double_format)(proto_tree*, int, tvbuff_t*, gint, gint, double, const char*, ...);

proto_item* (*p_proto_tree_add_uint)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
proto_item* (*p_proto_tree_add_uint_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
proto_item* (*p_proto_tree_add_uint_format)(proto_tree*, int, tvbuff_t*, gint, gint, guint32, const char*, ...);

proto_item* (*p_proto_tree_add_int)(proto_tree*, int, tvbuff_t*, gint, gint, gint32);
proto_item* (*p_proto_tree_add_int_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, gint32);
proto_item* (*p_proto_tree_add_int_format)(proto_tree*, int, tvbuff_t*, gint, gint, gint32, const char*, ...);

proto_item* (*p_proto_tree_add_text)(proto_tree*, tvbuff_t*, gint, gint, const char*, ...);

tvbuff_t* (*p_tvb_new_subset)(tvbuff_t*, gint, gint, gint);

guint (*p_tvb_length)(tvbuff_t*);
gint (*p_tvb_length_remaining)(tvbuff_t*, gint);
gboolean (*p_tvb_bytes_exist)(tvbuff_t*, gint, gint);
gboolean (*p_tvb_offset_exists)(tvbuff_t*, gint);
guint (*p_tvb_reported_length)(tvbuff_t*);
gint (*p_tvb_reported_length_remaining)(tvbuff_t*, gint);

guint8 (*p_tvb_get_guint8)(tvbuff_t*, gint);

guint16 (*p_tvb_get_ntohs)(tvbuff_t*, gint);
guint32 (*p_tvb_get_ntoh24)(tvbuff_t*, gint);
guint32 (*p_tvb_get_ntohl)(tvbuff_t*, gint);

guint16 (*p_tvb_get_letohs)(tvbuff_t*, gint);
guint32 (*p_tvb_get_letoh24)(tvbuff_t*, gint);
guint32 (*p_tvb_get_letohl)(tvbuff_t*, gint);

guint8* (*p_tvb_memcpy)(tvbuff_t*, guint8* target, gint, gint);
guint8* (*p_tvb_memdup)(tvbuff_t*, gint, gint);

const guint8* (*p_tvb_get_ptr)(tvbuff_t*, gint, gint);

gint (*p_tvb_find_guint8)(tvbuff_t*, gint, gint, guint8);
gint (*p_tvb_pbrk_guint8)(tvbuff_t *, gint, gint, guint8 *);

gint (*p_tvb_strnlen)(tvbuff_t*, gint, guint);

guint8 * (*p_tvb_format_text)(tvbuff_t*, gint, gint);

gint (*p_tvb_get_nstringz)(tvbuff_t*, gint, guint, guint8*);
gint (*p_tvb_get_nstringz0)(tvbuff_t*, gint, guint, guint8*);

gint (*p_tvb_find_line_end)(tvbuff_t*, gint, int, gint *);
gint (*p_tvb_find_line_end_unquoted)(tvbuff_t*, gint, int, gint *);

gint (*p_tvb_strneql)(tvbuff_t*, gint, const guint8 *, gint);
gint (*p_tvb_strncaseeql)(tvbuff_t*, gint, const guint8 *, gint);

gchar *(*p_tvb_bytes_to_str)(tvbuff_t*, gint, gint len);

struct pref_module *(*p_prefs_register_protocol)(int,
    void (*)(void));
void (*p_prefs_register_uint_preference)(struct pref_module *,
    const char *, const char *, const char *, guint, guint *);
void (*p_prefs_register_bool_preference)(struct pref_module *,
    const char *, const char *, const char *, gboolean *);
void (*p_prefs_register_enum_preference)(struct pref_module *,
    const char *, const char *, const char *, gint *, const enum_val_t *,
    gboolean);
void (*p_prefs_register_string_preference)(struct pref_module *,
    const char *, const char *, const char *, char**);

void (*p_register_giop_user)(giop_sub_dissector_t *, gchar *, int);
gboolean (*p_is_big_endian)(MessageHeader *);
guint32 (*p_get_CDR_encap_info)(tvbuff_t *, proto_tree *, gint *,
		gboolean, guint32, gboolean *, guint32 *);
void (*p_get_CDR_any)(tvbuff_t *, proto_tree *, gint *,
		gboolean, int, MessageHeader *);
gboolean (*p_get_CDR_boolean)(tvbuff_t *, int *);
guint8 (*p_get_CDR_char)(tvbuff_t *, int *);
gdouble (*p_get_CDR_double)(tvbuff_t *, int *, gboolean, int);
guint32 (*p_get_CDR_enum)(tvbuff_t *, int *, gboolean, int);
void (*p_get_CDR_fixed)(tvbuff_t *, gchar **, gint *, guint32,
		gint32);
gfloat (*p_get_CDR_float)(tvbuff_t *, int *, gboolean, int);
void (*p_get_CDR_interface)(tvbuff_t *, packet_info *, proto_tree *,
		int *, gboolean, int);
gint32 (*p_get_CDR_long)(tvbuff_t *, int *, gboolean, int);
void (*p_get_CDR_object)(tvbuff_t *, packet_info *, proto_tree *,
		int *, gboolean, int);
guint8 (*p_get_CDR_octet)(tvbuff_t *, int *);
void (*p_get_CDR_octet_seq)(tvbuff_t *, gchar **, int *, int);
gint16 (*p_get_CDR_short)(tvbuff_t *, int *, gboolean, int);
guint32 (*p_get_CDR_string)(tvbuff_t *, gchar **, int *, gboolean,
		int);
guint32 (*p_get_CDR_typeCode)(tvbuff_t *, proto_tree *, gint *,
	gboolean, int, MessageHeader *);
guint32 (*p_get_CDR_ulong)(tvbuff_t *, int *, gboolean, int);
guint16 (*p_get_CDR_ushort)(tvbuff_t *, int *, gboolean, int);
gint8 (*p_get_CDR_wchar)(tvbuff_t *, gchar **, int *,
		MessageHeader *);
guint32 (*p_get_CDR_wstring)(tvbuff_t *, gchar **, int *, gboolean,
		int, MessageHeader *);

#endif /* PLUGINS_NEED_ACCESS_TABLE */
