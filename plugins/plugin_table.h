/* plugin_table.h
 * Table of exported addresses for Ethereal plugins.
 *
 * $Id: plugin_table.h,v 1.7 2000/11/13 10:13:26 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * Copyright 2000 by Gilbert Ramirez <gram@xiexie.org>
 *
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
 *
 */

#ifdef PLUGINS_NEED_ADDRESS_TABLE

/* Some OSes (Win32) have DLLs that cannot reference symbols in the parent
   executable, so the executable needs to provide a collection of pointers
   to those functions for the DLL plugin to use. */

/* Typedefs to make our plugin_address_table_t struct look prettier */
typedef gint (*addr_check_col)(frame_data*, gint);
typedef void (*addr_col_add_fstr)(frame_data*, gint, gchar*, ...);
typedef void (*addr_col_append_fstr)(frame_data*, gint, gchar*, ...);
typedef void (*addr_col_add_str)(frame_data*, gint, const gchar*);
typedef void (*addr_col_append_str)(frame_data*, gint, gchar*);

typedef void (*addr_dfilter_init)(void);
typedef void (*addr_dfilter_cleanup)(void);

typedef int (*addr_proto_register_protocol)(char*, char*);
typedef void (*addr_proto_register_field_array)(int, hf_register_info*, int);
typedef void (*addr_proto_register_subtree_array)(int**, int);

typedef void (*addr_dissector_add)(const char *, guint32, dissector_t);
typedef void (*addr_old_dissector_add)(const char *, guint32, old_dissector_t);
typedef void (*addr_dissector_delete)(const char *, guint32, dissector_t);

typedef void (*addr_heur_dissector_add)(const char *, heur_dissector_t);

typedef void (*addr_dissect_data)(tvbuff_t *, packet_info *, proto_tree *);
typedef void (*addr_old_dissect_data)(const u_char *, int, frame_data *, proto_tree *);

typedef gboolean (*addr_proto_is_protocol_enabled)(int);

typedef int (*addr_proto_item_get_len)(proto_item*);
typedef void (*addr_proto_item_set_len)(proto_item*, gint);
typedef void (*addr_proto_item_set_text)(proto_item*, const char*, ...);
typedef proto_tree* (*addr_proto_item_add_subtree)(proto_item*, gint);
typedef proto_item* (*addr_proto_tree_add_item)(proto_tree*, int, tvbuff_t*, gint, gint, gboolean);
typedef proto_item* (*addr_proto_tree_add_item_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, gboolean);
typedef proto_item* (*addr_proto_tree_add_protocol_format)(proto_tree*, int, tvbuff_t*, gint, gint, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_bytes)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_bytes_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_bytes_format)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_time)(proto_tree*, int, tvbuff_t*, gint, gint, struct timeval*);
typedef proto_item* (*addr_proto_tree_add_time_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, struct timeval*);
typedef proto_item* (*addr_proto_tree_add_time_format)(proto_tree*, int, tvbuff_t*, gint, gint, struct timeval*, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_ipxnet)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_ipxnet_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_ipxnet_format)(proto_tree*, int, tvbuff_t*, gint, gint, guint32, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_ipv4)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_ipv4_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_ipv4_format)(proto_tree*, int, tvbuff_t*, gint, gint, guint32, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_ipv6)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_ipv6_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_ipv6_format)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_ether)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_ether_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_ether_format)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_string)(proto_tree*, int, tvbuff_t*, gint, gint, const char*);
typedef proto_item* (*addr_proto_tree_add_string_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, const char*);
typedef proto_item* (*addr_proto_tree_add_string_format)(proto_tree*, int, tvbuff_t*, gint, gint, const char*, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_boolean)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_boolean_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_boolean_format)(proto_tree*, int, tvbuff_t*, gint, gint, guint32, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_double)(proto_tree*, int, tvbuff_t*, gint, gint, double);
typedef proto_item* (*addr_proto_tree_add_double_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, double);
typedef proto_item* (*addr_proto_tree_add_double_format)(proto_tree*, int, tvbuff_t*, gint, gint, double, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_uint)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_uint_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_uint_format)(proto_tree*, int, tvbuff_t*, gint, gint, guint32, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_int)(proto_tree*, int, tvbuff_t*, gint, gint, gint32);
typedef proto_item* (*addr_proto_tree_add_int_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, gint32);
typedef proto_item* (*addr_proto_tree_add_int_format)(proto_tree*, int, tvbuff_t*, gint, gint, gint32, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_text)(proto_tree*, tvbuff_t*, gint, gint, const char*, ...);
typedef proto_item* (*addr_proto_tree_add_notext)(proto_tree*, tvbuff_t*, gint, gint);

typedef tvbuff_t* (*addr_tvb_new_subset)(tvbuff_t*, gint, gint, gint);

typedef guint (*addr_tvb_length)(tvbuff_t*);
typedef guint (*addr_tvb_length_remaining)(tvbuff_t*, gint);
typedef gboolean (*addr_tvb_bytes_exist)(tvbuff_t*, gint, gint);
typedef gboolean (*addr_tvb_offset_exists)(tvbuff_t*, gint);
typedef guint (*addr_tvb_reported_length)(tvbuff_t*);

typedef guint8 (*addr_tvb_get_guint8)(tvbuff_t*, gint);

typedef guint16 (*addr_tvb_get_ntohs)(tvbuff_t*, gint);
typedef guint32 (*addr_tvb_get_ntoh24)(tvbuff_t*, gint);
typedef guint32 (*addr_tvb_get_ntohl)(tvbuff_t*, gint);
#ifdef G_HAVE_GINT64
typedef guint64 (*addr_tvb_get_ntohll)(tvbuff_t*, gint);
#endif

typedef guint16 (*addr_tvb_get_letohs)(tvbuff_t*, gint);
typedef guint32 (*addr_tvb_get_letoh24)(tvbuff_t*, gint);
typedef guint32 (*addr_tvb_get_letohl)(tvbuff_t*, gint);
#ifdef G_HAVE_GINT64
typedef guint64 (*addr_tvb_get_letohll)(tvbuff_t*, gint);
#endif

typedef guint8* (*addr_tvb_memcpy)(tvbuff_t*, guint8* target, gint, gint);
typedef guint8* (*addr_tvb_memdup)(tvbuff_t*, gint, gint);

typedef guint8* (*addr_tvb_get_ptr)(tvbuff_t*, gint, gint);

typedef gint (*addr_tvb_find_guint8)(tvbuff_t*, gint, guint, guint8);
typedef gint (*addr_tvb_pbrk_guint8)(tvbuff_t *, gint, guint, guint8 *);

typedef gint (*addr_tvb_strnlen)(tvbuff_t*, gint, guint);

typedef guint8 * (*addr_tvb_format_text)(tvbuff_t*, gint, gint);

typedef gint (*addr_tvb_get_nstringz)(tvbuff_t*, gint, guint, guint8*);
typedef gint (*addr_tvb_get_nstringz0)(tvbuff_t*, gint, guint, guint8*);

typedef gint (*addr_tvb_find_line_end)(tvbuff_t*, gint, int, gint *);
typedef gint (*addr_tvb_find_line_end_unquoted)(tvbuff_t*, gint, int, gint *);

typedef gint (*addr_tvb_strneql)(tvbuff_t*, gint, const guint8 *, gint);
typedef gint (*addr_tvb_strncaseeql)(tvbuff_t*, gint, const guint8 *, gint);

typedef gchar *(*addr_tvb_bytes_to_str)(tvbuff_t*, gint, gint len);

typedef module_t *(*addr_prefs_register_module(const char *, const char *,
    void (*)(void));
typedef void (*addr_prefs_register_uint_preference(module_t *, const char *,
    const char *, const char *, guint, guint *);
typedef void (*addr_prefs_register_bool_preference)(module_t *, const char *,
    const char *, const char *, gboolean *);
typedef void (*addr_prefs_register_enum_preference)(module_t *, const char *,
    const char *, const char *, gint *, const enum_val *, gboolean);

typedef struct  {
	addr_check_col				p_check_col;
	addr_col_add_fstr			p_col_add_fstr;
	addr_col_append_fstr			p_col_append_fstr;
	addr_col_add_str			p_col_add_str;
	addr_col_append_str			p_col_append_str;

	addr_dfilter_init			p_dfilter_init;
	addr_dfilter_cleanup			p_dfilter_cleanup;

	packet_info				*p_pi;

	addr_proto_register_protocol		p_proto_register_protocol;
	addr_proto_register_field_array		p_proto_register_field_array;
	addr_proto_register_subtree_array	p_proto_register_subtree_array;

	addr_dissector_add			p_dissector_add;
	addr_old_dissector_add			p_old_dissector_add;
	addr_dissector_delete			p_dissector_delete;

	addr_heur_dissector_add			p_heur_dissector_add;

	addr_dissect_data			p_dissect_data;
	addr_old_dissect_data			p_old_dissect_data;

	addr_proto_is_protocol_enabled		p_proto_is_protocol_enabled;

	addr_proto_item_get_len			p_proto_item_get_len;
	addr_proto_item_set_len			p_proto_item_set_len;
	addr_proto_item_set_text		p_proto_item_set_text;
	addr_proto_item_add_subtree		p_proto_item_add_subtree;
	addr_proto_tree_add_item		p_proto_tree_add_item;
	addr_proto_tree_add_item_hidden		p_proto_tree_add_item_hidden;
	addr_proto_tree_add_protocol_format	p_proto_tree_add_protocol_format;
	addr_proto_tree_add_bytes		p_proto_tree_add_bytes;
	addr_proto_tree_add_bytes_hidden	p_proto_tree_add_bytes_hidden;
	addr_proto_tree_add_bytes_format	p_proto_tree_add_bytes_format;
	addr_proto_tree_add_time		p_proto_tree_add_time;
	addr_proto_tree_add_time_hidden		p_proto_tree_add_time_hidden;
	addr_proto_tree_add_time_format		p_proto_tree_add_time_format;
	addr_proto_tree_add_ipxnet		p_proto_tree_add_ipxnet;
	addr_proto_tree_add_ipxnet_hidden	p_proto_tree_add_ipxnet_hidden;
	addr_proto_tree_add_ipxnet_format	p_proto_tree_add_ipxnet_format;
	addr_proto_tree_add_ipv4		p_proto_tree_add_ipv4;
	addr_proto_tree_add_ipv4_hidden		p_proto_tree_add_ipv4_hidden;
	addr_proto_tree_add_ipv4_format		p_proto_tree_add_ipv4_format;
	addr_proto_tree_add_ipv6		p_proto_tree_add_ipv6;
	addr_proto_tree_add_ipv6_hidden		p_proto_tree_add_ipv6_hidden;
	addr_proto_tree_add_ipv6_format		p_proto_tree_add_ipv6_format;
	addr_proto_tree_add_ether		p_proto_tree_add_ether;
	addr_proto_tree_add_ether_hidden	p_proto_tree_add_ether_hidden;
	addr_proto_tree_add_ether_format	p_proto_tree_add_ether_format;
	addr_proto_tree_add_string		p_proto_tree_add_string;
	addr_proto_tree_add_string_hidden	p_proto_tree_add_string_hidden;
	addr_proto_tree_add_string_format	p_proto_tree_add_string_format;
	addr_proto_tree_add_boolean		p_proto_tree_add_boolean;
	addr_proto_tree_add_boolean_hidden	p_proto_tree_add_boolean_hidden;
	addr_proto_tree_add_boolean_format	p_proto_tree_add_boolean_format;
	addr_proto_tree_add_double		p_proto_tree_add_double;
	addr_proto_tree_add_double_hidden	p_proto_tree_add_double_hidden;
	addr_proto_tree_add_double_format	p_proto_tree_add_double_format;
	addr_proto_tree_add_uint		p_proto_tree_add_uint;
	addr_proto_tree_add_uint_hidden		p_proto_tree_add_uint_hidden;
	addr_proto_tree_add_uint_format		p_proto_tree_add_uint_format;
	addr_proto_tree_add_int			p_proto_tree_add_int;
	addr_proto_tree_add_int_hidden		p_proto_tree_add_int_hidden;
	addr_proto_tree_add_int_format		p_proto_tree_add_int_format;
	addr_proto_tree_add_text		p_proto_tree_add_text;
	addr_proto_tree_add_notext		p_proto_tree_add_notext;

	addr_tvb_new_subset			p_tvb_new_subset;

	addr_tvb_length				p_tvb_length;
	addr_tvb_length_remaining		p_tvb_length_remaining;
	addr_tvb_bytes_exist			p_tvb_bytes_exist;
	addr_tvb_offset_exists			p_tvb_offset_exists;
	addr_tvb_reported_length		p_tvb_reported_length;

	addr_tvb_get_guint8			p_tvb_get_guint8;

	addr_tvb_get_ntohs			p_tvb_get_ntohs;
	addr_tvb_get_ntoh24			p_tvb_get_ntoh24;
	addr_tvb_get_ntohl			p_tvb_get_ntohl;
#ifdef G_HAVE_GINT64
	addr_tvb_get_ntohll			p_tvb_get_ntohll;
#endif

	addr_tvb_get_letohs			p_tvb_get_letohs;
	addr_tvb_get_letoh24			p_tvb_get_letoh24;
	addr_tvb_get_letohl			p_tvb_get_letohl;
#ifdef G_HAVE_GINT64
	addr_tvb_get_letohll			p_tvb_get_letohll;
#endif

	addr_tvb_memcpy				p_tvb_memcpy;
	addr_tvb_memdup				p_tvb_memdup;

	addr_tvb_get_ptr			p_tvb_get_ptr;

	addr_tvb_find_guint8			p_tvb_find_guint8;
	addr_tvb_pbrk_guint8			p_tvb_pbrk_guint8;

	addr_tvb_strnlen			p_tvb_strnlen;

	addr_tvb_format_text			p_tvb_format_text;

	addr_tvb_get_nstringz			p_tvb_get_nstringz;
	addr_tvb_get_nstringz0			p_tvb_get_nstringz0;

	addr_tvb_find_line_end			p_tvb_find_line_end;
	addr_tvb_find_line_end_unquoted	p_tvb_find_line_end_unquoted;

	addr_tvb_strneql			p_tvb_strneql;
	addr_tvb_strncaseeql			p_tvb_strncaseeql;

	addr_tvb_bytes_to_str			p_tvb_bytes_to_str;

	addr_prefs_register_module		p_prefs_register_module;
	addr_prefs_register_uint_preference	p_prefs_register_uint_preference;
	addr_prefs_register_bool_preference	p_prefs_register_bool_preference;
	addr_prefs_register_enum_preference	p_prefs_register_enum_preference;
} plugin_address_table_t;

#else /* ! PLUGINS_NEED_ACCESS_TABLE */

typedef void	plugin_address_table_t;

#endif
