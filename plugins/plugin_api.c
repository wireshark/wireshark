/* plugin_api.c
 * Routines for Ethereal plugins.
 *
 * $Id: plugin_api.c,v 1.36 2002/02/20 08:24:52 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * Copyright 2000 by Gilbert Ramirez <gram@alumni.rice.edu>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>

#include <glib.h>

#include "plugin_api.h"

void
plugin_address_table_init(plugin_address_table_t *pat)
{
	p_check_col				= pat->p_check_col;
	p_col_clear				= pat->p_col_clear;
	p_col_add_fstr				= pat->p_col_add_fstr;
	p_col_append_fstr			= pat->p_col_append_fstr;
	p_col_prepend_fstr			= pat->p_col_prepend_fstr;
	p_col_add_str				= pat->p_col_add_str;
	p_col_append_str			= pat->p_col_append_str;
	p_col_set_str				= pat->p_col_set_str;
	p_register_init_routine			= pat->p_register_init_routine;
	p_register_postseq_cleanup_routine	= pat->p_register_postseq_cleanup_routine;
	p_match_strval				= pat->p_match_strval;
	p_val_to_str		 		= pat->p_val_to_str;
	p_conversation_new			= pat->p_conversation_new;
	p_find_conversation			= pat->p_find_conversation;
	p_conversation_set_dissector		= pat->p_conversation_set_dissector;
	p_proto_register_protocol		= pat->p_proto_register_protocol;
	p_proto_register_field_array		= pat->p_proto_register_field_array;
	p_proto_register_subtree_array		= pat->p_proto_register_subtree_array;
	p_dissector_add				= pat->p_dissector_add;
	p_dissector_delete			= pat->p_dissector_delete;
	p_dissector_add_handle			= pat->p_dissector_add_handle;
	p_heur_dissector_add			= pat->p_heur_dissector_add;
	p_register_dissector			= pat->p_register_dissector;
	p_find_dissector			= pat->p_find_dissector;
	p_create_dissector_handle		= pat->p_create_dissector_handle;
	p_call_dissector			= pat->p_call_dissector;
	p_proto_is_protocol_enabled		= pat->p_proto_is_protocol_enabled;
	p_proto_item_get_len			= pat->p_proto_item_get_len;
	p_proto_item_set_len			= pat->p_proto_item_set_len;
	p_proto_item_set_text			= pat->p_proto_item_set_text;
	p_proto_item_append_text		= pat->p_proto_item_append_text;
	p_proto_item_add_subtree		= pat->p_proto_item_add_subtree;
	p_proto_tree_add_item			= pat->p_proto_tree_add_item;
	p_proto_tree_add_item_hidden		= pat->p_proto_tree_add_item_hidden;
	p_proto_tree_add_protocol_format	= pat->p_proto_tree_add_protocol_format;
	p_proto_tree_add_bytes			= pat->p_proto_tree_add_bytes;
	p_proto_tree_add_bytes_hidden		= pat->p_proto_tree_add_bytes_hidden;
	p_proto_tree_add_bytes_format		= pat->p_proto_tree_add_bytes_format;
	p_proto_tree_add_time			= pat->p_proto_tree_add_time;
	p_proto_tree_add_time_hidden		= pat->p_proto_tree_add_time_hidden;
	p_proto_tree_add_time_format		= pat->p_proto_tree_add_time_format;
	p_proto_tree_add_ipxnet			= pat->p_proto_tree_add_ipxnet;
	p_proto_tree_add_ipxnet_hidden		= pat->p_proto_tree_add_ipxnet_hidden;
	p_proto_tree_add_ipxnet_format		= pat->p_proto_tree_add_ipxnet_format;
	p_proto_tree_add_ipv4			= pat->p_proto_tree_add_ipv4;
	p_proto_tree_add_ipv4_hidden		= pat->p_proto_tree_add_ipv4_hidden;
	p_proto_tree_add_ipv4_format		= pat->p_proto_tree_add_ipv4_format;
	p_proto_tree_add_ipv6			= pat->p_proto_tree_add_ipv6;
	p_proto_tree_add_ipv6_hidden		= pat->p_proto_tree_add_ipv6_hidden;
	p_proto_tree_add_ipv6_format		= pat->p_proto_tree_add_ipv6_format;
	p_proto_tree_add_ether			= pat->p_proto_tree_add_ether;
	p_proto_tree_add_ether_hidden		= pat->p_proto_tree_add_ether_hidden;
	p_proto_tree_add_ether_format		= pat->p_proto_tree_add_ether_format;
	p_proto_tree_add_string			= pat->p_proto_tree_add_string;
	p_proto_tree_add_string_hidden		= pat->p_proto_tree_add_string_hidden;
	p_proto_tree_add_string_format		= pat->p_proto_tree_add_string_format;
	p_proto_tree_add_boolean		= pat->p_proto_tree_add_boolean;
	p_proto_tree_add_boolean_hidden		= pat->p_proto_tree_add_boolean_hidden;
	p_proto_tree_add_boolean_format		= pat->p_proto_tree_add_boolean_format;
	p_proto_tree_add_double			= pat->p_proto_tree_add_double;
	p_proto_tree_add_double_hidden		= pat->p_proto_tree_add_double_hidden;
	p_proto_tree_add_double_format		= pat->p_proto_tree_add_double_format;
	p_proto_tree_add_uint			= pat->p_proto_tree_add_uint;
	p_proto_tree_add_uint_hidden		= pat->p_proto_tree_add_uint_hidden;
	p_proto_tree_add_uint_format		= pat->p_proto_tree_add_uint_format;
	p_proto_tree_add_int			= pat->p_proto_tree_add_int;
	p_proto_tree_add_int_hidden		= pat->p_proto_tree_add_int_hidden;
	p_proto_tree_add_int_format		= pat->p_proto_tree_add_int_format;
	p_proto_tree_add_text			= pat->p_proto_tree_add_text;
	p_tvb_new_subset			= pat->p_tvb_new_subset;
	p_tvb_set_free_cb			= pat->p_tvb_set_free_cb;
	p_tvb_set_child_real_data_tvbuff	= pat->p_tvb_set_child_real_data_tvbuff;
	p_tvb_new_real_data			= pat->p_tvb_new_real_data;
	p_tvb_length				= pat->p_tvb_length;
	p_tvb_length_remaining			= pat->p_tvb_length_remaining;
	p_tvb_bytes_exist			= pat->p_tvb_bytes_exist;
	p_tvb_offset_exists			= pat->p_tvb_offset_exists;
	p_tvb_reported_length			= pat->p_tvb_reported_length;
	p_tvb_reported_length_remaining		= pat->p_tvb_reported_length_remaining;
	p_tvb_get_guint8			= pat->p_tvb_get_guint8;
	p_tvb_get_ntohs				= pat->p_tvb_get_ntohs;
	p_tvb_get_ntoh24			= pat->p_tvb_get_ntoh24;
	p_tvb_get_ntohl				= pat->p_tvb_get_ntohl;
	p_tvb_get_letohs			= pat->p_tvb_get_letohs;
	p_tvb_get_letoh24			= pat->p_tvb_get_letoh24;
	p_tvb_get_letohl			= pat->p_tvb_get_letohl;
	p_tvb_memcpy				= pat->p_tvb_memcpy;
	p_tvb_memdup				= pat->p_tvb_memdup;
	p_tvb_get_ptr				= pat->p_tvb_get_ptr;
	p_tvb_find_guint8			= pat->p_tvb_find_guint8;
	p_tvb_pbrk_guint8			= pat->p_tvb_pbrk_guint8;
	p_tvb_strnlen				= pat->p_tvb_strnlen;
	p_tvb_format_text			= pat->p_tvb_format_text;
	p_tvb_get_nstringz			= pat->p_tvb_get_nstringz;
	p_tvb_get_nstringz0			= pat->p_tvb_get_nstringz0;
	p_tvb_find_line_end			= pat->p_tvb_find_line_end;
	p_tvb_find_line_end_unquoted		= pat->p_tvb_find_line_end_unquoted;
	p_tvb_strneql				= pat->p_tvb_strneql;
	p_tvb_strncaseeql			= pat->p_tvb_strncaseeql;
	p_tvb_bytes_to_str			= pat->p_tvb_bytes_to_str;
	p_prefs_register_protocol		= pat->p_prefs_register_protocol;
	p_prefs_register_uint_preference	= pat->p_prefs_register_uint_preference;
	p_prefs_register_bool_preference	= pat->p_prefs_register_bool_preference;
	p_prefs_register_enum_preference	= pat->p_prefs_register_enum_preference;
	p_prefs_register_string_preference	= pat->p_prefs_register_string_preference;

	/* GIOP Begin */

	p_register_giop_user			= pat->p_register_giop_user;
	p_is_big_endian				= pat->p_is_big_endian;
	p_get_CDR_encap_info                    = pat->p_get_CDR_encap_info;
 
	p_get_CDR_any				= pat->p_get_CDR_any;
	p_get_CDR_boolean			= pat->p_get_CDR_boolean;
	p_get_CDR_char				= pat->p_get_CDR_char;
	p_get_CDR_double			= pat->p_get_CDR_double;
	p_get_CDR_enum				= pat->p_get_CDR_enum;
	p_get_CDR_fixed				= pat->p_get_CDR_fixed;
	p_get_CDR_float				= pat->p_get_CDR_float;
	p_get_CDR_interface			= pat->p_get_CDR_interface;
	p_get_CDR_long				= pat->p_get_CDR_long;
	p_get_CDR_object			= pat->p_get_CDR_object;
	p_get_CDR_octet 			= pat->p_get_CDR_octet;
	p_get_CDR_octet_seq 			= pat->p_get_CDR_octet_seq;
	p_get_CDR_short 			= pat->p_get_CDR_short;
	p_get_CDR_string			= pat->p_get_CDR_string;
	p_get_CDR_typeCode			= pat->p_get_CDR_typeCode;
	p_get_CDR_ulong				= pat->p_get_CDR_ulong;
	p_get_CDR_ushort			= pat->p_get_CDR_ushort;
	p_get_CDR_wchar 			= pat->p_get_CDR_wchar;
	p_get_CDR_wstring 			= pat->p_get_CDR_wstring;

	/* GIOP End */

}
