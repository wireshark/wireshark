/* plugin_api.h
 * Routines for Ethereal plugins.
 *
 * $Id: plugin_api.h,v 1.14 2001/01/03 07:53:47 guy Exp $
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

/* #defines for those functions that call through pointers.
   #defined in this fashion so that the declaration of the functions,
   from the system header files, turn into declarations of pointers
   to functions, and the calls to it in plugins, in the plugins, turn
   into calls through the pointers. */
#define	check_col			(*p_check_col)
#define	col_add_fstr			(*p_col_add_fstr)
#define	col_append_fstr			(*p_col_append_fstr)
#define	col_add_str			(*p_col_add_str)
#define	col_append_str			(*p_col_append_str)

#define	dfilter_init			(*p_dfilter_init)
#define	dfilter_cleanup			(*p_dfilter_cleanup)

#define	proto_register_protocol		(*p_proto_register_protocol)
#define	proto_register_field_array	(*p_proto_register_field_array)
#define	proto_register_subtree_array	(*p_proto_register_subtree_array)

#define	dissector_add			(*p_dissector_add)
#define old_dissector_add		(*p_old_dissector_add)
#define dissector_delete		(*p_dissector_delete)

#define	heur_dissector_add		(*p_heur_dissector_add)

#define register_dissector		(*p_register_dissector)
#define find_dissector			(*p_find_dissector)
#define old_call_dissector		(*p_old_call_dissector)
#define call_dissector			(*p_call_dissector)

#define dissect_data			(*p_dissect_data)
#define old_dissect_data		(*p_old_dissect_data)

#define proto_is_protocol_enabled	(*p_proto_is_protocol_enabled)

#define proto_item_get_len		(*p_proto_item_get_len)
#define proto_item_set_len		(*p_proto_item_set_len)
#define proto_item_set_text		(*p_proto_item_set_text)
#define	proto_item_add_subtree		(*p_proto_item_add_subtree)
#define	proto_tree_add_item		(*p_proto_tree_add_item)
#define	proto_tree_add_item_hidden	(*p_proto_tree_add_item_hidden)
#define	proto_tree_add_protocol_format	(*p_proto_tree_add_protocol_format)
#define	proto_tree_add_bytes		(*p_proto_tree_add_bytes)
#define	proto_tree_add_bytes_hidden	(*p_proto_tree_add_bytes_hidden)
#define	proto_tree_add_bytes_format	(*p_proto_tree_add_bytes_format)
#define	proto_tree_add_time		(*p_proto_tree_add_time)
#define	proto_tree_add_time_hidden	(*p_proto_tree_add_time_hidden)
#define	proto_tree_add_time_format	(*p_proto_tree_add_time_format)
#define	proto_tree_add_ipxnet		(*p_proto_tree_add_ipxnet)
#define	proto_tree_add_ipxnet_hidden	(*p_proto_tree_add_ipxnet_hidden)
#define	proto_tree_add_ipxnet_format	(*p_proto_tree_add_ipxnet_format)
#define	proto_tree_add_ipv4		(*p_proto_tree_add_ipv4)
#define	proto_tree_add_ipv4_hidden	(*p_proto_tree_add_ipv4_hidden)
#define	proto_tree_add_ipv4_format	(*p_proto_tree_add_ipv4_format)
#define	proto_tree_add_ipv6		(*p_proto_tree_add_ipv6)
#define	proto_tree_add_ipv6_hidden	(*p_proto_tree_add_ipv6_hidden)
#define	proto_tree_add_ipv6_format	(*p_proto_tree_add_ipv6_format)
#define	proto_tree_add_ether		(*p_proto_tree_add_ether)
#define	proto_tree_add_ether_hidden	(*p_proto_tree_add_ether_hidden)
#define	proto_tree_add_ether_format	(*p_proto_tree_add_ether_format)
#define	proto_tree_add_string		(*p_proto_tree_add_string)
#define	proto_tree_add_string_hidden	(*p_proto_tree_add_string_hidden)
#define	proto_tree_add_string_format	(*p_proto_tree_add_string_format)
#define	proto_tree_add_boolean		(*p_proto_tree_add_boolean)
#define	proto_tree_add_boolean_hidden	(*p_proto_tree_add_boolean_hidden)
#define	proto_tree_add_boolean_format	(*p_proto_tree_add_boolean_format)
#define	proto_tree_add_double		(*p_proto_tree_add_double)
#define	proto_tree_add_double_hidden	(*p_proto_tree_add_double_hidden)
#define	proto_tree_add_double_format	(*p_proto_tree_add_double_format)
#define	proto_tree_add_uint		(*p_proto_tree_add_uint)
#define	proto_tree_add_uint_hidden	(*p_proto_tree_add_uint_hidden)
#define	proto_tree_add_uint_format	(*p_proto_tree_add_uint_format)
#define	proto_tree_add_int		(*p_proto_tree_add_int)
#define	proto_tree_add_int_hidden	(*p_proto_tree_add_int_hidden)
#define	proto_tree_add_int_format	(*p_proto_tree_add_int_format)
#define	proto_tree_add_text		(*p_proto_tree_add_text)
#define	proto_tree_add_notext		(*p_proto_tree_add_notext)

#define tvb_new_subset			(*p_tvb_new_subset)

#define tvb_length			(*p_tvb_length)
#define tvb_length_remaining		(*p_tvb_length_remaining)
#define tvb_bytes_exist			(*p_tvb_bytes_exist)
#define tvb_offset_exists		(*p_tvb_offset_exists)
#define tvb_reported_length		(*p_tvb_reported_length)

#define tvb_get_guint8			(*p_tvb_get_guint8)

#define tvb_get_ntohs			(*p_tvb_get_ntohs)
#define tvb_get_ntoh24			(*p_tvb_get_ntoh24)
#define tvb_get_ntohl			(*p_tvb_get_ntohl)
#ifdef G_HAVE_GINT64
#define tvb_get_ntohll			(*p_tvb_get_ntohll)
#endif

#define tvb_get_letohs			(*p_tvb_get_letohs)
#define tvb_get_letoh24			(*p_tvb_get_letoh24)
#define tvb_get_letohl			(*p_tvb_get_letohl)
#ifdef G_HAVE_GINT64
#define tvb_get_letohll			(*p_tvb_get_letohll)
#endif

#define tvb_memcpy			(*p_tvb_memcpy)
#define tvb_memdup			(*p_tvb_memdup)

#define tvb_get_ptr			(*p_tvb_get_ptr)

#define tvb_find_guint8			(*p_tvb_find_guint8)
#define tvb_pbrk_guint8			(*p_tvb_pbrk_guint8)

#define tvb_strnlen			(*p_tvb_strnlen)

#define tvb_format_text			(*p_tvb_format_text)

#define tvb_get_nstringz		(*p_tvb_get_nstringz)
#define tvb_get_nstringz0		(*p_tvb_get_nstringz0)

#define tvb_find_line_end		(*p_tvb_find_line_end)
#define tvb_find_line_end_unquoted	(*p_tvb_find_line_end_unquoted)

#define tvb_strneql			(*p_tvb_strneql)
#define tvb_strncaseeql			(*p_tvb_strncaseeql)

#define tvb_bytes_to_str		(*p_tvb_bytes_to_str)

#define prefs_register_protocol		(*p_prefs_register_protocol)
#define prefs_register_uint_preference	(*p_prefs_register_uint_preference)
#define prefs_register_bool_preference	(*p_prefs_register_bool_preference)
#define prefs_register_enum_preference	(*p_prefs_register_enum_preference)

#define pi	(*p_pi)

#endif

#include "packet.h"
#include "prefs.h"
#include "dfilter.h"

#include "plugin_table.h"

#ifdef PLUGINS_NEED_ADDRESS_TABLE
/* The parent executable will send us the pointer to a filled in
   plugin_address_table_t struct, and we copy the pointers from
   that table so that we can use functions from the parent executable. */
void plugin_address_table_init(plugin_address_table_t*);
#else
#define plugin_address_table_init(x)    ;
#endif
