/* plugin_api.h
 * Routines for Ethereal plugins.
 *
 * $Id: plugin_api.h,v 1.52 2003/06/03 02:32:55 gerald Exp $
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

#ifndef PLUGIN_API_H
#define PLUGIN_API_H

#ifdef PLUGINS_NEED_ADDRESS_TABLE

/* Some OSes (Win32) have DLLs that cannot reference symbols in the parent
   executable, so the executable needs to provide a collection of pointers
   to global variables and functions for the DLL plugin to use. */

/* #defines for those functions that are called through pointers,
   and global variables that are referred to through pointers.

   #defined in this fashion so that the declaration of the functions
   and variables, from the system header files, turn into declarations
   of pointers to functions and variables, and the references to them in
   plugins, in the plugins, turn into references through the pointers. */
#define	check_col			(*p_check_col)
#define	col_clear			(*p_col_clear)
#define	col_add_fstr			(*p_col_add_fstr)
#define	col_append_fstr			(*p_col_append_fstr)
#define	col_prepend_fstr		(*p_col_prepend_fstr)
#define	col_add_str			(*p_col_add_str)
#define	col_append_str			(*p_col_append_str)
#define	col_set_str			(*p_col_set_str)

#define register_init_routine		(*p_register_init_routine)
#define register_postseq_cleanup_routine	(*p_register_postseq_cleanup_routine)

#define match_strval			(*p_match_strval)
#define val_to_str			(*p_val_to_str)

#define conversation_new		(*p_conversation_new)
#define find_conversation		(*p_find_conversation)
#define conversation_set_dissector	(*p_conversation_set_dissector)

#define	proto_register_protocol		(*p_proto_register_protocol)
#define	proto_register_field_array	(*p_proto_register_field_array)
#define	proto_register_subtree_array	(*p_proto_register_subtree_array)

#define	dissector_add			(*p_dissector_add)
#define dissector_delete		(*p_dissector_delete)
#define	dissector_add_handle		(*p_dissector_add_handle)

#define	heur_dissector_add		(*p_heur_dissector_add)

#define register_dissector		(*p_register_dissector)
#define find_dissector			(*p_find_dissector)
#define create_dissector_handle		(*p_create_dissector_handle)
#define call_dissector			(*p_call_dissector)

#define tcp_dissect_pdus		(*p_tcp_dissect_pdus)

#define proto_is_protocol_enabled	(*p_proto_is_protocol_enabled)

#define proto_item_get_len		(*p_proto_item_get_len)
#define proto_item_set_end		(*p_proto_item_set_end)
#define proto_item_set_text		(*p_proto_item_set_text)
#define proto_item_append_text		(*p_proto_item_append_text)
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

#define tvb_new_subset			(*p_tvb_new_subset)

#define tvb_set_free_cb			(*p_tvb_set_free_cb)
#define tvb_set_child_real_data_tvbuff	(*p_tvb_set_child_real_data_tvbuff)
#define tvb_new_real_data		(*p_tvb_new_real_data)

#define tvb_length			(*p_tvb_length)
#define tvb_length_remaining		(*p_tvb_length_remaining)
#define tvb_bytes_exist			(*p_tvb_bytes_exist)
#define tvb_offset_exists		(*p_tvb_offset_exists)
#define tvb_reported_length		(*p_tvb_reported_length)
#define tvb_reported_length_remaining	(*p_tvb_reported_length_remaining)

#define tvb_get_guint8			(*p_tvb_get_guint8)

#define tvb_get_ntohs			(*p_tvb_get_ntohs)
#define tvb_get_ntoh24			(*p_tvb_get_ntoh24)
#define tvb_get_ntohl			(*p_tvb_get_ntohl)

#define tvb_get_letohs			(*p_tvb_get_letohs)
#define tvb_get_letoh24			(*p_tvb_get_letoh24)
#define tvb_get_letohl			(*p_tvb_get_letohl)

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
#define prefs_register_string_preference (*p_prefs_register_string_preference)

#define register_giop_user		(*p_register_giop_user)
#define is_big_endian			(*p_is_big_endian)
#define get_CDR_encap_info		(*p_get_CDR_encap_info)

#define get_CDR_any			(*p_get_CDR_any)
#define get_CDR_boolean			(*p_get_CDR_boolean)
#define get_CDR_char			(*p_get_CDR_char)
#define get_CDR_double			(*p_get_CDR_double)
#define get_CDR_enum			(*p_get_CDR_enum)
#define get_CDR_fixed			(*p_get_CDR_fixed)
#define get_CDR_float			(*p_get_CDR_float)
#define get_CDR_interface		(*p_get_CDR_interface)
#define get_CDR_long         	        (*p_get_CDR_long)
#define get_CDR_object			(*p_get_CDR_object)
#define get_CDR_octet         	        (*p_get_CDR_octet)
#define get_CDR_octet_seq     	        (*p_get_CDR_octet_seq)
#define get_CDR_short         	        (*p_get_CDR_short)
#define get_CDR_string			(*p_get_CDR_string)
#define get_CDR_typeCode		(*p_get_CDR_typeCode)
#define get_CDR_ulong			(*p_get_CDR_ulong)
#define get_CDR_ushort			(*p_get_CDR_ushort)
#define get_CDR_wchar			(*p_get_CDR_wchar)
#define get_CDR_wstring			(*p_get_CDR_wstring)

#define is_tpkt				(*p_is_tpkt)
#define dissect_tpkt_encap		(*p_dissect_tpkt_encap)

#define set_actual_length		(*p_set_actual_length)

#define decode_boolean_bitfield		(*p_decode_boolean_bitfield)
#define decode_numeric_bitfield		(*p_decode_numeric_bitfield)
#define decode_enumerated_bitfield	(*p_decode_enumerated_bitfield)
#define register_dissector_table	(*p_register_dissector_table)
#define except_throw			(*p_except_throw)
#define dissector_try_port		(*p_dissector_try_port)

#define conversation_add_proto_data	(*p_conversation_add_proto_data)
#define conversation_get_proto_data	(*p_conversation_get_proto_data)
#define conversation_delete_proto_data	(*p_conversation_delete_proto_data)
#define p_add_proto_data		(*p_p_add_proto_data)
#define p_get_proto_data		(*p_p_get_proto_data)

#define ip_to_str			(*p_ip_to_str)
#define ip6_to_str			(*p_ip6_to_str)
#define time_secs_to_str		(*p_time_secs_to_str)
#define time_msecs_to_str		(*p_time_msecs_to_str)
#define abs_time_to_str			(*p_abs_time_to_str)
                                                                                  
#define proto_get_id_by_filter_name	(*p_proto_get_id_by_filter_name)
#define proto_get_protocol_name		(*p_proto_get_protocol_name)
#define proto_get_protocol_short_name	(*p_proto_get_protocol_short_name)
#define proto_get_protocol_filter_name	(*p_proto_get_protocol_filter_name)
                                                                                  
#define prefs_register_obsolete_preference	(*p_prefs_register_obsolete_preference)
                                                                                  
#define add_new_data_source		(*p_add_new_data_source)
                                                                                  
#define fragment_table_init		(*p_fragment_table_init)
#define reassembled_table_init		(*p_reassembled_table_init)
#define fragment_add			(*p_fragment_add)
#define fragment_add_seq		(*p_fragment_add_seq)
#define fragment_add_seq_check		(*p_fragment_add_seq_check)
#define fragment_add_seq_next		(*p_fragment_add_seq_next)
#define fragment_get			(*p_fragment_get)
#define fragment_set_tot_len		(*p_fragment_set_tot_len)
#define fragment_get_tot_len		(*p_fragment_get_tot_len)
#define fragment_set_partial_reassembly	(*p_fragment_set_partial_reassembly)
#define fragment_delete			(*p_fragment_delete)
#define show_fragment_tree		(*p_show_fragment_tree)
#define show_fragment_seq_tree		(*p_show_fragment_seq_tree)

#define register_tap			(*p_register_tap)
#define tap_queue_packet		(*p_tap_queue_packet)

#define	asn1_open			(*p_asn1_open)
#define	asn1_close			(*p_asn1_close)
#define	asn1_octet_decode		(*p_asn1_octet_decode)
#define	asn1_tag_decode			(*p_asn1_tag_decode)
#define	asn1_id_decode			(*p_asn1_id_decode)
#define	asn1_length_decode		(*p_asn1_length_decode)
#define	asn1_header_decode		(*p_asn1_header_decode)
#define	asn1_eoc			(*p_asn1_eoc)
#define	asn1_eoc_decode			(*p_asn1_eoc_decode)
#define	asn1_null_decode		(*p_asn1_null_decode)
#define	asn1_bool_decode		(*p_asn1_bool_decode)
#define	asn1_int32_value_decode		(*p_asn1_int32_value_decode)
#define	asn1_int32_decode		(*p_asn1_int32_decode)
#define	asn1_uint32_value_decode	(*p_asn1_uint32_value_decode)
#define	asn1_uint32_decode		(*p_asn1_uint32_decode)
#define	asn1_bits_decode		(*p_asn1_bits_decode)
#define	asn1_string_value_decode	(*p_asn1_string_value_decode)
#define	asn1_string_decode		(*p_asn1_string_decode)
#define	asn1_octet_string_decode	(*p_asn1_octet_string_decode)
#define	asn1_subid_decode		(*p_asn1_subid_decode)
#define	asn1_oid_value_decode		(*p_asn1_oid_value_decode)
#define	asn1_oid_decode			(*p_asn1_oid_decode)
#define	asn1_sequence_decode		(*p_asn1_sequence_decode)
#define	asn1_err_to_str			(*p_asn1_err_to_str)

#define proto_item_set_len		(*p_proto_item_set_len)
#define	proto_tree_add_none_format	(*p_proto_tree_add_none_format)

#define except_init			(*p_except_init)
#define except_deinit			(*p_except_deinit)
#define except_rethrow			(*p_except_rethrow)
#define except_throwd			(*p_except_throwd)
#define except_throwf			(*p_except_throwf)
#define except_unhandled_catcher       	(*p_except_unhandled_catcher)
#define except_take_data	       	(*p_except_take_data)
#define except_set_allocator	       	(*p_except_set_allocator)
#define except_alloc			(*p_except_alloc)
#define except_free			(*p_except_free)
#define except_pop			(*p_except_pop)
#define except_setup_try		(*p_except_setup_try)

#define col_set_fence			(*p_col_set_fence)

#endif

#include <epan/packet.h>
#include <epan/conversation.h>
#include "prefs.h"
#include "reassemble.h"
#include "packet-giop.h"
#include "packet-tpkt.h"
#include "packet-tcp.h"
#include "tap.h"
#include "asn1.h"
#include "epan/except.h"

#include "plugin_table.h"

#ifdef PLUGINS_NEED_ADDRESS_TABLE
/* The parent executable will send us the pointer to a filled in
   plugin_address_table_t struct, and we copy the pointers from
   that table so that we can use functions from the parent executable. */
void plugin_address_table_init(plugin_address_table_t*);
#else
#define plugin_address_table_init(x)    ;
#endif

#endif /* PLUGIN_API_H */
