/* plugin_table.h
 * Table of exported addresses for Ethereal plugins.
 *
 * $Id: plugin_table.h,v 1.64 2003/06/03 02:32:56 gerald Exp $
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

#ifndef PLUGIN_TABLE_H
#define PLUGIN_TABLE_H

#ifdef PLUGINS_NEED_ADDRESS_TABLE

/* Some OSes (Win32) have DLLs that cannot reference symbols in the parent
   executable, so the executable needs to provide a collection of pointers
   to those functions for the DLL plugin to use. */

/* Typedefs to make our plugin_address_table_t struct look prettier */
typedef gint (*addr_check_col)(column_info*, gint);
typedef void (*addr_col_clear)(column_info*, gint);
typedef void (*addr_col_add_fstr)(column_info*, gint, const gchar*, ...);
typedef void (*addr_col_append_fstr)(column_info*, gint, const gchar*, ...);
typedef void (*addr_col_prepend_fstr)(column_info*, gint, const gchar*, ...);
typedef void (*addr_col_add_str)(column_info*, gint, const gchar*);
typedef void (*addr_col_append_str)(column_info*, gint, const gchar*);
typedef void (*addr_col_set_str)(column_info*, gint, gchar*);

typedef void (*addr_register_init_routine)(void (*func)(void));
typedef void (*addr_register_postseq_cleanup_routine)(void (*func)(void));

typedef gchar* (*addr_match_strval)(guint32, const value_string*);
typedef gchar* (*addr_val_to_str)(guint32, const value_string *, const char *);

typedef conversation_t *(*addr_conversation_new)(address *, address *,
    port_type, guint32, guint32, guint);
typedef conversation_t *(*addr_find_conversation)(address *, address *,
    port_type, guint32, guint32, guint);
typedef void (*addr_conversation_set_dissector)(conversation_t *,
    dissector_handle_t);

typedef int (*addr_proto_register_protocol)(char*, char*, char*);
typedef void (*addr_proto_register_field_array)(int, hf_register_info*, int);
typedef void (*addr_proto_register_subtree_array)(int**, int);

typedef void (*addr_dissector_add)(const char *, guint32, dissector_handle_t);
typedef void (*addr_dissector_delete)(const char *, guint32,
    dissector_handle_t);
typedef void (*addr_dissector_add_handle)(const char *,
    dissector_handle_t);

typedef void (*addr_heur_dissector_add)(const char *, heur_dissector_t, int);

typedef void (*addr_register_dissector)(const char *, dissector_t, int);
typedef dissector_handle_t (*addr_find_dissector)(const char *);
typedef dissector_handle_t (*addr_create_dissector_handle)(dissector_t dissector,
    int proto);
typedef int (*addr_call_dissector)(dissector_handle_t, tvbuff_t *,
    packet_info *, proto_tree *);

typedef void (*addr_tcp_dissect_pdus)(tvbuff_t *, packet_info *, proto_tree *,
    gboolean, guint, guint (*)(tvbuff_t *, int),
    void (*)(tvbuff_t *, packet_info *, proto_tree *));

typedef gboolean (*addr_proto_is_protocol_enabled)(int);

typedef int (*addr_proto_item_get_len)(proto_item*);
typedef void (*addr_proto_item_set_len)(proto_item*, gint);
typedef void (*addr_proto_item_set_text)(proto_item*, const char*, ...);
typedef void (*addr_proto_item_append_text)(proto_item*, const char*, ...);
typedef proto_tree* (*addr_proto_item_add_subtree)(proto_item*, gint);
typedef proto_item* (*addr_proto_tree_add_item)(proto_tree*, int, tvbuff_t*, gint, gint, gboolean);
typedef proto_item* (*addr_proto_tree_add_item_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, gboolean);
typedef proto_item* (*addr_proto_tree_add_protocol_format)(proto_tree*, int, tvbuff_t*, gint, gint, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_bytes)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_bytes_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_bytes_format)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_time)(proto_tree*, int, tvbuff_t*, gint, gint, nstime_t*);
typedef proto_item* (*addr_proto_tree_add_time_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, nstime_t*);
typedef proto_item* (*addr_proto_tree_add_time_format)(proto_tree*, int, tvbuff_t*, gint, gint, nstime_t*, const char*, ...);

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

typedef tvbuff_t* (*addr_tvb_new_subset)(tvbuff_t*, gint, gint, gint);

typedef void (*addr_tvb_set_free_cb)(tvbuff_t*, tvbuff_free_cb_t);
typedef void (*addr_tvb_set_child_real_data_tvbuff)(tvbuff_t*, tvbuff_t*);
typedef tvbuff_t* (*addr_tvb_new_real_data)(const guint8*, guint, gint);

typedef guint (*addr_tvb_length)(tvbuff_t*);
typedef gint (*addr_tvb_length_remaining)(tvbuff_t*, gint);
typedef gboolean (*addr_tvb_bytes_exist)(tvbuff_t*, gint, gint);
typedef gboolean (*addr_tvb_offset_exists)(tvbuff_t*, gint);
typedef guint (*addr_tvb_reported_length)(tvbuff_t*);
typedef gint (*addr_tvb_reported_length_remaining)(tvbuff_t*, gint);

typedef guint8 (*addr_tvb_get_guint8)(tvbuff_t*, gint);

typedef guint16 (*addr_tvb_get_ntohs)(tvbuff_t*, gint);
typedef guint32 (*addr_tvb_get_ntoh24)(tvbuff_t*, gint);
typedef guint32 (*addr_tvb_get_ntohl)(tvbuff_t*, gint);

typedef guint16 (*addr_tvb_get_letohs)(tvbuff_t*, gint);
typedef guint32 (*addr_tvb_get_letoh24)(tvbuff_t*, gint);
typedef guint32 (*addr_tvb_get_letohl)(tvbuff_t*, gint);

typedef guint8* (*addr_tvb_memcpy)(tvbuff_t*, guint8* target, gint, gint);
typedef guint8* (*addr_tvb_memdup)(tvbuff_t*, gint, gint);

typedef const guint8* (*addr_tvb_get_ptr)(tvbuff_t*, gint, gint);

typedef gint (*addr_tvb_find_guint8)(tvbuff_t*, gint, gint, guint8);
typedef gint (*addr_tvb_pbrk_guint8)(tvbuff_t *, gint, gint, guint8 *);

typedef gint (*addr_tvb_strnlen)(tvbuff_t*, gint, guint);

typedef guint8 * (*addr_tvb_format_text)(tvbuff_t*, gint, gint);

typedef gint (*addr_tvb_get_nstringz)(tvbuff_t*, gint, guint, guint8*);
typedef gint (*addr_tvb_get_nstringz0)(tvbuff_t*, gint, guint, guint8*);

typedef gint (*addr_tvb_find_line_end)(tvbuff_t*, gint, int, gint *, gboolean);
typedef gint (*addr_tvb_find_line_end_unquoted)(tvbuff_t*, gint, int, gint *);

typedef gint (*addr_tvb_strneql)(tvbuff_t*, gint, const guint8 *, gint);
typedef gint (*addr_tvb_strncaseeql)(tvbuff_t*, gint, const guint8 *, gint);

typedef gchar *(*addr_tvb_bytes_to_str)(tvbuff_t*, gint, gint len);

typedef struct pref_module *(*addr_prefs_register_protocol)(int,
    void (*)(void));
typedef void (*addr_prefs_register_uint_preference)(struct pref_module *,
    const char *, const char *, const char *, guint, guint *);
typedef void (*addr_prefs_register_bool_preference)(struct pref_module *,
    const char *, const char *, const char *, gboolean *);
typedef void (*addr_prefs_register_enum_preference)(struct pref_module *,
    const char *, const char *, const char *, gint *, const enum_val_t *,
    gboolean);
typedef void (*addr_prefs_register_string_preference)(struct pref_module *,
    const char *, const char *, const char *, char**);

typedef void (*addr_register_giop_user)(giop_sub_dissector_t *, gchar *, int);
typedef gboolean (*addr_is_big_endian)(MessageHeader *);
typedef guint32 (*addr_get_CDR_encap_info)(tvbuff_t *, proto_tree *, gint *,
		gboolean, guint32, gboolean *, guint32 *);
typedef void (*addr_get_CDR_any)(tvbuff_t *, proto_tree *, gint *,
		gboolean, int, MessageHeader *);
typedef gboolean (*addr_get_CDR_boolean)(tvbuff_t *, int *);
typedef guint8 (*addr_get_CDR_char)(tvbuff_t *, int *);
typedef gdouble (*addr_get_CDR_double)(tvbuff_t *, int *, gboolean, int);
typedef guint32 (*addr_get_CDR_enum)(tvbuff_t *, int *, gboolean, int);
typedef void (*addr_get_CDR_fixed)(tvbuff_t *, gchar **, gint *, guint32,
		gint32);
typedef gfloat (*addr_get_CDR_float)(tvbuff_t *, int *, gboolean, int);
typedef void (*addr_get_CDR_interface)(tvbuff_t *, packet_info *, proto_tree *,
		int *, gboolean, int);
typedef gint32 (*addr_get_CDR_long)(tvbuff_t *, int *, gboolean, int);
typedef void (*addr_get_CDR_object)(tvbuff_t *, packet_info *, proto_tree *,
		int *, gboolean, int);
typedef guint8 (*addr_get_CDR_octet)(tvbuff_t *, int *);
typedef void (*addr_get_CDR_octet_seq)(tvbuff_t *, gchar **, int *, guint32);
typedef gint16 (*addr_get_CDR_short)(tvbuff_t *, int *, gboolean, int);
typedef guint32 (*addr_get_CDR_string)(tvbuff_t *, gchar **, int *, gboolean,
		int);
typedef guint32 (*addr_get_CDR_typeCode)(tvbuff_t *, proto_tree *, gint *,
	gboolean, int, MessageHeader *);
typedef guint32 (*addr_get_CDR_ulong)(tvbuff_t *, int *, gboolean, int);
typedef guint16 (*addr_get_CDR_ushort)(tvbuff_t *, int *, gboolean, int);
typedef gint (*addr_get_CDR_wchar)(tvbuff_t *, gchar **, int *,
		MessageHeader *);
typedef guint32 (*addr_get_CDR_wstring)(tvbuff_t *, gchar **, int *, gboolean,
		int, MessageHeader *);

typedef int (*addr_is_tpkt)(tvbuff_t *, int);
typedef void (*addr_dissect_tpkt_encap)(tvbuff_t *, packet_info *,
    proto_tree *, gboolean, dissector_handle_t);

typedef void (*addr_set_actual_length)(tvbuff_t *, guint);

typedef const char *(*addr_decode_boolean_bitfield)(guint32, guint32, int,
    const char *, const char *);
typedef const char *(*addr_decode_numeric_bitfield)(guint32, guint32, int,
    const char *);
typedef const char *(*addr_decode_enumerated_bitfield)(guint32, guint32, int,
    const value_string *, const char *);

typedef dissector_table_t (*addr_register_dissector_table)(const char *, char *, ftenum_t ,int );
typedef void (*addr_except_throw)(long, long, const char *);
typedef gboolean (*addr_dissector_try_port)(dissector_table_t, guint32, tvbuff_t *, packet_info *, proto_tree *);

typedef void (*addr_conversation_add_proto_data)(conversation_t *, int, void *);
typedef void *(*addr_conversation_get_proto_data)(conversation_t *, int);
typedef void (*addr_conversation_delete_proto_data)(conversation_t *, int);
typedef void (*addr_p_add_proto_data)(frame_data *, int, void *);
typedef void *(*addr_p_get_proto_data)(frame_data *, int);

typedef gchar*	(*addr_ip_to_str)(const guint8 *);
typedef char*	(*addr_ip6_to_str)(const struct e_in6_addr *);
typedef gchar*	(*addr_time_secs_to_str)(guint32);
typedef gchar*	(*addr_time_msecs_to_str)(guint32);
typedef gchar*	(*addr_abs_time_to_str)(nstime_t*);

typedef int (*addr_proto_get_id_by_filter_name)(gchar* filter_name);
typedef char *(*addr_proto_get_protocol_name)(int n);
typedef char *(*addr_proto_get_protocol_short_name)(int proto_id);
typedef char *(*addr_proto_get_protocol_filter_name)(int proto_id);

typedef void (*addr_prefs_register_obsolete_preference)(module_t *, const char *);

typedef void (*addr_add_new_data_source)(packet_info *, tvbuff_t *, char *);

typedef void (*addr_fragment_table_init)(GHashTable **);
typedef void (*addr_reassembled_table_init)(GHashTable **);
typedef fragment_data *(*addr_fragment_add)(tvbuff_t *, int, packet_info *, guint32,
			GHashTable *, guint32, guint32, gboolean);
typedef fragment_data *(*addr_fragment_add_seq)(tvbuff_t *, int, packet_info *, guint32,
			GHashTable *, guint32, guint32, gboolean);
typedef fragment_data *(*addr_fragment_add_seq_check)(tvbuff_t *, int, packet_info *, guint32 id,
			GHashTable *, GHashTable *, guint32, guint32, gboolean);
typedef fragment_data *(*addr_fragment_add_seq_next)(tvbuff_t *, int, packet_info *, guint32,
			GHashTable *, GHashTable *, guint32, gboolean);
typedef fragment_data *(*addr_fragment_get)(packet_info *, guint32, GHashTable *);
typedef void (*addr_fragment_set_tot_len)(packet_info *, guint32, GHashTable *, guint32);
typedef guint32 (*addr_fragment_get_tot_len)(packet_info *, guint32, GHashTable *);
typedef void (*addr_fragment_set_partial_reassembly)(packet_info *, guint32, GHashTable *);
typedef unsigned char *(*addr_fragment_delete)(packet_info *, guint32, GHashTable *);
typedef gboolean (*addr_show_fragment_tree)(fragment_data *, const fragment_items *, proto_tree *, packet_info *, tvbuff_t *);
typedef gboolean (*addr_show_fragment_seq_tree)(fragment_data *, const fragment_items *, proto_tree *, packet_info *, tvbuff_t *);

typedef int (*addr_register_tap)(char *);
typedef void (*addr_tap_queue_packet)(int, packet_info *, void *);

typedef void (*addr_asn1_open)(ASN1_SCK *, tvbuff_t *, int );
typedef void (*addr_asn1_close)(ASN1_SCK *, int *);
typedef int (*addr_asn1_octet_decode)(ASN1_SCK *, guchar *);
typedef int (*addr_asn1_tag_decode)(ASN1_SCK *, guint *);
typedef int (*addr_asn1_id_decode)(ASN1_SCK *, guint *, guint *, guint *);
typedef int (*addr_asn1_length_decode)(ASN1_SCK *, gboolean *, guint *);
typedef int (*addr_asn1_header_decode)(ASN1_SCK *, guint *, guint *, guint *,
			gboolean *, guint *);
typedef int (*addr_asn1_eoc)(ASN1_SCK *, int );
typedef int (*addr_asn1_eoc_decode)(ASN1_SCK *, int );
typedef int (*addr_asn1_null_decode)(ASN1_SCK *, int );
typedef int (*addr_asn1_bool_decode)(ASN1_SCK *, int , gboolean *);
typedef int (*addr_asn1_int32_value_decode)(ASN1_SCK *, int , gint32 *);
typedef int (*addr_asn1_int32_decode)(ASN1_SCK *, gint32 *, guint *);
typedef int (*addr_asn1_uint32_value_decode)(ASN1_SCK *, int , guint *);
typedef int (*addr_asn1_uint32_decode)(ASN1_SCK *, guint32 *, guint *);
typedef int (*addr_asn1_bits_decode)(ASN1_SCK *, int , guchar **,
                             guint *, guchar *);
typedef int (*addr_asn1_string_value_decode)(ASN1_SCK *, int ,
			guchar **);
typedef int (*addr_asn1_string_decode)(ASN1_SCK *, guchar **, guint *,
			guint *, guint );
typedef int (*addr_asn1_octet_string_decode)(ASN1_SCK *, guchar **, guint *,
			guint *);
typedef int (*addr_asn1_subid_decode)(ASN1_SCK *, subid_t *);
typedef int (*addr_asn1_oid_value_decode)(ASN1_SCK *, int , subid_t **,
			guint *);
typedef int (*addr_asn1_oid_decode)( ASN1_SCK *, subid_t **, guint *, guint *);
typedef int (*addr_asn1_sequence_decode)( ASN1_SCK *, guint *, guint *);

typedef char *(*addr_asn1_err_to_str)(int );

typedef void (*addr_proto_item_set_end)(proto_item*, tvbuff_t *, gint);

typedef proto_item* (*addr_proto_tree_add_none_format)(proto_tree*, int, tvbuff_t*, gint, gint, const char*, ...);

typedef int (*addr_except_init)(void);
typedef void (*addr_except_deinit)(void);
typedef void (*addr_except_rethrow)(except_t *);
typedef void (*addr_except_throwd)(long, long, const char *, void *);
typedef void (*addr_except_throwf)(long, long, const char *, ...);
typedef void (*(*addr_except_unhandled_catcher)(void (*)(except_t *)))(except_t *);
typedef void *(*addr_except_take_data)(except_t *);
typedef void (*addr_except_set_allocator)(void *(*)(size_t), void (*)(void *));
typedef void *(*addr_except_alloc)(size_t);
typedef void (*addr_except_free)(void *);
typedef struct except_stacknode *(*addr_except_pop)(void);
typedef void (*addr_except_setup_try)(struct except_stacknode *, struct except_catch *, const except_id_t [], size_t);

typedef void (*addr_col_set_fence)(column_info*, gint);

typedef struct  {

#include "plugin_api_decls.h"

} plugin_address_table_t;

#else /* ! PLUGINS_NEED_ADDRESS_TABLE */

typedef void	plugin_address_table_t;

#endif /* PLUGINS_NEED_ADDRESS_TABLE */

#endif /* PLUGIN_TABLE_H */
