/* plugin_table.h
 * Table of exported addresses for Ethereal plugins.
 *
 * $Id: plugin_table.h,v 1.2 2000/04/04 21:46:29 guy Exp $
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

typedef void (*addr_dissector_add)(char *, guint32, dissector_t);

typedef proto_tree* (*addr_proto_item_add_subtree)(proto_item*, gint);
typedef proto_item* (*addr_proto_tree_add_item)(proto_tree*, int, gint, gint, ...);
typedef proto_item* (*addr_proto_tree_add_item_hidden)(proto_tree*, int, gint, gint, ...);
typedef proto_item* (*addr_proto_tree_add_protocol_format)(proto_tree*, int, gint, gint, const char*, ...);
typedef proto_item* (*addr_proto_tree_add_bytes_format)(proto_tree*, int, gint, gint, const guint8*, const char*, ...);
typedef proto_item* (*addr_proto_tree_add_time_format)(proto_tree*, int, gint, gint, struct timeval*, const char*, ...);
typedef proto_item* (*addr_proto_tree_add_ipxnet_format)(proto_tree*, int, gint, gint, guint32, const char*, ...);
typedef proto_item* (*addr_proto_tree_add_ipv4_format)(proto_tree*, int, gint, gint, guint32, const char*, ...);
typedef proto_item* (*addr_proto_tree_add_ipv6_format)(proto_tree*, int, gint, gint, guint8*, const char*, ...);
typedef proto_item* (*addr_proto_tree_add_ether_format)(proto_tree*, int, gint, gint, guint8*, const char*, ...);
typedef proto_item* (*addr_proto_tree_add_string_format)(proto_tree*, int, gint, gint, const char*, const char*, ...);
typedef proto_item* (*addr_proto_tree_add_boolean_format)(proto_tree*, int, gint, gint, guint32, const char*, ...);
typedef proto_item* (*addr_proto_tree_add_uint_format)(proto_tree*, int, gint, gint, guint32, const char*, ...);
typedef proto_item* (*addr_proto_tree_add_text)(proto_tree*, gint, gint, const char*, ...);
typedef proto_item* (*addr_proto_tree_add_notext)(proto_tree*, gint, gint);

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

	addr_proto_item_add_subtree		p_proto_item_add_subtree;
	addr_proto_tree_add_item		p_proto_tree_add_item;
	addr_proto_tree_add_item_hidden		p_proto_tree_add_item_hidden;
	addr_proto_tree_add_protocol_format	p_proto_tree_add_protocol_format;
	addr_proto_tree_add_bytes_format	p_proto_tree_add_bytes_format;
	addr_proto_tree_add_time_format		p_proto_tree_add_time_format;
	addr_proto_tree_add_ipxnet_format	p_proto_tree_add_ipxnet_format;
	addr_proto_tree_add_ipv4_format		p_proto_tree_add_ipv4_format;
	addr_proto_tree_add_ipv6_format		p_proto_tree_add_ipv6_format;
	addr_proto_tree_add_ether_format	p_proto_tree_add_ether_format;
	addr_proto_tree_add_string_format	p_proto_tree_add_string_format;
	addr_proto_tree_add_boolean_format	p_proto_tree_add_boolean_format;
	addr_proto_tree_add_uint_format		p_proto_tree_add_uint_format;
	addr_proto_tree_add_text		p_proto_tree_add_text;
	addr_proto_tree_add_notext		p_proto_tree_add_notext;
} plugin_address_table_t;

#else /* ! PLUGINS_NEED_ACCESS_TABLE */

typedef void	plugin_address_table_t;

#endif
