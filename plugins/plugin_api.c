/* plugin_api.c
 * Routines for Ethereal plugins.
 *
 * $Id: plugin_api.c,v 1.8 2000/05/31 18:32:14 gram Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>

#include "plugin_api.h"

packet_info			*p_pi = NULL;

void
plugin_address_table_init(plugin_address_table_t *pat)
{
	p_pi					= pat->p_pi;
	p_check_col				= pat->p_check_col;
	p_col_add_fstr				= pat->p_col_add_fstr;
	p_col_append_fstr			= pat->p_col_append_fstr;
	p_col_add_str				= pat->p_col_add_str;
	p_col_append_str			= pat->p_col_append_str;
	p_dfilter_init				= pat->p_dfilter_init;
	p_dfilter_cleanup			= pat->p_dfilter_cleanup;
	p_proto_register_protocol		= pat->p_proto_register_protocol;
	p_proto_register_field_array		= pat->p_proto_register_field_array;
	p_proto_register_subtree_array		= pat->p_proto_register_subtree_array;
	p_dissector_add				= pat->p_dissector_add;
	p_heur_dissector_add			= pat->p_heur_dissector_add;
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
	p_proto_tree_add_notext			= pat->p_proto_tree_add_notext;
}
