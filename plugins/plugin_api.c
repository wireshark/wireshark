/* plugin_api.c
 * Routines for Ethereal plugins.
 *
 * $Id: plugin_api.c,v 1.4 2000/02/12 11:24:24 guy Exp $
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

static plugin_address_table_t	*patable = NULL;
packet_info			*p_pi = NULL;


#ifdef pi
#undef pi
#endif

void
plugin_address_table_init(plugin_address_table_t *pat)
{
	patable = pat;
	p_pi = pat->pi;
}

gint
check_col(frame_data* fd, gint col)
{
	return patable->check_col(fd, col);
}

/*void col_add_fstr(frame_data*, gint, gchar*, ...);
void col_append_fstr(frame_data*, gint, gchar*, ...);*/

void
col_add_str(frame_data* fd, gint col, const gchar* str)
{
	patable->col_add_str(fd, col, str);
}

void
col_append_str(frame_data* fd, gint col, gchar* str)
{
	patable->col_append_str(fd, col, str);
}

void
dfilter_init(void)
{
	patable->dfilter_init();
}

void
dfilter_cleanup(void)
{
	patable->dfilter_cleanup();
}

int
proto_register_protocol(char* name, char* abbrev)
{
	return patable->proto_register_protocol(name, abbrev);
}

void
proto_register_field_array(int parent, hf_register_info* hf, int num_records)
{
	patable->proto_register_field_array(parent, hf, num_records);
}

void
proto_register_subtree_array(int** indices, int num_indices)
{
	patable->proto_register_subtree_array(indices, num_indices);
}

proto_tree *
proto_item_add_subtree(proto_item* pi, gint idx)
{
	return patable->proto_item_add_subtree(pi, idx);
}

proto_item *
proto_tree_add_item(proto_tree *tree, int hfindex, gint start, gint length, ...)
{
	proto_item	*pi;
	va_list		ap;

	va_start(ap, length);
	pi = patable->_proto_tree_add_item_value(tree, hfindex, start, length, 0, 1, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_item_hidden(proto_tree *tree, int hfindex, gint start, gint length, ...)
{
	proto_item	*pi;
	va_list		ap;

	va_start(ap, length);
	pi = patable->_proto_tree_add_item_value(tree, hfindex, start, length, 0, 0, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_item_format(proto_tree *tree, int hfindex, gint start, gint length, ...)
{
	proto_item	*pi;
	va_list		ap;

	va_start(ap, length);
	pi = patable->_proto_tree_add_item_value(tree, hfindex, start, length, 1, 1, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_notext(proto_tree *tree, gint start, gint length, ...)
{
	proto_item	*pi;
	va_list		ap;

	va_start(ap, length);
	pi = patable->_proto_tree_add_item_value(tree, patable->hf_text_only, start, length, 0, 1, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_text(proto_tree *tree, gint start, gint length, ...)
{
	proto_item	*pi;
	va_list		ap;

	va_start(ap, length);
	pi = patable->_proto_tree_add_item_value(tree, patable->hf_text_only, start, length, 1, 1, ap);
	va_end(ap);

	return pi;
}
