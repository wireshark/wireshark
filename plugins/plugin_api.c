/* plugin_api.c
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>

#include "plugin_api.h"

static plugin_address_table_t	*patable = NULL;
packet_info			*p_pi;


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

proto_tree*
proto_item_add_subtree(proto_item* pi, gint idx)
{
	patable->proto_item_add_subtree(pi, idx);
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
