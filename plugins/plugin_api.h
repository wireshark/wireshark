/* plugin_api.h
 */

#ifndef __PACKET_H__
#include "packet.h"
#endif

#ifdef PLUGINS_NEED_ADDRESS_TABLE
#define DLLEXPORT    __declspec(dllexport)

/* Some OSes (Win32) have DLLs that cannot reference symbols in the parent executable.
   So, the executable needs to provide a table of pointers for the DLL plugin to use. */

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

typedef proto_tree* (*addr_proto_item_add_subtree)(proto_item*, gint);
typedef proto_item* (*addr_proto_tree_add_item)(proto_tree*, int, gint, gint, ...);
typedef proto_item* (*addr_proto_tree_add_item_hidden)(proto_tree*, int, gint, gint, ...);
typedef proto_item* (*addr_proto_tree_add_item_format)(proto_tree*, int, gint, gint, ...);
typedef proto_item* (*addr_proto_tree_add_notext)(proto_tree*, gint, gint, ...);
typedef proto_item* (*addr_proto_tree_add_item_value)(proto_tree*, int, gint, gint, int, int,
				va_list);
extern packet_info *p_pi;

typedef struct  {

	addr_check_col				check_col;
	addr_col_add_fstr			col_add_fstr;
	addr_col_append_fstr			col_append_fstr;
	addr_col_add_str			col_add_str;
	addr_col_append_str			col_append_str;

	addr_dfilter_init			dfilter_init;
	addr_dfilter_cleanup			dfilter_cleanup;

	packet_info				*pi;

	addr_proto_register_protocol		proto_register_protocol;
	addr_proto_register_field_array		proto_register_field_array;
	addr_proto_register_subtree_array	proto_register_subtree_array;

	addr_proto_item_add_subtree		proto_item_add_subtree;
	addr_proto_tree_add_item_value		_proto_tree_add_item_value;
	int					hf_text_only;
} plugin_address_table_t;

/* The parent executable will send us the pointer to a filled in
   plugin_address_table_t struct, and we keep a copy of that pointer
   so that we can use functions in the parent executable. */
void plugin_address_table_init(plugin_address_table_t*);

/* Wrapper functions that use plugin_address_table_t */
gint check_col(frame_data*, gint);
void col_add_fstr(frame_data*, gint, gchar*, ...);
void col_append_fstr(frame_data*, gint, gchar*, ...);
void col_add_str(frame_data*, gint, const gchar*);
void col_append_str(frame_data*, gint, gchar*);

void dfilter_init(void);
void dfilter_cleanup(void);

int proto_register_protocol(char*, char*);
void proto_register_field_array(int, hf_register_info*, int);
void proto_register_subtree_array(int**, int);

proto_tree* proto_item_add_subtree(proto_item*, gint);
proto_item* proto_tree_add_item(proto_tree*, int, gint, gint, ...);
proto_item* proto_tree_add_item_hidden(proto_tree*, int, gint, gint, ...);
proto_item* proto_tree_add_item_format(proto_tree*, int, gint, gint, ...);
proto_item* proto_tree_add_notext(proto_tree*, gint, gint, ...);
proto_item* proto_tree_add_text(proto_tree*, gint, gint, ...);

#define pi	(*p_pi)


#else

/* ! PLUGINS_NEED_ACCESS_TABLE */
#define DLLEXPORT 
typedef void	plugin_address_table_t;
#define plugin_address_table_init(x) ;

#endif

