/* next_tvb.h
 * Definitions for "next tvb" list
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/* The buffers returned by these functions are all allocated with a
 * packet lifetime or are static buffers and does not have have to be freed.
 * However, take into account that when the packet dissection
 * completes, these buffers will be automatically reclaimed/freed.
 * If you need the buffer to remain for a longer scope than packet lifetime
 * you must copy the content to an wmem_file_scope() buffer.
 */

#ifndef __NEXT_TVB_H__
#define __NEXT_TVB_H__

#include "ws_symbol_export.h"

typedef enum {
  NTVB_HANDLE,
  NTVB_UINT,
  NTVB_STRING
} next_tvb_call_e;

/* For old code that hasn't yet been changed. */
#define NTVB_PORT	NTVB_UINT

typedef struct next_tvb_item {
  struct next_tvb_item *next;
  struct next_tvb_item *previous;
  next_tvb_call_e type;
  dissector_handle_t handle;
  dissector_table_t table;
  guint32 uint_val;
  const gchar *string;
  tvbuff_t *tvb;
  proto_tree *tree;
} next_tvb_item_t;

typedef struct {
  next_tvb_item_t *first;
  next_tvb_item_t *last;
  int count;
} next_tvb_list_t;

WS_DLL_PUBLIC void next_tvb_init(next_tvb_list_t *list);
WS_DLL_PUBLIC void next_tvb_add_handle(next_tvb_list_t *list, tvbuff_t *tvb, proto_tree *tree, dissector_handle_t handle);
WS_DLL_PUBLIC void next_tvb_add_uint(next_tvb_list_t *list, tvbuff_t *tvb, proto_tree *tree, dissector_table_t table, guint32 uint_val);
WS_DLL_PUBLIC void next_tvb_add_string(next_tvb_list_t *list, tvbuff_t *tvb, proto_tree *tree, dissector_table_t table, const gchar *string);
WS_DLL_PUBLIC void next_tvb_call(next_tvb_list_t *list, packet_info *pinfo, proto_tree *tree, dissector_handle_t handle, dissector_handle_t data_handle);

#endif /* __NEXT_TVB_H__ */
