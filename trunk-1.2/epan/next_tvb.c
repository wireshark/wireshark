/* next_tvb.c
 * Routines for "next tvb" list
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>

#include "next_tvb.h"

void next_tvb_init(next_tvb_list_t *list) {
  list->first = NULL;
  list->last = NULL;
  list->count = 0;
}

void next_tvb_add_handle(next_tvb_list_t *list, tvbuff_t *tvb, proto_tree *tree, dissector_handle_t handle) {
  next_tvb_item_t *item;

  item = ep_alloc(sizeof(next_tvb_item_t));

  item->type = NTVB_HANDLE;
  item->handle = handle;
  item->tvb = tvb;
  item->tree = tree;

  if (list->last) {
    list->last->next = item;
  } else {
    list->first = item;
  }
  item->next = NULL;
  item->previous = list->last;
  list->last = item;
  list->count++;
}

void next_tvb_add_port(next_tvb_list_t *list, tvbuff_t *tvb, proto_tree *tree, dissector_table_t table, guint32 port) {
  next_tvb_item_t *item;

  item = ep_alloc(sizeof(next_tvb_item_t));

  item->type = NTVB_PORT;
  item->table = table;
  item->port = port;
  item->tvb = tvb;
  item->tree = tree;

  if (list->last) {
    list->last->next = item;
  } else {
    list->first = item;
  }
  item->next = NULL;
  item->previous = list->last;
  list->last = item;
  list->count++;
}

void next_tvb_add_string(next_tvb_list_t *list, tvbuff_t *tvb, proto_tree *tree, dissector_table_t table, const gchar *string) {
  next_tvb_item_t *item;

  item = ep_alloc(sizeof(next_tvb_item_t));

  item->type = NTVB_STRING;
  item->table = table;
  item->string = string;
  item->tvb = tvb;
  item->tree = tree;

  if (list->last) {
    list->last->next = item;
  } else {
    list->first = item;
  }
  item->next = NULL;
  item->previous = list->last;
  list->last = item;
  list->count++;
}

void next_tvb_call(next_tvb_list_t *list, packet_info *pinfo, proto_tree *tree, dissector_handle_t handle, dissector_handle_t data_handle) {
  next_tvb_item_t *item;

  item = list->first;
  while (item) {
    if (item->tvb && tvb_length(item->tvb)) {
      switch (item->type) {
        case NTVB_HANDLE:
          call_dissector((item->handle) ? item->handle : ((handle) ? handle : data_handle), item->tvb, pinfo, (item->tree) ? item->tree : tree);
          break;
        case NTVB_PORT:
          dissector_try_port(item->table, item->port, item->tvb, pinfo, (item->tree) ? item->tree : tree);
          break;
        case NTVB_STRING:
          dissector_try_string(item->table, item->string, item->tvb, pinfo, (item->tree) ? item->tree : tree);
          break;
      }
    }
    item = item->next;
  }
}

