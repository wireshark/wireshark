/* next_tvb.c
 * Routines for "next tvb" list
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

#include "next_tvb.h"

void next_tvb_init(next_tvb_list_t *list) {
  list->first = NULL;
  list->last = NULL;
  list->count = 0;
}

void next_tvb_add_handle(next_tvb_list_t *list, tvbuff_t *tvb, proto_tree *tree, dissector_handle_t handle) {
  next_tvb_item_t *item;

  item = wmem_new(wmem_packet_scope(), next_tvb_item_t);

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

void next_tvb_add_uint(next_tvb_list_t *list, tvbuff_t *tvb, proto_tree *tree, dissector_table_t table, guint32 uint_val) {
  next_tvb_item_t *item;

  item = wmem_new(wmem_packet_scope(), next_tvb_item_t);

  item->type = NTVB_UINT;
  item->table = table;
  item->uint_val = uint_val;
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

  item = wmem_new(wmem_packet_scope(), next_tvb_item_t);

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
    if (item->tvb && tvb_captured_length(item->tvb)) {
      switch (item->type) {
        case NTVB_HANDLE:
          call_dissector((item->handle) ? item->handle : ((handle) ? handle : data_handle), item->tvb, pinfo, (item->tree) ? item->tree : tree);
          break;
        case NTVB_UINT:
          dissector_try_uint(item->table, item->uint_val, item->tvb, pinfo, (item->tree) ? item->tree : tree);
          break;
        case NTVB_STRING:
          dissector_try_string(item->table, item->string, item->tvb, pinfo, (item->tree) ? item->tree : tree, NULL);
          break;
      }
    }
    item = item->next;
  }
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
