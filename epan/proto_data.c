/* proto_data.c
 * Protocol-specific data
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/wmem_scopes.h>
#include <epan/packet_info.h>
#include <epan/proto_data.h>
#include <epan/proto.h>

/* Protocol-specific data attached to a frame_data structure - protocol
   index, key for multiple items with the same protocol index,
   and opaque pointer. */
typedef struct _proto_data {
  int   proto;
  uint32_t key;
  void *proto_data;
} proto_data_t;

static int
p_compare(const void *a, const void *b)
{
  const proto_data_t *ap = (const proto_data_t *)a;
  const proto_data_t *bp = (const proto_data_t *)b;

  if (ap -> proto > bp -> proto) {
    return 1;
  } else if (ap -> proto == bp -> proto) {
    if (ap->key > bp->key){
      return 1;
    } else if (ap -> key == bp -> key) {
      return 0;
    }
    return -1;
  } else {
    return -1;
  }
}

void
p_add_proto_data(wmem_allocator_t *scope, struct _packet_info* pinfo, int proto, uint32_t key, void *proto_data)
{
  proto_data_t     *p1;
  wmem_list_t     **proto_list;

  if (scope == pinfo->pool) {
    proto_list = &pinfo->proto_data;
  } else if (scope == wmem_file_scope()) {
    proto_list = &pinfo->fd->pfd;
  } else {
    DISSECTOR_ASSERT(!"invalid wmem scope");
  }

  if (*proto_list == NULL) {
    *proto_list = wmem_list_new(scope);
  }

  p1 = wmem_new(scope, proto_data_t);

  p1->proto = proto;
  p1->key = key;
  p1->proto_data = proto_data;

  /* Add it to the list */
  wmem_list_prepend(*proto_list, p1);
}

void
p_set_proto_data(wmem_allocator_t *scope, struct _packet_info* pinfo, int proto, uint32_t key, void *proto_data)
{
  /* Probably more dissectors should use this instead of p_add_proto_data. */
  proto_data_t  temp;
  wmem_list_t  *proto_list;
  wmem_list_frame_t *item;

  temp.proto = proto;
  temp.key = key;
  temp.proto_data = NULL;

  if (scope == pinfo->pool) {
    proto_list = pinfo->proto_data;
  } else if (scope == wmem_file_scope()) {
    proto_list = pinfo->fd->pfd;
  } else {
    DISSECTOR_ASSERT(!"invalid wmem scope");
  }

  if (proto_list) {
    item = wmem_list_find_custom(proto_list, &temp, p_compare);
    if (item) {
      proto_data_t *pd = (proto_data_t*)wmem_list_frame_data(item);
      pd->proto_data = proto_data;
      return;
    }
  }

  p_add_proto_data(scope, pinfo, proto, key, proto_data);
}

void *
p_get_proto_data(wmem_allocator_t *scope, struct _packet_info* pinfo, int proto, uint32_t key)
{
  proto_data_t  temp, *p1;
  wmem_list_t  *proto_list;
  wmem_list_frame_t *item;

  temp.proto = proto;
  temp.key = key;
  temp.proto_data = NULL;

  if (scope == pinfo->pool) {
    proto_list = pinfo->proto_data;
  } else if (scope == wmem_file_scope()) {
    proto_list = pinfo->fd->pfd;
  } else {
    DISSECTOR_ASSERT(!"invalid wmem scope");
  }

  if (!proto_list)
    return NULL;

  item = wmem_list_find_custom(proto_list, &temp, p_compare);

  if (item) {
    p1 = wmem_list_frame_data(item);
    return p1->proto_data;
  }

  return NULL;
}

void
p_remove_proto_data(wmem_allocator_t *scope, struct _packet_info* pinfo, int proto, uint32_t key)
{
  proto_data_t  temp;
  wmem_list_t  *proto_list;
  wmem_list_frame_t *item;

  temp.proto = proto;
  temp.key = key;
  temp.proto_data = NULL;

  if (scope == pinfo->pool) {
    proto_list = pinfo->proto_data;
  } else if (scope == wmem_file_scope()) {
    proto_list = pinfo->fd->pfd;
  } else {
    DISSECTOR_ASSERT(!"invalid wmem scope");
  }

  if (!proto_list)
    return;

  item = wmem_list_find_custom(proto_list, &temp, p_compare);
  if (item) {
    wmem_list_remove_frame(proto_list, item);
  }
}

GPtrArray *
p_get_proto_names_and_keys(wmem_allocator_t *scope, struct _packet_info* pinfo) {
  wmem_list_t  *proto_list;
  proto_data_t *temp;
  GPtrArray *ret;

  if (scope == pinfo->pool) {
    proto_list = pinfo->proto_data;
  } else if (scope == wmem_file_scope()) {
    proto_list = pinfo->fd->pfd;
  } else {
    DISSECTOR_ASSERT(!"invalid wmem scope");
  }

  if (!proto_list)
    return NULL;

  ret = g_ptr_array_new();

  for (wmem_list_frame_t *frame = wmem_list_head(proto_list);
      frame; frame = wmem_list_frame_next(frame)) {

    temp = wmem_list_frame_data(frame);
    g_ptr_array_add(ret, wmem_strdup_printf(pinfo->pool, "[%s, key %u]",proto_get_protocol_name(temp->proto), temp->key));
  }
  return ret;
}

#define PROTO_DEPTH_KEY 0x3c233fb5 // printf "0x%02x%02x\n" ${RANDOM} ${RANDOM}

void p_set_proto_depth(struct _packet_info *pinfo, int proto, unsigned depth) {
  p_set_proto_data(pinfo->pool, pinfo, proto, PROTO_DEPTH_KEY, GUINT_TO_POINTER(depth));
}

unsigned p_get_proto_depth(struct _packet_info *pinfo, int proto) {
  return GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto, PROTO_DEPTH_KEY));
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
