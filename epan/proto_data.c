/* proto_data.c
 * Protocol-specific data
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

#include "config.h"

#include <glib.h>

#if 0
#include <epan/epan.h>
#include <wiretap/wtap.h>
#endif
#include <epan/wmem/wmem.h>
#include <epan/packet_info.h>
#include <epan/proto_data.h>
#include <epan/proto.h>
#if 0
#include <epan/packet.h>
#endif
#if 0
#include <epan/timestamp.h>
#endif

/* Protocol-specific data attached to a frame_data structure - protocol
   index and opaque pointer. */
typedef struct _proto_data {
  int   proto;
  guint32 key;
  void *proto_data;
} proto_data_t;

static gint
p_compare(gconstpointer a, gconstpointer b)
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
p_add_proto_data(wmem_allocator_t *tmp_scope, struct _packet_info* pinfo, int proto, guint32 key, void *proto_data)
{
  proto_data_t     *p1;
  GSList          **proto_list;
  wmem_allocator_t *scope;

  if (tmp_scope == pinfo->pool) {
    scope = tmp_scope;
    proto_list = &pinfo->proto_data;
  } else {
    scope = wmem_file_scope();
    proto_list = &pinfo->fd->pfd;
  }

  p1 = (proto_data_t *)wmem_alloc(scope, sizeof(proto_data_t));

  p1->proto = proto;
  p1->key = key;
  p1->proto_data = proto_data;

  /* Add it to the GSLIST */
  *proto_list = g_slist_prepend(*proto_list, p1);
}

void *
p_get_proto_data(wmem_allocator_t *scope, struct _packet_info* pinfo, int proto, guint32 key)
{
  proto_data_t  temp, *p1;
  GSList       *item;

  temp.proto = proto;
  temp.key = key;
  temp.proto_data = NULL;

  if (scope == pinfo->pool) {
    item = g_slist_find_custom(pinfo->proto_data, &temp, p_compare);
  } else {
    item = g_slist_find_custom(pinfo->fd->pfd, &temp, p_compare);
  }

  if (item) {
    p1 = (proto_data_t *)item->data;
    return p1->proto_data;
  }

  return NULL;
}

void
p_remove_proto_data(wmem_allocator_t *scope, struct _packet_info* pinfo, int proto, guint32 key)
{
  proto_data_t  temp;
  GSList       *item;
  GSList      **proto_list;

  temp.proto = proto;
  temp.key = key;
  temp.proto_data = NULL;

  if (scope == pinfo->pool) {
    item = g_slist_find_custom(pinfo->fd->pfd, &temp, p_compare);
    proto_list = &pinfo->proto_data;
  } else {
    item = g_slist_find_custom(pinfo->fd->pfd, &temp, p_compare);
    proto_list = &pinfo->fd->pfd;
  }

  if (item) {
    *proto_list = g_slist_remove(*proto_list, item->data);
  }
}

gchar *
p_get_proto_name_and_key(wmem_allocator_t *scope, struct _packet_info* pinfo, guint pfd_index){
  proto_data_t  *temp;

  if (scope == pinfo->pool) {
    temp = (proto_data_t *)g_slist_nth_data(pinfo->proto_data, pfd_index);
  } else {
    temp = (proto_data_t *)g_slist_nth_data(pinfo->fd->pfd, pfd_index);
  }

  return wmem_strdup_printf(wmem_packet_scope(),"[%s, key %u]",proto_get_protocol_name(temp->proto), temp->key);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
