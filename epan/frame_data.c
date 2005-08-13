/* frame_data.c
 * Routines for packet disassembly
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "frame_data.h"
#include "packet.h"
#include "emem.h"

#include <glib.h>

/* Protocol-specific data attached to a frame_data structure - protocol
   index and opaque pointer. */
typedef struct _frame_proto_data {
  int proto;
  void *proto_data;
} frame_proto_data;

/* XXX - I declared this static, because it only seems to be used by
 * p_get_proto_data and p_add_proto_data
 */
static gint p_compare(gconstpointer a, gconstpointer b)
{
  const frame_proto_data *ap = (const frame_proto_data *)a;
  const frame_proto_data *bp = (const frame_proto_data *)b;

  if (ap -> proto > bp -> proto)
    return 1;
  else if (ap -> proto == bp -> proto)
    return 0;
  else
    return -1;

}


void
p_add_proto_data(frame_data *fd, int proto, void *proto_data)
{
  frame_proto_data *p1 = se_alloc(sizeof(frame_proto_data));

  g_assert(p1 != NULL);

  p1 -> proto = proto;
  p1 -> proto_data = proto_data;

  /* Add it to the GSLIST */

  fd -> pfd = g_slist_insert_sorted(fd -> pfd,
				    (gpointer *)p1,
				    p_compare);

}

void *
p_get_proto_data(frame_data *fd, int proto)
{
  frame_proto_data temp, *p1;
  GSList *item;

  temp.proto = proto;
  temp.proto_data = NULL;

  item = g_slist_find_custom(fd->pfd, (gpointer *)&temp, p_compare);

  if (item) {
    p1 = (frame_proto_data *)item->data;
    return p1->proto_data;
  }

  return NULL;

}

void
p_rem_proto_data(frame_data *fd, int proto)
{
  frame_proto_data temp;
  GSList *item;

  temp.proto = proto;
  temp.proto_data = NULL;

  item = g_slist_find_custom(fd->pfd, (gpointer *)&temp, p_compare);

  if (item) {
    fd->pfd = g_slist_remove(fd->pfd, item->data);
  }
}
