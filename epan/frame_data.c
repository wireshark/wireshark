/* frame_data.c
 * Routines for packet disassembly
 *
 * $Id: frame_data.c,v 1.1 2001/04/01 04:11:50 hagbard Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "frame_data.h"
#include "packet.h"

#include <glib.h>

/* Protocol-specific data attached to a frame_data structure - protocol
   index and opaque pointer. */
typedef struct _frame_proto_data {
  int proto;
  void *proto_data;
} frame_proto_data;

static GMemChunk *frame_proto_data_area = NULL;

/* 
 * Free up any space allocated for frame proto data areas and then 
 * allocate a new area.
 *
 * We can free the area, as the structures it contains are pointed to by
 * frames, that will be freed as well.
 */
static void
packet_init_protocol(void)
{

  if (frame_proto_data_area)
    g_mem_chunk_destroy(frame_proto_data_area);

  frame_proto_data_area = g_mem_chunk_new("frame_proto_data_area",
					  sizeof(frame_proto_data),
					  20 * sizeof(frame_proto_data), /* FIXME*/
					  G_ALLOC_ONLY);

}

void
frame_data_init(void)
{
  	register_init_routine(&packet_init_protocol);
}

void 
frame_data_cleanup(void)
{
  /* this function intentionally left blank :) */
}

/* XXX - I declared this static, because it only seems to be used by
 * p_get_proto_data and p_add_proto_data
 */
static gint p_compare(gconstpointer a, gconstpointer b)
{

  if (((frame_proto_data *)a) -> proto > ((frame_proto_data *)b) -> proto)
    return 1;
  else if (((frame_proto_data *)a) -> proto == ((frame_proto_data *)b) -> proto)
    return 0;
  else
    return -1;

}


void
p_add_proto_data(frame_data *fd, int proto, void *proto_data)
{
  frame_proto_data *p1 = g_mem_chunk_alloc(frame_proto_data_area);
 
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

    fd->pfd = g_slist_remove(fd->pfd, item);

  }

}



