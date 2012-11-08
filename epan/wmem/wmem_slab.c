/* wmem_slab.c
 * Wireshark Memory Manager Slab Allocator
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <string.h>
#include <glib.h>

#include "wmem_core.h"
#include "wmem_slab.h"

typedef struct _wmem_slab_chunk_t {
    struct _wmem_slab_chunk_t *next;
} wmem_slab_chunk_t;

struct _wmem_slab_t {
    size_t             chunk_size;
    wmem_slab_chunk_t *free_list;

    wmem_allocator_t  *allocator;
};

/* arbitrary, nice round value */
#define WMEM_CHUNKS_PER_ALLOC 8

static void
wmem_slab_alloc_chunks(wmem_slab_t *slab)
{
    guint              i;
    guint8            *chunks;
    wmem_slab_chunk_t *chunk;

    /* We use a guint8 so that all the necessary pointer arithmetic is easy */
    chunks = (guint8*) wmem_alloc(slab->allocator,
                                  slab->chunk_size * WMEM_CHUNKS_PER_ALLOC);

    /* Now pick each chunk out of the allocated block and add it to the
     * slab's free_list */
    for (i=0; i<WMEM_CHUNKS_PER_ALLOC; i++) {
        chunk = (wmem_slab_chunk_t *) (chunks + (i * slab->chunk_size));
        chunk->next = slab->free_list;
        slab->free_list = chunk;
    }
}

void *
wmem_slab_alloc(wmem_slab_t *slab)
{
    wmem_slab_chunk_t *chunk;

    if (slab->free_list == NULL) {
        wmem_slab_alloc_chunks(slab);
    }

    chunk = slab->free_list;
    slab->free_list = chunk->next;

    return (void *) chunk;
}

void
wmem_slab_free(wmem_slab_t *slab, void *object)
{
    wmem_slab_chunk_t *chunk;
    chunk = (wmem_slab_chunk_t *) object;

    chunk->next = slab->free_list;
    slab->free_list = chunk;
}

wmem_slab_t *
wmem_create_slab(wmem_allocator_t *allocator, const size_t chunk_size)
{
    wmem_slab_t *slab;
    
    slab = wmem_alloc(allocator, sizeof(wmem_slab_t));

    slab->chunk_size = (chunk_size > sizeof(wmem_slab_chunk_t)) ?
                            chunk_size :
                            sizeof(wmem_slab_chunk_t);
    slab->free_list  = NULL;
    slab->allocator  = allocator;

    return slab;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
