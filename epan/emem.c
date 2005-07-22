/* emem.c
 * Ethereal memory management and garbage collection functions
 * Ronnie Sahlberg 2005
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <stdio.h>
#include <malloc.h>
#include <glib.h>
#include "emem.h"

/* When required, allocate more memory from the OS in this size chunks */
#define EMEM_PACKET_CHUNK_SIZE 10485760

typedef struct _emem_chunk_t {
	struct _emem_chunk_t *next;
	unsigned int	amount_free;
	unsigned int	free_offset;
	char *buf;
} emem_chunk_t;

typedef struct _emem_header_t {
  emem_chunk_t *free_list;
  emem_chunk_t *used_list;
} emem_header_t;

static emem_header_t emem_packet_mem;

/* Initialize the packet-lifetime memory allocation pool.
 * This function should be called only once when Etehreal or Tethereal starts
 * up.
 */
void
ep_init_chunk(void)
{
	emem_packet_mem.free_list=NULL;	
	emem_packet_mem.used_list=NULL;	
}

/* allocate 'size' amount of memory with an allocation lifetime until the
 * next packet.
 */
void *
ep_alloc(size_t size)
{
	void *buf;

	/* round up to 8 byte boundary */
	if(size&0x07){
		size=(size+7)&0xfffffff8;
	}

	/* make sure we dont try to allocate too much (arbitrary limit) */
	g_assert(size<(EMEM_PACKET_CHUNK_SIZE>>2));

	/* we dont have any free data, so we must allocate a new one */
	if(!emem_packet_mem.free_list){
		emem_chunk_t *npc;
		npc=g_malloc(sizeof(emem_chunk_t));
		npc->next=NULL;
		npc->amount_free=EMEM_PACKET_CHUNK_SIZE;
		npc->free_offset=0;
		npc->buf=g_malloc(EMEM_PACKET_CHUNK_SIZE);
		emem_packet_mem.free_list=npc;
	}

	/* oops, we need to allocate more memory to serve this request
         * than we have free. move this node to the used list and try again
	 */
	if(size>emem_packet_mem.free_list->amount_free){
		emem_chunk_t *npc;
		npc=emem_packet_mem.free_list;
		emem_packet_mem.free_list=emem_packet_mem.free_list->next;
		npc->next=emem_packet_mem.used_list;
		emem_packet_mem.used_list=npc;
	}

	/* we dont have any free data, so we must allocate a new one */
	if(!emem_packet_mem.free_list){
		emem_chunk_t *npc;
		npc=g_malloc(sizeof(emem_chunk_t));
		npc->next=NULL;
		npc->amount_free=EMEM_PACKET_CHUNK_SIZE;
		npc->free_offset=0;
		npc->buf=g_malloc(EMEM_PACKET_CHUNK_SIZE);
		emem_packet_mem.free_list=npc;
	}


	buf=emem_packet_mem.free_list->buf+emem_packet_mem.free_list->free_offset;

	emem_packet_mem.free_list->amount_free-=size;
	emem_packet_mem.free_list->free_offset+=size;

	return buf;
}

/* release all allocated memory back to the pool.
 */
void
ep_free_all(void)
{
	emem_chunk_t *npc;

	/* move all used chunks ove to the free list */
	while(emem_packet_mem.used_list){
		npc=emem_packet_mem.used_list;
		emem_packet_mem.used_list=emem_packet_mem.used_list->next;
		npc->next=emem_packet_mem.free_list;
		emem_packet_mem.free_list=npc;
	}

	/* clear them all out */
	for(npc=emem_packet_mem.free_list;npc;npc=npc->next){
		npc->amount_free=EMEM_PACKET_CHUNK_SIZE;
		npc->free_offset=0;
	}
}
		


