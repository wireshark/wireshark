/* slab.h
 * Definitions for very simple slab handling
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

#ifndef __SLAB_H__
#define __SLAB_H__

#define NITEMS_PER_SLAB	100

/*
 * Generate declaration of a union type containing the specified type of
 * slab-allocated item, and a pointer to an object of that type, for use
 * in the macros below.
 */
#define SLAB_ITEM_TYPE_DEFINE(type)			\
	union type ## slab_item {			\
		type slab_item;				\
		union type ## slab_item *next_free;	\
	};

/*
 * Generate definition of the free list pointer.
 */
#define SLAB_FREE_LIST_DEFINE(type)		\
	union type ## slab_item *type ## _free_list = NULL;

/*
 * Generate an external declaration of the free list pointer.
 */
#define SLAB_FREE_LIST_DECLARE(type)		\
	union type ## slab_item *type ## _free_list;

/* we never free any memory we have allocated, when it is returned to us
   we just store it in the free list until (hopefully) it gets used again
*/
#define SLAB_ALLOC(item, type)					\
	if(!type ## _free_list){				\
		int i;						\
		union type ## slab_item *tmp;			\
		tmp=g_malloc(NITEMS_PER_SLAB*sizeof(*tmp));	\
		for(i=0;i<NITEMS_PER_SLAB;i++){			\
			tmp[i].next_free = type ## _free_list;	\
			type ## _free_list = &tmp[i];		\
		}						\
	}							\
	item = &(type ## _free_list->slab_item);		\
	type ## _free_list = type ## _free_list->next_free;

#define SLAB_FREE(item, type)						\
{									\
	((union type ## slab_item *)(void *)item)->next_free = type ## _free_list;	\
	type ## _free_list = (union type ## slab_item *)(void *)item;		\
}

#endif /* slab.h */
