/* slab.h
 * Definitions for very simple slab handling
 *
 * $Id: slab.h,v 1.2 2003/12/03 08:53:36 guy Exp $
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

#ifndef __SLAB_H__
#define __SLAB_H__

#define NITEMS_PER_SLAB	100

typedef struct _freed_item {
	struct _freed_item *next;
} freed_item_t;

/* we never free any memory we have allocated, when it is returned to us
   we just store it in the free list until (hopefully) it gets used again
*/
#define SLAB_ALLOC(item, list)					\
	if(!list){						\
		int i;						\
		char *tmp;					\
		tmp=(char *)g_malloc(NITEMS_PER_SLAB*		\
		    ((sizeof(*item) > sizeof(freed_item_t)) ?	\
			sizeof(*item) : sizeof(freed_item_t)));	\
		for(i=0;i<NITEMS_PER_SLAB;i++){			\
			item=(void *)tmp;			\
			((freed_item_t *)((void *)item))->next=	\
			    (freed_item_t *)((void *)list);	\
			list=item;				\
			tmp+=					\
			    ((sizeof(*item) > sizeof(freed_item_t)) ?\
				sizeof(*item) : sizeof(freed_item_t));\
		}						\
	}							\
	item=list;						\
	list=(void *)(((freed_item_t *)((void *)item))->next);

#define SLAB_FREE(item, list)				\
{							\
	((freed_item_t *)((void *)item))->next=		\
	    (freed_item_t *)((void *)list);		\
	list=item;					\
}

#endif /* slab.h */
