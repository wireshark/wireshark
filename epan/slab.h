/* slab.h
 * Definitions for very simple slab handling
 *
 * $Id: slab.h,v 1.1 2003/12/02 09:11:16 sahlberg Exp $
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

/* we never free any memory we have allocated, when it is returned to us
   we just store it in the free list until (hopefully) it gets used again
*/
#define SLAB_ALLOC(item, next, list)				\
	if(!list){						\
		int i;						\
		void *tmp;					\
		tmp=g_malloc(100*sizeof(*item));		\
		for(i=0;i<100;i++){				\
			item=tmp;				\
			item=&item[i];				\
			next=list;				\
			list=item;				\
		}						\
	}							\
	item=list;						\
	list=next;

#define SLAB_FREE(item, next, list)			\
	next=list;					\
	list=item;

#endif /* slab.h */
