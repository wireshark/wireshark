/* ptvcursor.c
 * 
 * Proto Tree TVBuff cursor
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * $Id: ptvcursor.c,v 1.5 2002/01/10 04:44:34 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2000 Gerald Combs
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

#include "ptvcursor.h"


struct ptvcursor {
	proto_tree	*tree;
	tvbuff_t	*tvb;
	gint		offset;
};


/* Allocates an initializes a ptvcursor_t with 3 variables:
 * 	proto_tree, tvbuff, and offset. */
ptvcursor_t*
ptvcursor_new(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	ptvcursor_t	*ptvc;

	ptvc = g_new(ptvcursor_t, 1);
	ptvc->tree	= tree;
	ptvc->tvb	= tvb;
	ptvc->offset	= offset;
	return ptvc;
}


/* Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* */
proto_item*
ptvcursor_add(ptvcursor_t *ptvc, int hf, gint length, gboolean endianness)
{
	proto_item	*item;

	item = ptvcursor_add_no_advance(ptvc, hf, length, endianness);
	ptvc->offset += proto_item_get_len(item);
	return item;
}

/* Gets data from tvbuff, adds it to proto_tree, *DOES NOT* increment
 * offset, and returns proto_item* */
proto_item*
ptvcursor_add_no_advance(ptvcursor_t* ptvc, int hf, gint length,
		gboolean endianness)
{
	proto_item	*item;

	item = proto_tree_add_item(ptvc->tree, hf, ptvc->tvb, ptvc->offset,
			length, endianness);

	return item;
}

/* Frees memory for ptvcursor_t, but nothing deeper than that. */
void
ptvcursor_free(ptvcursor_t *ptvc)
{
	g_free(ptvc);
}
/* Returns tvbuff. */
tvbuff_t*
ptvcursor_tvbuff(ptvcursor_t* ptvc)
{
	return ptvc->tvb;
}

/* Returns current offset. */
gint
ptvcursor_current_offset(ptvcursor_t* ptvc)
{
	return ptvc->offset;
}
