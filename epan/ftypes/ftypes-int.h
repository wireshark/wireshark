/*
 * $Id: ftypes-int.h,v 1.5 2002/01/21 07:37:39 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2001 Gerald Combs
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

#ifndef FTYPES_INT_H
#define FTYPES_INT_H

#include <epan/packet.h>
#include "ftypes.h"

typedef void (*FvalueNewFunc)(fvalue_t*);
typedef void (*FvalueFreeFunc)(fvalue_t*);

typedef gboolean (*FvalueFromString)(fvalue_t*, char*, LogFunc);

typedef void (*FvalueSetFunc)(fvalue_t*, gpointer, gboolean);
typedef void (*FvalueSetIntegerFunc)(fvalue_t*, guint32);
typedef void (*FvalueSetFloatingFunc)(fvalue_t*, gdouble);

typedef gpointer (*FvalueGetFunc)(fvalue_t*);
typedef guint32 (*FvalueGetIntegerFunc)(fvalue_t*);
typedef double (*FvalueGetFloatingFunc)(fvalue_t*);

typedef gboolean (*FvalueCmp)(fvalue_t*, fvalue_t*);

typedef guint (*FvalueLen)(fvalue_t*);
typedef void (*FvalueSlice)(fvalue_t*, GByteArray *, guint offset, guint length);

struct _ftype_t {
	const char		*name;
	const char		*pretty_name;
	int			wire_size;
	FvalueNewFunc		new_value;
	FvalueFreeFunc		free_value;
	FvalueFromString	val_from_string;

	/* could be union */
	FvalueSetFunc		set_value;
	FvalueSetIntegerFunc	set_value_integer;
	FvalueSetFloatingFunc	set_value_floating;

	/* could be union */
	FvalueGetFunc		get_value;
	FvalueGetIntegerFunc	get_value_integer;
	FvalueGetFloatingFunc	get_value_floating;

	FvalueCmp		cmp_eq;
	FvalueCmp		cmp_ne;
	FvalueCmp		cmp_gt;
	FvalueCmp		cmp_ge;
	FvalueCmp		cmp_lt;
	FvalueCmp		cmp_le;

	FvalueLen		len;
	FvalueSlice		slice;
};


void
ftype_register(enum ftenum ftype, ftype_t *ft);

#endif
