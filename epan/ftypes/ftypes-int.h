/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef FTYPES_INT_H
#define FTYPES_INT_H

#include <epan/packet.h>
#include "ftypes.h"


void
ftype_register(enum ftenum ftype, ftype_t *ft);

/* These are the ftype registration functions that need to be called.
 * This list and the initialization function could be produced
 * via a script, like the dissector registration, but there's so few
 * that I don't mind doing it by hand for now. */
void ftype_register_bytes(void);
void ftype_register_double(void);
void ftype_register_integers(void);
void ftype_register_ipv4(void);
void ftype_register_ipv6(void);
void ftype_register_guid(void);
void ftype_register_none(void);
void ftype_register_string(void);
void ftype_register_time(void);
void ftype_register_tvbuff(void);
void ftype_register_pcre(void);

typedef void (*FvalueNewFunc)(fvalue_t*);
typedef void (*FvalueFreeFunc)(fvalue_t*);

typedef gboolean (*FvalueFromUnparsed)(fvalue_t*, const char*, gboolean, LogFunc);
typedef gboolean (*FvalueFromString)(fvalue_t*, const char*, LogFunc);
typedef void (*FvalueToStringRepr)(fvalue_t*, ftrepr_t, char*volatile);
typedef int (*FvalueStringReprLen)(fvalue_t*, ftrepr_t);

typedef void (*FvalueSetByteArrayFunc)(fvalue_t*, GByteArray *);
typedef void (*FvalueSetBytesFunc)(fvalue_t*, const guint8 *);
typedef void (*FvalueSetGuidFunc)(fvalue_t*, const e_guid_t *);
typedef void (*FvalueSetTimeFunc)(fvalue_t*, const nstime_t *);
typedef void (*FvalueSetStringFunc)(fvalue_t*, const gchar *value);
typedef void (*FvalueSetTvbuffFunc)(fvalue_t*, tvbuff_t *value);
typedef void (*FvalueSetUnsignedIntegerFunc)(fvalue_t*, guint32);
typedef void (*FvalueSetSignedIntegerFunc)(fvalue_t*, gint32);
typedef void (*FvalueSetInteger64Func)(fvalue_t*, guint64);
typedef void (*FvalueSetFloatingFunc)(fvalue_t*, gdouble);

typedef gpointer (*FvalueGetFunc)(fvalue_t*);
typedef guint32 (*FvalueGetUnsignedIntegerFunc)(fvalue_t*);
typedef gint32  (*FvalueGetSignedIntegerFunc)(fvalue_t*);
typedef guint64 (*FvalueGetInteger64Func)(fvalue_t*);
typedef double (*FvalueGetFloatingFunc)(fvalue_t*);

typedef gboolean (*FvalueCmp)(const fvalue_t*, const fvalue_t*);

typedef guint (*FvalueLen)(fvalue_t*);
typedef void (*FvalueSlice)(fvalue_t*, GByteArray *, guint offset, guint length);

struct _ftype_t {
	ftenum_t		ftype;
	const char		*name;
	const char		*pretty_name;
	int			wire_size;
	FvalueNewFunc		new_value;
	FvalueFreeFunc		free_value;
	FvalueFromUnparsed	val_from_unparsed;
	FvalueFromString	val_from_string;
	FvalueToStringRepr	val_to_string_repr;
	FvalueStringReprLen	len_string_repr;

	/* could be union */
	FvalueSetByteArrayFunc	set_value_byte_array;
	FvalueSetBytesFunc	set_value_bytes;
	FvalueSetGuidFunc	set_value_guid;
	FvalueSetTimeFunc	set_value_time;
	FvalueSetStringFunc	set_value_string;
	FvalueSetTvbuffFunc	set_value_tvbuff;
	FvalueSetUnsignedIntegerFunc	set_value_uinteger;
	FvalueSetSignedIntegerFunc		set_value_sinteger;
	FvalueSetInteger64Func	set_value_integer64;
	FvalueSetFloatingFunc	set_value_floating;

	/* could be union */
	FvalueGetFunc		get_value;
	FvalueGetUnsignedIntegerFunc	get_value_uinteger;
	FvalueGetSignedIntegerFunc		get_value_sinteger;
	FvalueGetInteger64Func	get_value_integer64;
	FvalueGetFloatingFunc	get_value_floating;

	FvalueCmp		cmp_eq;
	FvalueCmp		cmp_ne;
	FvalueCmp		cmp_gt;
	FvalueCmp		cmp_ge;
	FvalueCmp		cmp_lt;
	FvalueCmp		cmp_le;
	FvalueCmp		cmp_bitwise_and;
	FvalueCmp		cmp_contains;
	FvalueCmp		cmp_matches;

	FvalueLen		len;
	FvalueSlice		slice;
};

/* Free all memory used by an fvalue_t. With MSVC and a
 * libwireshark.dll, we need a special declaration.
 */

#define FVALUE_CLEANUP(fv)					\
	{							\
		register FvalueFreeFunc	free_value;		\
		free_value = (fv)->ftype->free_value;	\
		if (free_value) {				\
			free_value((fv));			\
		}						\
	}

#define FVALUE_FREE(fv)						\
	{							\
		FVALUE_CLEANUP(fv)				\
		g_slice_free(fvalue_t, fv);			\
	}

#endif
