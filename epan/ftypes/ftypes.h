/* ftypes.h
 * Definitions for field types
 *
 * $Id$
 *
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


#ifndef __FTYPES_H__
#define __FTYPES_H__

#include <glib.h>
#include "../emem.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* field types */
enum ftenum {
	FT_NONE,	/* used for text labels with no value */
	FT_PROTOCOL,
	FT_BOOLEAN,	/* TRUE and FALSE come from <glib.h> */
	FT_UINT8,
	FT_UINT16,
	FT_UINT24,	/* really a UINT32, but displayed as 3 hex-digits if FD_HEX*/
	FT_UINT32,
	FT_UINT64,
	FT_INT8,
	FT_INT16,
	FT_INT24,	/* same as for UINT24 */
	FT_INT32,
	FT_INT64,
	FT_FLOAT,
	FT_DOUBLE,
	FT_ABSOLUTE_TIME,
	FT_RELATIVE_TIME,
	FT_STRING,
	FT_STRINGZ,	/* for use with proto_tree_add_item() */
	FT_UINT_STRING,	/* for use with proto_tree_add_item() */
	/*FT_UCS2_LE, */    /* Unicode, 2 byte, Little Endian     */
	FT_ETHER,
	FT_BYTES,
	FT_UINT_BYTES,
	FT_IPv4,
	FT_IPv6,
	FT_IPXNET,
	FT_FRAMENUM,	/* a UINT32, but if selected lets you go to frame with that number */
	FT_PCRE,	/* a compiled Perl-Compatible Regular Expression object */
	FT_GUID,	/* GUID, UUID */
	FT_OID,		/* OBJECT IDENTIFIER */
	FT_EUI64,
	FT_AX25,
	FT_NUM_TYPES /* last item number plus one */
};

#define IS_FT_INT(ft)    ((ft)==FT_INT8||(ft)==FT_INT16||(ft)==FT_INT24||(ft)==FT_INT32||(ft)==FT_INT64)
#define IS_FT_UINT(ft)   ((ft)==FT_UINT8||(ft)==FT_UINT16||(ft)==FT_UINT24||(ft)==FT_UINT32||(ft)==FT_UINT64||(ft)==FT_FRAMENUM)
#define IS_FT_TIME(ft)   ((ft)==FT_ABSOLUTE_TIME||(ft)==FT_RELATIVE_TIME)
#define IS_FT_STRING(ft) ((ft)==FT_STRING||(ft)==FT_STRINGZ)

/* field types lengths */
#define FT_ETHER_LEN        6
#define FT_GUID_LEN         16
#define FT_IPv4_LEN         4
#define FT_IPv6_LEN         16
#define FT_IPXNET_LEN       4
#define FT_EUI64_LEN        8
#define FT_AX25_ADDR_LEN    7

typedef enum ftenum ftenum_t;
typedef struct _ftype_t ftype_t;

/* String representation types. */
enum ftrepr {
	FTREPR_DISPLAY,
	FTREPR_DFILTER
};

typedef enum ftrepr ftrepr_t;

/* Initialize the ftypes subsytem. Called once. */
void
ftypes_initialize(void);

/* ---------------- FTYPE ----------------- */

/* Return a string representing the name of the type */
const char*
ftype_name(ftenum_t ftype);

/* Return a string presenting a "pretty" representation of the
 * name of the type. The pretty name means more to the user than
 * that "FT_*" name. */
const char*
ftype_pretty_name(ftenum_t ftype);

/* Returns length of field in packet, or 0 if not determinable/defined. */
int
ftype_length(ftenum_t ftype);

gboolean
ftype_can_slice(enum ftenum ftype);

gboolean
ftype_can_eq(enum ftenum ftype);

gboolean
ftype_can_ne(enum ftenum ftype);

gboolean
ftype_can_gt(enum ftenum ftype);

gboolean
ftype_can_ge(enum ftenum ftype);

gboolean
ftype_can_lt(enum ftenum ftype);

gboolean
ftype_can_le(enum ftenum ftype);

gboolean
ftype_can_bitwise_and(enum ftenum ftype);

gboolean
ftype_can_contains(enum ftenum ftype);

gboolean
ftype_can_matches(enum ftenum ftype);

/* ---------------- FVALUE ----------------- */

#include <epan/ipv4.h>
#include <epan/ipv6-utils.h>
#include <epan/guid-utils.h>

#include <epan/tvbuff.h>
#include <epan/nstime.h>
#include <epan/dfilter/drange.h>

typedef struct _fvalue_t {
	ftype_t	*ftype;
	union {
		/* Put a few basic types in here */
		guint32		uinteger;
		gint32		sinteger;
		guint64		integer64;
		gdouble		floating;
		gchar		*string;
		guchar		*ustring;
		GByteArray	*bytes;
		ipv4_addr	ipv4;
		ipv6_addr	ipv6;
		e_guid_t	guid;
		nstime_t	time;
		tvbuff_t	*tvb;
		GRegex	        *re;
	} value;

	/* The following is provided for private use
	 * by the fvalue. */
	gboolean	fvalue_gboolean1;

} fvalue_t;

typedef void (*FvalueNewFunc)(fvalue_t*);
typedef void (*FvalueFreeFunc)(fvalue_t*);
typedef void (*LogFunc)(const char*,...);

typedef gboolean (*FvalueFromUnparsed)(fvalue_t*, char*, gboolean, LogFunc);
typedef gboolean (*FvalueFromString)(fvalue_t*, char*, LogFunc);
typedef void (*FvalueToStringRepr)(fvalue_t*, ftrepr_t, char*);
typedef int (*FvalueStringReprLen)(fvalue_t*, ftrepr_t);

typedef void (*FvalueSetFunc)(fvalue_t*, gpointer, gboolean);
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
	FvalueSetFunc		set_value;
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


fvalue_t*
fvalue_new(ftenum_t ftype);

void
fvalue_init(fvalue_t *fv, ftenum_t ftype);

/* Free all memory used by an fvalue_t. With MSVC and a
 * libwireshark.dll, we need a special declaration.
 */
WS_VAR_IMPORT struct ws_memory_slab fvalue_t_slab;


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
		sl_free(&fvalue_t_slab, fv);			\
	}


fvalue_t*
fvalue_from_unparsed(ftenum_t ftype, char *s, gboolean allow_partial_value, LogFunc logfunc);

fvalue_t*
fvalue_from_string(ftenum_t ftype, char *s, LogFunc logfunc);

/* Returns the length of the string required to hold the
 * string representation of the the field value.
 *
 * Returns -1 if the string cannot be represented in the given rtype.
 *
 * The length DOES NOT include the terminating NUL. */
int
fvalue_string_repr_len(fvalue_t *fv, ftrepr_t rtype);

/* Creates the string representation of the field value.
 * If given non-NULL 'buf', the string is written at the memory
 * location pointed to by 'buf'. If 'buf' is NULL, new memory
 * is malloc'ed and the string representation is written there.
 * The pointer to the beginning of the string representation is
 * returned. If 'buf' was NULL, this points to the newly-allocated
 * memory. if 'buf' was non-NULL, then the return value will be
 * 'buf'.
 *
 * Returns NULL if the string cannot be represented in the given rtype.*/
extern char *
fvalue_to_string_repr(fvalue_t *fv, ftrepr_t rtype, char *buf);

ftype_t*
fvalue_ftype(fvalue_t *fv);

const char*
fvalue_type_name(fvalue_t *fv);

void
fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied);

void
fvalue_set_uinteger(fvalue_t *fv, guint32 value);

void
fvalue_set_sinteger(fvalue_t *fv, gint32 value);

void
fvalue_set_integer64(fvalue_t *fv, guint64 value);

void
fvalue_set_floating(fvalue_t *fv, gdouble value);

gpointer
fvalue_get(fvalue_t *fv);

extern guint32
fvalue_get_uinteger(fvalue_t *fv);

extern gint32
fvalue_get_sinteger(fvalue_t *fv);

guint64
fvalue_get_integer64(fvalue_t *fv);

extern double
fvalue_get_floating(fvalue_t *fv);

gboolean
fvalue_eq(const fvalue_t *a, const fvalue_t *b);

gboolean
fvalue_ne(const fvalue_t *a, const fvalue_t *b);

gboolean
fvalue_gt(const fvalue_t *a, const fvalue_t *b);

gboolean
fvalue_ge(const fvalue_t *a, const fvalue_t *b);

gboolean
fvalue_lt(const fvalue_t *a, const fvalue_t *b);

gboolean
fvalue_le(const fvalue_t *a, const fvalue_t *b);

gboolean
fvalue_bitwise_and(const fvalue_t *a, const fvalue_t *b);

gboolean
fvalue_contains(const fvalue_t *a, const fvalue_t *b);

gboolean
fvalue_matches(const fvalue_t *a, const fvalue_t *b);

guint
fvalue_length(fvalue_t *fv);

fvalue_t*
fvalue_slice(fvalue_t *fv, drange *dr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FTYPES_H__ */
