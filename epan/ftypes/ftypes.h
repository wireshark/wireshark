/* ftypes.h
 * Definitions for field types
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
#include "../wmem/wmem.h"
#include "ws_symbol_export.h"

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
	FT_UINT24,	/* really a UINT32, but displayed as 6 hex-digits if FD_HEX*/
	FT_UINT32,
	FT_UINT40,	/* really a UINT64, but displayed as 10 hex-digits if FD_HEX*/
	FT_UINT48,	/* really a UINT64, but displayed as 12 hex-digits if FD_HEX*/
	FT_UINT56,	/* really a UINT64, but displayed as 14 hex-digits if FD_HEX*/
	FT_UINT64,
	FT_INT8,
	FT_INT16,
	FT_INT24,	/* same as for UINT24 */
	FT_INT32,
	FT_INT40, /* same as for UINT40 */
	FT_INT48, /* same as for UINT48 */
	FT_INT56, /* same as for UINT56 */
	FT_INT64,
	FT_IEEE_11073_SFLOAT,
	FT_IEEE_11073_FLOAT,
	FT_FLOAT,
	FT_DOUBLE,
	FT_ABSOLUTE_TIME,
	FT_RELATIVE_TIME,
	FT_STRING,
	FT_STRINGZ,	/* for use with proto_tree_add_item() */
	FT_UINT_STRING,	/* for use with proto_tree_add_item() */
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
	FT_VINES,
	FT_REL_OID,	/* RELATIVE-OID */
	FT_SYSTEM_ID,
	FT_STRINGZPAD,	/* for use with proto_tree_add_item() */
	FT_FCWWN,
	FT_NUM_TYPES /* last item number plus one */
};

#define IS_FT_INT(ft)    ((ft)==FT_INT8||(ft)==FT_INT16||(ft)==FT_INT24||(ft)==FT_INT32||(ft)==FT_INT40||(ft)==FT_INT48||(ft)==FT_INT56||(ft)==FT_INT64)
#define IS_FT_UINT(ft)   ((ft)==FT_UINT8||(ft)==FT_UINT16||(ft)==FT_UINT24||(ft)==FT_UINT32||(ft)==FT_UINT40||(ft)==FT_UINT48||(ft)==FT_UINT56||(ft)==FT_UINT64||(ft)==FT_FRAMENUM)
#define IS_FT_TIME(ft)   ((ft)==FT_ABSOLUTE_TIME||(ft)==FT_RELATIVE_TIME)
#define IS_FT_STRING(ft) ((ft)==FT_STRING||(ft)==FT_STRINGZ||(ft)==FT_STRINGZPAD)

/* field types lengths */
#define FT_ETHER_LEN        6
#define FT_GUID_LEN         16
#define FT_IPv4_LEN         4
#define FT_IPv6_LEN         16
#define FT_IPXNET_LEN       4
#define FT_EUI64_LEN        8
#define FT_AX25_ADDR_LEN    7
#define FT_VINES_ADDR_LEN	  6
#define FT_FCWWN_LEN        8

typedef enum ftenum ftenum_t;

enum ft_framenum_type {
    FT_FRAMENUM_NONE,
    FT_FRAMENUM_REQUEST,
    FT_FRAMENUM_RESPONSE,
    FT_FRAMENUM_ACK,
    FT_FRAMENUM_DUP_ACK,
    FT_FRAMENUM_NUM_TYPES /* last item number plus one */
};

typedef enum ft_framenum_type ft_framenum_type_t;

struct _ftype_t;
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

/* given two types, are they similar - for example can two
 * duplicate fields be registered of these two types. */
gboolean
ftype_similar_types(const enum ftenum ftype_a, const enum ftenum ftype_b);

/* Return a string representing the name of the type */
WS_DLL_PUBLIC
const char*
ftype_name(ftenum_t ftype);

/* Return a string presenting a "pretty" representation of the
 * name of the type. The pretty name means more to the user than
 * that "FT_*" name. */
WS_DLL_PUBLIC
const char*
ftype_pretty_name(ftenum_t ftype);

/* Returns length of field in packet, or 0 if not determinable/defined. */
int
ftype_length(ftenum_t ftype);

WS_DLL_PUBLIC
gboolean
ftype_can_slice(enum ftenum ftype);

WS_DLL_PUBLIC
gboolean
ftype_can_eq(enum ftenum ftype);

WS_DLL_PUBLIC
gboolean
ftype_can_ne(enum ftenum ftype);

WS_DLL_PUBLIC
gboolean
ftype_can_gt(enum ftenum ftype);

WS_DLL_PUBLIC
gboolean
ftype_can_ge(enum ftenum ftype);

WS_DLL_PUBLIC
gboolean
ftype_can_lt(enum ftenum ftype);

WS_DLL_PUBLIC
gboolean
ftype_can_le(enum ftenum ftype);

gboolean
ftype_can_bitwise_and(enum ftenum ftype);

WS_DLL_PUBLIC
gboolean
ftype_can_contains(enum ftenum ftype);

WS_DLL_PUBLIC
gboolean
ftype_can_matches(enum ftenum ftype);

/* ---------------- FVALUE ----------------- */

#include <epan/ipv4.h>
#include <epan/ipv6.h>
#include <epan/guid-utils.h>

#include <epan/tvbuff.h>
#include <wsutil/nstime.h>
#include <epan/dfilter/drange.h>

typedef struct _protocol_value_t
{
	tvbuff_t	*tvb;
	gchar		*proto_string;
} protocol_value_t;

typedef struct _fvalue_t {
	ftype_t	*ftype;
	union {
		/* Put a few basic types in here */
		guint32			uinteger;
		gint32			sinteger;
		guint64			integer64;
		guint64			uinteger64;
		gint64			sinteger64;
		gdouble			floating;
		gchar			*string;
		guchar			*ustring;
		GByteArray		*bytes;
		ipv4_addr_and_mask	ipv4;
		ipv6_addr_and_prefix	ipv6;
		e_guid_t		guid;
		nstime_t		time;
        protocol_value_t protocol;
		GRegex			*re;
		guint16			sfloat_ieee_11073;
		guint32			float_ieee_11073;
	} value;

	/* The following is provided for private use
	 * by the fvalue. */
	gboolean	fvalue_gboolean1;

} fvalue_t;

fvalue_t*
fvalue_new(ftenum_t ftype);

void
fvalue_init(fvalue_t *fv, ftenum_t ftype);

WS_DLL_PUBLIC
fvalue_t*
fvalue_from_unparsed(ftenum_t ftype, const char *s, gboolean allow_partial_value, gchar **err_msg);

fvalue_t*
fvalue_from_string(ftenum_t ftype, const char *s, gchar **err_msg);

/* Returns the length of the string required to hold the
 * string representation of the the field value.
 *
 * Returns -1 if the string cannot be represented in the given rtype.
 *
 * The length DOES NOT include the terminating NUL. */
WS_DLL_PUBLIC
int
fvalue_string_repr_len(fvalue_t *fv, ftrepr_t rtype, int field_display);

/* Creates the string representation of the field value.
 * Memory for the buffer is allocated based on wmem allocator
 * provided.
 *
 * field_display parameter should be a BASE_ value (enum field_display_e)
 * BASE_NONE should be used if field information isn't available.
 *
 * Returns NULL if the string cannot be represented in the given rtype.*/
WS_DLL_PUBLIC char *
fvalue_to_string_repr(wmem_allocator_t *scope, fvalue_t *fv, ftrepr_t rtype, int field_display);

WS_DLL_PUBLIC ftenum_t
fvalue_type_ftenum(fvalue_t *fv);

const char*
fvalue_type_name(fvalue_t *fv);

void
fvalue_set_byte_array(fvalue_t *fv, GByteArray *value);

void
fvalue_set_bytes(fvalue_t *fv, const guint8 *value);

void
fvalue_set_guid(fvalue_t *fv, const e_guid_t *value);

void
fvalue_set_time(fvalue_t *fv, const nstime_t *value);

void
fvalue_set_string(fvalue_t *fv, const gchar *value);

void
fvalue_set_protocol(fvalue_t *fv, tvbuff_t *value, const gchar *name);

void
fvalue_set_uinteger(fvalue_t *fv, guint32 value);

void
fvalue_set_sinteger(fvalue_t *fv, gint32 value);

void
fvalue_set_uinteger64(fvalue_t *fv, guint64 value);

void
fvalue_set_sinteger64(fvalue_t *fv, gint64 value);

void
fvalue_set_floating(fvalue_t *fv, gdouble value);

WS_DLL_PUBLIC
gpointer
fvalue_get(fvalue_t *fv);

WS_DLL_PUBLIC guint32
fvalue_get_uinteger(fvalue_t *fv);

WS_DLL_PUBLIC gint32
fvalue_get_sinteger(fvalue_t *fv);

WS_DLL_PUBLIC
guint64
fvalue_get_uinteger64(fvalue_t *fv);

WS_DLL_PUBLIC
gint64
fvalue_get_sinteger64(fvalue_t *fv);

WS_DLL_PUBLIC double
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
fvalue_slice(fvalue_t *fv, drange_t *dr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FTYPES_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
