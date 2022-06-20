/** @file
 * Definitions for field types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __FTYPES_H__
#define __FTYPES_H__

#include <wireshark.h>

#include <wsutil/regex.h>
#include <epan/wmem_scopes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* field types */
enum ftenum {
	FT_NONE,	/* used for text labels with no value */
	FT_PROTOCOL,
	FT_BOOLEAN,	/* TRUE and FALSE come from <glib.h> */
	FT_CHAR,	/* 1-octet character as 0-255 */
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
	FT_STRING,	/* counted string, with no null terminator */
	FT_STRINGZ,	/* null-terminated string */
	FT_UINT_STRING,	/* counted string, with count being the first part of the value */
	FT_ETHER,
	FT_BYTES,
	FT_UINT_BYTES,
	FT_IPv4,
	FT_IPv6,
	FT_IPXNET,
	FT_FRAMENUM,	/* a UINT32, but if selected lets you go to frame with that number */
	FT_GUID,	/* GUID, UUID */
	FT_OID,		/* OBJECT IDENTIFIER */
	FT_EUI64,
	FT_AX25,
	FT_VINES,
	FT_REL_OID,	/* RELATIVE-OID */
	FT_SYSTEM_ID,
	FT_STRINGZPAD,	/* null-padded string */
	FT_FCWWN,
	FT_STRINGZTRUNC,	/* null-truncated string */
	FT_NUM_TYPES /* last item number plus one */
};

#define IS_FT_INT32(ft) \
	((ft) == FT_INT8 ||  \
	 (ft) == FT_INT16 || \
	 (ft) == FT_INT24 || \
	 (ft) == FT_INT32)

#define IS_FT_INT64(ft) \
	((ft) == FT_INT40 || \
	 (ft) == FT_INT48 || \
	 (ft) == FT_INT56 || \
	 (ft) == FT_INT64)

#define IS_FT_INT(ft) (IS_FT_INT32(ft) || IS_FT_INT64(ft))

#define IS_FT_UINT32(ft) \
	((ft) == FT_CHAR ||   \
	 (ft) == FT_UINT8 ||  \
	 (ft) == FT_UINT16 || \
	 (ft) == FT_UINT24 || \
	 (ft) == FT_UINT32 || \
	 (ft) == FT_FRAMENUM)

#define IS_FT_UINT64(ft) \
	((ft) == FT_UINT40 || \
	 (ft) == FT_UINT48 || \
	 (ft) == FT_UINT56 || \
	 (ft) == FT_UINT64)

#define IS_FT_UINT(ft) (IS_FT_UINT32(ft) || IS_FT_UINT64(ft))

#define IS_FT_TIME(ft) \
	((ft) == FT_ABSOLUTE_TIME || (ft) == FT_RELATIVE_TIME)

#define IS_FT_STRING(ft) \
	((ft) == FT_STRING || (ft) == FT_STRINGZ || (ft) == FT_STRINGZPAD || \
	 (ft) == FT_STRINGZTRUNC || (ft) == FT_UINT_STRING)

/* field types lengths */
#define FT_ETHER_LEN		6
#define FT_GUID_LEN		16
#define FT_IPv4_LEN		4
#define FT_IPv6_LEN		16
#define FT_IPXNET_LEN		4
#define FT_EUI64_LEN		8
#define FT_AX25_ADDR_LEN	7
#define FT_VINES_ADDR_LEN	6
#define FT_FCWWN_LEN		8
#define FT_VARINT_MAX_LEN	10	/* Because 64 / 7 = 9 and 64 % 7 = 1, get an uint64 varint need reads up to 10 bytes. */

typedef enum ftenum ftenum_t;

enum ft_framenum_type {
	FT_FRAMENUM_NONE,
	FT_FRAMENUM_REQUEST,
	FT_FRAMENUM_RESPONSE,
	FT_FRAMENUM_ACK,
	FT_FRAMENUM_DUP_ACK,
	FT_FRAMENUM_RETRANS_PREV,
	FT_FRAMENUM_RETRANS_NEXT,
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

/* Initialize the ftypes subsystem. Called once. */
void
ftypes_initialize(void);

void
ftypes_register_pseudofields(void);

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
ftype_can_cmp(enum ftenum ftype);

gboolean
ftype_can_bitwise_and(enum ftenum ftype);

gboolean
ftype_can_unary_minus(enum ftenum ftype);

gboolean
ftype_can_add(enum ftenum ftype);

gboolean
ftype_can_subtract(enum ftenum ftype);

gboolean
ftype_can_multiply(enum ftenum ftype);

gboolean
ftype_can_divide(enum ftenum ftype);

gboolean
ftype_can_modulo(enum ftenum ftype);

WS_DLL_PUBLIC
gboolean
ftype_can_contains(enum ftenum ftype);

WS_DLL_PUBLIC
gboolean
ftype_can_matches(enum ftenum ftype);

WS_DLL_PUBLIC
gboolean
ftype_can_is_zero(enum ftenum ftype);

WS_DLL_PUBLIC
gboolean
ftype_can_is_negative(enum ftenum ftype);

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
	int		length;
	gchar		*proto_string;
	gboolean	tvb_is_private;
} protocol_value_t;

typedef struct _fvalue_t {
	ftype_t	*ftype;
	union {
		/* Put a few basic types in here */
		guint32			uinteger;
		gint32			sinteger;
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
		protocol_value_t 	protocol;
		guint16			sfloat_ieee_11073;
		guint32			float_ieee_11073;
	} value;
} fvalue_t;

fvalue_t*
fvalue_new(ftenum_t ftype);

fvalue_t*
fvalue_dup(const fvalue_t *fv);

void
fvalue_init(fvalue_t *fv, ftenum_t ftype);

void
fvalue_cleanup(fvalue_t *fv);

void
fvalue_free(fvalue_t *fv);

WS_DLL_PUBLIC
fvalue_t*
fvalue_from_literal(ftenum_t ftype, const char *s, gboolean allow_partial_value, gchar **err_msg);

fvalue_t*
fvalue_from_string(ftenum_t ftype, const char *s, gchar **err_msg);

fvalue_t*
fvalue_from_charconst(ftenum_t ftype, unsigned long number, gchar **err_msg);

/* Creates the string representation of the field value.
 * Memory for the buffer is allocated based on wmem allocator
 * provided.
 *
 * field_display parameter should be a BASE_ value (enum field_display_e)
 * BASE_NONE should be used if field information isn't available.
 *
 * Returns NULL if the string cannot be represented in the given rtype.*/
WS_DLL_PUBLIC char *
fvalue_to_string_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype, int field_display);

#define fvalue_to_debug_repr(scope, fv) \
	fvalue_to_string_repr(scope, fv, FTREPR_DFILTER, 0)

WS_DLL_PUBLIC ftenum_t
fvalue_type_ftenum(fvalue_t *fv);

const char*
fvalue_type_name(const fvalue_t *fv);

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
fvalue_set_protocol(fvalue_t *fv, tvbuff_t *value, const gchar *name, int length);

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
const guint8 *
fvalue_get_bytes(fvalue_t *fv);

WS_DLL_PUBLIC
const e_guid_t *
fvalue_get_guid(fvalue_t *fv);

WS_DLL_PUBLIC
const nstime_t *
fvalue_get_time(fvalue_t *fv);

WS_DLL_PUBLIC
const char *
fvalue_get_string(fvalue_t *fv);

WS_DLL_PUBLIC
tvbuff_t *
fvalue_get_protocol(fvalue_t *fv);

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
fvalue_contains(const fvalue_t *a, const fvalue_t *b);

gboolean
fvalue_matches(const fvalue_t *a, const ws_regex_t *re);

gboolean
fvalue_is_zero(const fvalue_t *a);

gboolean
fvalue_is_negative(const fvalue_t *a);

guint
fvalue_length(fvalue_t *fv);

fvalue_t*
fvalue_slice(fvalue_t *fv, drange_t *dr);

fvalue_t*
fvalue_bitwise_and(const fvalue_t *a, const fvalue_t *b, char **err_msg);

fvalue_t*
fvalue_unary_minus(const fvalue_t *fv, char **err_msg);

fvalue_t*
fvalue_add(const fvalue_t *a, const fvalue_t *b, gchar **err_msg);

fvalue_t*
fvalue_subtract(const fvalue_t *a, const fvalue_t *b, gchar **err_msg);

fvalue_t*
fvalue_multiply(const fvalue_t *a, const fvalue_t *b, gchar **err_msg);

fvalue_t*
fvalue_divide(const fvalue_t *a, const fvalue_t *b, gchar **err_msg);

fvalue_t*
fvalue_modulo(const fvalue_t *a, const fvalue_t *b, gchar **err_msg);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FTYPES_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
