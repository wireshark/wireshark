/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <errno.h>
#include "ftypes-int.h"
#include <epan/addr_resolv.h>
#include <epan/strutil.h>
#include <epan/to_str.h>

#include <wsutil/pint.h>
#include <wsutil/safe-math.h>

static bool
binary_strtoll(const char *s, int64_t *ptr, char **err_msg);

static bool
binary_strtoull(const char *s, uint64_t *ptr, char **err_msg);

static void
int_fvalue_new(fvalue_t *fv)
{
	memset(&fv->value, 0, sizeof(fv->value));
}

static void
set_uinteger(fvalue_t *fv, uint32_t value)
{
	fv->value.uinteger = value;
}

static void
set_sinteger(fvalue_t *fv, int32_t value)
{
	fv->value.sinteger = value;
}


static uint32_t
get_uinteger(fvalue_t *fv)
{
	return fv->value.uinteger;
}

static int32_t
get_sinteger(fvalue_t *fv)
{
	return fv->value.sinteger;
}

static bool
_uint_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg,
		   uint64_t max)
{
	uint64_t value;

	if (!binary_strtoull(s, &value, err_msg))
		return false;

	if (value > max) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" too big for this field, maximum %"PRIu64".", s, max);
		return false;
	}

	fv->value.uinteger = (uint32_t)value;
	return true;
}

static bool
uint32_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _uint_from_literal (fv, s, allow_partial_value, err_msg, UINT32_MAX);
}

static bool
uint24_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _uint_from_literal (fv, s, allow_partial_value, err_msg, 0xFFFFFF);
}

static bool
uint16_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _uint_from_literal (fv, s, allow_partial_value, err_msg, UINT16_MAX);
}

static bool
uint8_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _uint_from_literal (fv, s, allow_partial_value, err_msg, UINT8_MAX);
}

static bool
uint_from_charconst(fvalue_t *fv, unsigned long num, char **err_msg _U_)
{
	fv->value.uinteger = (uint32_t)num;
	return true;
}

static bool
_sint_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg,
		   int64_t max, int64_t min)
{
	int64_t value;

	if (!binary_strtoll(s, &value, err_msg))
		return false;

	if (value > max) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" too big for this field, maximum %"PRId64".",
				s, max);
		return false;
	}
	else if (value < min) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" too small for this field, minimum %"PRId64".",
				s, min);
		return false;
	}

	fv->value.sinteger = (int32_t)value;
	return true;
}

static bool
sint32_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _sint_from_literal (fv, s, allow_partial_value, err_msg, INT32_MAX, INT32_MIN);
}

static bool
sint24_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _sint_from_literal (fv, s, allow_partial_value, err_msg, 0x7FFFFF, -0x800000);
}

static bool
sint16_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _sint_from_literal (fv, s, allow_partial_value, err_msg, INT16_MAX, INT16_MIN);
}

static bool
sint8_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _sint_from_literal (fv, s, allow_partial_value, err_msg, INT8_MAX, INT8_MIN);
}

static bool
sint_from_charconst(fvalue_t *fv, unsigned long num, char **err_msg _U_)
{
	fv->value.sinteger = (int32_t)num;
	return true;
}

static char *
integer_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	uint32_t val;

	size_t size = 11 + 1; /* enough for 2^31-1, in decimal */
	char *result = wmem_alloc(scope, size);
	char *buf = result;

	if (fv->value.sinteger < 0) {
		*buf++ = '-';
		val = -fv->value.sinteger;
	} else {
		val = fv->value.sinteger;
	}
	guint32_to_str_buf(val, buf, size);
	return result;
}

static char *
uinteger_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display)
{
	size_t size = 10 + 1; /* enough for 2^32-1, in decimal or 0xXXXXXXXX */
	char *result = wmem_alloc(scope, size);
	char *buf = result;

	if ((field_display & 0xff) == BASE_HEX ||
			(field_display & 0xff) == BASE_HEX_DEC) {
		/* This format perfectly fits into 11 bytes. */
		*buf++ = '0';
		*buf++ = 'x';

		switch (fv->ftype->ftype) {

		case FT_UINT8:
			buf = guint8_to_hex(buf, fv->value.uinteger);
			break;

		case FT_UINT16:
			buf = word_to_hex(buf, fv->value.uinteger);
			break;

		case FT_UINT24:
			buf = guint8_to_hex(buf, (fv->value.uinteger & 0x00ff0000) >> 16);
			buf = word_to_hex(buf, (fv->value.uinteger & 0x0000ffff));
			break;

		default:
			buf = dword_to_hex(buf, fv->value.uinteger);
			break;
		}

		*buf++ = '\0';
	}
	else {
		guint32_to_str_buf(fv->value.uinteger, buf, size);
	}
	return result;
}

static char *
char_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display)
{
	size_t size = 7 + 1; /* enough for '\OOO' or '\xXX' */
	char *result = wmem_alloc(scope, size);
	char *buf = result;

	/*
	 * The longest possible strings are "'\OOO'" and "'\xXX'", which
	 * take 7 bytes, including the terminating '\0'.
	 */
	*buf++ = '\'';
	if (g_ascii_isprint(fv->value.uinteger)) {
		/* This perfectly fits into 4 or 5 bytes. */
		if (fv->value.uinteger == '\\' || fv->value.uinteger == '\'')
			*buf++ = '\\';
		*buf++ = (char)fv->value.uinteger;
	}
	else {
		*buf++ = '\\';
		switch (fv->value.uinteger) {

		case '\0':
			*buf++ = '0';
			break;

		case '\a':
			*buf++ = 'a';
			break;

		case '\b':
			*buf++ = 'b';
			break;

		case '\f':
			*buf++ = 'f';
			break;

		case '\n':
			*buf++ = 'n';
			break;

		case '\r':
			*buf++ = 'r';
			break;

		case '\t':
			*buf++ = 't';
			break;

		case '\v':
			*buf++ = 'v';
			break;

		default:
			if (field_display == BASE_HEX) {
				*buf++ = 'x';
				buf = guint8_to_hex(buf, fv->value.uinteger);
			}
			else {
				*buf++ = ((fv->value.uinteger >> 6) & 0x7) + '0';
				*buf++ = ((fv->value.uinteger >> 3) & 0x7) + '0';
				*buf++ = ((fv->value.uinteger >> 0) & 0x7) + '0';
			}
			break;
		}
	}
	*buf++ = '\'';
	*buf++ = '\0';
	return result;
}

static bool
ipxnet_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg)
{
	/*
	 * Don't request an error message if bytes_from_literal fails;
	 * if it does, we'll report an error specific to this address
	 * type.
	 */
	if (uint32_from_literal(fv, s, true, NULL)) {
		return true;
	}

	/* XXX - Try resolving as an IPX host name and parse that? */

	if (err_msg != NULL)
		*err_msg = ws_strdup_printf("\"%s\" is not a valid IPX network address.", s);
	return false;
}

static char *
ipxnet_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype, int field_display _U_)
{
	return uinteger_to_repr(scope, fv, rtype, BASE_HEX);
}

static enum ft_result
uint64_cmp_order(const fvalue_t *a, const fvalue_t *b, int *cmp)
{
	uint64_t val_a, val_b;
	enum ft_result res;

	res = fvalue_to_uinteger64(a, &val_a);
	if (res != FT_OK)
		return res;

	res = fvalue_to_uinteger64(b, &val_b);
	if (res != FT_OK)
		return res;

	if (val_a == val_b)
		*cmp = 0;
	else
		*cmp = val_a < val_b ? -1 : 1;

	return FT_OK;
}

static enum ft_result
uint_cmp_order(const fvalue_t *a, const fvalue_t *b, int *cmp)
{
	return uint64_cmp_order(a, b, cmp);
}

static enum ft_result
sint64_cmp_order(const fvalue_t *a, const fvalue_t *b, int *cmp)
{
	int64_t val_a, val_b;
	enum ft_result res;

	res = fvalue_to_sinteger64(a, &val_a);
	if (res != FT_OK)
		return res;

	res = fvalue_to_sinteger64(b, &val_b);
	if (res != FT_OK)
		return res;

	if (val_a == val_b)
		*cmp = 0;
	else
		*cmp = val_a < val_b ? -1 : 1;

	return FT_OK;
}

static enum ft_result
sint_cmp_order(const fvalue_t *a, const fvalue_t *b, int *cmp)
{
	return sint64_cmp_order(a, b, cmp);
}

static void
int64_fvalue_new(fvalue_t *fv)
{
	fv->value.sinteger64 = 0;
}

static void
set_uinteger64(fvalue_t *fv, uint64_t value)
{
	fv->value.uinteger64 = value;
}

static void
set_sinteger64(fvalue_t *fv, int64_t value)
{
	fv->value.sinteger64 = value;
}

static uint64_t
get_uinteger64(fvalue_t *fv)
{
	return fv->value.uinteger64;
}

static int64_t
get_sinteger64(fvalue_t *fv)
{
	return fv->value.sinteger64;
}

static bool
binary_strtoull(const char *s, uint64_t *ptr, char **err_msg)
{
	char *endptr;

	errno = 0;
	if (s[0] == '0' && (s[1] == 'b' || s[1] == 'B')) {
		*ptr = g_ascii_strtoull(s + 2, &endptr, 2);
	}
	else {
		*ptr = g_ascii_strtoull(s, &endptr, 0);
	}

	if (errno == EINVAL || endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" is not a valid number.", s);
		return false;
	}
	if (errno == ERANGE) {
		if (*ptr == UINT64_MAX) {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("\"%s\" causes an integer overflow.", s);
			}
		}
		else if (err_msg != NULL) {
			/*
			 * XXX - can "strtol()" set errno to
			 * ERANGE without returning LONG_MAX?
			 */
			*err_msg = ws_strdup_printf("\"%s\" is not an integer.", s);
		}
		return false;
	}

	return true;
}

static bool
_uint64_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg,
		   uint64_t max)
{
	uint64_t value;

	if (!binary_strtoull(s, &value, err_msg))
		return false;

	if (value > max) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" too big for this field, maximum %" PRIu64".", s, max);
		return false;
	}

	fv->value.uinteger64 = value;
	return true;
}

static bool
uint64_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _uint64_from_literal (fv, s, allow_partial_value, err_msg, UINT64_MAX);
}

static bool
uint56_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _uint64_from_literal (fv, s, allow_partial_value, err_msg, G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFF));
}

static bool
uint48_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _uint64_from_literal (fv, s, allow_partial_value, err_msg, G_GUINT64_CONSTANT(0xFFFFFFFFFFFF));
}

static bool
uint40_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _uint64_from_literal (fv, s, allow_partial_value, err_msg, G_GUINT64_CONSTANT(0xFFFFFFFFFF));
}

static bool
uint64_from_charconst(fvalue_t *fv, unsigned long num, char **err_msg _U_)
{
	fv->value.uinteger64 = (uint64_t)num;
	return true;
}

static bool
binary_strtoll(const char *s, int64_t *ptr, char **err_msg)
{
	char *endptr;

	errno = 0;
	if (s[0] == '0' && (s[1] == 'b' || s[1] == 'B')) {
		*ptr = g_ascii_strtoll(s + 2, &endptr, 2);
	}
	else {
		*ptr = g_ascii_strtoll(s, &endptr, 0);
	}

	if (errno == EINVAL || endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" is not a valid number.", s);
		return false;
	}
	if (errno == ERANGE) {
		if (*ptr == INT64_MAX) {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("\"%s\" causes an integer overflow.", s);
			}
		}
		else if (*ptr == INT64_MIN) {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("\"%s\" causes an integer underflow.", s);
			}
		}
		else if (err_msg != NULL) {
			/*
			 * XXX - can "strtol()" set errno to
			 * ERANGE without returning LONG_MAX?
			 */
			*err_msg = ws_strdup_printf("\"%s\" is not an integer.", s);
		}
		return false;
	}

	return true;
}

static bool
_sint64_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg,
		   int64_t max, int64_t min)
{
	int64_t value;

	if (!binary_strtoll(s, &value, err_msg))
		return false;

	if (value > max) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" too big for this field, maximum %" PRId64".", s, max);
		return false;
	}
	else if (value < min) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" too small for this field, minimum %" PRId64 ".", s, min);
		return false;
	}

	fv->value.sinteger64 = value;
	return true;
}

static bool
sint64_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _sint64_from_literal (fv, s, allow_partial_value, err_msg, INT64_MAX, INT64_MIN);
}

static bool
sint56_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _sint64_from_literal (fv, s, allow_partial_value, err_msg, G_GINT64_CONSTANT(0x7FFFFFFFFFFFFF), G_GINT64_CONSTANT(-0x80000000000000));
}

static bool
sint48_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _sint64_from_literal (fv, s, allow_partial_value, err_msg, G_GINT64_CONSTANT(0x7FFFFFFFFFFF), G_GINT64_CONSTANT(-0x800000000000));
}

static bool
sint40_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value, char **err_msg)
{
	return _sint64_from_literal (fv, s, allow_partial_value, err_msg, G_GINT64_CONSTANT(0x7FFFFFFFFF), G_GINT64_CONSTANT(-0x8000000000));
}

static bool
sint64_from_charconst(fvalue_t *fv, unsigned long num, char **err_msg _U_)
{
	fv->value.sinteger64 = (int64_t)num;
	return true;
}

static char *
integer64_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	uint64_t val;

	size_t size = 20 + 1; /* enough for -2^63-1, in decimal */
	char *result = wmem_alloc(scope, size);
	char *buf = result;

	if (fv->value.sinteger64 < 0) {
		*buf++ = '-';
		val = -fv->value.sinteger64;
	}
	else {
		val = fv->value.sinteger64;
	}
	guint64_to_str_buf(val, buf, size);
	return result;
}

static char *
uinteger64_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	size_t size = 20 + 1; /* enough for 2^64-1, in decimal or 0xXXXXXXXXXXXXXXXX */
	char *result = wmem_alloc(scope, size);
	char *buf = result;

	if (field_display == BASE_HEX || field_display == BASE_HEX_DEC) {
		/* This format perfectly fits into 19 bytes. */
		*buf++ = '0';
		*buf++ = 'x';

		buf = qword_to_hex(buf, fv->value.uinteger64);
		*buf++ = '\0';
	}
	else {
		guint64_to_str_buf(fv->value.uinteger64, buf, size);
	}
	return result;
}

static enum ft_result
uint_bitwise_and(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr _U_)
{
	dst->value.uinteger = a->value.uinteger & b->value.uinteger;
	return FT_OK;
}

static unsigned
uint_hash(const fvalue_t *fv)
{
	int64_t val = fv->value.uinteger;
	return g_int64_hash(&val);
}

static bool
uint_is_zero(const fvalue_t *fv)
{
	return fv->value.uinteger == 0;
}

static bool
uint_is_negative(const fvalue_t *fv _U_)
{
	return false;
}

static enum ft_result
uint_unary_minus(fvalue_t *dst, const fvalue_t *src, char **err_ptr)
{
	/* Unsigned integers are promoted to signed 32 bits. */
	if (src->value.uinteger > INT32_MAX) {
		if (err_ptr)
			*err_ptr = ws_strdup_printf("%"G_GUINT32_FORMAT" overflows gint32",
							src->value.uinteger);
		return FT_ERROR;
	}
	FTYPE_LOOKUP(FT_INT32, dst->ftype);
	dst->value.sinteger = -(int32_t)src->value.uinteger;
	return FT_OK;
}

static enum ft_result
uint64_bitwise_and(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr _U_)
{
	dst->value.uinteger64 = a->value.uinteger64 & b->value.uinteger64;
	return FT_OK;
}

static unsigned
uint64_hash(const fvalue_t *fv)
{
	int64_t val = fv->value.uinteger64;
	return g_int64_hash(&val);
}

static bool
uint64_is_zero(const fvalue_t *fv)
{
	return fv->value.uinteger64 == 0;
}

static bool
uint64_is_negative(const fvalue_t *fv _U_)
{
	return false;
}

static enum ft_result
uint64_unary_minus(fvalue_t *dst, const fvalue_t *src, char **err_ptr)
{
	/* Unsigned64 integers are promoted to signed 64 bits. */
	if (src->value.uinteger64 > INT64_MAX) {
		if (err_ptr)
			*err_ptr = ws_strdup_printf("%"PRIu64" overflows gint64",
							src->value.uinteger64);
		return FT_ERROR;
	}
	FTYPE_LOOKUP(FT_INT64, dst->ftype);
	dst->value.sinteger64 = -(int64_t)src->value.uinteger64;
	return FT_OK;
}

static enum ft_result
sint_bitwise_and(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr _U_)
{
	dst->value.sinteger = a->value.sinteger & b->value.sinteger;
	return FT_OK;
}

static unsigned
sint_hash(const fvalue_t *fv)
{
	int64_t val = fv->value.sinteger;
	return g_int64_hash(&val);
}

static bool
sint_is_zero(const fvalue_t *fv)
{
	return fv->value.sinteger == 0;
}

static bool
sint_is_negative(const fvalue_t *fv)
{
	return fv->value.sinteger < 0;
}

static enum ft_result
sint_unary_minus(fvalue_t * dst, const fvalue_t *src, char **err_ptr _U_)
{
	dst->value.sinteger = -src->value.sinteger;
	return FT_OK;
}

static enum ft_result
sint64_bitwise_and(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr _U_)
{
	dst->value.sinteger64 = a->value.sinteger64 & b->value.sinteger64;
	return FT_OK;
}

static unsigned
sint64_hash(const fvalue_t *fv)
{
	int64_t val = fv->value.sinteger64;
	return g_int64_hash(&val);
}

static bool
sint64_is_zero(const fvalue_t *fv)
{
	return fv->value.sinteger64 == 0;
}

static bool
sint64_is_negative(const fvalue_t *fv)
{
	return fv->value.sinteger64 < 0;
}

static enum ft_result
sint64_unary_minus(fvalue_t * dst, const fvalue_t *src, char **err_ptr _U_)
{
	dst->value.sinteger64 = -src->value.sinteger64;
	return FT_OK;
}

static enum ft_result
sint_add(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (!psnip_safe_int32_add(&dst->value.sinteger, a->value.sinteger, b->value.sinteger)) {
		*err_ptr = ws_strdup_printf("sint_add: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
_sint_subtract(int32_t *sint_dst, int32_t sint_a, int32_t sint_b, char **err_ptr)
{
	if (!psnip_safe_int32_sub(sint_dst, sint_a, sint_b)) {
		*err_ptr = ws_strdup_printf("sint_subtract: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
sint_subtract(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	return _sint_subtract(&dst->value.sinteger, a->value.sinteger, b->value.sinteger, err_ptr);
}

static enum ft_result
sint_multiply(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (!psnip_safe_int32_mul(&dst->value.sinteger, a->value.sinteger, b->value.sinteger)) {
		*err_ptr = ws_strdup_printf("sint_multiply: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
sint_divide(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (b->value.sinteger == 0) {
		*err_ptr = ws_strdup_printf("sint_divide: division by zero");
		return FT_ERROR;
	}

	if (!psnip_safe_int32_div(&dst->value.sinteger, a->value.sinteger, b->value.sinteger)) {
		*err_ptr = ws_strdup_printf("sint_divide: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
sint_modulo(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (b->value.sinteger == 0) {
		*err_ptr = ws_strdup_printf("sint_modulo: division by zero");
		return FT_ERROR;
	}

	if (!psnip_safe_int32_mod(&dst->value.sinteger, a->value.sinteger, b->value.sinteger)) {
		*err_ptr = ws_strdup_printf("sint_modulo: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
uint_add(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (!psnip_safe_uint32_add(&dst->value.uinteger, a->value.uinteger, b->value.uinteger)) {
		*err_ptr = ws_strdup_printf("uint_add: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
uint_subtract(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (b->value.uinteger > a->value.uinteger) {
		/* Uses signed arithmetic. */
		if (a->value.uinteger > INT32_MAX ||
				b->value.uinteger > INT32_MAX) {
			*err_ptr = ws_strdup_printf("uint_subtract: signed overflow");
			return FT_ERROR;
		}
		FTYPE_LOOKUP(FT_INT32, dst->ftype);
		return _sint_subtract(&dst->value.sinteger, (int32_t)a->value.uinteger, (int32_t)b->value.uinteger, err_ptr);
	}

	if (!psnip_safe_uint32_sub(&dst->value.uinteger, a->value.uinteger, b->value.uinteger)) {
		*err_ptr = ws_strdup_printf("uint_subtract: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
uint_multiply(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (!psnip_safe_uint32_mul(&dst->value.uinteger, a->value.uinteger, b->value.uinteger)) {
		*err_ptr = ws_strdup_printf("uint_multiply: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
uint_divide(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (b->value.uinteger == 0) {
		*err_ptr = ws_strdup_printf("uint_divide: division by zero");
		return FT_ERROR;
	}

	if (!psnip_safe_uint32_div(&dst->value.uinteger, a->value.uinteger, b->value.uinteger)) {
		*err_ptr = ws_strdup_printf("uint_divide: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
uint_modulo(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (b->value.uinteger == 0) {
		*err_ptr = ws_strdup_printf("uint_modulo: division by zero");
		return FT_ERROR;
	}

	if (!psnip_safe_uint32_mod(&dst->value.uinteger, a->value.uinteger, b->value.uinteger)) {
		*err_ptr = ws_strdup_printf("uint_modulo: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
sint64_add(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (!psnip_safe_int64_add(&dst->value.sinteger64, a->value.sinteger64, b->value.sinteger64)) {
		*err_ptr = ws_strdup_printf("sint64_add: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
_sint64_subtract(int64_t *sint_dst, int64_t sint_a, int64_t sint_b, char **err_ptr)
{
	if (!psnip_safe_int64_sub(sint_dst, sint_a, sint_b)) {
		*err_ptr = ws_strdup_printf("sint64_subtract: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
sint64_subtract(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	return _sint64_subtract(&dst->value.sinteger64, a->value.sinteger64, b->value.sinteger64, err_ptr);
}

static enum ft_result
sint64_multiply(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (!psnip_safe_int64_mul(&dst->value.sinteger64, a->value.sinteger64, b->value.sinteger64)) {
		*err_ptr = ws_strdup_printf("sint64_multiply: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
sint64_divide(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (b->value.sinteger64 == 0) {
		*err_ptr = ws_strdup_printf("sint64_divide: division by zero");
		return FT_ERROR;
	}

	if (!psnip_safe_int64_div(&dst->value.sinteger64, a->value.sinteger64, b->value.sinteger64)) {
		*err_ptr = ws_strdup_printf("sint64_divide: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
sint64_modulo(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (b->value.sinteger64 == 0) {
		*err_ptr = ws_strdup_printf("sint64_modulo: division by zero");
		return FT_ERROR;
	}

	if (!psnip_safe_int64_mod(&dst->value.sinteger64, a->value.sinteger64, b->value.sinteger64)) {
		*err_ptr = ws_strdup_printf("sint64_modulo: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
uint64_add(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (!psnip_safe_uint64_add(&dst->value.uinteger64, a->value.uinteger64, b->value.uinteger64)) {
		*err_ptr = ws_strdup_printf("uint64_add: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
uint64_subtract(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (b->value.uinteger64 > a->value.uinteger64) {
		/* Uses signed arithmetic. */
		if (a->value.uinteger64 > INT64_MAX ||
				b->value.uinteger64 > INT64_MAX) {
			*err_ptr = ws_strdup_printf("uint64_subtract: signed overflow");
			return FT_ERROR;
		}
		FTYPE_LOOKUP(FT_INT64, dst->ftype);
		return _sint64_subtract(&dst->value.sinteger64, (int64_t)a->value.uinteger64, (int64_t)b->value.uinteger64, err_ptr);
	}

	if (!psnip_safe_uint64_sub(&dst->value.uinteger64, a->value.uinteger64, b->value.uinteger64)) {
		*err_ptr = ws_strdup_printf("uint64_subtract: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
uint64_multiply(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (!psnip_safe_uint64_mul(&dst->value.uinteger64, a->value.uinteger64, b->value.uinteger64)) {
		*err_ptr = ws_strdup_printf("uint64_multiply: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
uint64_divide(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (b->value.uinteger64 == 0) {
		*err_ptr = ws_strdup_printf("uint64_divide: division by zero");
		return FT_ERROR;
	}

	if (!psnip_safe_uint64_div(&dst->value.uinteger64, a->value.uinteger64, b->value.uinteger64)) {
		*err_ptr = ws_strdup_printf("uint64_divide: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result
uint64_modulo(fvalue_t *dst, const fvalue_t *a, const fvalue_t *b, char **err_ptr)
{
	if (b->value.uinteger64 == 0) {
		*err_ptr = ws_strdup_printf("uint64_modulo: division by zero");
		return FT_ERROR;
	}

	if (!psnip_safe_uint64_mod(&dst->value.uinteger64, a->value.uinteger64, b->value.uinteger64)) {
		*err_ptr = ws_strdup_printf("uint64_modulo: overflow");
		return FT_ERROR;
	}
	return FT_OK;
}

static enum ft_result uint_val_to_uinteger64(const fvalue_t *src, uint64_t *dst)
{
	*dst = src->value.uinteger;
	return FT_OK;
}

static enum ft_result uint_val_to_sinteger64(const fvalue_t *src, int64_t *dst)
{
	*dst = (int64_t)src->value.uinteger;
	return FT_OK;
}

static enum ft_result sint_val_to_uinteger64(const fvalue_t *src, uint64_t *dst)
{
	if (src->value.sinteger < 0)
		return FT_OVERFLOW;

	*dst = (uint64_t)src->value.sinteger;
	return FT_OK;
}

static enum ft_result sint_val_to_sinteger64(const fvalue_t *src, int64_t *dst)
{
	*dst = src->value.sinteger;
	return FT_OK;
}

static enum ft_result uint64_val_to_uinteger64(const fvalue_t *src, uint64_t *dst)
{
	*dst = src->value.uinteger64;
	return FT_OK;
}

static enum ft_result uint64_val_to_sinteger64(const fvalue_t *src, int64_t *dst)
{
	if (src->value.uinteger64 > INT64_MAX)
		return FT_OVERFLOW;

	*dst = (int64_t)src->value.uinteger64;
	return FT_OK;
}

static enum ft_result sint64_val_to_uinteger64(const fvalue_t *src, uint64_t *dst)
{
	if (src->value.sinteger64 < 0)
		return FT_OVERFLOW;

	*dst = (uint64_t)src->value.sinteger64;
	return FT_OK;
}

static enum ft_result sint64_val_to_sinteger64(const fvalue_t *src, int64_t *dst)
{
	*dst = src->value.sinteger64;
	return FT_OK;
}

/* BOOLEAN-specific */

static bool
boolean_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg)
{
	if (g_ascii_strcasecmp(s, "true") == 0) {
		fv->value.uinteger64 = 1;
		return true;
	}
	if (g_ascii_strcasecmp(s, "false") == 0) {
		fv->value.uinteger64 = 0;
		return true;
	}

	char *endptr;
	errno = 0;
	int64_t val = g_ascii_strtoll(s, &endptr, 0);
	if (errno == 0 && *endptr == '\0') {
		/* This is a valid number. */
		fv->value.uinteger64 = (val != 0);
		return true;
	}
	if (err_msg)
		*err_msg = ws_strdup_printf("\"%s\" is not a valid boolean", s);
	return false;
}

static bool
boolean_from_string(fvalue_t *fv, const char *s, size_t len, char **err_msg _U_)
{
	if (g_ascii_strncasecmp(s, "true", len) == 0) {
		fv->value.uinteger64 = 1;
		return true;
	}
	if (g_ascii_strncasecmp(s, "false", len) == 0) {
		fv->value.uinteger64 = 0;
		return true;
	}

	if (err_msg)
		*err_msg = ws_strdup_printf("expected \"True\" or \"False\", not \"%s\"", s);
	return false;
}

static char *
boolean_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype, int field_display _U_)
{
	bool val = fv->value.uinteger64;
	const char *str = NULL;

	switch (rtype) {
		case FTREPR_DFILTER:
		case FTREPR_DISPLAY:
			str = val ? "True" : "False";
			break;
		case FTREPR_JSON:
			str = val ? "1" : "0";
			break;
	}

	return wmem_strdup(scope, str);
}

/* False is less than True (arbitrary):
 * A  B   cmp(A, B)
 * T  T   0
 * F  F   0
 * F  T  -1
 * T  F   1
 */
static enum ft_result
boolean_cmp_order(const fvalue_t *a, const fvalue_t *b, int *cmp)
{
	uint64_t val_a, val_b;
	enum ft_result res;

	val_a = a->value.uinteger64;
	res = fvalue_to_uinteger64(b, &val_b);
	if (res != FT_OK)
		return res;

	if (val_a) {
		if (val_b) {
			*cmp = 0;
		}
		else {
			*cmp = 1;
		}
	}
	else if (val_b) {
		*cmp = -1;
	}
	else {
		*cmp = 0;
	}

	return FT_OK;
}

static unsigned
boolean_hash(const fvalue_t *fv)
{
	int val;

	if (fv->value.uinteger64)
		val = 1;
	else
		val = 0;
	return g_int_hash(&val);
}

/* EUI64-specific */
static bool
eui64_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg)
{
	GByteArray	*bytes;
	bool	res;
	union {
		uint64_t value;
		uint8_t bytes[8];
	} eui64;

	/*
	 * Don't request an error message if uint64_from_literal fails;
	 * if it does, we'll try parsing it as a sequence of bytes, and
	 * report an error if *that* fails.
	 */
	if (uint64_from_literal(fv, s, true, NULL)) {
		return true;
	}

	bytes = g_byte_array_new();
	res = hex_str_to_bytes(s, bytes, true);
	if (!res || bytes->len != 8) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" is not a valid EUI-64 address.", s);
		g_byte_array_free(bytes, true);
		return false;
	}

	memcpy(eui64.bytes, bytes->data, 8);
	g_byte_array_free(bytes, true);
	fv->value.uinteger64 = GUINT64_FROM_BE(eui64.value);
	return true;
}

static char *
eui64_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	union {
		uint64_t value;
		uint8_t bytes[8];
	} eui64;

	/* Copy and convert the address from host to network byte order. */
	eui64.value = GUINT64_TO_BE(fv->value.uinteger64);

	return wmem_strdup_printf(scope, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
	    eui64.bytes[0], eui64.bytes[1], eui64.bytes[2], eui64.bytes[3],
	    eui64.bytes[4], eui64.bytes[5], eui64.bytes[6], eui64.bytes[7]);
}

void
ftype_register_integers(void)
{
	static ftype_t char_type = {
		FT_CHAR,			/* ftype */
		"FT_CHAR",			/* name */
		"Character (8 bits)",		/* pretty name */
		1,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		uint8_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint_from_charconst,		/* val_from_charconst */
		char_to_repr,			/* val_to_string_repr */

		uint_val_to_uinteger64,		/* val_to_uinteger64 */
		uint_val_to_sinteger64,		/* val_to_sinteger64 */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uint_cmp_order,			/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		uint_hash,			/* hash */
		uint_is_zero,			/* is_zero */
		uint_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		uint_bitwise_and,		/* bitwise_and */
		uint_unary_minus,		/* unary_minus */
		uint_add,			/* add */
		uint_subtract,			/* subtract */
		uint_multiply,			/* multiply */
		uint_divide,			/* divide */
		uint_modulo,			/* modulo */
	};
	static ftype_t uint8_type = {
		FT_UINT8,			/* ftype */
		"FT_UINT8",			/* name */
		"Unsigned integer (8 bits)",	/* pretty name */
		1,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		uint8_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint_from_charconst,		/* val_from_charconst */
		uinteger_to_repr,		/* val_to_string_repr */

		uint_val_to_uinteger64,		/* val_to_uinteger64 */
		uint_val_to_sinteger64,		/* val_to_sinteger64 */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uint_cmp_order,			/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		uint_hash,			/* hash */
		uint_is_zero,			/* is_zero */
		uint_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		uint_bitwise_and,		/* bitwise_and */
		uint_unary_minus,		/* unary_minus */
		uint_add,			/* add */
		uint_subtract,			/* subtract */
		uint_multiply,			/* multiply */
		uint_divide,			/* divide */
		uint_modulo,			/* modulo */
	};
	static ftype_t uint16_type = {
		FT_UINT16,			/* ftype */
		"FT_UINT16",			/* name */
		"Unsigned integer (16 bits)",	/* pretty_name */
		2,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		uint16_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint_from_charconst,		/* val_from_charconst */
		uinteger_to_repr,		/* val_to_string_repr */

		uint_val_to_uinteger64,		/* val_to_uinteger64 */
		uint_val_to_sinteger64,		/* val_to_sinteger64 */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uint_cmp_order,			/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		uint_hash,			/* hash */
		uint_is_zero,			/* is_zero */
		uint_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		uint_bitwise_and,		/* bitwise_and */
		uint_unary_minus,		/* unary_minus */
		uint_add,			/* add */
		uint_subtract,			/* subtract */
		uint_multiply,			/* multiply */
		uint_divide,			/* divide */
		uint_modulo,			/* modulo */
	};
	static ftype_t uint24_type = {
		FT_UINT24,			/* ftype */
		"FT_UINT24",			/* name */
		"Unsigned integer (24 bits)",	/* pretty_name */
		3,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		uint24_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint_from_charconst,		/* val_from_charconst */
		uinteger_to_repr,		/* val_to_string_repr */

		uint_val_to_uinteger64,		/* val_to_uinteger64 */
		uint_val_to_sinteger64,		/* val_to_sinteger64 */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uint_cmp_order,			/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		uint_hash,			/* hash */
		uint_is_zero,			/* is_zero */
		uint_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		uint_bitwise_and,		/* bitwise_and */
		uint_unary_minus,		/* unary_minus */
		uint_add,			/* add */
		uint_subtract,			/* subtract */
		uint_multiply,			/* multiply */
		uint_divide,			/* divide */
		uint_modulo,			/* modulo */
	};
	static ftype_t uint32_type = {
		FT_UINT32,			/* ftype */
		"FT_UINT32",			/* name */
		"Unsigned integer (32 bits)",	/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		uint32_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint_from_charconst,		/* val_from_charconst */
		uinteger_to_repr,		/* val_to_string_repr */

		uint_val_to_uinteger64,		/* val_to_uinteger64 */
		uint_val_to_sinteger64,		/* val_to_sinteger64 */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uint_cmp_order,			/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		uint_hash,			/* hash */
		uint_is_zero,			/* is_zero */
		uint_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		uint_bitwise_and,		/* bitwise_and */
		uint_unary_minus,		/* unary_minus */
		uint_add,			/* add */
		uint_subtract,			/* subtract */
		uint_multiply,			/* multiply */
		uint_divide,			/* divide */
		uint_modulo,			/* modulo */
	};
	static ftype_t uint40_type = {
		FT_UINT40,			/* ftype */
		"FT_UINT40",			/* name */
		"Unsigned integer (40 bits)",	/* pretty_name */
		5,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		uint40_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint64_from_charconst,		/* val_from_charconst */
		uinteger64_to_repr,		/* val_to_string_repr */

		uint64_val_to_uinteger64,	/* val_to_uinteger64 */
		uint64_val_to_sinteger64,	/* val_to_sinteger64 */

		{ .set_value_uinteger64 = set_uinteger64 },	/* union set_value */
		{ .get_value_uinteger64 = get_uinteger64 },	/* union get_value */

		uint64_cmp_order,		/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		uint64_hash,			/* hash */
		uint64_is_zero,			/* is_zero */
		uint64_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		uint64_bitwise_and,		/* bitwise_and */
		uint64_unary_minus,		/* unary_minus */
		uint64_add,			/* add */
		uint64_subtract,		/* subtract */
		uint64_multiply,		/* multiply */
		uint64_divide,			/* divide */
		uint64_modulo,			/* modulo */
	};
	static ftype_t uint48_type = {
		FT_UINT48,			/* ftype */
		"FT_UINT48",			/* name */
		"Unsigned integer (48 bits)",	/* pretty_name */
		6,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		uint48_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint64_from_charconst,		/* val_from_charconst */
		uinteger64_to_repr,		/* val_to_string_repr */

		uint64_val_to_uinteger64,	/* val_to_uinteger64 */
		uint64_val_to_sinteger64,	/* val_to_sinteger64 */

		{ .set_value_uinteger64 = set_uinteger64 },	/* union set_value */
		{ .get_value_uinteger64 = get_uinteger64 },	/* union get_value */

		uint64_cmp_order,		/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		uint64_hash,			/* hash */
		uint64_is_zero,			/* is_zero */
		uint64_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		uint64_bitwise_and,		/* bitwise_and */
		uint64_unary_minus,		/* unary_minus */
		uint64_add,			/* add */
		uint64_subtract,		/* subtract */
		uint64_multiply,		/* multiply */
		uint64_divide,			/* divide */
		uint64_modulo,			/* modulo */
	};
	static ftype_t uint56_type = {
		FT_UINT56,			/* ftype */
		"FT_UINT56",			/* name */
		"Unsigned integer (56 bits)",	/* pretty_name */
		7,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		uint56_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint64_from_charconst,		/* val_from_charconst */
		uinteger64_to_repr,		/* val_to_string_repr */

		uint64_val_to_uinteger64,	/* val_to_uinteger64 */
		uint64_val_to_sinteger64,	/* val_to_sinteger64 */

		{ .set_value_uinteger64 = set_uinteger64 },	/* union set_value */
		{ .get_value_uinteger64 = get_uinteger64 },	/* union get_value */

		uint64_cmp_order,		/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		uint64_hash,			/* hash */
		uint64_is_zero,			/* is_zero */
		uint64_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		uint64_bitwise_and,		/* bitwise_and */
		uint64_unary_minus,		/* unary_minus */
		uint64_add,			/* add */
		uint64_subtract,		/* subtract */
		uint64_multiply,		/* multiply */
		uint64_divide,			/* divide */
		uint64_modulo,			/* modulo */
	};
	static ftype_t uint64_type = {
		FT_UINT64,			/* ftype */
		"FT_UINT64",			/* name */
		"Unsigned integer (64bits)",	/* pretty_name */
		8,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		uint64_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint64_from_charconst,		/* val_from_charconst */
		uinteger64_to_repr,		/* val_to_string_repr */

		uint64_val_to_uinteger64,	/* val_to_uinteger64 */
		uint64_val_to_sinteger64,	/* val_to_sinteger64 */

		{ .set_value_uinteger64 = set_uinteger64 },	/* union set_value */
		{ .get_value_uinteger64 = get_uinteger64 },	/* union get_value */

		uint64_cmp_order,		/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		uint64_hash,			/* hash */
		uint64_is_zero,			/* is_zero */
		uint64_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		uint64_bitwise_and,		/* bitwise_and */
		uint64_unary_minus,		/* unary_minus */
		uint64_add,			/* add */
		uint64_subtract,		/* subtract */
		uint64_multiply,		/* multiply */
		uint64_divide,			/* divide */
		uint64_modulo,			/* modulo */
	};
	static ftype_t int8_type = {
		FT_INT8,			/* ftype */
		"FT_INT8",			/* name */
		"Signed integer (8bits)",	/* pretty_name */
		1,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		sint8_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint_from_charconst,		/* val_from_charconst */
		integer_to_repr,		/* val_to_string_repr */

		sint_val_to_uinteger64,		/* val_to_uinteger64 */
		sint_val_to_sinteger64,		/* val_to_sinteger64 */

		{ .set_value_sinteger = set_sinteger },	/* union set_value */
		{ .get_value_sinteger = get_sinteger },	/* union get_value */

		sint_cmp_order,			/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		sint_hash,			/* hash */
		sint_is_zero,			/* is_zero */
		sint_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		sint_bitwise_and,		/* bitwise_and */
		sint_unary_minus,		/* unary_minus */
		sint_add,			/* add */
		sint_subtract,			/* subtract */
		sint_multiply,			/* multiply */
		sint_divide,			/* divide */
		sint_modulo,			/* modulo */
	};
	static ftype_t int16_type = {
		FT_INT16,			/* ftype */
		"FT_INT16",			/* name */
		"Signed integer (16 bits)",	/* pretty_name */
		2,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		sint16_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint_from_charconst,		/* val_from_charconst */
		integer_to_repr,		/* val_to_string_repr */

		sint_val_to_uinteger64,		/* val_to_uinteger64 */
		sint_val_to_sinteger64,		/* val_to_sinteger64 */

		{ .set_value_sinteger = set_sinteger },	/* union set_value */
		{ .get_value_sinteger = get_sinteger },	/* union get_value */

		sint_cmp_order,			/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		sint_hash,			/* hash */
		sint_is_zero,			/* is_zero */
		sint_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		sint_bitwise_and,		/* bitwise_and */
		sint_unary_minus,		/* unary_minus */
		sint_add,			/* add */
		sint_subtract,			/* subtract */
		sint_multiply,			/* multiply */
		sint_divide,			/* divide */
		sint_modulo,			/* modulo */
	};
	static ftype_t int24_type = {
		FT_INT24,			/* ftype */
		"FT_INT24",			/* name */
		"Signed integer (24 bits)",	/* pretty_name */
		3,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		sint24_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint_from_charconst,		/* val_from_charconst */
		integer_to_repr,		/* val_to_string_repr */

		sint_val_to_uinteger64,		/* val_to_uinteger64 */
		sint_val_to_sinteger64,		/* val_to_sinteger64 */

		{ .set_value_sinteger = set_sinteger },	/* union set_value */
		{ .get_value_sinteger = get_sinteger },	/* union get_value */

		sint_cmp_order,			/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		sint_hash,			/* hash */
		sint_is_zero,			/* is_zero */
		sint_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		sint_bitwise_and,		/* bitwise_and */
		sint_unary_minus,		/* unary_minus */
		sint_add,			/* add */
		sint_subtract,			/* subtract */
		sint_multiply,			/* multiply */
		sint_divide,			/* divide */
		sint_modulo,			/* modulo */
	};
	static ftype_t int32_type = {
		FT_INT32,			/* ftype */
		"FT_INT32",			/* name */
		"Signed integer (32 bits)",	/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		sint32_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint_from_charconst,		/* val_from_charconst */
		integer_to_repr,		/* val_to_string_repr */

		sint_val_to_uinteger64,		/* val_to_uinteger64 */
		sint_val_to_sinteger64,		/* val_to_sinteger64 */

		{ .set_value_sinteger = set_sinteger },	/* union set_value */
		{ .get_value_sinteger = get_sinteger },	/* union get_value */

		sint_cmp_order,			/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		sint_hash,			/* hash */
		sint_is_zero,			/* is_zero */
		sint_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		sint_bitwise_and,		/* bitwise_and */
		sint_unary_minus,		/* unary_minus */
		sint_add,			/* add */
		sint_subtract,			/* subtract */
		sint_multiply,			/* multiply */
		sint_divide,			/* divide */
		sint_modulo,			/* modulo */
	};
	static ftype_t int40_type = {
		FT_INT40,			/* ftype */
		"FT_INT40",			/* name */
		"Signed integer (40 bits)",	/* pretty_name */
		5,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		sint40_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint64_from_charconst,		/* val_from_charconst */
		integer64_to_repr,		/* val_to_string_repr */

		sint64_val_to_uinteger64,	/* val_to_uinteger64 */
		sint64_val_to_sinteger64,	/* val_to_sinteger64 */

		{ .set_value_sinteger64 = set_sinteger64 },	/* union set_value */
		{ .get_value_sinteger64 = get_sinteger64 },	/* union get_value */

		sint64_cmp_order,		/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		sint64_hash,			/* hash */
		sint64_is_zero,			/* is_zero */
		sint64_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		sint64_bitwise_and,		/* bitwise_and */
		sint64_unary_minus,		/* unary_minus */
		sint64_add,			/* add */
		sint64_subtract,		/* subtract */
		sint64_multiply,		/* multiply */
		sint64_divide,			/* divide */
		sint64_modulo,			/* modulo */
	};
	static ftype_t int48_type = {
		FT_INT48,			/* ftype */
		"FT_INT48",			/* name */
		"Signed integer (48 bits)",	/* pretty_name */
		6,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		sint48_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint64_from_charconst,		/* val_from_charconst */
		integer64_to_repr,		/* val_to_string_repr */

		sint64_val_to_uinteger64,	/* val_to_uinteger64 */
		sint64_val_to_sinteger64,	/* val_to_sinteger64 */

		{ .set_value_sinteger64 = set_sinteger64 },	/* union set_value */
		{ .get_value_sinteger64 = get_sinteger64 },	/* union get_value */

		sint64_cmp_order,		/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		sint64_hash,			/* hash */
		sint64_is_zero,			/* is_zero */
		sint64_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		sint64_bitwise_and,		/* bitwise_and */
		sint64_unary_minus,		/* unary_minus */
		sint64_add,			/* add */
		sint64_subtract,		/* subtract */
		sint64_multiply,		/* multiply */
		sint64_divide,			/* divide */
		sint64_modulo,			/* modulo */
	};
	static ftype_t int56_type = {
		FT_INT56,			/* ftype */
		"FT_INT56",			/* name */
		"Signed integer (56 bits)",	/* pretty_name */
		7,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		sint56_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint64_from_charconst,		/* val_from_charconst */
		integer64_to_repr,		/* val_to_string_repr */

		sint64_val_to_uinteger64,	/* val_to_uinteger64 */
		sint64_val_to_sinteger64,	/* val_to_sinteger64 */

		{ .set_value_sinteger64 = set_sinteger64 },	/* union set_value */
		{ .get_value_sinteger64 = get_sinteger64 },	/* union get_value */

		sint64_cmp_order,		/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		sint64_hash,			/* hash */
		sint64_is_zero,			/* is_zero */
		sint64_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		sint64_bitwise_and,		/* bitwise_and */
		sint64_unary_minus,		/* unary_minus */
		sint64_add,			/* add */
		sint64_subtract,		/* subtract */
		sint64_multiply,		/* multiply */
		sint64_divide,			/* divide */
		sint64_modulo,			/* modulo */
	};
	static ftype_t int64_type = {
		FT_INT64,			/* ftype */
		"FT_INT64",			/* name */
		"Signed integer (64 bits)",	/* pretty_name */
		8,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		sint64_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint64_from_charconst,		/* val_from_charconst */
		integer64_to_repr,		/* val_to_string_repr */

		sint64_val_to_uinteger64,	/* val_to_uinteger64 */
		sint64_val_to_sinteger64,	/* val_to_sinteger64 */

		{ .set_value_sinteger64 = set_sinteger64 },	/* union set_value */
		{ .get_value_sinteger64 = get_sinteger64 },	/* union get_value */

		sint64_cmp_order,		/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		sint64_hash,			/* hash */
		sint64_is_zero,			/* is_zero */
		sint64_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		sint64_bitwise_and,		/* bitwise_and */
		sint64_unary_minus,		/* unary_minus */
		sint64_add,			/* add */
		sint64_subtract,		/* subtract */
		sint64_multiply,		/* multiply */
		sint64_divide,			/* divide */
		sint64_modulo,			/* modulo */
	};
	static ftype_t boolean_type = {
		FT_BOOLEAN,			/* ftype */
		"FT_BOOLEAN",			/* name */
		"Boolean",			/* pretty_name */
		0,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		boolean_from_literal,		/* val_from_literal */
		boolean_from_string,		/* val_from_string */
		uint64_from_charconst,		/* val_from_charconst */
		boolean_to_repr,		/* val_to_string_repr */

		uint64_val_to_uinteger64,	/* val_to_uinteger64 */
		uint64_val_to_sinteger64,	/* val_to_sinteger64 */

		{ .set_value_uinteger64 = set_uinteger64 },	/* union set_value */
		{ .get_value_uinteger64 = get_uinteger64 },	/* union get_value */

		boolean_cmp_order,		/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		boolean_hash,			/* hash */
		uint64_is_zero,			/* is_zero */
		uint64_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		NULL,				/* bitwise_and */
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};

	static ftype_t ipxnet_type = {
		FT_IPXNET,			/* ftype */
		"FT_IPXNET",			/* name */
		"IPX network number",		/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		ipxnet_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		ipxnet_to_repr,			/* val_to_string_repr */

		uint_val_to_uinteger64,		/* val_to_uinteger64 */
		uint_val_to_sinteger64,		/* val_to_sinteger64 */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uint_cmp_order,			/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		uint_hash,			/* hash */
		uint_is_zero,			/* is_zero */
		uint_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		uint_bitwise_and,		/* bitwise_and */
		uint_unary_minus,		/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};

	static ftype_t framenum_type = {
		FT_FRAMENUM,			/* ftype */
		"FT_FRAMENUM",			/* name */
		"Frame number",			/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		uint32_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint_from_charconst,		/* val_from_charconst */
		uinteger_to_repr,		/* val_to_string_repr */

		uint_val_to_uinteger64,		/* val_to_uinteger64 */
		uint_val_to_sinteger64,		/* val_to_sinteger64 */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uint_cmp_order,			/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		uint_hash,			/* hash */
		uint_is_zero,			/* is_zero */
		uint_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		uint_bitwise_and,		/* bitwise_and */
		uint_unary_minus,		/* unary_minus */
		uint_add,			/* add */
		uint_subtract,			/* subtract */
		uint_multiply,			/* multiply */
		uint_divide,			/* divide */
		uint_modulo,			/* modulo */
	};

	static ftype_t eui64_type = {
		FT_EUI64,			/* ftype */
		"FT_EUI64",			/* name */
		"EUI64 address",		/* pretty_name */
		FT_EUI64_LEN,			/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* copy_value */
		NULL,				/* free_value */
		eui64_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		eui64_to_repr,			/* val_to_string_repr */

		uint64_val_to_uinteger64,	/* val_to_uinteger64 */
		uint64_val_to_sinteger64,	/* val_to_sinteger64 */

		{ .set_value_uinteger64 = set_uinteger64 },	/* union set_value */
		{ .get_value_uinteger64 = get_uinteger64 },	/* union get_value */

		uint64_cmp_order,		/* cmp_order */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		uint64_hash,			/* hash */
		uint64_is_zero,			/* is_zero */
		uint64_is_negative,		/* is_negative */
		NULL,				/* len */
		NULL,				/* slice */
		uint64_bitwise_and,		/* bitwise_and */
		uint64_unary_minus,		/* unary_minus */
		uint64_add,			/* add */
		uint64_subtract,		/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};

	ftype_register(FT_CHAR, &char_type);
	ftype_register(FT_UINT8, &uint8_type);
	ftype_register(FT_UINT16, &uint16_type);
	ftype_register(FT_UINT24, &uint24_type);
	ftype_register(FT_UINT32, &uint32_type);
	ftype_register(FT_UINT40, &uint40_type);
	ftype_register(FT_UINT48, &uint48_type);
	ftype_register(FT_UINT56, &uint56_type);
	ftype_register(FT_UINT64, &uint64_type);
	ftype_register(FT_INT8, &int8_type);
	ftype_register(FT_INT16, &int16_type);
	ftype_register(FT_INT24, &int24_type);
	ftype_register(FT_INT32, &int32_type);
	ftype_register(FT_INT40, &int40_type);
	ftype_register(FT_INT48, &int48_type);
	ftype_register(FT_INT56, &int56_type);
	ftype_register(FT_INT64, &int64_type);
	ftype_register(FT_BOOLEAN, &boolean_type);
	ftype_register(FT_IPXNET, &ipxnet_type);
	ftype_register(FT_FRAMENUM, &framenum_type);
	ftype_register(FT_EUI64, &eui64_type);
}

void
ftype_register_pseudofields_integer(int proto)
{
	static int hf_ft_char;
	static int hf_ft_uint8;
	static int hf_ft_uint16;
	static int hf_ft_uint24;
	static int hf_ft_uint32;
	static int hf_ft_uint40;
	static int hf_ft_uint48;
	static int hf_ft_uint56;
	static int hf_ft_uint64;
	static int hf_ft_int8;
	static int hf_ft_int16;
	static int hf_ft_int24;
	static int hf_ft_int32;
	static int hf_ft_int40;
	static int hf_ft_int48;
	static int hf_ft_int56;
	static int hf_ft_int64;
	static int hf_ft_boolean;
	static int hf_ft_ipxnet;
	static int hf_ft_framenum;
	static int hf_ft_eui64;

	static hf_register_info hf_ftypes[] = {
		{ &hf_ft_char,
		    { "FT_CHAR", "_ws.ftypes.char",
			FT_CHAR, BASE_HEX, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_uint8,
		    { "FT_UINT8", "_ws.ftypes.uint8",
			FT_UINT8, BASE_HEX, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_uint16,
		    { "FT_UINT16", "_ws.ftypes.uint16",
			FT_UINT16, BASE_HEX, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_uint24,
		    { "FT_UINT24", "_ws.ftypes.uint24",
			FT_UINT24, BASE_HEX, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_uint32,
		    { "FT_UINT32", "_ws.ftypes.uint32",
			FT_UINT32, BASE_HEX, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_uint40,
		    { "FT_UINT40", "_ws.ftypes.uint40",
			FT_UINT40, BASE_HEX, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_uint48,
		    { "FT_UINT48", "_ws.ftypes.uint48",
			FT_UINT48, BASE_HEX, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_uint56,
		    { "FT_UINT56", "_ws.ftypes.uint56",
			FT_UINT56, BASE_HEX, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_uint64,
		    { "FT_UINT64", "_ws.ftypes.uint64",
			FT_UINT64, BASE_HEX, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_int8,
		    { "FT_INT8", "_ws.ftypes.int8",
			FT_INT8, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_int16,
		    { "FT_INT16", "_ws.ftypes.int16",
			FT_INT16, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_int24,
		    { "FT_INT24", "_ws.ftypes.int24",
			FT_INT24, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_int32,
		    { "FT_INT32", "_ws.ftypes.int32",
			FT_INT32, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_int40,
		    { "FT_INT40", "_ws.ftypes.int40",
			FT_INT40, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_int48,
		    { "FT_INT48", "_ws.ftypes.int48",
			FT_INT48, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_int56,
		    { "FT_INT56", "_ws.ftypes.int56",
			FT_INT56, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_int64,
		    { "FT_INT64", "_ws.ftypes.int64",
			FT_INT64, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_boolean,
		    { "FT_BOOLEAN", "_ws.ftypes.boolean",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_ipxnet,
		    { "FT_IPXNET", "_ws.ftypes.ipxnet",
			FT_IPXNET, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_framenum,
		    { "FT_FRAMENUM", "_ws.ftypes.framenum",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_ft_eui64,
		    { "FT_EUI64", "_ws.ftypes.eui64",
			FT_EUI64, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
	};

	proto_register_field_array(proto, hf_ftypes, array_length(hf_ftypes));
}

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
