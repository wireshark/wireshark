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

static void
int_fvalue_new(fvalue_t *fv)
{
	memset(&fv->value, 0, sizeof(fv->value));
}

static void
set_uinteger(fvalue_t *fv, guint32 value)
{
	fv->value.uinteger = value;
}

static void
set_sinteger(fvalue_t *fv, gint32 value)
{
	fv->value.sinteger = value;
}


static guint32
get_uinteger(fvalue_t *fv)
{
	return fv->value.uinteger;
}

static gint32
get_sinteger(fvalue_t *fv)
{
	return fv->value.sinteger;
}

static unsigned long
binary_strtoul(const char *s, char **endptr)
{
	const char *binstr = s;

	if (*binstr == '+') {
		binstr++;
	}

	if (binstr[0] == '0' && (binstr[1] == 'b' || binstr[1] == 'B')) {
		return strtoul(binstr + 2, endptr, 2);
	}

	return strtoul(s, endptr, 0);
}

static gboolean
uint_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg,
		   guint32 max)
{
	unsigned long value;
	char	*endptr;

	/*
	 * Try to parse it as a number.
	 */
	if (strchr (s, '-') && strtol(s, NULL, 0) < 0) {
		/*
		 * Probably a negative integer, but will be
		 * "converted in the obvious manner" by strtoul().
		 */
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" too small for this field, minimum 0.", s);
		return FALSE;
	}

	errno = 0;
	value = binary_strtoul(s, &endptr);

	if (errno == EINVAL || endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" is not a valid number.", s);
		return FALSE;
	}
	if (errno == ERANGE) {
		if (err_msg != NULL) {
			if (value == ULONG_MAX) {
				*err_msg = ws_strdup_printf("\"%s\" causes an integer overflow.",
				    s);
			}
			else {
				/*
				 * XXX - can "strtoul()" set errno to
				 * ERANGE without returning ULONG_MAX?
				 */
				*err_msg = ws_strdup_printf("\"%s\" is not an integer.", s);
			}
		}
		return FALSE;
	}

	if (value > max) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" too big for this field, maximum %u.", s, max);
		return FALSE;
	}

	fv->value.uinteger = (guint32)value;
	return TRUE;
}

static gboolean
uint32_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return uint_from_literal (fv, s, allow_partial_value, err_msg, G_MAXUINT32);
}

static gboolean
uint24_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return uint_from_literal (fv, s, allow_partial_value, err_msg, 0xFFFFFF);
}

static gboolean
uint16_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return uint_from_literal (fv, s, allow_partial_value, err_msg, G_MAXUINT16);
}

static gboolean
uint8_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return uint_from_literal (fv, s, allow_partial_value, err_msg, G_MAXUINT8);
}

static gboolean
uint_from_charconst(fvalue_t *fv, unsigned long num, gchar **err_msg _U_)
{
	fv->value.uinteger = (guint32)num;
	return TRUE;
}

static long
binary_strtol(const char *s, char **endptr)
{
	const char *binstr = s;
	gboolean negative = FALSE;

	if (*binstr == '+') {
		binstr++;
	}
	else if (*binstr == '-') {
		binstr++;
		negative = TRUE;
	}

	if (binstr[0] == '0' && (binstr[1] == 'b' || binstr[1] == 'B')) {
		long value = strtol(binstr + 2, endptr, 2);
		return negative ? -value : +value;
	}

	return strtol(s, endptr, 0);
}

static gboolean
sint_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg,
		   gint32 max, gint32 min)
{
	long value;
	char *endptr;

	/*
	 * Try to parse it as a number.
	 */
	if (!strchr (s, '-') && strtoul(s, NULL, 0) > G_MAXINT32) {
		/*
		 * Probably a positive integer > G_MAXINT32, but
		 * will be "converted in the obvious manner" by
		 * strtol().
		 */
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" causes an integer overflow.", s);
		return FALSE;
	}

	errno = 0;
	value = binary_strtol(s, &endptr);

	if (errno == EINVAL || endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" is not a valid number.", s);
		return FALSE;
	}
	if (errno == ERANGE) {
		if (err_msg != NULL) {
			if (value == LONG_MAX) {
				*err_msg = ws_strdup_printf("\"%s\" causes an integer overflow.", s);
			}
			else if (value == LONG_MIN) {
				*err_msg = ws_strdup_printf("\"%s\" causes an integer underflow.", s);
			}
			else {
				/*
				 * XXX - can "strtol()" set errno to
				 * ERANGE without returning ULONG_MAX?
				 */
				*err_msg = ws_strdup_printf("\"%s\" is not an integer.", s);
			}
		}
		return FALSE;
	}

	if (value > max) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" too big for this field, maximum %d.",
				s, max);
		return FALSE;
	} else if (value < min) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" too small for this field, minimum %d.",
				s, min);
		return FALSE;
	}

	fv->value.sinteger = (gint32)value;
	return TRUE;
}

static gboolean
sint32_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return sint_from_literal (fv, s, allow_partial_value, err_msg, G_MAXINT32, G_MININT32);
}

static gboolean
sint24_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return sint_from_literal (fv, s, allow_partial_value, err_msg, 0x7FFFFF, -0x800000);
}

static gboolean
sint16_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return sint_from_literal (fv, s, allow_partial_value, err_msg, G_MAXINT16, G_MININT16);
}

static gboolean
sint8_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return sint_from_literal (fv, s, allow_partial_value, err_msg, G_MAXINT8, G_MININT8);
}

static gboolean
sint_from_charconst(fvalue_t *fv, unsigned long num, gchar **err_msg _U_)
{
	fv->value.sinteger = (gint32)num;
	return TRUE;
}

static char *
integer_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	guint32 val;

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

static gboolean
ipxnet_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	/*
	 * Don't request an error message if bytes_from_literal fails;
	 * if it does, we'll report an error specific to this address
	 * type.
	 */
	if (uint32_from_literal(fv, s, TRUE, NULL)) {
		return TRUE;
	}

	/* XXX - Try resolving as an IPX host name and parse that? */

	if (err_msg != NULL)
		*err_msg = ws_strdup_printf("\"%s\" is not a valid IPX network address.", s);
	return FALSE;
}

static char *
ipxnet_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype, int field_display _U_)
{
	return uinteger_to_repr(scope, fv, rtype, BASE_HEX);
}

static int
uinteger_cmp_order(const fvalue_t *a, const fvalue_t *b)
{
	if (a->value.uinteger == b->value.uinteger)
		return 0;
	return a->value.uinteger < b->value.uinteger ? -1 : 1;
}

static int
sinteger_cmp_order(const fvalue_t *a, const fvalue_t *b)
{
	if (a->value.sinteger == b->value.sinteger)
		return 0;
	return a->value.sinteger < b->value.sinteger ? -1 : 1;
}

static int
uinteger64_cmp_order(const fvalue_t *a, const fvalue_t *b)
{
	if (a->value.uinteger64 == b->value.uinteger64)
		return 0;
	return a->value.uinteger64 < b->value.uinteger64 ? -1 : 1;
}

static int
sinteger64_cmp_order(const fvalue_t *a, const fvalue_t *b)
{
	if (a->value.sinteger64 == b->value.sinteger64)
		return 0;
	return a->value.sinteger64 < b->value.sinteger64 ? -1 : 1;
}

static gboolean
cmp_bitwise_and(const fvalue_t *a, const fvalue_t *b)
{
	return ((a->value.uinteger & b->value.uinteger) != 0);
}

static void
int64_fvalue_new(fvalue_t *fv)
{
	fv->value.sinteger64 = 0;
}

static void
set_uinteger64(fvalue_t *fv, guint64 value)
{
	fv->value.uinteger64 = value;
}

static void
set_sinteger64(fvalue_t *fv, gint64 value)
{
	fv->value.sinteger64 = value;
}

static guint64
get_uinteger64(fvalue_t *fv)
{
	return fv->value.uinteger64;
}

static gint64
get_sinteger64(fvalue_t *fv)
{
	return fv->value.sinteger64;
}

static unsigned long long
binary_strtoull(const char *s, char **endptr)
{
	const char *binstr = s;

	if (*binstr == '+') {
		binstr++;
	}

	if (binstr[0] == '0' && (binstr[1] == 'b' || binstr[1] == 'B')) {
		return g_ascii_strtoull(binstr + 2, endptr, 2);
	}

	return g_ascii_strtoull(s, endptr, 0);
}

static gboolean
_uint64_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg,
		   guint64 max)
{
	guint64 value;
	char	*endptr;

	if (strchr (s, '-') && g_ascii_strtoll(s, NULL, 0) < 0) {
		/*
		 * Probably a negative integer, but will be
		 * "converted in the obvious manner" by g_ascii_strtoull().
		 */
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" causes an integer underflow.", s);
		return FALSE;
	}

	errno = 0;
	value = binary_strtoull(s, &endptr);

	if (errno == EINVAL || endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" is not a valid number.", s);
		return FALSE;
	}
	if (errno == ERANGE) {
		if (err_msg != NULL) {
			if (value == G_MAXUINT64) {
				*err_msg = ws_strdup_printf("\"%s\" causes an integer overflow.", s);
			}
			else {
				/*
				 * XXX - can "strtoul()" set errno to
				 * ERANGE without returning ULONG_MAX?
				 */
				*err_msg = ws_strdup_printf("\"%s\" is not an integer.", s);
			}
		}
		return FALSE;
	}

	if (value > max) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" too big for this field, maximum %" PRIu64".", s, max);
		return FALSE;
	}

	fv->value.uinteger64 = value;
	return TRUE;
}

static gboolean
uint64_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return _uint64_from_literal (fv, s, allow_partial_value, err_msg, G_MAXUINT64);
}

static gboolean
uint56_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return _uint64_from_literal (fv, s, allow_partial_value, err_msg, G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFF));
}

static gboolean
uint48_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return _uint64_from_literal (fv, s, allow_partial_value, err_msg, G_GUINT64_CONSTANT(0xFFFFFFFFFFFF));
}

static gboolean
uint40_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return _uint64_from_literal (fv, s, allow_partial_value, err_msg, G_GUINT64_CONSTANT(0xFFFFFFFFFF));
}

static gboolean
uint64_from_charconst(fvalue_t *fv, unsigned long num, gchar **err_msg _U_)
{
	fv->value.uinteger64 = (guint64)num;
	return TRUE;
}

static long long
binary_strtoll(const char *s, char **endptr)
{
	const char *binstr = s;
	gboolean negative = FALSE;

	if (*binstr == '+') {
		binstr++;
	}
	else if (*binstr == '-') {
		binstr++;
		negative = TRUE;
	}

	if (binstr[0] == '0' && (binstr[1] == 'b' || binstr[1] == 'B')) {
		long long value = g_ascii_strtoll(binstr + 2, endptr, 2);
		return negative ? -value : +value;
	}

	return g_ascii_strtoll(s, endptr, 0);
}

static gboolean
_sint64_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg,
		   gint64 max, gint64 min)
{
	gint64 value;
	char   *endptr;

	if (!strchr (s, '-') && g_ascii_strtoull(s, NULL, 0) > G_MAXINT64) {
		/*
		 * Probably a positive integer > G_MAXINT64, but will be
		 * "converted in the obvious manner" by g_ascii_strtoll().
		 */
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" causes an integer overflow.", s);
		return FALSE;
	}

	errno = 0;
	value = binary_strtoll(s, &endptr);

	if (errno == EINVAL || endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" is not a valid number.", s);
		return FALSE;
	}
	if (errno == ERANGE) {
		if (err_msg != NULL) {
			if (value == G_MAXINT64) {
				*err_msg = ws_strdup_printf("\"%s\" causes an integer overflow.", s);
			}
			else if (value == G_MININT64) {
				*err_msg = ws_strdup_printf("\"%s\" causes an integer underflow.", s);
			}
			else {
				/*
				 * XXX - can "strtol()" set errno to
				 * ERANGE without returning LONG_MAX?
				 */
				*err_msg = ws_strdup_printf("\"%s\" is not an integer.", s);
			}
		}
		return FALSE;
	}

	if (value > max) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" too big for this field, maximum %" PRIu64".", s, max);
		return FALSE;
	} else if (value < min) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" too small for this field, maximum %" PRIu64 ".", s, max);
		return FALSE;
	}

	fv->value.sinteger64 = (guint64)value;
	return TRUE;
}

static gboolean
sint64_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return _sint64_from_literal (fv, s, allow_partial_value, err_msg, G_MAXINT64, G_MININT64);
}

static gboolean
sint56_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return _sint64_from_literal (fv, s, allow_partial_value, err_msg, G_GINT64_CONSTANT(0x7FFFFFFFFFFFFF), G_GINT64_CONSTANT(-0x80000000000000));
}

static gboolean
sint48_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return _sint64_from_literal (fv, s, allow_partial_value, err_msg, G_GINT64_CONSTANT(0x7FFFFFFFFFFF), G_GINT64_CONSTANT(-0x800000000000));
}

static gboolean
sint40_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	return _sint64_from_literal (fv, s, allow_partial_value, err_msg, G_GINT64_CONSTANT(0x7FFFFFFFFF), G_GINT64_CONSTANT(-0x8000000000));
}

static gboolean
sint64_from_charconst(fvalue_t *fv, unsigned long num, gchar **err_msg _U_)
{
	fv->value.sinteger64 = (gint64)num;
	return TRUE;
}

static char *
integer64_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	guint64 val;

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

static gboolean
cmp_bitwise_and64(const fvalue_t *a, const fvalue_t *b)
{
	return ((a->value.uinteger64 & b->value.uinteger64) != 0);
}

/* BOOLEAN-specific */

static gboolean
boolean_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	if (g_ascii_strcasecmp(s, "true") == 0) {
		fv->value.uinteger64 = 1;
		return TRUE;
	}
	if (g_ascii_strcasecmp(s, "false") == 0) {
		fv->value.uinteger64 = 0;
		return TRUE;
	}

	return uint64_from_literal(fv, s, allow_partial_value, err_msg);
}

static char *
boolean_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	if (fv->value.uinteger64)
		return wmem_strdup(scope, "1");
	return wmem_strdup(scope, "0");
}

/* False is less than True (arbitrary):
 * A  B   cmp(A, B)
 * T  T   0
 * F  F   0
 * F  T  -1
 * T  F   1
 */
static int
boolean_cmp_order(const fvalue_t *a, const fvalue_t *b)
{
	if (a->value.uinteger64) {
		if (b->value.uinteger64) {
			return 0;
		}
		return 1;
	}
	if (b->value.uinteger64) {
		return -1;
	}
	return 0;
}

/* EUI64-specific */
static gboolean
eui64_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	GByteArray	*bytes;
	gboolean	res;
	union {
		guint64 value;
		guint8  bytes[8];
	} eui64;

	/*
	 * Don't request an error message if uint64_from_literal fails;
	 * if it does, we'll try parsing it as a sequence of bytes, and
	 * report an error if *that* fails.
	 */
	if (uint64_from_literal(fv, s, TRUE, NULL)) {
		return TRUE;
	}

	bytes = g_byte_array_new();
	res = hex_str_to_bytes(s, bytes, TRUE);
	if (!res || bytes->len != 8) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" is not a valid EUI-64 address.", s);
		g_byte_array_free(bytes, TRUE);
		return FALSE;
	}

	memcpy(eui64.bytes, bytes->data, 8);
	g_byte_array_free(bytes, TRUE);
	fv->value.uinteger64 = GUINT64_FROM_BE(eui64.value);
	return TRUE;
}

static char *
eui64_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	union {
		guint64 value;
		guint8  bytes[8];
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
		"Character, 1 byte",		/* pretty name */
		1,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		uint8_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint_from_charconst,		/* val_from_charconst */
		char_to_repr,			/* val_to_string_repr */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uinteger_cmp_order,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t uint8_type = {
		FT_UINT8,			/* ftype */
		"FT_UINT8",			/* name */
		"Unsigned integer, 1 byte",	/* pretty name */
		1,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		uint8_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint_from_charconst,		/* val_from_charconst */
		uinteger_to_repr,		/* val_to_string_repr */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uinteger_cmp_order,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t uint16_type = {
		FT_UINT16,			/* ftype */
		"FT_UINT16",			/* name */
		"Unsigned integer, 2 bytes",	/* pretty_name */
		2,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		uint16_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint_from_charconst,		/* val_from_charconst */
		uinteger_to_repr,		/* val_to_string_repr */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uinteger_cmp_order,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t uint24_type = {
		FT_UINT24,			/* ftype */
		"FT_UINT24",			/* name */
		"Unsigned integer, 3 bytes",	/* pretty_name */
		3,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		uint24_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint_from_charconst,		/* val_from_charconst */
		uinteger_to_repr,		/* val_to_string_repr */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uinteger_cmp_order,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t uint32_type = {
		FT_UINT32,			/* ftype */
		"FT_UINT32",			/* name */
		"Unsigned integer, 4 bytes",	/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		uint32_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint_from_charconst,		/* val_from_charconst */
		uinteger_to_repr,		/* val_to_string_repr */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uinteger_cmp_order,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t uint40_type = {
		FT_UINT40,			/* ftype */
		"FT_UINT40",			/* name */
		"Unsigned integer, 5 bytes",	/* pretty_name */
		5,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		uint40_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint64_from_charconst,		/* val_from_charconst */
		uinteger64_to_repr,		/* val_to_string_repr */

		{ .set_value_uinteger64 = set_uinteger64 },	/* union set_value */
		{ .get_value_uinteger64 = get_uinteger64 },	/* union get_value */

		uinteger64_cmp_order,
		cmp_bitwise_and64,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};
	static ftype_t uint48_type = {
		FT_UINT48,			/* ftype */
		"FT_UINT48",			/* name */
		"Unsigned integer, 6 bytes",	/* pretty_name */
		6,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		uint48_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint64_from_charconst,		/* val_from_charconst */
		uinteger64_to_repr,		/* val_to_string_repr */

		{ .set_value_uinteger64 = set_uinteger64 },	/* union set_value */
		{ .get_value_uinteger64 = get_uinteger64 },	/* union get_value */

		uinteger64_cmp_order,
		cmp_bitwise_and64,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};
	static ftype_t uint56_type = {
		FT_UINT56,			/* ftype */
		"FT_UINT56",			/* name */
		"Unsigned integer, 7 bytes",	/* pretty_name */
		7,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		uint56_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint64_from_charconst,		/* val_from_charconst */
		uinteger64_to_repr,		/* val_to_string_repr */

		{ .set_value_uinteger64 = set_uinteger64 },	/* union set_value */
		{ .get_value_uinteger64 = get_uinteger64 },	/* union get_value */

		uinteger64_cmp_order,
		cmp_bitwise_and64,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};
	static ftype_t uint64_type = {
		FT_UINT64,			/* ftype */
		"FT_UINT64",			/* name */
		"Unsigned integer, 8 bytes",	/* pretty_name */
		8,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		uint64_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint64_from_charconst,		/* val_from_charconst */
		uinteger64_to_repr,		/* val_to_string_repr */

		{ .set_value_uinteger64 = set_uinteger64 },	/* union set_value */
		{ .get_value_uinteger64 = get_uinteger64 },	/* union get_value */

		uinteger64_cmp_order,
		cmp_bitwise_and64,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};
	static ftype_t int8_type = {
		FT_INT8,			/* ftype */
		"FT_INT8",			/* name */
		"Signed integer, 1 byte",	/* pretty_name */
		1,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		sint8_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint_from_charconst,		/* val_from_charconst */
		integer_to_repr,		/* val_to_string_repr */

		{ .set_value_sinteger = set_sinteger },	/* union set_value */
		{ .get_value_sinteger = get_sinteger },	/* union get_value */

		sinteger_cmp_order,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t int16_type = {
		FT_INT16,			/* ftype */
		"FT_INT16",			/* name */
		"Signed integer, 2 bytes",	/* pretty_name */
		2,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		sint16_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint_from_charconst,		/* val_from_charconst */
		integer_to_repr,		/* val_to_string_repr */

		{ .set_value_sinteger = set_sinteger },	/* union set_value */
		{ .get_value_sinteger = get_sinteger },	/* union get_value */

		sinteger_cmp_order,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t int24_type = {
		FT_INT24,			/* ftype */
		"FT_INT24",			/* name */
		"Signed integer, 3 bytes",	/* pretty_name */
		3,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		sint24_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint_from_charconst,		/* val_from_charconst */
		integer_to_repr,		/* val_to_string_repr */

		{ .set_value_sinteger = set_sinteger },	/* union set_value */
		{ .get_value_sinteger = get_sinteger },	/* union get_value */

		sinteger_cmp_order,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t int32_type = {
		FT_INT32,			/* ftype */
		"FT_INT32",			/* name */
		"Signed integer, 4 bytes",	/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		sint32_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint_from_charconst,		/* val_from_charconst */
		integer_to_repr,		/* val_to_string_repr */

		{ .set_value_sinteger = set_sinteger },	/* union set_value */
		{ .get_value_sinteger = get_sinteger },	/* union get_value */

		sinteger_cmp_order,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t int40_type = {
		FT_INT40,			/* ftype */
		"FT_INT40",			/* name */
		"Signed integer, 5 bytes",	/* pretty_name */
		5,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		sint40_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint64_from_charconst,		/* val_from_charconst */
		integer64_to_repr,		/* val_to_string_repr */

		{ .set_value_sinteger64 = set_sinteger64 },	/* union set_value */
		{ .get_value_sinteger64 = get_sinteger64 },	/* union get_value */

		sinteger64_cmp_order,
		cmp_bitwise_and64,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};
	static ftype_t int48_type = {
		FT_INT48,			/* ftype */
		"FT_INT48",			/* name */
		"Signed integer, 6 bytes",	/* pretty_name */
		6,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		sint48_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint64_from_charconst,		/* val_from_charconst */
		integer64_to_repr,		/* val_to_string_repr */

		{ .set_value_sinteger64 = set_sinteger64 },	/* union set_value */
		{ .get_value_sinteger64 = get_sinteger64 },	/* union get_value */

		sinteger64_cmp_order,
		cmp_bitwise_and64,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};
	static ftype_t int56_type = {
		FT_INT56,			/* ftype */
		"FT_INT56",			/* name */
		"Signed integer, 7 bytes",	/* pretty_name */
		7,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		sint56_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint64_from_charconst,		/* val_from_charconst */
		integer64_to_repr,		/* val_to_string_repr */

		{ .set_value_sinteger64 = set_sinteger64 },	/* union set_value */
		{ .get_value_sinteger64 = get_sinteger64 },	/* union get_value */

		sinteger64_cmp_order,
		cmp_bitwise_and64,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};
	static ftype_t int64_type = {
		FT_INT64,			/* ftype */
		"FT_INT64",			/* name */
		"Signed integer, 8 bytes",	/* pretty_name */
		8,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		sint64_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		sint64_from_charconst,		/* val_from_charconst */
		integer64_to_repr,		/* val_to_string_repr */

		{ .set_value_sinteger64 = set_sinteger64 },	/* union set_value */
		{ .get_value_sinteger64 = get_sinteger64 },	/* union get_value */

		sinteger64_cmp_order,
		cmp_bitwise_and64,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};
	static ftype_t boolean_type = {
		FT_BOOLEAN,			/* ftype */
		"FT_BOOLEAN",			/* name */
		"Boolean",			/* pretty_name */
		0,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		boolean_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint64_from_charconst,		/* val_from_charconst */
		boolean_to_repr,		/* val_to_string_repr */

		{ .set_value_uinteger64 = set_uinteger64 },	/* union set_value */
		{ .get_value_uinteger64 = get_uinteger64 },	/* union get_value */

		boolean_cmp_order,		/* cmp_eq */
		NULL,				/* cmp_bitwise_and */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};

	static ftype_t ipxnet_type = {
		FT_IPXNET,			/* ftype */
		"FT_IPXNET",			/* name */
		"IPX network number",		/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		ipxnet_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		ipxnet_to_repr,			/* val_to_string_repr */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uinteger_cmp_order,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};

	static ftype_t framenum_type = {
		FT_FRAMENUM,			/* ftype */
		"FT_FRAMENUM",			/* name */
		"Frame number",			/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		uint32_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		uint_from_charconst,		/* val_from_charconst */
		uinteger_to_repr,		/* val_to_string_repr */

		{ .set_value_uinteger = set_uinteger },	/* union set_value */
		{ .get_value_uinteger = get_uinteger },	/* union get_value */

		uinteger_cmp_order,
		NULL,				/* cmp_bitwise_and */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};

	static ftype_t eui64_type = {
		FT_EUI64,			/* ftype */
		"FT_EUI64",			/* name */
		"EUI64 address",		/* pretty_name */
		FT_EUI64_LEN,			/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		eui64_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		eui64_to_repr,			/* val_to_string_repr */

		{ .set_value_uinteger64 = set_uinteger64 },	/* union set_value */
		{ .get_value_uinteger64 = get_uinteger64 },	/* union get_value */

		uinteger64_cmp_order,
		cmp_bitwise_and64,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
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
