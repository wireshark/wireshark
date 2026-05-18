/* strtoi.c
 * Utilities to convert strings to integers
 *
 * Copyright 2016, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <errno.h>

#include <glib.h>

#include <jtckdint.h>
#include "strtoi.h"
#include <wsutil/ws_assert.h>

bool ws_strtoi64(const char* str, const char** endptr, int64_t* cint)
{
	char* end;
	int64_t val;

	ws_assert(cint);

	if (!str) {
		errno = EINVAL;
		return false;
	}

	errno = 0;
	val = g_ascii_strtoll(str, &end, 10);
	if ((val == 0 && end == str) || (endptr == NULL && *end != '\0')) {
		*cint = 0;
		if (endptr != NULL)
			*endptr = end;
		errno = EINVAL;
		return false;
	}
	if ((val == INT64_MAX || val == INT64_MIN) && errno == ERANGE) {
		/*
		 * Return the value, so our caller knows whether to
		 * report the value as "too small" or "too large".
		 */
		*cint = val;
		if (endptr != NULL)
			*endptr = end;
		/* errno is already set */
		return false;
	}
	if (endptr != NULL)
		*endptr = end;
	*cint = val;
	return true;
}

#define DEFINE_WS_STRTOI_BITS(bits) \
bool ws_strtoi##bits(const char* str, const char** endptr, int##bits##_t* cint) \
{ \
	int64_t val = 0; \
	if (!ws_strtoi64(str, endptr, &val)) { \
		/* \
		 * For ERANGE, return either INT##bits##_MIN or \
		 * INT##bits##_MAX so our caller knows whether \
		 * to report the value as "too small" or "too \
		 * large". \
		 * \
		 * For other errors, return 0, for parallelism \
		 * with ws_strtoi64(). \
		 */ \
		if (errno == ERANGE) { \
			if (val < 0) \
				*cint = INT##bits##_MIN; \
			else \
				*cint = INT##bits##_MAX; \
		} else \
			*cint = 0; \
		return false; \
	} \
	if (val < INT##bits##_MIN) { \
		/* \
		 * Return INT##bits##_MIN so our caller knows whether to \
		 * report the value as "too small" or "too large". \
		 */ \
		*cint = INT##bits##_MIN; \
		errno = ERANGE; \
		return false; \
	} \
	if (val > INT##bits##_MAX) { \
		/* \
		 * Return INT##bits##_MAX so our caller knows whether to \
		 * report the value as "too small" or "too large". \
		 */ \
		*cint = INT##bits##_MAX; \
		errno = ERANGE; \
		return false; \
	} \
	*cint = (int##bits##_t)val; \
	return true; \
}

DEFINE_WS_STRTOI_BITS(32)
DEFINE_WS_STRTOI_BITS(16)
DEFINE_WS_STRTOI_BITS(8)

bool ws_strtoi(const char* str, const char** endptr, int* cint)
{
	int64_t val = 0;
	if (!ws_strtoi64(str, endptr, &val)) {
		/*
		 * For ERANGE, return either INT_MIN or
		 * INT_MAX so our caller knows whether
		 * to report the value as "too small" or "too
		 * large".
		 *
		 * For other errors, return 0, for parallelism
		 * with ws_strtoi64().
		 */
		if (errno == ERANGE) {
			if (val < 0)
				*cint = INT_MIN;
			else
				*cint = INT_MAX;
		} else
			*cint = 0;
		return false;
	}
	if (val < INT_MIN) {
		/*
		 * Return INT_MIN so our caller knows whether to
		 * report the value as "too small" or "too large".
		 */
		*cint = INT_MIN;
		errno = ERANGE;
		return false;
	}
	if (val > INT_MAX) {
		/*
		 * Return INT_MAX so our caller knows whether to
		 * report the value as "too small" or "too large".
		 */
		*cint = INT_MAX;
		errno = ERANGE;
		return false;
	}
	*cint = (int)val;
	return true;
}

bool ws_basestrtou64(const char* str, const char** endptr, uint64_t* cint, int base)
{
	char* end;
	uint64_t val;

	ws_assert(cint);

	if (!str) {
		errno = EINVAL;
		return false;
	}

	if (str[0] == '-' || str[0] == '+') {
		/*
		 * Unsigned numbers don't have a sign.
		 */
		*cint = 0;
		if (endptr != NULL)
			*endptr = str;
		errno = EINVAL;
		return false;
	}
	errno = 0;
	val = g_ascii_strtoull(str, &end, base);
	if ((val == 0 && end == str) || (endptr == NULL && *end != '\0')) {
		*cint = 0;
		if (endptr != NULL)
			*endptr = end;
		errno = EINVAL;
		return false;
	}
	if (val == UINT64_MAX && errno == ERANGE) {
		/*
		 * Return the value, because ws_strtoi64() does.
		 */
		*cint = val;
		if (endptr != NULL)
			*endptr = end;
		/* errno is already set */
		return false;
	}
	if (endptr != NULL)
		*endptr = end;
	*cint = val;
	return true;
}

bool ws_strtou64(const char* str, const char** endptr, uint64_t* cint)
{
	return ws_basestrtou64(str, endptr, cint, 10);
}

bool ws_hexstrtou64(const char* str, const char** endptr, uint64_t* cint)
{
	return ws_basestrtou64(str, endptr, cint, 16);
}

#define DEFINE_WS_STRTOU_BITS(bits) \
bool ws_basestrtou##bits(const char* str, const char** endptr, uint##bits##_t* cint, int base) \
{ \
	uint64_t val; \
	if (!ws_basestrtou64(str, endptr, &val, base)) { \
		/* \
		 * For ERANGE, return UINT##bits##_MAX for parallelism \
		 * with ws_strtoi##bits(). \
		 * \
		 * For other errors, return 0, for parallelism \
		 * with ws_basestrtou64(). \
		 */ \
		if (errno == ERANGE) \
			*cint = UINT##bits##_MAX; \
		else \
			*cint = 0; \
		return false; \
	} \
	if (val > UINT##bits##_MAX) { \
		/* \
		 * Return UINT##bits##_MAX for parallelism with \
		 * ws_strtoi##bits(). \
		 */ \
		*cint = UINT##bits##_MAX; \
		errno = ERANGE; \
		return false; \
	} \
	*cint = (uint##bits##_t)val; \
	return true; \
} \
\
bool ws_strtou##bits(const char* str, const char** endptr, uint##bits##_t* cint) \
{ \
	return ws_basestrtou##bits(str, endptr, cint, 10); \
} \
\
bool ws_hexstrtou##bits(const char* str, const char** endptr, uint##bits##_t* cint) \
{ \
	return ws_basestrtou##bits(str, endptr, cint, 16); \
}

DEFINE_WS_STRTOU_BITS(32)
DEFINE_WS_STRTOU_BITS(16)
DEFINE_WS_STRTOU_BITS(8)

bool ws_basestrtou(const char* str, const char** endptr, unsigned* cint, int base)
{
	uint64_t val;
	if (!ws_basestrtou64(str, endptr, &val, base)) {
		/*
		 * For ERANGE, return UINT_MAX for parallelism
		 * with ws_strtoi().
		 *
		 * For other errors, return 0, for parallelism
		 * with ws_basestrtou64().
		 */
		if (errno == ERANGE)
			*cint = UINT_MAX;
		else
			*cint = 0;
		return false;
	}
	if (val > UINT_MAX) {
		/*
		 * Return UINT_MAX for parallelism with
		 * ws_strtoi().
		 */
		*cint = UINT_MAX;
		errno = ERANGE;
		return false;
	}
	*cint = (unsigned)val;
	return true;
}

bool ws_strtou(const char* str, const char** endptr, unsigned* cint)
{
	return ws_basestrtou(str, endptr, cint, 10);
}

bool ws_hexstrtou(const char* str, const char** endptr, unsigned* cint)
{
	return ws_basestrtou(str, endptr, cint, 16);
}

static int
ws_parse_long_long(const uint8_t *buf, size_t len, const uint8_t **endptr, uint64_t *cint, int base)
{
	/* This code is derived from the g_parse_long_long code from GLib
	 * which itself is derived from the strtol(3) code from GNU libc
	 * (and, thus, GNUlib), both released under the GNU Lesser General
	 * Public License v 2.1, opting to apply the terms of the ordinarly
	 * GNU General Public License, version 2, as allowed under section
	 * 3 of that license.
	 *
	 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
	 * Copyright (C) 1991,92,94,95,96,97,98,99,2000,01,02
	 *        Free Software Foundation, Inc.
	 */

	const uint8_t *save;
	const uint8_t *hex_x = NULL;
	uint64_t val, cutoff, cutlim;
	unsigned char c;
	bool overflow = false;

	if (*buf == '0') {
		if ((len > 1) && (base == 0 || base == 16) && g_ascii_toupper(buf[1]) == 'X') {
			hex_x = &buf[1];
			buf += 2;
			len -= 2;
			base = 16;
		} else if (base == 0) {
			base = 8;
		}
	} else if (base == 0) {
		base = 10;
	}

	save = buf;
	cutoff = UINT64_MAX / base;
	cutlim = UINT64_MAX % base;

	val = 0;
	for (; len; --len) {
		c = *buf;
		if (c >= '0' && c <= '9') {
			c -= '0';
		} else if (g_ascii_isalpha(c)) {
			c = g_ascii_toupper(c) - 'A' + 10;
		} else {
			break;
		}
		if (c >= base) {
			break;
		}
		buf++;
		/* Check for overflow */
		if (val > cutoff || (val == cutoff && c > cutlim)) {
			overflow = true;
			if (endptr == NULL) {
				/* If we don't care about the end, just stop */
				*cint = UINT64_MAX;
				return ERANGE;
			}
		} else {
			val *= base;
			val += c;
		}
	}

	if (buf == save) {
		/* no conversion. We call that failure, except for the
		 * corner case of base 0 or 16 and starting with "0x",
		 * which converts to 0 and first invalid is the "x". */
		*cint = 0;
		if (endptr != NULL) {
			if (hex_x) {
				*endptr = hex_x;
				return 0;
			}
			*endptr = buf;
		}
		return EINVAL;
	}

        if (len && endptr == NULL) {
		*cint = 0;
		return EINVAL;
        }

	if (endptr != NULL) {
		/* This can point one past the end if fully converted; that is legal
		 * in C, but cannot be dereferenced. The caller should have enough
		 * information to know not to dereference it in that case. */
		*endptr = buf;
	}

	if (G_UNLIKELY(overflow)) {
		*cint = UINT64_MAX;
		return ERANGE;
	}

	*cint = val;
	return 0;
}

bool ws_basebuftou64(const uint8_t* buf, size_t len, const uint8_t** endptr, uint64_t* cint, int base)
{
	/* This code is derived from the g_parse_long_long code from GLib
	 * which itself is derived from the strtol(3) code from GNU libc
	 * (and, thus, GNUlib), both released under the GNU Lesser General
	 * Public License v 2.1, opting to apply the terms of the ordinarly
	 * GNU General Public License, version 2, as allowed under section
	 * 3 of that license.
	 *
	 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
	 * Copyright (C) 1991,92,94,95,96,97,98,99,2000,01,02
	 *        Free Software Foundation, Inc.
	 */
	const uint8_t *end = buf;
        int err;

	ws_assert(cint);

	if (!buf) {
#ifdef WS_ASSERT_ENABLED
		ws_warn_badarg("!buf");
#endif
		errno = EINVAL;
		return false;
	}

	if (buf[0] == '\0' || buf[0] == '-' || buf[0] == '+') {
		/*
		 * Unsigned numbers don't have a sign.
		 */
		*cint = 0;
		if (endptr != NULL)
			*endptr = buf;
		errno = EINVAL;
		return false;
	}

	if (len == 0 || base == 1 || base > 36) {
		*cint = 0;
		if (endptr != NULL)
			*endptr = buf;
		errno = EINVAL;
		return false;
	}

	/* Skip white space (we could not) */
	while (g_ascii_isspace(*end)) {
		++end;
		if (--len == 0) {
			*cint = 0;
			if (endptr != NULL)
				*endptr = buf;
			errno = EINVAL;
			return false;
		}
	}

	err = ws_parse_long_long(end, len, endptr, cint, base);
        errno = err;
	return !err;
}

bool ws_buftou64(const uint8_t* buf, size_t len, const uint8_t** endptr, uint64_t* cint)
{
	return ws_basebuftou64(buf, len, endptr, cint, 10);
}

bool ws_hexbuftou64(const uint8_t* buf, size_t len, const uint8_t** endptr, uint64_t* cint)
{
	return ws_basebuftou64(buf, len, endptr, cint, 16);
}

#define DEFINE_WS_BUFTOU_BITS(bits) \
bool ws_basebuftou##bits(const uint8_t* buf, size_t len, const uint8_t** endptr, uint##bits##_t* cint, int base) \
{ \
	uint64_t val; \
	if (!ws_basebuftou64(buf, len, endptr, &val, base)) { \
		/* \
		 * For ERANGE, return UINT##bits##_MAX for parallelism \
		 * with ws_strtoi##bits(). \
		 * \
		 * For other errors, return 0, for parallelism \
		 * with ws_basestrtou64(). \
		 */ \
		if (errno == ERANGE) \
			*cint = UINT##bits##_MAX; \
		else \
			*cint = 0; \
		return false; \
	} \
	if (val > UINT##bits##_MAX) { \
		/* \
		 * Return UINT##bits##_MAX for parallelism with \
		 * ws_strtoi##bits(). \
		 */ \
		*cint = UINT##bits##_MAX; \
		errno = ERANGE; \
		return false; \
	} \
	*cint = (uint##bits##_t)val; \
	return true; \
} \
\
bool ws_buftou##bits(const uint8_t* buf, size_t len, const uint8_t** endptr, uint##bits##_t* cint) \
{ \
	return ws_basebuftou##bits(buf, len, endptr, cint, 10); \
} \
\
bool ws_hexbuftou##bits(const uint8_t* buf, size_t len, const uint8_t** endptr, uint##bits##_t* cint) \
{ \
	return ws_basebuftou##bits(buf, len, endptr, cint, 16); \
}

DEFINE_WS_BUFTOU_BITS(32)
DEFINE_WS_BUFTOU_BITS(16)
DEFINE_WS_BUFTOU_BITS(8)

bool ws_basebuftoi64(const uint8_t* buf, size_t len, const uint8_t** endptr, int64_t* cint, int base)
{
	const uint8_t *end = buf;
	uint64_t val;
        bool negative = false;
        int err;

	ws_assert(cint);

	if (!buf) {
#ifdef WS_ASSERT_ENABLED
		ws_warn_badarg("!buf");
#endif
		errno = EINVAL;
		return false;
	}

	if (buf[0] == '\0') {
		*cint = 0;
		if (endptr != NULL)
			*endptr = buf;
		errno = EINVAL;
		return false;
	}

	if (len == 0 || base == 1 || base > 36) {
		*cint = 0;
		if (endptr != NULL)
			*endptr = buf;
		errno = EINVAL;
		return false;
	}

	/* Skip white space (we could not) */
	while (g_ascii_isspace(*end)) {
		++end;
		if (--len == 0) {
			*cint = 0;
			if (endptr != NULL)
				*endptr = buf;
			errno = EINVAL;
			return false;
		}
	}

	if (*end == '+') {
                ++end;
		--len;
        } else if (*end == '-') {
                negative = true;
                ++end;
		--len;
	}

	err = ws_parse_long_long(end, len, endptr, &val, base);
        if (err == EINVAL) {
            *cint = 0;
            errno = EINVAL;
            return false;
        }

        if (negative) {
            if (ckd_mul(cint, val, -1)) {
                *cint = INT64_MIN;
                errno = ERANGE;
                return false;
            }
        } else {
            if (ckd_mul(cint, val, 1)) {
                *cint = INT64_MAX;
                errno = ERANGE;
                return false;
            }
        }

	return true;
}

bool ws_buftoi64(const uint8_t* buf, size_t len, const uint8_t** endptr, int64_t* cint)
{
	return ws_basebuftoi64(buf, len, endptr, cint, 10);
}

bool ws_hexbuftoi64(const uint8_t* buf, size_t len, const uint8_t** endptr, int64_t* cint)
{
	return ws_basebuftoi64(buf, len, endptr, cint, 16);
}

#define DEFINE_WS_BUFTOI_BITS(bits) \
bool ws_basebuftoi##bits(const uint8_t* buf, size_t len, const uint8_t** endptr, int##bits##_t* cint, int base) \
{ \
	int64_t val = 0; \
	if (!ws_basebuftoi64(buf, len, endptr, &val, base)) { \
		/* \
		 * For ERANGE, return either INT##bits##_MIN or \
		 * INT##bits##_MAX so our caller knows whether \
		 * to report the value as "too small" or "too \
		 * large". \
		 * \
		 * For other errors, return 0, for parallelism \
		 * with ws_strtoi64(). \
		 */ \
		if (errno == ERANGE) { \
			if (val < 0) \
				*cint = INT##bits##_MIN; \
			else \
				*cint = INT##bits##_MAX; \
		} else \
			*cint = 0; \
		return false; \
	} \
	if (val < INT##bits##_MIN) { \
		/* \
		 * Return INT##bits##_MIN so our caller knows whether to \
		 * report the value as "too small" or "too large". \
		 */ \
		*cint = INT##bits##_MIN; \
		errno = ERANGE; \
		return false; \
	} \
	if (val > INT##bits##_MAX) { \
		/* \
		 * Return INT##bits##_MAX so our caller knows whether to \
		 * report the value as "too small" or "too large". \
		 */ \
		*cint = INT##bits##_MAX; \
		errno = ERANGE; \
		return false; \
	} \
	*cint = (int##bits##_t)val; \
	return true; \
} \
\
bool ws_buftoi##bits(const uint8_t* buf, size_t len, const uint8_t** endptr, int##bits##_t* cint) \
{ \
	return ws_basebuftoi##bits(buf, len, endptr, cint, 10); \
} \
\
bool ws_hexbuftoi##bits(const uint8_t* buf, size_t len, const uint8_t** endptr, int##bits##_t* cint) \
{ \
	return ws_basebuftoi##bits(buf, len, endptr, cint, 16); \
}

DEFINE_WS_BUFTOI_BITS(32)
DEFINE_WS_BUFTOI_BITS(16)
DEFINE_WS_BUFTOI_BITS(8)

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 noexpandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
