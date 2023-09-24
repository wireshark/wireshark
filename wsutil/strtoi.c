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
\
bool ws_hexstrtou(const char* str, const char** endptr, unsigned* cint)
{
	return ws_basestrtou(str, endptr, cint, 16);
}

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
