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

#include "strtoi.h"
#include <errno.h>

gboolean ws_strtoi64(const gchar* str, const gchar** endptr, gint64* cint)
{
	gchar* end;
	gint64 val;

	g_assert(cint);

	if (!str) {
		errno = EINVAL;
		return FALSE;
	}

	errno = 0;
	val = g_ascii_strtoll(str, &end, 10);
	if ((val == 0 && end == str) || (endptr == NULL && *end != '\0')) {
		*cint = 0;
		if (endptr != NULL)
			*endptr = end;
		errno = EINVAL;
		return FALSE;
	}
	if ((val == G_MAXINT64 || val == G_MININT64) && errno == ERANGE) {
		/*
		 * Return the value, so our caller knows whether to
		 * report the value as "too small" or "too large".
		 */
		*cint = val;
		if (endptr != NULL)
			*endptr = end;
		/* errno is already set */
		return FALSE;
	}
	if (endptr != NULL)
		*endptr = end;
	*cint = val;
	return TRUE;
}

#define DEFINE_WS_STRTOI_BITS(bits) \
gboolean ws_strtoi##bits(const gchar* str, const gchar** endptr, gint##bits* cint) \
{ \
	gint64 val = 0; \
	if (!ws_strtoi64(str, endptr, &val)) { \
		/* \
		 * For ERANGE, return either G_MININT##bits or \
		 * G_MAXINT##bits so our caller knows whether \
		 * to report the value as "too small" or "too \
		 * large". \
		 * \
		 * For other errors, return 0, for parallelism \
		 * with ws_strtoi64(). \
		 */ \
		if (errno == ERANGE) { \
			if (val < 0) \
				*cint = G_MININT##bits; \
			else \
				*cint = G_MAXINT##bits; \
		} else \
			*cint = 0; \
		return FALSE; \
	} \
	if (val < G_MININT##bits) { \
		/* \
		 * Return G_MININT##bits so our caller knows whether to \
		 * report the value as "too small" or "too large". \
		 */ \
		*cint = G_MININT##bits; \
		errno = ERANGE; \
		return FALSE; \
	} \
	if (val > G_MAXINT##bits) { \
		/* \
		 * Return G_MAXINT##bits so our caller knows whether to \
		 * report the value as "too small" or "too large". \
		 */ \
		*cint = G_MAXINT##bits; \
		errno = ERANGE; \
		return FALSE; \
	} \
	*cint = (gint##bits)val; \
	return TRUE; \
}

DEFINE_WS_STRTOI_BITS(32)
DEFINE_WS_STRTOI_BITS(16)
DEFINE_WS_STRTOI_BITS(8)

gboolean ws_strtoi(const gchar* str, const gchar** endptr, gint* cint)
{
	gint64 val = 0;
	if (!ws_strtoi64(str, endptr, &val)) {
		/*
		 * For ERANGE, return either G_MININT or
		 * G_MAXINT so our caller knows whether
		 * to report the value as "too small" or "too
		 * large".
		 *
		 * For other errors, return 0, for parallelism
		 * with ws_strtoi64().
		 */
		if (errno == ERANGE) {
			if (val < 0)
				*cint = G_MININT;
			else
				*cint = G_MAXINT;
		} else
			*cint = 0;
		return FALSE;
	}
	if (val < G_MININT) {
		/*
		 * Return G_MININT so our caller knows whether to
		 * report the value as "too small" or "too large".
		 */
		*cint = G_MININT;
		errno = ERANGE;
		return FALSE;
	}
	if (val > G_MAXINT) {
		/*
		 * Return G_MAXINT so our caller knows whether to
		 * report the value as "too small" or "too large".
		 */
		*cint = G_MAXINT;
		errno = ERANGE;
		return FALSE;
	}
	*cint = (gint)val;
	return TRUE;
}

gboolean ws_basestrtou64(const gchar* str, const gchar** endptr, guint64* cint, int base)
{
	gchar* end;
	guint64 val;

	g_assert(cint);

	if (!str) {
		errno = EINVAL;
		return FALSE;
	}

	if (str[0] == '-' || str[0] == '+') {
		/*
		 * Unsigned numbers don't have a sign.
		 */
		*cint = 0;
		if (endptr != NULL)
			*endptr = str;
		errno = EINVAL;
		return FALSE;
	}
	errno = 0;
	val = g_ascii_strtoull(str, &end, base);
	if ((val == 0 && end == str) || (endptr == NULL && *end != '\0')) {
		*cint = 0;
		if (endptr != NULL)
			*endptr = end;
		errno = EINVAL;
		return FALSE;
	}
	if (val == G_MAXUINT64 && errno == ERANGE) {
		/*
		 * Return the value, because ws_strtoi64() does.
		 */
		*cint = val;
		if (endptr != NULL)
			*endptr = end;
		/* errno is already set */
		return FALSE;
	}
	if (endptr != NULL)
		*endptr = end;
	*cint = val;
	return TRUE;
}

gboolean ws_strtou64(const gchar* str, const gchar** endptr, guint64* cint)
{
	return ws_basestrtou64(str, endptr, cint, 10);
}

gboolean ws_hexstrtou64(const gchar* str, const gchar** endptr, guint64* cint)
{
	return ws_basestrtou64(str, endptr, cint, 16);
}

#define DEFINE_WS_STRTOU_BITS(bits) \
gboolean ws_basestrtou##bits(const gchar* str, const gchar** endptr, guint##bits* cint, int base) \
{ \
	guint64 val; \
	if (!ws_basestrtou64(str, endptr, &val, base)) { \
		/* \
		 * For ERANGE, return G_MAXUINT##bits for parallelism \
		 * with ws_strtoi##bits(). \
		 * \
		 * For other errors, return 0, for parallelism \
		 * with ws_basestrtou64(). \
		 */ \
		if (errno == ERANGE) \
			*cint = G_MAXUINT##bits; \
		else \
			*cint = 0; \
		return FALSE; \
	} \
	if (val > G_MAXUINT##bits) { \
		/* \
		 * Return G_MAXUINT##bits for parallelism with \
		 * ws_strtoi##bits(). \
		 */ \
		*cint = G_MAXUINT##bits; \
		errno = ERANGE; \
		return FALSE; \
	} \
	*cint = (guint##bits)val; \
	return TRUE; \
} \
\
gboolean ws_strtou##bits(const gchar* str, const gchar** endptr, guint##bits* cint) \
{ \
	return ws_basestrtou##bits(str, endptr, cint, 10); \
} \
\
gboolean ws_hexstrtou##bits(const gchar* str, const gchar** endptr, guint##bits* cint) \
{ \
	return ws_basestrtou##bits(str, endptr, cint, 16); \
}

DEFINE_WS_STRTOU_BITS(32)
DEFINE_WS_STRTOU_BITS(16)
DEFINE_WS_STRTOU_BITS(8)

gboolean ws_basestrtou(const gchar* str, const gchar** endptr, guint* cint, int base)
{
	guint64 val;
	if (!ws_basestrtou64(str, endptr, &val, base)) {
		/*
		 * For ERANGE, return G_MAXUINT for parallelism
		 * with ws_strtoi().
		 *
		 * For other errors, return 0, for parallelism
		 * with ws_basestrtou64().
		 */
		if (errno == ERANGE)
			*cint = G_MAXUINT;
		else
			*cint = 0;
		return FALSE;
	}
	if (val > G_MAXUINT) {
		/*
		 * Return G_MAXUINT for parallelism with
		 * ws_strtoi().
		 */
		*cint = G_MAXUINT;
		errno = ERANGE;
		return FALSE;
	}
	*cint = (guint)val;
	return TRUE;
}

gboolean ws_strtou(const gchar* str, const gchar** endptr, guint* cint)
{
	return ws_basestrtou(str, endptr, cint, 10);
}
\
gboolean ws_hexstrtou(const gchar* str, const gchar** endptr, guint* cint)
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
