/* wmem_strutl.c
 * Wireshark Memory Manager String Utilities
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <stdarg.h>

#ifdef _WIN32
#include <stdio.h>
#endif

#include <glib.h>
#include <glib/gprintf.h>

#include "wmem_core.h"
#include "wmem_allocator.h"
#include "wmem_strutl.h"

gchar *
wmem_strdup(wmem_allocator_t *allocator, const gchar *src)
{
    size_t len;

    /* If the string is NULL, just return the string "<NULL>" so that the
     * callers don't have to bother checking it. */
    if (!src) {
        src = "<NULL>";
    }

    len = strlen(src) + 1; /* +1 for the null-terminator */

    return (gchar *)memcpy(wmem_alloc(allocator, len), src, len);
}

gchar *
wmem_strndup(wmem_allocator_t *allocator, const gchar *src, const size_t len)
{
    gchar *dst;
    guint i;

    dst = (gchar *)wmem_alloc(allocator, len+1);

    for (i=0; (i < len) && src[i]; i++) {
        dst[i] = src[i];
    }

    dst[i] = '\0';

    return dst;
}

gchar *
wmem_strdup_printf(wmem_allocator_t *allocator, const gchar *fmt, ...)
{
    va_list ap;
    gchar *dst;

    va_start(ap, fmt);
    dst = wmem_strdup_vprintf(allocator, fmt, ap);
    va_end(ap);

    return dst;
}

/*
 * Using g_printf_string_upper_bound() to find the needed length almost doubles
 * the execution time of this function. Instead we use a pre allocated buffer
 * which may waste a bit of memory but are faster. As this is mostly called with
 * packet scoped memory(?) that shouldn't matter that much.
 * In my test file all strings was less than 72 characters long and quite a few
 * over 68 characters long. Chose 80 as the default.
 */
#ifndef _WIN32
#define WMEM_STRDUP_VPRINTF_DEFAULT_BUFFER 80
gchar *
wmem_strdup_vprintf(wmem_allocator_t *allocator, const gchar *fmt, va_list ap)
{
    va_list ap2;
    gchar *dst;
    int needed_len;

    G_VA_COPY(ap2, ap);

    /* needed_len = g_printf_string_upper_bound(fmt, ap2); */

    dst = (gchar *)wmem_alloc(allocator, WMEM_STRDUP_VPRINTF_DEFAULT_BUFFER);

    /* Returns: the number of characters which would be produced if the buffer was large enough
     * (not including the null, for which we add +1 ourselves). */
    needed_len = g_vsnprintf(dst, (gulong) WMEM_STRDUP_VPRINTF_DEFAULT_BUFFER, fmt, ap2) + 1;
    va_end(ap2);

    if (needed_len > WMEM_STRDUP_VPRINTF_DEFAULT_BUFFER) {
        wmem_free(allocator, dst);
        dst = (gchar *)wmem_alloc(allocator, needed_len);
        G_VA_COPY(ap2, ap);
        g_vsnprintf(dst, (gulong) needed_len, fmt, ap2);
        va_end(ap2);
    }

    return dst;
}
#else /* _WIN32 */
/*
 * GLib's v*printf routines are surprisingly slow on Windows, at least with
 * GLib 2.40.0. This appears to be due to GLib using the gnulib version of
 * vasnprintf when compiled under MinGW. If GLib ever ends up using the
 * native Windows v*printf routines this can be removed.
 */
gchar *
wmem_strdup_vprintf(wmem_allocator_t *allocator, const gchar *fmt, va_list ap)
{
    va_list ap2;
    gchar *dst;
    int needed_len;

    G_VA_COPY(ap2, ap);

    needed_len = _vscprintf(fmt, ap2) + 1;

    dst = (gchar *)wmem_alloc(allocator, needed_len);

    vsprintf_s(dst, needed_len, fmt, ap2);

    va_end(ap2);

    return dst;
}
#endif /* _WIN32 */

gchar *
wmem_strconcat(wmem_allocator_t *allocator, const gchar *first, ...)
{
    gsize   len;
    va_list args;
    gchar   *s;
    gchar   *concat;
    gchar   *ptr;

    if (!first)
        return NULL;

    len = 1 + strlen(first);
    va_start(args, first);
    while ((s = va_arg(args, gchar*))) {
        len += strlen(s);
    }
    va_end(args);

    ptr = concat = (gchar *)wmem_alloc(allocator, len);

    ptr = g_stpcpy(ptr, first);
    va_start(args, first);
    while ((s = va_arg(args, gchar*))) {
        ptr = g_stpcpy(ptr, s);
    }
    va_end(args);

    return concat;
}

gchar *
wmem_strjoin(wmem_allocator_t *allocator,
             const gchar *separator, const gchar *first, ...)
{
    gsize   len;
    va_list args;
    gsize separator_len;
    gchar   *s;
    gchar   *concat;
    gchar   *ptr;

    if (!first)
        return NULL;

    if (separator == NULL) {
        separator = "";
    }

    separator_len = strlen (separator);

    len = 1 + strlen(first); /* + 1 for null byte */
    va_start(args, first);
    while ((s = va_arg(args, gchar*))) {
        len += (separator_len + strlen(s));
    }
    va_end(args);

    ptr = concat = (gchar *)wmem_alloc(allocator, len);
    ptr = g_stpcpy(ptr, first);
    va_start(args, first);
    while ((s = va_arg(args, gchar*))) {
        ptr = g_stpcpy(ptr, separator);
        ptr = g_stpcpy(ptr, s);
    }
    va_end(args);

    return concat;

}

gchar *
wmem_strjoinv(wmem_allocator_t *allocator,
              const gchar *separator, gchar **str_array)
{
    gchar *string = NULL;

    if (!str_array)
        return NULL;

    if (separator == NULL) {
        separator = "";
    }

    if (str_array[0]) {
        gint i;
        gchar *ptr;
        gsize len, separator_len;

        separator_len = strlen(separator);

        /* Get first part of length. Plus one for null byte. */
        len = 1 + strlen(str_array[0]);
        /* Get the full length, including the separators. */
        for (i = 1; str_array[i] != NULL; i++) {
            len += separator_len;
            len += strlen(str_array[i]);
        }

        /* Allocate and build the string. */
        string = (gchar *)wmem_alloc(allocator, len);
        ptr = g_stpcpy(string, str_array[0]);
        for (i = 1; str_array[i] != NULL; i++) {
            ptr = g_stpcpy(ptr, separator);
            ptr = g_stpcpy(ptr, str_array[i]);
        }
    }

    return string;

}

gchar **
wmem_strsplit(wmem_allocator_t *allocator, const gchar *src,
        const gchar *delimiter, int max_tokens)
{
    gchar *splitted;
    gchar *s;
    guint tokens;
    guint sep_len;
    guint i;
    gchar **vec;

    if (!src || !delimiter || !delimiter[0])
        return NULL;

    /* An empty string results in an empty vector. */
    if (!src[0]) {
        vec = wmem_new0(allocator, gchar *);
        return vec;
    }

    splitted = wmem_strdup(allocator, src);
    sep_len = (guint)strlen(delimiter);

    if (max_tokens < 1)
        max_tokens = INT_MAX;

    /* Calculate the number of fields. */
    s = splitted;
    tokens = 1;
    while (tokens < (guint)max_tokens && (s = strstr(s, delimiter))) {
        s += sep_len;
        tokens++;
    }

    vec = wmem_alloc_array(allocator, gchar *, tokens + 1);

    /* Populate the array of string tokens. */
    s = splitted;
    vec[0] = s;
    tokens = 1;
    while (tokens < (guint)max_tokens && (s = strstr(s, delimiter))) {
        for (i = 0; i < sep_len; i++)
            s[i] = '\0';
        s += sep_len;
        vec[tokens] = s;
        tokens++;

    }

    vec[tokens] = NULL;

    return vec;
}

/*
 * wmem_ascii_strdown:
 * based on g_ascii_strdown.
 */
gchar*
wmem_ascii_strdown(wmem_allocator_t *allocator, const gchar *str, gssize len)
{
    gchar *result, *s;

    g_return_val_if_fail (str != NULL, NULL);

    if (len < 0)
        len = strlen (str);

    result = wmem_strndup(allocator, str, len);
    for (s = result; *s; s++)
        *s = g_ascii_tolower (*s);

    return result;
}
/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
