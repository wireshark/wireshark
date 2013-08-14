/* wmem_strutl.c
 * Wireshark Memory Manager String Utilities
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>
#include <stdarg.h>

#include <glib.h>

#include "wmem_core.h"
#include "wmem_allocator.h"
#include "wmem_strutl.h"

gchar *
wmem_strdup(wmem_allocator_t *allocator, const gchar *src)
{
    size_t len;

    /* If the string is NULL, just return the string "<NULL>" so that the
     * callers don't have to bother checking it. */
    if(!src) {
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

gchar *
wmem_strdup_vprintf(wmem_allocator_t *allocator, const gchar *fmt, va_list ap)
{
    va_list ap2;
    gsize len;
    gchar* dst;

    G_VA_COPY(ap2, ap);

    len = g_printf_string_upper_bound(fmt, ap);

    dst = (gchar *)wmem_alloc(allocator, len+1);
    g_vsnprintf(dst, (gulong) len, fmt, ap2);
    va_end(ap2);

    return dst;
}

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

gchar **
wmem_strsplit(wmem_allocator_t *allocator, const gchar *src,
        const gchar *delimiter, int max_tokens)
{
    gchar* splitted;
    gchar* s;
    guint tokens;
    guint str_len;
    guint sep_len;
    guint i;
    gchar** vec;
    enum { AT_START, IN_PAD, IN_TOKEN } state;
    guint curr_tok = 0;

    if (    ! src
            || ! delimiter
            || ! delimiter[0])
        return NULL;

    s = splitted = wmem_strdup(allocator, src);
    str_len = (guint) strlen(splitted);
    sep_len = (guint) strlen(delimiter);

    if (max_tokens < 1) max_tokens = INT_MAX;

    tokens = 1;


    while (tokens <= (guint)max_tokens && ( s = strstr(s,delimiter) )) {
        tokens++;

        for(i=0; i < sep_len; i++ )
            s[i] = '\0';

        s += sep_len;

    }

    vec = wmem_alloc_array(allocator, gchar*,tokens+1);
    state = AT_START;

    for (i=0; i< str_len; i++) {
        switch(state) {
            case AT_START:
                if (splitted[i] == '\0') {
                    state = IN_PAD;
                }
                else {
                    vec[curr_tok] = &(splitted[i]);
                    curr_tok++;
                    state = IN_TOKEN;
                }
                break;
            case IN_TOKEN:
                if (splitted[i] == '\0') {
                    state = IN_PAD;
                }
                break;
            case IN_PAD:
                if (splitted[i] != '\0') {
                    vec[curr_tok] = &(splitted[i]);
                    curr_tok++;
                    state = IN_TOKEN;
                }
                break;
        }
    }

    vec[curr_tok] = NULL;

    return vec;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
