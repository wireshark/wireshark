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
#define _GNU_SOURCE
#include "config.h"
#include "wmem_strutl.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>

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

#ifdef HAVE_VASPRINTF
static char *
_strdup_vasprintf(const char *fmt, va_list ap)
{
    char *str = NULL;
    int ret;

    ret = vasprintf(&str, fmt, ap);
    if (ret == -1 && errno == ENOMEM) {
        /* Out of memory. We have to mimic GLib here and abort. */
        g_error("%s: failed to allocate memory", G_STRLOC);
    }
    return str;
}
#endif /* HAVE_VASPRINTF */

#define WMEM_STRDUP_VPRINTF_DEFAULT_BUFFER 256
char *
wmem_strdup_vprintf(wmem_allocator_t *allocator, const char *fmt, va_list ap)
{
    va_list ap2;
    char buf[WMEM_STRDUP_VPRINTF_DEFAULT_BUFFER];
    int needed_len;
    char *new_buf;
    size_t new_buf_size;

#ifdef HAVE_VASPRINTF
    if (allocator == NULL) {
        return _strdup_vasprintf(fmt, ap);
    }
#endif

    va_copy(ap2, ap);
    needed_len = vsnprintf(buf, sizeof(buf), fmt, ap2);
    va_end(ap2);

    new_buf_size = needed_len + 1;
    new_buf = wmem_alloc(allocator, new_buf_size);

    if (new_buf_size <= WMEM_STRDUP_VPRINTF_DEFAULT_BUFFER) {
        memcpy(new_buf, buf, new_buf_size);
        return new_buf;
    }
    vsnprintf(new_buf, new_buf_size, fmt, ap);
    return new_buf;
}

/* Return the first occurrence of needle in haystack.
 * If not found, return NULL.
 * If either haystack or needle has 0 length, return NULL.*/
const guint8 *
ws_memmem(const void *_haystack, size_t haystack_len,
                const void *_needle, size_t needle_len)
{
#ifdef HAVE_MEMMEM
    return memmem(_haystack, haystack_len, _needle, needle_len);
#else
    /* Algorithm copied from GNU's glibc 2.3.2 memmem() under LGPL 2.1+ */
    const guint8 *haystack = _haystack;
    const guint8 *needle = _needle;
    const guint8 *begin;
    const guint8 *const last_possible = haystack + haystack_len - needle_len;

    if (needle_len == 0) {
        return NULL;
    }

    if (needle_len > haystack_len) {
        return NULL;
    }

    for (begin = haystack ; begin <= last_possible; ++begin) {
        if (begin[0] == needle[0] &&
                !memcmp(&begin[1], needle + 1,
                    needle_len - 1)) {
            return begin;
        }
    }

    return NULL;
#endif /* HAVE_MEMMEM */
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
