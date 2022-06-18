/** @file
 * Definitions for the Wireshark Memory Manager String Buffer
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_STRBUF_H__
#define __WMEM_STRBUF_H__

#include <string.h>
#include <glib.h>

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-strbuf String Buffer
 *
 *    A string object implementation on top of wmem.
 *
 *    @{
 */

/* Holds a wmem-allocated string-buffer.
 *  len is the length of the string (not counting the null-terminator) and
 *      should be the same as strlen(str) unless the string contains embedded
 *      nulls.
 *  alloc_len is the length of the raw buffer pointed to by str, regardless of
 *      what string is actually being stored (i.e. the buffer contents)
 *  max_len is the maximum permitted alloc_len (NOT the maximum permitted len,
 *      which must be one shorter than alloc_len to permit null-termination).
 *      When max_len is 0 (the default), no maximum is enforced.
 */
struct _wmem_strbuf_t {
    /* read-only fields */
    wmem_allocator_t *allocator;
    gchar *str;
    gsize len;

    /* private fields */
    gsize alloc_len;
    gsize max_len;
};

typedef struct _wmem_strbuf_t wmem_strbuf_t;

WS_DLL_PUBLIC
wmem_strbuf_t *
wmem_strbuf_sized_new(wmem_allocator_t *allocator,
                      gsize alloc_len, gsize max_len)
G_GNUC_MALLOC;

#define wmem_strbuf_new_label(ALLOCATOR) \
    wmem_strbuf_sized_new((ALLOCATOR), 0, ITEM_LABEL_LENGTH)

WS_DLL_PUBLIC
wmem_strbuf_t *
wmem_strbuf_new(wmem_allocator_t *allocator, const gchar *str)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
wmem_strbuf_t *
wmem_strbuf_new_len(wmem_allocator_t *allocator, const gchar *str, size_t len)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
wmem_strbuf_t *
wmem_strbuf_dup(wmem_allocator_t *allocator, const wmem_strbuf_t *strbuf)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
void
wmem_strbuf_append(wmem_strbuf_t *strbuf, const gchar *str);

/* Appends up to append_len bytes (as allowed by strbuf->max_len) from
 * str. Ensures that strbuf is null terminated afterwards but will copy
 * embedded nulls. */
WS_DLL_PUBLIC
void
wmem_strbuf_append_len(wmem_strbuf_t *strbuf, const gchar *str, gsize append_len);

WS_DLL_PUBLIC
void
wmem_strbuf_append_printf(wmem_strbuf_t *strbuf, const gchar *format, ...)
G_GNUC_PRINTF(2, 3);

WS_DLL_PUBLIC
void
wmem_strbuf_append_vprintf(wmem_strbuf_t *strbuf, const gchar *fmt, va_list ap);

WS_DLL_PUBLIC
void
wmem_strbuf_append_c(wmem_strbuf_t *strbuf, const gchar c);

WS_DLL_PUBLIC
void
wmem_strbuf_append_unichar(wmem_strbuf_t *strbuf, const gunichar c);

WS_DLL_PUBLIC
void
wmem_strbuf_truncate(wmem_strbuf_t *strbuf, const gsize len);

WS_DLL_PUBLIC
const gchar *
wmem_strbuf_get_str(const wmem_strbuf_t *strbuf);

WS_DLL_PUBLIC
gsize
wmem_strbuf_get_len(const wmem_strbuf_t *strbuf);

WS_DLL_PUBLIC
int
wmem_strbuf_strcmp(const wmem_strbuf_t *sb1, const wmem_strbuf_t *sb2);

WS_DLL_PUBLIC
const char *
wmem_strbuf_strstr(const wmem_strbuf_t *haystack, const wmem_strbuf_t *needle);

/** Truncates the allocated memory down to the minimal amount, frees the header
 *  structure, and returns a non-const pointer to the raw string. The
 *  wmem_strbuf_t structure cannot be used after this is called. Basically a
 *  destructor for when you still need the underlying C-string.
 */
WS_DLL_PUBLIC
char *
wmem_strbuf_finalize(wmem_strbuf_t *strbuf);

WS_DLL_PUBLIC
void
wmem_strbuf_destroy(wmem_strbuf_t *strbuf);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_STRBUF_H__ */

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
