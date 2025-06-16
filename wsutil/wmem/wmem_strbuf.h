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

#include <ws_codepoints.h>

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
 *  alloc_size is the size of the raw buffer pointed to by str, regardless of
 *      what string is actually being stored (i.e. the buffer contents)
 */
struct _wmem_strbuf_t {
    /* read-only fields */
    wmem_allocator_t *allocator;
    char *str;
    size_t len;

    /* private fields */
    size_t alloc_size;
};

typedef struct _wmem_strbuf_t wmem_strbuf_t;

WS_DLL_PUBLIC
wmem_strbuf_t *
wmem_strbuf_new_sized(wmem_allocator_t *allocator, size_t alloc_size)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
wmem_strbuf_t *
wmem_strbuf_new(wmem_allocator_t *allocator, const char *str)
G_GNUC_MALLOC;

#define wmem_strbuf_create(allocator) \
    wmem_strbuf_new(allocator, "")

WS_DLL_PUBLIC
wmem_strbuf_t *
wmem_strbuf_new_len(wmem_allocator_t *allocator, const char *str, size_t len)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
wmem_strbuf_t *
wmem_strbuf_dup(wmem_allocator_t *allocator, const wmem_strbuf_t *strbuf)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
void
wmem_strbuf_append(wmem_strbuf_t *strbuf, const char *str);

/* Appends up to append_len bytes from str. Ensures that strbuf
 * is null terminated afterwards but will copy embedded nulls. */
WS_DLL_PUBLIC
void
wmem_strbuf_append_len(wmem_strbuf_t *strbuf, const char *str, size_t append_len);

WS_DLL_PUBLIC
void
wmem_strbuf_append_printf(wmem_strbuf_t *strbuf, const char *format, ...)
G_GNUC_PRINTF(2, 3);

WS_DLL_PUBLIC
void
wmem_strbuf_append_vprintf(wmem_strbuf_t *strbuf, const char *fmt, va_list ap);

WS_DLL_PUBLIC
void
wmem_strbuf_append_c(wmem_strbuf_t *strbuf, const char c);

WS_DLL_PUBLIC
void
wmem_strbuf_append_c_count(wmem_strbuf_t *strbuf, const char c, size_t count);

WS_DLL_PUBLIC
void
wmem_strbuf_append_unichar(wmem_strbuf_t *strbuf, const gunichar c);

#define wmem_strbuf_append_unichar_repl(buf) \
            wmem_strbuf_append_unichar(buf, UNICODE_REPLACEMENT_CHARACTER)

/* As wmem_strbuf_append_unichar but appends a REPLACEMENT CHARACTER
 * instead for any invalid Unicode codepoints.
 */
WS_DLL_PUBLIC
void
wmem_strbuf_append_unichar_validated(wmem_strbuf_t *strbuf, const gunichar c);

WS_DLL_PUBLIC
void
wmem_strbuf_append_hex(wmem_strbuf_t *strbuf, uint8_t);

/* Returns the number of characters written (4, 6 or 10). */
WS_DLL_PUBLIC
size_t
wmem_strbuf_append_hex_unichar(wmem_strbuf_t *strbuf, gunichar);

WS_DLL_PUBLIC
void
wmem_strbuf_truncate(wmem_strbuf_t *strbuf, const size_t len);

WS_DLL_PUBLIC
const char *
wmem_strbuf_get_str(const wmem_strbuf_t *strbuf);

WS_DLL_PUBLIC
size_t
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

/* Validates the string buffer as UTF-8.
 * Unlike g_utf8_validate(), accepts embedded NUL bytes as valid UTF-8.
 * If endpptr is non-NULL, then the end of the valid range is stored there
 * (i.e. the first invalid character, or the end of the buffer otherwise).
 */
WS_DLL_PUBLIC
bool
wmem_strbuf_utf8_validate(wmem_strbuf_t *strbuf, const char **endptr);

WS_DLL_PUBLIC
void
wmem_strbuf_utf8_make_valid(wmem_strbuf_t *strbuf);

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
