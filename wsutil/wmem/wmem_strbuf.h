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

/**
 * @brief Create a new string buffer with a specified initial allocation size.
 *
 * Allocates and initializes a new `wmem_strbuf_t` structure using the given memory allocator,
 * with space preallocated for `alloc_size` bytes.
 *
 * @param allocator Pointer to the memory allocator to use.
 * @param alloc_size Initial number of bytes to allocate for the buffer.
 * @return Pointer to the newly created string buffer, or NULL on failure.
 */
WS_DLL_PUBLIC
wmem_strbuf_t *
wmem_strbuf_new_sized(wmem_allocator_t *allocator, size_t alloc_size)
G_GNUC_MALLOC;

/**
 * @brief Create a new string buffer initialized with a copy of the given string.
 *
 * Allocates and initializes a new `wmem_strbuf_t` structure using the specified memory allocator,
 * and copies the contents of the null-terminated string `str` into the buffer.
 *
 * @param allocator Pointer to the memory allocator to use.
 * @param str Null-terminated string to initialize the buffer with.
 * @return Pointer to the newly created string buffer, or NULL on failure.
 */
WS_DLL_PUBLIC
wmem_strbuf_t *
wmem_strbuf_new(wmem_allocator_t *allocator, const char *str)
G_GNUC_MALLOC;

#define wmem_strbuf_create(allocator) \
    wmem_strbuf_new(allocator, "")

/**
 * @brief Create a new string buffer initialized with a substring of specified length.
 *
 * Allocates and initializes a new `wmem_strbuf_t` structure using the specified memory allocator,
 * and copies up to `len` bytes from the string `str` into the buffer. The resulting buffer is
 * null-terminated.
 *
 * @param allocator Pointer to the memory allocator to use.
 * @param str Source string to copy into the buffer.
 * @param len Number of bytes to copy from the source string.
 * @return Pointer to the newly created string buffer, or NULL on failure.
 */
WS_DLL_PUBLIC
wmem_strbuf_t *
wmem_strbuf_new_len(wmem_allocator_t *allocator, const char *str, size_t len)
G_GNUC_MALLOC;

/**
 * @brief Duplicate an existing string buffer using the specified memory allocator.
 *
 * Creates a new `wmem_strbuf_t` instance by copying the contents of the given `strbuf`,
 * allocating memory for the duplicate using the provided allocator.
 *
 * @param allocator Pointer to the memory allocator to use.
 * @param strbuf Pointer to the source string buffer to duplicate.
 * @return Pointer to the newly created duplicate string buffer, or NULL on failure.
 */
WS_DLL_PUBLIC
wmem_strbuf_t *
wmem_strbuf_dup(wmem_allocator_t *allocator, const wmem_strbuf_t *strbuf)
G_GNUC_MALLOC;

/**
 * @brief Append a null-terminated string to the end of a string buffer.
 *
 * Adds the contents of `str` to the end of the given `wmem_strbuf_t` buffer,
 * resizing the buffer if necessary to accommodate the new data.
 *
 * @param strbuf Pointer to the string buffer to append to.
 * @param str Null-terminated string to append.
 */
WS_DLL_PUBLIC
void
wmem_strbuf_append(wmem_strbuf_t *strbuf, const char *str);

/**
 * @brief Append a specified number of bytes from a string to a string buffer.
 *
 * Appends up to `append_len` bytes from the string `str` to the end of the given
 * `wmem_strbuf_t` buffer. Embedded null characters in `str` will be copied, and the
 * resulting buffer will be null-terminated.
 *
 * @param strbuf Pointer to the string buffer to append to.
 * @param str Source string to copy bytes from.
 * @param append_len Number of bytes to append from the source string.
 */
WS_DLL_PUBLIC
void
wmem_strbuf_append_len(wmem_strbuf_t *strbuf, const char *str, size_t append_len);

/**
 * @brief Append formatted text to a string buffer.
 *
 * Formats a string using printf-style formatting and appends it to the end of the given
 * `wmem_strbuf_t` buffer. The buffer is resized if necessary to accommodate the new content.
 *
 * @param strbuf Pointer to the string buffer to append to.
 * @param format Format string (as used in printf).
 * @param ... Additional arguments to format into the string.
 */
WS_DLL_PUBLIC
void
wmem_strbuf_append_printf(wmem_strbuf_t *strbuf, const char *format, ...)
G_GNUC_PRINTF(2, 3);

/**
 * @brief Append formatted text to a string buffer using a va_list.
 *
 * Formats a string using a printf-style format string and a va_list of arguments,
 * then appends the result to the end of the given `wmem_strbuf_t` buffer.
 * The buffer is resized if necessary to accommodate the new content.
 *
 * @param strbuf Pointer to the string buffer to append to.
 * @param fmt Format string (as used in printf).
 * @param ap va_list containing the arguments to format into the string.
 */
WS_DLL_PUBLIC
void
wmem_strbuf_append_vprintf(wmem_strbuf_t *strbuf, const char *fmt, va_list ap);

/**
 * @brief Append a single character to a string buffer.
 *
 * Adds the character `c` to the end of the given `wmem_strbuf_t` buffer,
 * resizing the buffer if necessary. The buffer remains null-terminated.
 *
 * @param strbuf Pointer to the string buffer to append to.
 * @param c Character to append.
 */
WS_DLL_PUBLIC
void
wmem_strbuf_append_c(wmem_strbuf_t *strbuf, const char c);

/**
 * @brief Append a character to a string buffer multiple times.
 *
 * Appends the character `c` to the end of the given `wmem_strbuf_t` buffer
 * `count` times. The buffer is resized if necessary and remains null-terminated.
 *
 * @param strbuf Pointer to the string buffer to append to.
 * @param c Character to append.
 * @param count Number of times to append the character.
 */
WS_DLL_PUBLIC
void
wmem_strbuf_append_c_count(wmem_strbuf_t *strbuf, const char c, size_t count);

/**
 * @brief Append a Unicode character to a string buffer.
 *
 * Converts the given Unicode character `c` to its UTF-8 representation and appends it
 * to the end of the specified `wmem_strbuf_t` buffer. The buffer is resized if necessary
 * and remains null-terminated.
 *
 * @param strbuf Pointer to the string buffer to append to.
 * @param c Unicode character (gunichar) to append.
 */
WS_DLL_PUBLIC
void
wmem_strbuf_append_unichar(wmem_strbuf_t *strbuf, const gunichar c);

#define wmem_strbuf_append_unichar_repl(buf) \
            wmem_strbuf_append_unichar(buf, UNICODE_REPLACEMENT_CHARACTER)

/**
 * @brief Append a validated Unicode character to a string buffer.
 *
 * Converts the given Unicode character `c` to its UTF-8 representation and appends it
 * to the end of the specified `wmem_strbuf_t` buffer. If `c` is not a valid Unicode codepoint,
 * a standard replacement character (U+FFFD) is appended instead. The buffer is resized if necessary
 * and remains null-terminated.
 *
 * @param strbuf Pointer to the string buffer to append to.
 * @param c Unicode character (gunichar) to validate and append.
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
