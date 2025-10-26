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

/**
 * @brief Internal structure representing a wmem-allocated string buffer.
 *
 * This structure holds a string buffer allocated via the wmem memory management system.
 * It supports efficient string manipulation and resizing, including embedded NUL bytes.
 */
struct _wmem_strbuf_t {
    /**
     * Pointer to the `wmem_allocator_t` used to manage memory for this buffer.
     */
    wmem_allocator_t *allocator;

    /**
     * Pointer to the raw character buffer containing the string.
     * May include embedded NULs.
     */
    char *str;

    /**
     * Logical length of the string content, excluding the null terminator.
     * May differ from `strlen(str)` if the string contains embedded NULs.
     */
    size_t len;

    /**
     * Total size of the allocated buffer pointed to by `str`,
     * regardless of actual string content.
     */
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


/**
 * @brief Create a new wmem string buffer initialized with an empty string.
 *
 * This macro wraps `wmem_strbuf_new()` with an empty string as the initial value.
 *
 * @param allocator The `wmem_allocator_t` used to manage memory for the buffer.
 *
 * @return A pointer to the newly created `wmem_strbuf_t`.
 */
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

/**
 * @brief Append the Unicode replacement character (U+FFFD) to a wmem string buffer.
 *
 * This macro appends the standard Unicode replacement character to the given
 * `wmem_strbuf_t`, typically used to indicate an unknown or invalid character.
 *
 * @param buf Pointer to the `wmem_strbuf_t` to append to.
 */
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

/**
 * @brief Append a hexadecimal representation of a byte to a wmem string buffer.
 *
 * Converts the given 8-bit unsigned integer into a two-character hexadecimal string
 * and appends it to the specified `wmem_strbuf_t`. For example, passing the value
 * `123` will append the string `"7B"` (in uppercase) to the buffer.
 *
 * @param strbuf Pointer to the `wmem_strbuf_t` to append to.
 * @param ch The 8-bit unsigned integer to convert and append as hexadecimal.
 */
WS_DLL_PUBLIC
void
wmem_strbuf_append_hex(wmem_strbuf_t *strbuf, uint8_t ch);

/**
 * @brief Append a hexadecimal representation of a Unicode character to a wmem string buffer.
 *
 * Converts the given Unicode character (`gunichar`) into its hexadecimal representation
 * and appends it to the specified `wmem_strbuf_t`.
 *
 * @param strbuf Pointer to the string buffer to append to.
 * @param ch Unicode character to convert and append.
 * @return Number of characters appended to the buffer (4, 6, or 10).
 */
WS_DLL_PUBLIC
size_t
wmem_strbuf_append_hex_unichar(wmem_strbuf_t *strbuf, gunichar ch);

/**
 * @brief Truncate a wmem string buffer to a specified length.
 *
 * Reduces the length of the given `wmem_strbuf_t` to `len` characters. If the buffer
 * currently contains more than `len` characters, the excess characters are removed.
 * If the buffer contains fewer than `len` characters, no changes are made.
 *
 * @note This operation does not reallocate the buffer; it simply adjusts the logical length.
 *
 * @param strbuf Pointer to the string buffer to truncate.
 * @param len The target length to truncate the buffer to.
 */
WS_DLL_PUBLIC
void
wmem_strbuf_truncate(wmem_strbuf_t *strbuf, const size_t len);

/**
 * @brief Retrieve the current string content from a wmem string buffer.
 *
 * Returns a pointer to the internal null-terminated string stored in the given
 * `wmem_strbuf_t`. This string reflects all content appended to the buffer so far.
 *
 * @param strbuf Pointer to the string buffer to query.
 * @return Pointer to the internal null-terminated string.
 */
WS_DLL_PUBLIC
const char *
wmem_strbuf_get_str(const wmem_strbuf_t *strbuf);

/**
 * @brief Retrieve the current length of a wmem string buffer.
 *
 * Returns the number of characters currently stored in the given `wmem_strbuf_t`,
 * excluding the null terminator. This reflects the logical length of the string
 * content in the buffer.
 *
 * @param strbuf Pointer to the string buffer to query.
 * @return The length of the string content in the buffer.
 */
WS_DLL_PUBLIC
size_t
wmem_strbuf_get_len(const wmem_strbuf_t *strbuf);

/**
 * @brief Compare the contents of two wmem string buffers.
 *
 * Performs a string comparison between the contents of `sb1` and `sb2`, similar to `strcmp()`.
 * Returns an integer less than, equal to, or greater than zero if the string in `sb1` is found,
 * respectively, to be less than, to match, or be greater than the string in `sb2`.
 *
 * @note The comparison is case-sensitive and uses standard C string semantics.
 *
 * @param sb1 Pointer to the first `wmem_strbuf_t` to compare.
 * @param sb2 Pointer to the second `wmem_strbuf_t` to compare.
 * @return An integer indicating the lexical relationship between the two strings.
 */
WS_DLL_PUBLIC
int
wmem_strbuf_strcmp(const wmem_strbuf_t *sb1, const wmem_strbuf_t *sb2);

/**
 * @brief Search for a substring within a wmem string buffer.
 *
 * Searches for the contents of `needle` within the contents of `haystack`, both represented
 * as `wmem_strbuf_t` structures. If the substring is found, a pointer to its first occurrence
 * within the `haystack` string is returned. If not found, the function returns `NULL`.
 *
 * @param haystack Pointer to the string buffer to search within.
 * @param needle Pointer to the string buffer containing the substring to search for.
 * @return Pointer to the first occurrence of `needle` in `haystack`, or `NULL` if not found.
 */
WS_DLL_PUBLIC
const char *
wmem_strbuf_strstr(const wmem_strbuf_t *haystack, const wmem_strbuf_t *needle);

/**
 * @brief Finalize a wmem string buffer and extract its raw string.
 *
 * Truncates the allocated memory of the given `wmem_strbuf_t` to the minimal required size,
 * frees the internal buffer structure, and returns a non-const pointer to the resulting
 * null-terminated C string. After this call, the original `wmem_strbuf_t` is no longer valid
 * and must not be used.
 *
 * This function is typically used when the caller needs to retain ownership of the final
 * string but no longer requires the dynamic buffer interface.
 *
 * @param strbuf Pointer to the string buffer to finalize.
 * @return Pointer to the raw, null-terminated C string. The caller assumes ownership.
 */
WS_DLL_PUBLIC
char *
wmem_strbuf_finalize(wmem_strbuf_t *strbuf);

/**
 * @brief Destroy a wmem string buffer and release its associated memory.
 *
 * Frees all memory allocated for the given `wmem_strbuf_t`, including its internal
 * string storage. After this call, the buffer is no longer valid and must not be used.
 *
 * @note This function should be used when the buffer is no longer needed and its
 *       contents do not need to be retained.
 * @note If you need to keep the final string, use `wmem_strbuf_finalize()` instead.
 *
 * @param strbuf Pointer to the string buffer to destroy.
 */
WS_DLL_PUBLIC
void
wmem_strbuf_destroy(wmem_strbuf_t *strbuf);

/**
 * @brief Validate the contents of a wmem string buffer as UTF-8.
 *
 * Checks whether the contents of the given `wmem_strbuf_t` form a valid UTF-8 sequence.
 * Unlike `g_utf8_validate()`, this function accepts embedded NUL (`\0`) bytes as valid.
 * If `endptr` is non-NULL, it will be set to point to the first invalid byte in the buffer,
 * or to the end of the buffer if the entire content is valid.
 *
 * @param strbuf Pointer to the string buffer to validate.
 * @param endptr Optional pointer to receive the end of the valid range.
 * @return `true` if the buffer contains valid UTF-8, `false` otherwise.
 */
WS_DLL_PUBLIC
bool
wmem_strbuf_utf8_validate(wmem_strbuf_t *strbuf, const char **endptr);


/**
 * @brief Ensure the contents of a wmem string buffer are valid UTF-8.
 *
 * Replaces any invalid UTF-8 sequences in the given `wmem_strbuf_t`
 * with the Unicode replacement character (`U+FFFD`). This guarantees that the resulting buffer
 * contains only valid UTF-8.
 *
 * @note This function modifies the buffer in-place.
 *
 * @param strbuf Pointer to the string buffer to sanitize.
 */
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
