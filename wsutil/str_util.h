/** @file
 * String utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __STR_UTIL_H__
#define __STR_UTIL_H__

#include <wireshark.h>
#include <wsutil/wmem/wmem.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Concatenate multiple strings into a single newly allocated string.
 *
 * Appends all non-NULL strings passed as variadic arguments into a single buffer.
 * No separator is added between strings.
 *
 * @param allocator Memory allocator to use for the returned string.
 * @param first The first string to concatenate.
 * @param ... Additional strings to concatenate, ending with NULL.
 * @return A newly allocated null-terminated string containing the concatenated result.
 *
 * @note The returned string is allocated using `allocator` and should be freed appropriately.
 */
WS_DLL_PUBLIC
char *
wmem_strconcat(wmem_allocator_t *allocator, const char *first, ...)
G_GNUC_MALLOC G_GNUC_NULL_TERMINATED;

/**
 * @brief Join multiple strings using a separator into a single newly allocated string.
 *
 * Inserts the specified separator between each non-NULL string in the variadic list.
 *
 * @param allocator Memory allocator to use for the returned string.
 * @param separator Separator string to insert between each element.
 * @param first The first string to join.
 * @param ... Additional strings to join, ending with NULL.
 * @return A newly allocated null-terminated string containing the joined result.
 *
 * @note The returned string is allocated using `allocator` and should be freed appropriately.
 */
WS_DLL_PUBLIC
char *
wmem_strjoin(wmem_allocator_t *allocator,
             const char *separator, const char *first, ...)
G_GNUC_MALLOC G_GNUC_NULL_TERMINATED;


/**
 * @brief Joins a number of strings together to form one long string,
 * with the optional separator inserted between each of them.
 *
 * As g_strjoinv, with the returned string wmem allocated.
 *
 * @param allocator  The wmem scope to use to allocate the returned string
 * @param separator A string to insert between each of the strings, or NULL.
 * @param str_array A NULL-terminated array of strings to join
 *
 * @note If str_array has no items, the return value is an empty string.
 * str_array should not be NULL (NULL is returned with an warning.)
 * NULL as a separator is equivalent to the empty string.
 */
WS_DLL_PUBLIC
char *
wmem_strjoinv(wmem_allocator_t *allocator,
              const char *separator, char **str_array)
G_GNUC_MALLOC;

/**
 * @brief Splits a string into a maximum of max_tokens pieces, using the given
 * delimiter.
 *
 * If max_tokens is reached, the remainder of string is appended
 * to the last token. Successive tokens are not folded and will instead result
 * in an empty string as element.
 *
 * If src or delimiter are NULL, or if delimiter is empty, this will return
 * NULL.
 *
 * Do not use with a NULL allocator, use g_strsplit instead.
 */
WS_DLL_PUBLIC
char **
wmem_strsplit(wmem_allocator_t *allocator, const char *src,
        const char *delimiter, int max_tokens);

/**
 * @brief Converts all upper case ASCII letters to lower case ASCII letters.
 *
 * Based on g_ascii_strdown
 * @param allocator  An enumeration of the different types of available allocators.
 * @param str a string.
 * @param len length of str in bytes, or -1 if str is nul-terminated.
 *
 * @return a newly-allocated string, with all the upper case
 *               characters in str converted to lower case, with
 *               semantics that exactly match g_ascii_tolower(). (Note
 *               that this is unlike the old g_strdown(), which modified
 *               the string in place.)
 **/
WS_DLL_PUBLIC
char*
wmem_ascii_strdown(wmem_allocator_t *allocator, const char *str, ssize_t len);

/**
 *  @brief In-place converstion of upper-case ASCII letters to lower-case.
 *
 *  Convert all upper-case ASCII letters to their ASCII lower-case
 *  equivalents, in place, with a simple non-locale-dependent
 *  ASCII mapping (A-Z -> a-z).
 *  All other characters are left unchanged, as the mapping to
 *  lower case may be locale-dependent.
 *
 *  The string is assumed to be in a character encoding, such as
 *  an ISO 8859 or other EUC encoding, or UTF-8, in which all
 *  bytes in the range 0x00 through 0x7F are ASCII characters and
 *  non-ASCII characters are constructed from one or more bytes in
 *  the range 0x80 through 0xFF.
 *
 * @param str The string to be lower-cased.
 * @return    ptr to the string
 */
WS_DLL_PUBLIC
char *ascii_strdown_inplace(char *str);

/**
 *  @brief In-place converstion of lower-case ASCII letters to upper-case.
 *
 * Convert all lower-case ASCII letters to their ASCII upper-case
 *  equivalents, in place, with a simple non-locale-dependent
 *  ASCII mapping (a-z -> A-Z).
 *  All other characters are left unchanged, as the mapping to
 *  lower case may be locale-dependent.
 *
 *  The string is assumed to be in a character encoding, such as
 *  an ISO 8859 or other EUC encoding, or UTF-8, in which all
 *  bytes in the range 0x00 through 0x7F are ASCII characters and
 *  non-ASCII characters are constructed from one or more bytes in
 *  the range 0x80 through 0xFF.
 *
 * @param str The string to be upper-cased.
 * @return    ptr to the string
 */
WS_DLL_PUBLIC
char *ascii_strup_inplace(char *str);

/**
 * @brief Check if an entire string consists of printable characters
 *
 * @param str    The string to be checked
 * @return       true if the entire string is printable, otherwise false
 */
WS_DLL_PUBLIC
bool isprint_string(const char *str);

/** Given a not-necessarily-null-terminated string, expected to be in
 *  UTF-8 but possibly containing invalid sequences (as it may have come
 *  from packet data), and the length of the string, deterimine if the
 *  string is valid UTF-8 consisting entirely of printable characters.
 *
 *  This means that it:
 *
 *   does not contain an illegal UTF-8 sequence (including overlong encodings,
 *   the sequences reserved for UTF-16 surrogate halves, and the values for
 *   code points above U+10FFFF that are no longer in Unicode)
 *
 *   does not contain a non-printable Unicode character such as control
 *   characters (including internal NULL bytes)
 *
 *   does not end in a partial sequence that could begin a valid character;
 *
 *   does not start with a partial sequence that could end a valid character;
 *
 * and thus guarantees that the result of format_text() would be the same as
 * that of wmem_strndup() with the same parameters.
 *
 * @param str    The string to be checked
 * @param length The number of bytes to validate
 * @return       true if the entire string is valid and printable UTF-8,
 *               otherwise false
 */
WS_DLL_PUBLIC
bool isprint_utf8_string(const char *str, const unsigned length);

/**
 * @brief Check if an entire string consists of digits
 *
 * @param str    The string to be checked
 * @return       true if the entire string is digits, otherwise false
 */
WS_DLL_PUBLIC
bool isdigit_string(const unsigned char *str);

/** Finds the first occurrence of string 'needle' in string 'haystack'.
 *  The matching is done ignoring the case of ASCII characters in a
 *  non-locale-dependent way.
 *
 *  The string is assumed to be in a character encoding, such as
 *  an ISO 8859 or other EUC encoding, or UTF-8, in which all
 *  bytes in the range 0x00 through 0x7F are ASCII characters and
 *  non-ASCII characters are constructed from one or more bytes in
 *  the range 0x80 through 0xFF.
 *
 * @param haystack The string possibly containing the substring
 * @param needle The substring to be searched
 * @return A pointer into 'haystack' where 'needle' is first found.
 *   Otherwise it returns NULL.
 */
WS_DLL_PUBLIC
const char *ws_ascii_strcasestr(const char *haystack, const char *needle);

/** Like the memchr() function, except it scans backwards from the end.
 *
 * @param haystack Pointer to the bytes of memory to search
 * @param ch The character to search
 * @param n The length of bytes to search from the end
 * @return A pointer to the last occurrence of "ch" in "haystack".
 * If "ch" isn't found or "n" is 0, returns NULL.
 */
WS_DLL_PUBLIC
const uint8_t *ws_memrchr(const void *haystack, int ch, size_t n);

/**
 * @brief Escape a null-terminated string for safe display or output.
 *
 * Converts control characters, quotes, and other non-printable bytes into
 * escaped sequences (e.g., `\n`, `\\`, `\"`) suitable for logging or serialization.
 * Optionally wraps the result in double quotes.
 *
 * @param alloc Memory allocator to use for the returned string.
 * @param string Null-terminated input string to escape.
 * @param add_quotes If true, the result will be wrapped in double quotes.
 * @return A newly allocated escaped string, or NULL on failure.
 */
WS_DLL_PUBLIC
char *ws_escape_string(wmem_allocator_t *alloc, const char *string, bool add_quotes);

/**
 * @brief Escape a string of specified length for safe display or output.
 *
 * Similar to `ws_escape_string()`, but allows escaping of strings that are not
 * null-terminated or contain embedded nulls. Useful for binary-safe formatting.
 *
 * @param alloc Memory allocator to use for the returned string.
 * @param string Pointer to the input buffer to escape.
 * @param len Number of bytes to process from `string`.
 * @param add_quotes If true, the result will be wrapped in double quotes.
 * @return A newly allocated escaped string, or NULL on failure.
 */
WS_DLL_PUBLIC
char *ws_escape_string_len(wmem_allocator_t *alloc, const char *string, ssize_t len, bool add_quotes);

/**
 * @brief Escape null bytes in a string for safe display or logging.
 *
 * Scans the input buffer and replaces each null byte (`\0`) with the literal string `"\\0"`,
 * making the result printable and distinguishable in output. Optionally wraps the result
 * in double quotes.
 *
 * @param alloc Memory allocator to use for the returned string.
 * @param string Pointer to the input buffer.
 * @param len Number of bytes to process from `string`.
 * @param add_quotes If true, the result will be wrapped in double quotes.
 * @return A newly allocated null-terminated string with escaped nulls, or NULL on failure.
 *
 * @note The returned string is allocated using `alloc` and must be freed appropriately.
 * @note This function is binary-safe and does not rely on null termination in the input.
 */
WS_DLL_PUBLIC
char *ws_escape_null(wmem_allocator_t *alloc, const char *string, size_t len, bool add_quotes);

/**
 * @brief Escape as in a number of CSV dialects.
 *
 * @param alloc  The wmem scope to use to allocate the returned string
 * @param string  The input string to escape
 * @param add_quotes  Whether to surround the string with quote_char
 * @param quote_char  The quote character, always escaped in some way.
 * @param double_quote  Whether to escape the quote character by doubling it
 * @param escape_whitespace  Whether to escape whitespace with a backslash
 * @return  The escaped string
 *
 * @note If double_quote is false, then quote_or_delim is escaped with a
 * backslash ('\'). The quote character can be '\0', in which case it is
 * ignored. If any character is being escaped with a backslash (i.e.,
 * quote_char is not '\0' and double_quote is false, or escape_whitespace
 * is true), then backslash is also escaped.  If add_quotes is false, then
 * quote_char can either be a quote character (if the string will be quoted
 * later after further manipulation) or the delimiter (to escape it, since
 * the string is not being quoted.).
 */
WS_DLL_PUBLIC
char *ws_escape_csv(wmem_allocator_t *alloc, const char *string, bool add_quotes, char quote_char, bool double_quote, bool escape_whitespace);

/**
 * @brief Convert a hexadecimal character to its numeric value.
 *
 * Converts a single ASCII character representing a hexadecimal digit
 * ('0'–'9', 'a'–'f', 'A'–'F') into its corresponding integer value (0–15).
 *
 * @param ch The character to convert.
 * @return The numeric value of the hex digit, or -1 if `ch` is not a valid hex character.
 */
WS_DLL_PUBLIC
int ws_xton(char ch);

/**
 * @brief Unit types used by `format_size_wmem()` for formatting size values.
 *
 * Specifies the base unit to append to a formatted size string. Some units adapt
 * their suffix depending on whether a prefix (e.g., "K", "Mi") is applied.
 * For example, "bytes" becomes "B" when prefixed, and "bits/s" becomes "bps".
 *
 * These values are used in conjunction with formatting flags to control output
 * from functions like `format_size_wmem()` and `format_size()`.
 */
typedef enum {
    FORMAT_SIZE_UNIT_NONE,          /**< No unit will be appended. You must supply your own. */
    /* XXX - This does not append a trailing space if there is no prefix.
     * That's good if you intend to list the unit somewhere else, e.g. in a
     * legend, header, or other column, but doesn't work well if intending
     * to append your own unit. You can test whether there's a prefix or
     * not with g_ascii_isdigit() (plus special handling for inf and NaN).
     */
    FORMAT_SIZE_UNIT_BYTES,         /**< "bytes" for un-prefixed sizes, "B" otherwise. */
    FORMAT_SIZE_UNIT_BITS,          /**< "bits" for un-prefixed sizes, "b" otherwise. */
    FORMAT_SIZE_UNIT_BITS_S,        /**< "bits/s" for un-prefixed sizes, "bps" otherwise. */
    FORMAT_SIZE_UNIT_BYTES_S,       /**< "bytes/s" for un-prefixed sizes, "Bps" otherwise. */
    FORMAT_SIZE_UNIT_PACKETS,       /**< "packets" */
    FORMAT_SIZE_UNIT_PACKETS_S,     /**< "packets/s" */
    FORMAT_SIZE_UNIT_EVENTS,        /**< "events" */
    FORMAT_SIZE_UNIT_EVENTS_S,      /**< "events/s" */
    FORMAT_SIZE_UNIT_FIELDS,        /**< "fields" */
    /* These next two aren't really for format_size (which takes an int) */
    FORMAT_SIZE_UNIT_SECONDS,       /**< "seconds" for un-prefixed sizes, "s" otherwise. */
    FORMAT_SIZE_UNIT_ERLANGS,       /**< "erlangs" for un-prefixed sizes, "E" otherwise. */
} format_size_units_e;

#define FORMAT_SIZE_PREFIX_SI   (1 << 0)    /**< SI (power of 1000) prefixes will be used. */
#define FORMAT_SIZE_PREFIX_IEC  (1 << 1)    /**< IEC (power of 1024) prefixes will be used. */

/** Given a floating point value, return it in a human-readable format
 *
 * Prefixes up to "E/Ei" (exa, exbi) and down to "a" (atto; negative
 * prefixes are SI-only) are currently supported. Values outside that
 * range will use scientific notation.
 *
 * @param allocator memory allocator to use for the returned string.
 * @param size The size value
 * @param unit The base unit to use (e.g., bytes, bits), specified by `format_size_units_e`.
 * @param flags Flags to control the output (unit of measurement,
 * SI vs IEC, etc). Unit and prefix flags may be ORed together.
 * @param precision Maximum number of digits to appear after the
 * decimal point. Trailing zeros are removed, as is the decimal
 * point if not digits follow it.
 * @return A newly-allocated string representing the value.
 */
WS_DLL_PUBLIC
char *format_units(wmem_allocator_t *allocator, double size,
                   format_size_units_e unit, uint16_t flags,
                   int precision);

/** Given a size, return its value in a human-readable format
 *
 * Prefixes up to "T/Ti" (tera, tebi) are currently supported.
 *
 * @param allocator memory allocator to use for the returned string.
 * @param size The size value
 * @param unit The base unit to use (e.g., bytes, bits), specified by `format_size_units_e`.
 * @param flags Flags to control the output (unit of measurement,
 * SI vs IEC, etc). Unit and prefix flags may be ORed together.
 * @return A newly-allocated string representing the value.
 */
WS_DLL_PUBLIC
char *format_size_wmem(wmem_allocator_t *allocator, int64_t size,
                        format_size_units_e unit, uint16_t flags);

/**
 * @brief Convenience macro for formatting a size value using the NULL allocator.
 *
 * This macro wraps `format_size_wmem()` with a NULL allocator.
 *
 * @param size The size value to format.
 * @param unit The base unit to use (e.g., bytes, bits), specified by `format_size_units_e`.
 * @param flags Flags to control formatting behavior (e.g., SI vs IEC, unit suffixes). Unit and prefix flags may be ORed together.
 * @return A newly allocated null-terminated string representing the formatted size, or NULL on failure.
 */
#define format_size(size, unit, flags) \
    format_size_wmem(NULL, size, unit, flags)

/**
 * @brief Return a printable character or '.' if non-printable.
 *
 * Converts the input character to itself if it is printable,
 * or returns '.' if it is a control or non-printable character.
 *
 * @param c The character to evaluate.
 * @return A printable character or '.'.
 */
WS_DLL_PUBLIC
char printable_char_or_period(char c);

/**
 * @brief Return the symbolic name of an error code.
 *
 * Converts a numeric error code (typically from `errno`) to its symbolic name
 * (e.g., `"EINVAL"`, `"ENOMEM"`), storing the result in `buf`.
 *
 * @param errnum The error code to translate.
 * @param buf Buffer to store the symbolic name.
 * @param buf_size Size of the buffer in bytes.
 * @return Pointer to `buf`, containing the symbolic name or a fallback string.
 *
 * @note The returned pointer is always non-NULL.
 */
WS_DLL_PUBLIC WS_RETNONNULL
const char *ws_strerrorname_r(int errnum, char *buf, size_t buf_size);

/**
 * @brief Create a string of underscores for visual alignment or highlighting.
 *
 * Allocates a string consisting of `len` underscores (`_`), optionally offset
 * by `offset` spaces. Useful for underlining or aligning output in diagnostics.
 *
 * @param allocator Memory allocator to use for the returned string.
 * @param offset Number of leading spaces before the underscores.
 * @param len Number of underscores to generate.
 * @return A newly allocated null-terminated string, or NULL on failure.
 *
 * @note The returned string is allocated using `allocator` and must be freed appropriately.
 */
WS_DLL_PUBLIC
char *ws_strdup_underline(wmem_allocator_t *allocator, long offset, size_t len);

/** Given a wmem scope, a not-necessarily-null-terminated string,
 *  expected to be in UTF-8 but possibly containing invalid sequences
 *  (as it may have come from packet data), and the length of the string,
 *  generate a valid UTF-8 string from it, allocated in the specified
 *  wmem scope, that:
 *
 *   shows printable Unicode characters as themselves;
 *
 *   shows non-printable ASCII characters as C-style escapes (octal
 *   if not one of the standard ones such as LF -> '\n');
 *
 *   shows non-printable Unicode-but-not-ASCII characters as
 *   their universal character names;
 *
 *   Replaces illegal UTF-8 sequences with U+FFFD (replacement character) ;
 *
 *  and return a pointer to it.
 *
 * @param allocator The wmem scope
 * @param string A pointer to the input string
 * @param len The length of the input string
 * @return A pointer to the formatted string
 *
 * @see tvb_format_text()
 */
WS_DLL_PUBLIC
char *format_text(wmem_allocator_t* allocator, const char *string, size_t len);

/** Same as format_text() but accepts a nul-terminated string.
 *
 * @param allocator The wmem scope
 * @param string A pointer to the input string
 * @return A pointer to the formatted string
 *
 * @see tvb_format_text()
 */
WS_DLL_PUBLIC
char *format_text_string(wmem_allocator_t* allocator, const char *string);

/**
 * Same as format_text() but replaces any whitespace characters
 * (space, tab, carriage return, new line, vertical tab, or formfeed)
 * with a space.
 *
 * @param allocator The wmem scope
 * @param line A pointer to the input string
 * @param len The length of the input string
 * @return A pointer to the formatted string
 *
 */
WS_DLL_PUBLIC
char *format_text_wsp(wmem_allocator_t* allocator, const char *line, size_t len);

/**
 * Given a string, generate a string from it that shows non-printable
 * characters as the chr parameter passed, except a whitespace character
 * (space, tab, carriage return, new line, vertical tab, or formfeed)
 * which will be replaced by a space, and return a pointer to it.
 *
 * This does *not* treat the input string as UTF-8.
 *
 * This is useful for displaying binary data that frequently but not always
 * contains text; otherwise the number of C escape codes makes it unreadable.
 *
 * @param allocator The wmem scope
 * @param string A pointer to the input string
 * @param len The length of the input string
 * @param chr The character to use to replace non-printable characters
 * @return A pointer to the formatted string
 *
 */
WS_DLL_PUBLIC
char *format_text_chr(wmem_allocator_t *allocator,
                        const char *string, size_t len, char chr);

/** Given a wmem scope and an 8-bit character
 *  generate a valid UTF-8 string from it, allocated in the specified
 *  wmem scope, that:
 *
 *   shows printable Unicode characters as themselves;
 *
 *   shows non-printable ASCII characters as C-style escapes (hex
 *   if not one of the standard ones such as LF -> '\n');
 *
 *  and return a pointer to it.
 *
 * @param allocator The wmem scope
 * @param c A character to format
 * @return A pointer to the formatted string
 */
WS_DLL_PUBLIC
char *format_char(wmem_allocator_t *allocator, char c);

/**
 * Truncate a UTF-8 string in place so that it is no larger than len bytes,
 * ensuring that the string is null terminated and ends with a complete
 * character instead of a partial sequence (e.g., possibly truncating up
 * to 3 additional bytes if the terminal character is 4 bytes long).
 *
 * The buffer holding the string must be large enough (at least len + 1
 * including the null terminator), and the first len bytes of the buffer
 * must be a valid UTF-8 string, except for possibly ending in a partial
 * sequence or not being null terminated. This is a convenience function
 * that for speed does not check either of those conditions.
 *
 * A common use case is when a valid UTF-8 string has been copied into a
 * buffer of length len+1 via snprintf, strlcpy, or strlcat and truncated,
 * to ensure that the final UTF-8 character is not a partial sequence.
 *
 * @param string A pointer to the input string
 * @param len The maximum length to truncate to
 * @return    ptr to the string
 */
WS_DLL_PUBLIC
char* ws_utf8_truncate(char *string, size_t len);

/**
 * @brief Convert a buffer of EBCDIC-encoded bytes to ASCII in-place.
 *
 * This function modifies the given buffer by converting each byte from EBCDIC
 * to its corresponding ASCII representation. The conversion is done in-place.
 *
 * @param buf Pointer to the buffer containing EBCDIC-encoded bytes.
 * @param bytes Number of bytes in the buffer to convert.
 */
WS_DLL_PUBLIC
void EBCDIC_to_ASCII(uint8_t *buf, unsigned bytes);

/**
 * @brief Convert a single EBCDIC-encoded byte to its ASCII equivalent.
 *
 * @param c EBCDIC-encoded byte.
 * @return The corresponding ASCII-encoded byte.
 */
WS_DLL_PUBLIC
uint8_t EBCDIC_to_ASCII1(uint8_t c);

/**
 * @enum hex_dump_enc
 * @brief Character encoding types supported by hex dump formatting.
 *
 * Specifies the encoding used when rendering the ASCII portion of a hex dump.
 * This affects how byte values are interpreted and displayed in the printable column.
 */
typedef enum {
    HEXDUMP_ENC_ASCII = 0,   /**< Interpret bytes as standard ASCII characters. */
    HEXDUMP_ENC_EBCDIC = 1   /**< Interpret bytes using EBCDIC encoding. */
} hex_dump_enc;

/*
 * Hexdump options for ASCII:
 */

/**
 * @brief Bitmask for extracting ASCII display options from a hexdump configuration.
 */
#define HEXDUMP_ASCII_MASK            (0x0003U)

/**
 * @brief Extract the ASCII display option from a hexdump flags value.
 *
 * @param option The full hexdump option bitfield.
 * @return The masked ASCII option value.
 */
#define HEXDUMP_ASCII_OPTION(option)  ((option) & HEXDUMP_ASCII_MASK)

/**
 * @brief Include ASCII section in hexdump output without delimiters.
 *
 * This reflects legacy `tshark` behavior, where the ASCII portion is appended
 * directly after the hex bytes.
 */
#define HEXDUMP_ASCII_INCLUDE (0x0000U)

/**
 * @brief Include ASCII section with delimiters for reliable parsing.
 *
 * Useful when post-processing or detecting the end of hex data programmatically.
 */
#define HEXDUMP_ASCII_DELIMIT (0x0001U)

/**
 * @brief Exclude ASCII section from hexdump output entirely.
 *
 * Use this when the ASCII portion is unnecessary or undesired in reports.
 */
#define HEXDUMP_ASCII_EXCLUDE (0x0002U)

/**
 * @brief Generate a formatted hex dump of a byte buffer.
 *
 * This function produces a hex dump of the given buffer `cp`, formatting it
 * according to the specified encoding and ASCII display options. Each formatted
 * line is passed to the user-supplied `print_line` callback.
 *
 * @param print_line Callback function to receive each formatted line of output.
 *                   It should return true to continue dumping, or false to abort early.
 * @param fp User-defined context pointer passed to `print_line` (e.g., a file handle or buffer).
 * @param cp Pointer to the byte buffer to be dumped.
 * @param length Number of bytes in the buffer.
 * @param encoding Encoding style for the hex dump (e.g., canonical, compact).
 * @param ascii_option ASCII display mode (e.g., include, exclude, delimit), masked via `HEXDUMP_ASCII_OPTION()`.
 * @return true if the entire buffer was dumped successfully; false if aborted early by `print_line`.
 *
 * @note This function does not write directly to stdout or a file; output is routed through `print_line`.
 */
WS_DLL_PUBLIC
bool hex_dump_buffer(bool (*print_line)(void *, const char *), void *fp,
                                    const unsigned char *cp, unsigned length,
                                    hex_dump_enc encoding,
                                    unsigned ascii_option);

/**
 * @brief Selects a singular or plural string based on a count.
 *
 * Useful for formatting messages that depend on quantity.
 *
 * @param d The numeric count.
 * @param s The singular form of the string.
 * @param p The plural form of the string.
 * @return `s` if `d == 1`, otherwise `p`.
 */
#define plurality(d,s,p) ((d) == 1 ? (s) : (p))

/**
 * @brief Converts a boolean value to a string literal.
 *
 * @param val Boolean expression.
 * @return `"TRUE"` if `val` is non-zero, `"FALSE"` otherwise.
 */
#define true_or_false(val) ((val) ? "TRUE" : "FALSE")

/**
 * @brief Returns a string or a placeholder if NULL.
 *
 * @param val Pointer to a string.
 * @return `val` if non-NULL, otherwise `"[NULL]"`.
 */
#define string_or_null(val) ((val) ? (val) : "[NULL]")

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __STR_UTIL_H__ */
