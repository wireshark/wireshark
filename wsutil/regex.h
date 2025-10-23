/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_REGEX_H__
#define __WSUTIL_REGEX_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif

struct _ws_regex;
typedef struct _ws_regex ws_regex_t;

/**
 * @brief Compiles a regular expression pattern.
 *
 * Parses and compiles the given null-terminated pattern string into a regex object.
 * On failure, sets an error message in `errmsg`.
 *
 * @param patt The pattern string to compile.
 * @param errmsg Pointer to a string for error reporting (set on failure).
 * @return A pointer to the compiled regex object, or NULL on error.
 */
WS_DLL_PUBLIC ws_regex_t *ws_regex_compile(const char *patt, char **errmsg);

/**
 * @def WS_REGEX_CASELESS
 * @brief Enables case-insensitive matching.
 */
#define WS_REGEX_CASELESS (1U << 0)

/**
 * @def WS_REGEX_NEVER_UTF
 * @brief Disables UTF-8 mode, even if requested in the pattern.
 */
#define WS_REGEX_NEVER_UTF (1U << 1)

/**
 * @def WS_REGEX_ANCHORED
 * @brief Anchors the pattern to the start of the subject string.
 */
#define WS_REGEX_ANCHORED (1U << 2)

/**
 * @brief Compiles a regular expression with extended options.
 *
 * Compiles a pattern of specified length with optional flags for case sensitivity,
 * UTF-8 handling, and anchoring. On failure, sets an error message in `errmsg`.
 *
 * @param patt The pattern string to compile.
 * @param size Length of the pattern string.
 * @param errmsg Pointer to a string for error reporting (set on failure).
 * @param flags Bitmask of WS_REGEX_* options.
 * @return A pointer to the compiled regex object, or NULL on error.
 */
WS_DLL_PUBLIC ws_regex_t *ws_regex_compile_ex(const char *patt, ssize_t size, char **errmsg, unsigned flags);

/**
 * @brief Matches a null-terminated subject string against a compiled regex.
 *
 * Tests whether the subject string matches the compiled pattern.
 *
 * @param re Pointer to the compiled regex object.
 * @param subj Null-terminated subject string to match.
 * @return true if the pattern matches, false otherwise.
 */
WS_DLL_PUBLIC bool ws_regex_matches(const ws_regex_t *re, const char *subj);

/**
 * @brief Matches a subject string of specified length against a compiled regex.
 *
 * Tests whether the subject string matches the compiled pattern, using explicit length.
 *
 * @param re Pointer to the compiled regex object.
 * @param subj Subject string to match.
 * @param subj_length Length of the subject string in bytes.
 * @return true if the pattern matches, false otherwise.
 */
WS_DLL_PUBLIC bool ws_regex_matches_length(const ws_regex_t *re,
                                           const char *subj, ssize_t subj_length);

/**
 * @brief Finds the position of a match within a subject string.
 *
 * Returns the start and end positions of the first match in `pos_vect`.
 * Handles lookbehind correctly when using `subj_offset`.
 *
 * @note Using a nonzero subj_offset produces different results than
 * passing a pointer to the later offset as subj when the pattern
 * begins with a lookbehind.
 *
 * @note `pos_vect[0]` is the start index, `pos_vect[1]` is the end index.
 * The difference is the match length.
 *
 * @param re Pointer to the compiled regex object.
 * @param subj Subject string to match.
 * @param subj_length Length of the subject string.
 * @param subj_offset Offset into the subject string to begin matching.
 * @param pos_vect Output array of two size_t values for match positions.
 * @return true if a match is found, false otherwise.
 */
WS_DLL_PUBLIC bool ws_regex_matches_pos(const ws_regex_t *re,
                                        const char *subj, ssize_t subj_length,
                                        size_t subj_offset, size_t pos_vect[2]);

/**
 * @brief Frees a compiled regex object.
 *
 * Releases memory associated with the compiled regex.
 *
 * @param re Pointer to the regex object to free.
 */
WS_DLL_PUBLIC void ws_regex_free(ws_regex_t *re);

/**
 * @brief Returns the original pattern string from a compiled regex.
 *
 * Retrieves the pattern used to compile the regex object.
 *
 * @param re Pointer to the compiled regex object.
 * @return The original pattern string.
 */
WS_DLL_PUBLIC const char *ws_regex_pattern(const ws_regex_t *re);


#ifdef __cplusplus
}
#endif

#endif /* __WSUTIL_REGEX_H__ */
