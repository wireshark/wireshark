/** @file
 *
 * JSON parsing functions.
 *
 * Copyright 2016, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSJSON_H__
#define __WSJSON_H__

#include "ws_symbol_export.h"

#include <inttypes.h>
#include <stdbool.h>

#include "jsmn.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Check if a buffer is valid JSON.
 *
 * @param buf - A buffer containing JSON.
 * @param len - The length of the JSON data in the buffer.
 * @return true if the JSON is valid.
 *
 * @note This requires that the buffer be complete valid JSON that requires
 * no more than 1024 tokens. For larger objects, or to parse what may be an
 * incomplete string, call json_parse[_len] and check the return value.
 */
WS_DLL_PUBLIC bool json_validate(const uint8_t *buf, const size_t len);

/**
 * Parse a JSON string and write the token's addresses into the tokens array.
 *
 * @param buf - A null-terminated string containing JSON.
 * @param tokens - An array for storing the parsed tokens. Can be NULL, to validate only.
 * @param max_tokens - The length of `tokens`. Ignored if `tokens` is NULL.
 * @return The number of tokens needed, or a jsmnerr (which are negative).
 *
 * @note This calls strlen() and requires that buf be a null-terminated string.
 * This can be called with NULL tokens in order to determine the number of
 * tokens necessary.
 */
WS_DLL_PUBLIC int json_parse(const char *buf, jsmntok_t *tokens, unsigned int max_tokens);

/**
 * Parse a JSON buffer and write the token's addresses into the tokens array.
 *
 * @param buf - A buffer containing JSON, not necessarily null-terminated.
 * @param len - The length of the JSON data in the buffer.
 * @param tokens - An array for storing the parsed tokens. Can be NULL, to validate only.
 * @param max_tokens - The length of `tokens`. Ignored if tokens is NULL.
 * @return The number of tokens needed, or a jsmnerr (which are negative).
 *
 * @note This still stops parsing after the first '\0' byte, if any. It's
 * useful if a buffer is not null-terminated or if the length is already
 * known. This can be called with NULL tokens in order to determine the number
 * of tokens necessary.
 */
WS_DLL_PUBLIC int json_parse_len(const char *buf, size_t len, jsmntok_t *tokens, unsigned int max_tokens);

/**
 * Get the pointer to an object belonging to the parent object and named as the name variable.
 *
 * @param buf - A buffer containing JSON, not necessarily null-terminated.
 * @param parent - JSON object to search within for the `name`.
 * @param name - The name to search the parent object for.
 * @return Pointer to the object named `name` within the parent object, or NULL if not found.
 */
WS_DLL_PUBLIC jsmntok_t *json_get_object(const char *buf, jsmntok_t *parent, const char *name);

/**
 * Get the pointer to an array belonging to the parent object and named as the name variable.
 *
 * @param buf - A buffer containing JSON, not necessarily null-terminated.
 * @param parent - JSON object to search within for the `name`.
 * @param name - The name to search the parent object for.
 * @return Pointer to the array named `name` within the parent object, or NULL if not found.
 */
WS_DLL_PUBLIC jsmntok_t *json_get_array(const char *buf, jsmntok_t *parent, const char *name);

/**
 * Get the number of elements of an array.
 *
 * @param array - JSON array.
 * @return The number of elements in an array or -1 if the JSON object is not an array.
 */
WS_DLL_PUBLIC int json_get_array_len(jsmntok_t *array);

/**
 * Get the pointer to idx element of an array.
 *
 * @note This requires iterating through the parent's elements and is inefficient
 * for iterating over an array's elements. If accessing array objects in a loop,
 * instead use `json_get_next_object`.
 *
 * @param parent - JSON array.
 * @param idx - index of element.
 * @return Pointer to idx element of an array or NULL if not found.
 */
WS_DLL_PUBLIC jsmntok_t *json_get_array_index(jsmntok_t *parent, int idx);

/**
 * Get the pointer to the next JSON element which is a sibling of `cur`.
 *
 * This is used for efficiently iterating over elements of a JSON array.
 *
 * @note This does not perform bounds checking and so can go out of bounds!
 * Be sure to track how many times this is called.
 *
 * @param cur - JSON array element.
 * @return Pointer to next sibling element.
 */
WS_DLL_PUBLIC jsmntok_t *json_get_next_object(jsmntok_t *cur);

/**
 * Get the unescaped value of a string object belonging to the parent object and named as the name variable.
 *
 * @param buf - A buffer containing JSON, not necessarily null-terminated.
 * @param parent - JSON object to search within for the `name`.
 * @param name - The name to search the parent object for.
 * @return Pointer to a string belonging to the parent object and named as the 'name' variable or NULL if not found.
 *
 * @note This modifies the input buffer.
 */
WS_DLL_PUBLIC char *json_get_string(char *buf, jsmntok_t *parent, const char *name);

/**
 * Get the value of a number object belonging to the parent object and named as the name variable.
 *
 * @param buf - A buffer containing JSON, not necessarily null-terminated.
 * @param parent - JSON object to search within for the `name`.
 * @param name - The name to search the parent object for.
 * @param val - Location to store the retrieved value.
 * @return false if not found.
 *
 * @note This modifies the input buffer. Scientific notation not supported yet.
 */
WS_DLL_PUBLIC bool json_get_double(char *buf, jsmntok_t *parent, const char *name, double *val);

/**
 * Get the value of a number object belonging to the parent object and named as the name variable.
 *
 * @param buf - A buffer containing JSON, not necessarily null-terminated.
 * @param parent - JSON object to search within for the `name`.
 * @param name - The name to search the parent object for.
 * @param val - Location to store the retrieved value.
 * @return false if not found.
 *
 * @note This modifies the input buffer.
 */
WS_DLL_PUBLIC bool json_get_int(char *buf, jsmntok_t *parent, const char *name, int64_t *val);

/**
 * Get the value of a boolean belonging to the parent object and named as the name variable.
 *
 * @param buf - A buffer containing JSON, not necessarily null-terminated.
 * @param parent - JSON object to search within for the `name`.
 * @param name - The name to search the parent object for.
 * @param val - Location to store the retrieved value.
 * @return false if not found.
 *
 * @note This modifies the input buffer.
 */
WS_DLL_PUBLIC bool json_get_boolean(char *buf, jsmntok_t *parent, const char *name, bool *val);

/**
 * Decode the contents of a JSON string value by overwriting the input data.

 * @param text - JSON string to decode.
 * @return true on success and false if invalid characters were encountered.
 */
WS_DLL_PUBLIC bool json_decode_string_inplace(char *text);

#ifdef __cplusplus
}
#endif

#endif

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
