/** @file
 * Routines for serializing data as JSON.
 *
 * Copyright 2018, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __JSON_DUMPER_H__
#define __JSON_DUMPER_H__

#include "ws_symbol_export.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Example:
 *
 *  json_dumper dumper = {
 *      .output_file = stdout, // or .output_string = g_string_new(NULL)
 *      .flags = JSON_DUMPER_FLAGS_PRETTY_PRINT,
 *  };
 *  json_dumper_begin_object(&dumper);
 *  json_dumper_set_member_name(&dumper, "key");
 *  json_dumper_value_string(&dumper, "value");
 *  json_dumper_set_member_name(&dumper, "array");
 *  json_dumper_begin_array(&dumper);
 *  json_dumper_value_anyf(&dumper, "true");
 *  json_dumper_value_double(&dumper, 1.0);
 *  json_dumper_begin_base64(&dumper);
 *  json_dumper_write_base64(&dumper, (const unsigned char *)"abcd", 4);
 *  json_dumper_write_base64(&dumper, (const unsigned char *)"1234", 4);
 *  json_dumper_end_base64(&dumper);
 *  json_dumper_begin_object(&dumper);
 *  json_dumper_end_object(&dumper);
 *  json_dumper_begin_array(&dumper);
 *  json_dumper_end_array(&dumper);
 *  json_dumper_end_array(&dumper);
 *  json_dumper_end_object(&dumper);
 *  json_dumper_finish(&dumper);
 */

/** Maximum object/array nesting depth. */
#define JSON_DUMPER_MAX_DEPTH   1100
/**
 * @brief State and configuration for incrementally writing JSON output to a file or string.
 */
typedef struct json_dumper {
    FILE    *output_file;    /**< Output file handle; if non-NULL, JSON is written here. */
    GString *output_string;  /**< Output GLib string buffer; if non-NULL, JSON is appended here. */
#define JSON_DUMPER_FLAGS_PRETTY_PRINT  (1 << 0)   /**< Enable pretty-printed output with indentation and newlines. */
#define JSON_DUMPER_DOT_TO_UNDERSCORE   (1 << 1)   /**< Replace '.' with '_' in all object key names. */
#define JSON_DUMPER_FLAGS_NO_DEBUG      (1 << 17)  /**< Suppress fatal ws_error messages on misuse; intended to improve fuzzing throughput. */
    int     flags;           /**< Bitmask of JSON_DUMPER_* flags controlling output formatting and error handling behaviour. */
    /* For internal use; initialize with zeroes. */
    unsigned current_depth;  /**< Current nesting depth of open objects and arrays. */
    int     base64_state;    /**< Incremental base64 encoder state used when streaming binary data. */
    int     base64_save;     /**< Partially accumulated bits carried over between incremental base64 encoding calls. */
    uint8_t state[JSON_DUMPER_MAX_DEPTH]; /**< Per-depth state flags tracking whether a separator is needed before the next value. */
    /* Internal write buffer */
#define JD_BUF_SIZE 8192
    char    buf[JD_BUF_SIZE]; /**< Internal buffer to batch small writes. */
    size_t  buf_pos;         /**< Current position in internal buffer. */
} json_dumper;

/**
 * @brief Begins a new JSON object.
 *
 * Starts a JSON object context. Must be paired with a call to json_dumper_end_object().
 *
 * @param dumper The JSON dumper context.
 */
WS_DLL_PUBLIC void
json_dumper_begin_object(json_dumper *dumper);

/**
 * @brief Sets the name of the next member in a JSON object.
 *
 * Specifies the key for the next value to be written inside an open JSON object.
 *
 * @param dumper The JSON dumper context.
 * @param name The name of the member key.
 */
WS_DLL_PUBLIC void
json_dumper_set_member_name(json_dumper *dumper, const char *name);

/**
 * @brief Ends the current JSON object.
 *
 * Closes the current object context started by json_dumper_begin_object().
 *
 * @param dumper The JSON dumper context.
 */
WS_DLL_PUBLIC void
json_dumper_end_object(json_dumper *dumper);

/**
 * @brief Begins a new JSON array.
 *
 * Starts a JSON array context. Must be paired with a call to json_dumper_end_array().
 *
 * @param dumper The JSON dumper context.
 */
WS_DLL_PUBLIC void
json_dumper_begin_array(json_dumper *dumper);

/**
 * @brief Ends the current JSON array.
 *
 * Closes the current array context started by json_dumper_begin_array().
 *
 * @param dumper The JSON dumper context.
 */
WS_DLL_PUBLIC void
json_dumper_end_array(json_dumper *dumper);

/**
 * @brief Writes a string value to the JSON output.
 *
 * Adds a properly escaped string value to the current object or array.
 *
 * @param dumper The JSON dumper context.
 * @param value The string value to write.
 */
WS_DLL_PUBLIC void
json_dumper_value_string(json_dumper *dumper, const char *value);

/**
 * @brief Writes a string value that is known to not require JSON escaping.
 *
 * Skips the escape-scanning overhead. The caller guarantees the string
 * contains no characters that need escaping (no control chars, backslash, or quotes).
 *
 * @param dumper The JSON dumper context.
 * @param value The pre-validated string value.
 * @param len Length of the string.
 */
WS_DLL_PUBLIC void
json_dumper_value_string_noesc(json_dumper *dumper, const char *value, size_t len);

/**
 * @brief Writes a double-precision numeric value to the JSON output.
 *
 * Adds a floating-point number to the current object or array.
 *
 * @param dumper The JSON dumper context.
 * @param value The double value to write.
 */
WS_DLL_PUBLIC void
json_dumper_value_double(json_dumper *dumper, double value);

/**
 * @brief Writes a formatted literal value to the JSON output.
 *
 * Dumps a literal value such as a number, "true", "false", or "null" using printf-style formatting.
 *
 * @param dumper The JSON dumper context.
 * @param format The format string for the value.
 * @param ... Additional arguments for formatting.
 */
WS_DLL_PUBLIC void
json_dumper_value_anyf(json_dumper *dumper, const char *format, ...)
G_GNUC_PRINTF(2, 3);

/**
 * @brief Writes a formatted literal value using a va_list.
 *
 * Similar to json_dumper_value_anyf(), but accepts a va_list for formatting.
 * String values must be properly quoted and escaped by the caller.
 * Not safe for untrusted input.
 *
 * @param dumper The JSON dumper context.
 * @param format The format string for the value.
 * @param ap The va_list of arguments.
 */
WS_DLL_PUBLIC void
json_dumper_value_va_list(json_dumper *dumper, const char *format, va_list ap);

/**
 * @brief Writes a signed 64-bit integer value without printf overhead.
 *
 * @param dumper The JSON dumper context.
 * @param value The integer value to write.
 */
WS_DLL_PUBLIC void
json_dumper_value_int(json_dumper *dumper, int64_t value);

/**
 * @brief Writes an unsigned 64-bit integer value without printf overhead.
 *
 * @param dumper The JSON dumper context.
 * @param value The integer value to write.
 */
WS_DLL_PUBLIC void
json_dumper_value_uint(json_dumper *dumper, uint64_t value);

/**
 * @brief Begins a base64-encoded data block.
 *
 * Starts a base64 encoding context for binary data. Must be paired with json_dumper_end_base64().
 *
 * @param dumper The JSON dumper context.
 */
WS_DLL_PUBLIC void
json_dumper_begin_base64(json_dumper *dumper);

/**
 * @brief Ends a base64-encoded data block.
 *
 * Closes the base64 encoding context started by json_dumper_begin_base64().
 *
 * @param dumper The JSON dumper context.
 */
WS_DLL_PUBLIC void
json_dumper_end_base64(json_dumper *dumper);

/**
 * @brief Writes binary data in base64 format.
 *
 * Encodes and writes the given binary data as base64 within an active base64 context.
 *
 * @param dumper The JSON dumper context.
 * @param data Pointer to the binary data.
 * @param len Length of the binary data in bytes.
 */
WS_DLL_PUBLIC void
json_dumper_write_base64(json_dumper *dumper, const unsigned char *data, size_t len);

/**
 * @brief Finalizes the JSON output.
 *
 * Completes the JSON dump and checks for structural correctness (e.g., matching open/close calls).
 *
 * @param dumper The JSON dumper context.
 * @return true if the output is valid and complete, false if errors occurred.
 */
WS_DLL_PUBLIC bool
json_dumper_finish(json_dumper *dumper);

#ifdef __cplusplus
}
#endif

#endif /* __JSON_DUMPER_H__ */

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
