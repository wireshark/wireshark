/** @file
 *
 * text_import_regex.h
 * Regex based alternative to the state machine for text import
 * February 2021, Paul Weiß <paulniklasweiss@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on text_import.h by Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*
 *******************************************************************************/


#ifndef __TEXT_IMPORT_REGEX_H__
#define __TEXT_IMPORT_REGEX_H__

#include <glib.h>

#include "text_import.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Parses data based on the specified encoding.
 *
 * @param start_field Pointer to the start of the field containing the data.
 * @param end_field Pointer to the end of the field containing the data.
 * @param encoding The encoding type of the data (e.g., HEX, OCT, BIN, BASE64).
 */
void parse_data(unsigned char* start_field, unsigned char* end_field, enum data_encoding encoding);

/**
 * @brief Parses directory information from a given field.
 * @param start_field Pointer to the start of the field.
 * @param end_field Pointer to the end of the field.
 * @param in_indicator Pointer to the input indicator string.
 * @param out_indicator Pointer to the output indicator string.
 */
void parse_dir(const unsigned char* start_field, const unsigned char* end_field, const char* in_indicator, const char* out_indicator);

/**
 * @brief Parses time information from a given field and updates the timestamp.
 *
 * @param start_field Pointer to the start of the time field in the input data.
 * @param end_field Pointer to the end of the time field in the input data.
 * @param format The format string specifying how to parse the time field.
 */
void parse_time(const unsigned char* start_field, const unsigned char* end_field, const char* format);

/**
 * @brief Parses sequence number from a given field.
 *
 * @param start_field Pointer to the start of the field.
 * @param end_field Pointer to the end of the field.
 */
void parse_seqno(const unsigned char* start_field, const unsigned char* end_field);

/**
 * @brief Flushes the current packet and prepares for the next one.
 */
void flush_packet(void);

/**
* @brief Imports text data using regular expressions.
*
* @param info Pointer to the import information structure.
* @return int Status of the import operation (1 for success, 0 for failure).
*/
int text_import_regex(const text_import_info_t *info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TEXT_IMPORT_REGEX_H__ */
