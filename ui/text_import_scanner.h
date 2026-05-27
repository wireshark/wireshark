/** @file
 *
 * text_import_scanner.h
 * Scanner for text import
 * November 2010, Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on text2pcap.h by Ashok Narayanan <ashokn@cisco.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*
 *******************************************************************************/


#ifndef __TEXT_IMPORT_SCANNER_H__
#define __TEXT_IMPORT_SCANNER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Lexer token types produced by the hex dump text import scanner.
 */
typedef enum {
    T_BYTE      = 1, /**< A single hex byte value (two hex digits) */
    T_BYTES,         /**< A run of hex byte values on one line */
    T_OFFSET,        /**< A line offset value (hex, octal, or decimal) */
    T_DIRECTIVE,     /**< A parser directive or direction indicator */
    T_TEXT,          /**< A printable ASCII text column or annotation */
    T_EOL,           /**< End of a logical input line */
    T_EOF            /**< End of the input file */
} token_t;

/**
 * @brief Return status of a text import operation.
 */
typedef enum {
    IMPORT_SUCCESS,      /**< Import completed and all packets were written successfully */
    IMPORT_FAILURE,      /**< Import failed during parsing or packet writing */
    IMPORT_INIT_FAILED   /**< Import could not start due to initialisation failure (e.g. could not open output file) */
} import_status_t;

import_status_t parse_token(token_t token, char *str);

extern FILE *text_importin;

/**
 * @brief Scans an input file for text import data
 *
 * @param input_file The file to be scanned
 * @return The status of the scan operation
 */
import_status_t text_import_scan(FILE *input_file);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TEXT_IMPORT_SCANNER_H__ */
