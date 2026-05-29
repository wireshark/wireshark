/** @file
 *
 * Definitions for routines common to multiple modules in the Lucent/Ascend
 * capture file reading code, but not used outside that code.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __ASCEND_INT_H__
#define __ASCEND_INT_H__

#include <stdbool.h>
#include "ws_symbol_export.h"

/**
 * @brief Holds per-file state for reading an Ascend capture file.
 */
typedef struct {
    time_t   inittime;               /**< Timestamp of the first packet, used as the reference epoch for relative time calculations. */
    bool     adjusted;               /**< Whether the timestamps in this file have been adjusted to an absolute epoch. */
    int64_t  next_packet_seek_start; /**< File offset at which to begin seeking for the next packet record. */
} ascend_t;


/**
 * @brief Holds the parsed value of a single token produced by the Ascend file lexer.
 */
typedef struct {
    int      length;                      /**< Length in bytes of the token's string representation. */
    uint32_t u32_val;                     /**< Parsed 32-bit unsigned integer value of the token, if applicable. */
    uint16_t u16_val;                     /**< Parsed 16-bit unsigned integer value of the token, if applicable. */
    uint8_t  u8_val;                      /**< Parsed 8-bit unsigned integer value of the token, if applicable. */
    char     str_val[ASCEND_MAX_STR_LEN]; /**< Parsed string value of the token, if applicable; NUL-terminated. */
} ascend_token_t;

/**
 * @brief Tracks the full parser state while reading and decoding a single Ascend capture record.
 */
typedef struct {
    FILE_T               fh;                 /**< File handle for the Ascend capture file being parsed. */
    const char          *ascend_parse_error; /**< Human-readable parse error string; NULL if no error has occurred. */
    int                  err;                /**< Wiretap error code set if a read or parse error is encountered. */
    char                *err_info;           /**< Additional detail string associated with @p err; must be freed by the caller. */
    struct ascend_phdr  *pseudo_header;      /**< Pointer to the Ascend pseudo-header populated during parsing. */
    uint8_t             *pkt_data;           /**< Pointer to the buffer receiving the decoded packet payload bytes. */
    bool                 saw_timestamp;      /**< Whether a timestamp record has been encountered for the current packet. */
    time_t               timestamp;          /**< Parsed wall-clock timestamp of the current packet record. */
    int64_t              first_hexbyte;      /**< File offset of the first hex data byte of the current packet record. */
    uint32_t             wirelen;            /**< Original on-wire length of the current packet in bytes. */
    uint32_t             caplen;             /**< Captured length of the current packet in bytes. */
    time_t               secs;              /**< Seconds component of the current packet's arrival timestamp. */
    uint32_t             usecs;             /**< Microseconds component of the current packet's arrival timestamp. */
    ascend_token_t       token;             /**< Most recently scanned token from the Ascend file lexer. */
} ascend_state_t;

/**
 * @brief Runs the Ascend parser on the given packet data.
 *
 * @param pd Pointer to the packet data.
 * @param parser_state Pointer to the parser state structure.
 * @param err Pointer to an integer where any error code will be stored.
 * @param err_info Pointer to a string where any error information will be stored.
*/
extern bool
run_ascend_parser(uint8_t *pd, ascend_state_t *parser_state, int *err, char **err_info);

#endif /* ! __ASCEND_INT_H__ */
