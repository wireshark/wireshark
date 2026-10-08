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

#include <glib.h>
#include <stdbool.h>
#include "ws_symbol_export.h"

/*
 * Maximum length of a line. Real lines are around 80 characters; this
 * just keeps the scanner from reading arbitrarily far into a non-Ascend
 * file.
 */
#define ASCEND_MAX_LINE_LEN 1024

/**
 * @brief Holds per-file state for reading an Ascend capture file.
 */
typedef struct {
    time_t inittime;
    bool adjusted;
    int64_t next_packet_seek_start;
} ascend_t;

typedef struct {
    int length;
    uint32_t u32_val;
    uint16_t u16_val;
    uint8_t u8_val;
    char str_val[ASCEND_MAX_STR_LEN];
} ascend_token_t;

typedef struct {
    FILE_T               fh;                 /**< File handle for the Ascend capture file being parsed. */
    const char          *ascend_parse_error; /**< Human-readable parse error string; NULL if no error has occurred. */
    int                  err;                /**< Wiretap error code set if a read or parse error is encountered. */
    char                *err_info;           /**< Additional detail string associated with @p err; must be freed by the caller. */
    struct ascend_phdr  *pseudo_header;      /**< Pointer to the Ascend pseudo-header populated during parsing. */
    uint8_t             *pkt_data;           /**< Pointer to the buffer receiving the decoded packet payload bytes. */
    bool                 saw_timestamp;      /**< Whether a timestamp record has been encountered for the current packet. */
    time_t               timestamp;          /**< Parsed wall-clock timestamp of the current packet record. */
    unsigned             line_len;           /**< Number of characters read on the current line. */
    int64_t              first_hexbyte;      /**< File offset of the first hex data byte of the current packet record. */
    uint32_t             wirelen;            /**< Original on-wire length of the current packet in bytes. */
    uint32_t             caplen;             /**< Captured length of the current packet in bytes. */
    time_t               secs;              /**< Seconds component of the current packet's arrival timestamp. */
    uint32_t             usecs;             /**< Microseconds component of the current packet's arrival timestamp. */
    ascend_token_t       token;             /**< Most recently scanned token from the Ascend file lexer. */
} ascend_state_t;

extern bool
run_ascend_parser(uint8_t *pd, ascend_state_t *parser_state, int *err, char **err_info);

#endif /* ! __ASCEND_INT_H__ */
