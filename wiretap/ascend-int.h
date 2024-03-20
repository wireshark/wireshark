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
    FILE_T fh;
    const char *ascend_parse_error;
    int err;
    char *err_info;
    struct ascend_phdr *pseudo_header;
    uint8_t *pkt_data;

    bool saw_timestamp;
    time_t timestamp;

    int64_t first_hexbyte;
    uint32_t wirelen;
    uint32_t caplen;
    time_t secs;
    uint32_t usecs;

    ascend_token_t token;
} ascend_state_t;

extern bool
run_ascend_parser(uint8_t *pd, ascend_state_t *parser_state, int *err, char **err_info);

#endif /* ! __ASCEND_INT_H__ */
