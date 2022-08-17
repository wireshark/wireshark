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
    gboolean adjusted;
    gint64 next_packet_seek_start;
} ascend_t;

typedef struct {
    int length;
    guint32 u32_val;
    guint16 u16_val;
    guint8 u8_val;
    char str_val[ASCEND_MAX_STR_LEN];
} ascend_token_t;

typedef struct {
    FILE_T fh;
    const gchar *ascend_parse_error;
    int err;
    gchar *err_info;
    struct ascend_phdr *pseudo_header;
    guint8 *pkt_data;

    gboolean saw_timestamp;
    time_t timestamp;

    gint64 first_hexbyte;
    guint32 wirelen;
    guint32 caplen;
    time_t secs;
    guint32 usecs;

    ascend_token_t token;
} ascend_state_t;

extern bool
run_ascend_parser(guint8 *pd, ascend_state_t *parser_state, int *err, gchar **err_info);

#endif /* ! __ASCEND_INT_H__ */
