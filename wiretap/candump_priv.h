/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for candump log file format
 * Copyright (c) 2019 by Maksim Salau <maksim.salau@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CANDUMP_PRIV_H__
#define CANDUMP_PRIV_H__

#include <gmodule.h>
#include <wiretap/wtap.h>
#include <wiretap/socketcan.h>
#include <epan/dissectors/packet-socketcan.h>

//#define CANDUMP_DEBUG

typedef struct {
    uint8_t    length;
    uint8_t    data[CANFD_MAX_DLEN];
} msg_data_t;

typedef struct {
    nstime_t   ts;
    uint32_t   id;
    bool       is_fd;
    uint8_t    flags;
    msg_data_t data;
} msg_t;

typedef struct {
    int64_t v0;
    int64_t v1;
} token_t;

typedef struct {
    wtap *tmp_file;
    char *tmp_filename;
} candump_priv_t;

typedef struct {
    bool is_msg_valid;
    msg_t    msg;

    FILE_T  fh;
    uint64_t file_bytes_read;

    int     err;
    char   *err_info;
    char   *parse_error;

    token_t token;
} candump_state_t;

bool
run_candump_parser(candump_state_t *state, int *err, char **err_info);

#ifdef CANDUMP_DEBUG
#include <stdio.h>
#define candump_debug_printf(...) printf(__VA_ARGS__)
#else
#define candump_debug_printf(...) (void)0
#endif

#endif  /* CANDUMP_PRIV_H__ */
