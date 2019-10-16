/* candump-priv.h
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
    guint8     length;
    guint8     data[CANFD_MAX_DLEN];
} msg_data_t;

typedef struct {
    nstime_t   ts;
    guint32    id;
    gboolean   is_fd;
    guint8     flags;
    msg_data_t data;
} msg_t;

typedef struct {
    gint64 v0;
    gint64 v1;
} token_t;

typedef struct {
    wtap *tmp_file;
    char *tmp_filename;
} candump_priv_t;

typedef struct {
    gboolean is_msg_valid;
    msg_t    msg;

    FILE_T  fh;
    guint64 file_bytes_read;

    int     err;
    gchar  *err_info;
    gchar  *parse_error;

    token_t token;
} candump_state_t;

gboolean
run_candump_parser(candump_state_t *state, int *err, gchar **err_info);

#include <wsutil/ws_printf.h>

/* Uncomment the following line to make decoder verbose */
//#undef NDEBUG

#ifdef NDEBUG
#undef  ws_debug_printf
#define ws_debug_printf(...) (void)0
#endif

#endif  /* CANDUMP_PRIV_H__ */
