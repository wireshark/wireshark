/** @file
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __LOGCAT_H__
#define __LOGCAT_H__

#include <glib.h>

#include "wtap.h"

/* The log format can be found on:
 * https://android.googlesource.com/platform/system/core/+/master/include/log/logger.h
 * Log format is assumed to be little-endian (Android platform).
 */
/* maximum size of a message payload in a log entry */
#define LOGGER_ENTRY_MAX_PAYLOAD 4076

struct logger_entry {
    uint16_t len;   /* length of the payload */
    uint16_t __pad; /* no matter what, we get 2 bytes of padding */
    int32_t  pid;   /* generating process's pid */
    int32_t  tid;   /* generating process's tid */
    int32_t  sec;   /* seconds since Epoch */
    int32_t  nsec;  /* nanoseconds */
/*    char    msg[0]; *//* the entry's payload */
};

struct logger_entry_v2 {
    uint16_t len;    /* length of the payload */
    uint16_t hdr_size; /* sizeof(struct logger_entry_v2) */
    int32_t  pid;    /* generating process's pid */
    int32_t  tid;    /* generating process's tid */
    int32_t  sec;    /* seconds since Epoch */
    int32_t  nsec;   /* nanoseconds */
    union {
                        /* v1: not present */
        uint32_t euid;  /* v2: effective UID of logger */
        uint32_t lid;   /* v3: log id of the payload */
    } id;
/*    char    msg[0]; *//* the entry's payload */
};

wtap_open_return_val  logcat_open(wtap *wth, int *err, char **err_info);

int      logcat_exported_pdu_length(const uint8_t *pd);
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
