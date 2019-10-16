/* logcat.h
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
    guint16 len;    /* length of the payload */
    guint16 __pad;  /* no matter what, we get 2 bytes of padding */
    gint32  pid;    /* generating process's pid */
    gint32  tid;    /* generating process's tid */
    gint32  sec;    /* seconds since Epoch */
    gint32  nsec;   /* nanoseconds */
/*    char    msg[0]; *//* the entry's payload */
};

struct logger_entry_v2 {
    guint16 len;    /* length of the payload */
    guint16 hdr_size; /* sizeof(struct logger_entry_v2) */
    gint32  pid;    /* generating process's pid */
    gint32  tid;    /* generating process's tid */
    gint32  sec;    /* seconds since Epoch */
    gint32  nsec;   /* nanoseconds */
    union {
                        /* v1: not present */
        guint32 euid;   /* v2: effective UID of logger */
        guint32 lid;    /* v3: log id of the payload */
    } id;
/*    char    msg[0]; *//* the entry's payload */
};

wtap_open_return_val  logcat_open(wtap *wth, int *err, gchar **err_info);

gboolean logcat_binary_dump_open(wtap_dumper *wdh, int *err);

int      logcat_dump_can_write_encap(int encap);

gint     logcat_exported_pdu_length(const guint8 *pd);
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
