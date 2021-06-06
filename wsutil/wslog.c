/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2021 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "wslog.h"

#include <stdio.h>
#include <stdarg.h>

#define LOGBUFSIZE  256

void ws_log_full(const char *log_domain, GLogLevelFlags log_level,
                    const char *file, int line, const char *func,
                    const char *format, ...)
{
    va_list ap;
    char log_msg[LOGBUFSIZE];

    va_start(ap, format);
    vsnprintf(log_msg, sizeof(log_msg), format, ap);
    va_end(ap);

    g_log(log_domain, log_level, "%s(%d):%s: %s", file, line, func, log_msg);
}
