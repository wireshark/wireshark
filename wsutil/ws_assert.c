/* ws_assert.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "ws_assert.h"
#include <stdlib.h>

#include "wslog.h"


void ws_assert_failed(const char *file, int line, const char *function,
                    const char *domain, const char *assertion,
                    bool unreachable)
{
    if (unreachable)
        ws_log_full(domain, LOG_LEVEL_ERROR, file, line, function,
                        "assertion \"not reached\" failed");
    else
        ws_log_full(domain, LOG_LEVEL_ERROR, file, line, function,
                        "assertion failed: %s", assertion);

    abort();
}
