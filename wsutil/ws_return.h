/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_RETURN_H__
#define __WS_RETURN_H__

#include <wsutil/wslog.h>
#include <wsutil/wmem/wmem.h>

/*
 * These macros can be used as an alternative to ws_assert() to
 * assert some condition on function arguments. This must only be used
 * to catch programming errors, in situations where an assertion is
 * appropriate. And it should only be used if failing the condition
 * doesn't necessarily lead to an inconsistent state for the program.
 *
 * It is possible to set the fatal log domain to "InvalidArg" to abort
 * execution for debugging purposes, if one of these checks fail.
 */

#define ws_warn_badarg(str) \
    ws_log_full(LOG_DOMAIN_EINVAL, LOG_LEVEL_INFO, \
                    __FILE__, __LINE__, __func__, \
                    "bad argument: %s", str)

#define ws_return_str_if(expr, scope) \
        do { \
            if (expr) { \
                ws_warn_badarg(#expr); \
                return wmem_strdup(scope, "(invalid argument)"); \
            } \
        } while (0)

#define ws_return_val_if(expr, val) \
        do { \
            if (expr) { \
                ws_warn_badarg(#expr); \
                return (val); \
            } \
        } while (0)

#endif /* WS_RETURN_H_ */
