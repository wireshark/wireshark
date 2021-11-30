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
 * It is possible to set the fatal log level to "critical" to abort
 * execution for debugging purposes, if one of these checks fail.
 */

#define ws_warn_zero_len(var) ws_critical("Zero length '%s' passed to %s()", var, __func__)

#define ws_warn_null_ptr(var) ws_critical("Null pointer '%s' passed to %s()", var, __func__)


#define ws_return_str_if_zero(scope, len) \
        do { \
            if (!(len)) { \
                ws_warn_zero_len(#len); \
                return wmem_strdup(scope, "(zero length)"); \
            } \
        } while (0)

#define ws_return_str_if_null(scope, ptr) \
        do { \
            if (!(ptr)) { \
                ws_warn_null_ptr(#ptr); \
                return wmem_strdup(scope, "(null pointer)"); \
            } \
        } while (0)

#define ws_return_val_if_zero(len, val) \
        do { \
            if (!(len)) { \
                ws_warn_zero_len(#len); \
                return (val); \
            } \
        } while (0)

#define ws_return_val_if_null(ptr, val) \
        do { \
            if (!(ptr)) { \
                ws_warn_null_ptr(#ptr); \
                return (val); \
            } \
        } while (0)

#endif /* WS_RETURN_H_ */
